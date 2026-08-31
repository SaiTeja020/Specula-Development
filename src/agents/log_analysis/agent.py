"""
Log Analysis Agent — Main Orchestrator.

Consumes normalized OCSF events from Kafka (CONSUMED_TOPIC), runs
deterministic rule-based and statistical anomaly detection, then
orchestrates LLM narration via llm_reasoner.assess_batch(). Publishes
grounded findings to FINDINGS_TOPIC via Kafka only.

IMPORT BOUNDARY (enforced by test_agent_integration.py test 9.6):
    This file MUST NOT import any Cypher-write function or Neo4j driver.
    Only dfkg_read_client and kafka_producer are permitted I/O deps.
    If you see any Cypher-write function or Neo4j driver class imported
    here, it is a bug — remove it immediately.

WRITE PATH:
    Zero direct DFKG writes. Kafka (kafka_producer) is the only output
    path. Downstream consumers of the Kafka finding stream handle
    DFKG persistence.

RBAC MANIFEST (see config.ALLOWED_TOOLS / FORBIDDEN_TOOLS):
    Allowed:   mcp-dfkg-cypher (read), detect_anomaly, parse_log_batch,
               query_dfkg, publish_finding (Kafka), retrieve_similar_events.
    Forbidden: mcp-vmi-sandbox, mcp-threat-intel, retrieve_similar_cases,
               any direct Cypher-write function.

Non-goals:
    - No Malware/ATT&CK_Technique/NetworkEndpoint graph edges.
    - No retrieve_similar_cases (cross-case).
    - No Daubert readiness claim — agent_traces is interim (item #45).
    - No persistent checkpointing (TODO: harness §9.5).
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from src.agents.log_analysis import config
from src.agents.log_analysis.anomaly_detector import (
    BaselineStore,
    detect_anomaly,
    update_baseline,
)
from src.agents.log_analysis.dedup import fingerprint, is_duplicate, write_fingerprint
from src.agents.log_analysis.detection_rules import load_signatures, run_rule_layer
from src.agents.log_analysis.finding_builder import build_finding
from src.agents.log_analysis.llm_reasoner import AssessmentResult, assess_batch
from src.schemas.ocsf_base import OCSFBaseEvent

logger = logging.getLogger(__name__)

# ─── FORCE_DEAD_END flag (test-injectable, per implementation plan §7c) ────────
# Set to True in tests to simulate dead-end without waiting real clock time.
FORCE_DEAD_END: bool = False


class LogAnalysisAgent:
    """
    Log Analysis Agent.

    Consumes ProcessActivity (1007) and FileActivity (1001) events from
    Kafka via run_on_batch(), runs rule + anomaly detection, then uses
    the LLM reasoner to narrate and publish grounded findings.

    Args:
        model_router:      Callable(prompt: str) -> str. Calls the LLM.
        kafka_consumer:    Iterable yielding (events, kafka_offset) tuples.
        kafka_producer:    Callable(topic: str, payload: dict) -> None.
        dfkg_read_client:  Object with .query(uid: str) -> list[str] method.
        vector_client:     VectorRetrievalMCPServer instance (event-level only).
        redis_client:      Redis client satisfying dedup.RedisClient protocol.
        loop_budget:       Max ReAct iterations (default: config.LOOP_BUDGET_MAX_ITERATIONS).
        system_prompt:     System prompt template for LLM (loaded from config YAML).
    """

    ROLE: str = config.AGENT_ROLE

    # Whitelist check: node/edge types this agent may construct Cypher params for.
    _ALLOWED_NODE_TYPES = config.ALLOWED_NODE_TYPES
    _ALLOWED_EDGE_TYPES = config.ALLOWED_EDGE_TYPES
    _FORBIDDEN_EDGE_TYPES = config.FORBIDDEN_EDGE_TYPES

    def __init__(
        self,
        model_router: Any,
        kafka_consumer: Any,
        kafka_producer: Any,
        dfkg_read_client: Any,
        vector_client: Any,
        redis_client: Any,
        loop_budget: int = config.LOOP_BUDGET_MAX_ITERATIONS,
        system_prompt: str = "",
    ) -> None:
        self._model_router = model_router
        self._kafka_consumer = kafka_consumer
        self._kafka_producer = kafka_producer
        self._dfkg_read_client = dfkg_read_client
        self._vector_client = vector_client
        self._redis_client = redis_client
        self._loop_budget = loop_budget
        self._system_prompt = system_prompt

        self._baseline_store = BaselineStore()
        self._signatures = load_signatures()

        # TODO: wire persistent checkpointing (harness §9.5)
        self._agent_traces: list[dict] = []

        # Progress tracking for dead-end detection (§7c).
        self._last_progress_time: float = time.time()

    # ─── Core batch processing ──────────────────────────────────────────────

    def run_on_batch(
        self,
        events: list[OCSFBaseEvent],
        kafka_offset: int,
        case_dedup_ttl_seconds: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Process a batch of OCSF events through the full detection pipeline.

        Steps:
          1. Filter to CONSUMED_CLASS_UIDS — others pass through untouched.
          2. Update anomaly baseline for all in-scope events.
          3. Run rule layer per event.
          4. Compute anomaly signals per event.
          5. Skip events where both layers are silent.
          6. Invoke LLM reasoner for suspicious events.
          7. Dedup, build, and publish findings.

        Args:
            events:                 Batch of OCSFBaseEvent objects.
            kafka_offset:           Kafka offset of this batch.
            case_dedup_ttl_seconds: TTL for dedup Redis entries (case window).

        Returns:
            List of published finding dicts.
        """
        # ── Step 1: Filter to in-scope events ────────────────────────────────
        in_scope = [e for e in events if e.class_uid in config.CONSUMED_CLASS_UIDS]
        if not in_scope:
            logger.debug("Batch at offset=%d: no in-scope events, skipping.", kafka_offset)
            return []

        # ── Step 2: Update anomaly baseline for all in-scope events ───────────
        for event in in_scope:
            update_baseline(self._baseline_store, event)

        # ── Step 3: Rule layer ────────────────────────────────────────────────
        rule_signals_per_event: list[list[dict]] = [
            run_rule_layer(e, self._signatures) for e in in_scope
        ]

        # ── Step 4: Anomaly layer ─────────────────────────────────────────────
        anomaly_signals_per_event: list[dict | None] = [
            detect_anomaly(self._baseline_store, e) for e in in_scope
        ]

        # ── Step 5: Filter out silent events ──────────────────────────────────
        has_signal = [
            bool(rule_signals_per_event[i]) or anomaly_signals_per_event[i] is not None
            for i in range(len(in_scope))
        ]
        suspicious_events = [e for i, e in enumerate(in_scope) if has_signal[i]]
        suspicious_rule_sigs = [s for i, s in enumerate(rule_signals_per_event) if has_signal[i]]
        suspicious_anomaly_sigs = [s for i, s in enumerate(anomaly_signals_per_event) if has_signal[i]]

        if not suspicious_events:
            logger.debug(
                "Batch at offset=%d: all %d events passed rule+anomaly check silently.",
                kafka_offset, len(in_scope),
            )
            return []

        # ── Step 6: LLM reasoning ─────────────────────────────────────────────
        assessment_results: list[AssessmentResult] = assess_batch(
            events=suspicious_events,
            rule_signals=suspicious_rule_sigs,
            anomaly_signals=suspicious_anomaly_sigs,
            model_router=self._model_router,
            dfkg_read_client=self._dfkg_read_client,
            system_prompt=self._system_prompt,
        )

        # ── Step 7: Dedup, build, publish ─────────────────────────────────────
        published: list[dict[str, Any]] = []

        for result in assessment_results:
            event = result.event
            time_bucket = self._time_bucket(event)
            affected_entity_uids = self._extract_entity_uids(event, result)

            fp = fingerprint(result.pattern, affected_entity_uids, time_bucket)

            # ── Dedup check ───────────────────────────────────────────────────
            if is_duplicate(fp, self._redis_client):
                logger.debug(
                    "Duplicate finding suppressed: pattern=%s uid=%s",
                    result.pattern, event.uid,
                )
                continue

            # ── dfkg_refs validation (belt-and-braces, item #20) ─────────────
            if not result.dfkg_refs:
                if not result.degraded:
                    # Non-degraded path with empty refs: surface the error.
                    logger.error(
                        "Skipping finding for event uid=%s: dfkg_refs is empty "
                        "(non-degraded path). This violates item #20.",
                        event.uid,
                    )
                    continue
                else:
                    # Degraded path: no deterministic signals either → skip cleanly.
                    logger.info(
                        "Skipping degraded finding for event uid=%s: "
                        "no signals and no dfkg_refs — clean skip per §7a.",
                        event.uid,
                    )
                    continue

            # ── Build finding ─────────────────────────────────────────────────
            try:
                finding = build_finding(
                    source_event=event,
                    agent_role=self.ROLE,
                    summary=result.summary,
                    severity=result.severity,
                    pattern=result.pattern,
                    affected_count=len(affected_entity_uids),
                    timeline_range=(
                        str(getattr(event, "time", "")),
                        str(getattr(event, "time", "")),
                    ),
                    dfkg_refs=result.dfkg_refs,
                    kafka_offset=kafka_offset,
                    confidence=result.confidence,
                )
            except (ValueError, TypeError) as exc:
                logger.error("build_finding failed for event uid=%s: %s", event.uid, exc)
                continue

            # ── Attach escalation flag (item #41) ─────────────────────────────
            if result.confidence < config.LOW_CONFIDENCE_ESCALATION_THRESHOLD:
                finding["escalated"] = True

            # ── Attach degradation marker (§7a) ──────────────────────────────
            if result.degraded:
                finding["confidence"] = 0.0
                finding["escalated"] = True
                finding["summary"] = (
                    "model_unavailable — rule/anomaly-only pass. " + finding["summary"]
                )

            # ── Publish to Kafka ───────────────────────────────────────────────
            try:
                self._kafka_producer(config.FINDINGS_TOPIC, finding)
            except Exception as exc:
                logger.error(
                    "Kafka publish failed for finding (pattern=%s, uid=%s): %s",
                    result.pattern, event.uid, exc,
                )
                continue

            # ── Write dedup fingerprint ONLY after successful publish ─────────
            write_fingerprint(fp, self._redis_client, ttl_seconds=case_dedup_ttl_seconds)

            # ── Append agent trace (item #28) ─────────────────────────────────
            trace = {
                "agent_role": self.ROLE,
                "thought": f"Detected {result.pattern} on event uid={event.uid}",
                "action": "publish_finding",
                "observation": result.summary[:200],
                "model_used": result.model_used,
                "latency_ms": result.latency_ms,
            }
            self._agent_traces.append(trace)

            self._last_progress_time = time.time()
            published.append(finding)

        return published

    # ─── Kafka consumer loop ─────────────────────────────────────────────────

    def consume_loop(self, case_dedup_ttl_seconds: int | None = None) -> None:
        """
        Pull from CONSUMED_TOPIC / CONSUMER_GROUP using a tumbling window:
        up to BATCH_MAX_EVENTS events or BATCH_MAX_SECONDS seconds,
        whichever fires first. [RESOLVED item #4]

        Calls run_on_batch per window.
        Exits when the consumer is exhausted or an unrecoverable error occurs.
        """
        logger.info(
            "LogAnalysisAgent starting consume_loop on topic=%s group=%s",
            config.CONSUMED_TOPIC,
            config.CONSUMER_GROUP,
        )
        for events, kafka_offset in self._kafka_consumer:
            if FORCE_DEAD_END:
                logger.info("FORCE_DEAD_END flag set — exposing dead-end signal.")
                self._expose_dead_end_signal()
                break

            self._check_dead_end()
            self.run_on_batch(events, kafka_offset, case_dedup_ttl_seconds)

    # ─── Dead-end detection (§7c) ─────────────────────────────────────────────

    def _check_dead_end(self) -> None:
        """
        If no progress for DEAD_END_NO_PROGRESS_SECONDS, expose dead-end
        signal to the Supervisor. This agent does NOT implement dead-end
        detection logic itself — it only exposes the signal.
        """
        elapsed = time.time() - self._last_progress_time
        if elapsed > config.DEAD_END_NO_PROGRESS_SECONDS:
            self._expose_dead_end_signal()

    def _expose_dead_end_signal(self) -> None:
        """Publish a dead-end signal that the Supervisor polls."""
        logger.warning(
            "LogAnalysisAgent dead-end signal: no progress for >%ds.",
            config.DEAD_END_NO_PROGRESS_SECONDS,
        )
        # TODO: integrate with Supervisor inactivity heuristic (Master doc §10/§14.1)

    # ─── Helper methods ───────────────────────────────────────────────────────

    @staticmethod
    def _time_bucket(event: OCSFBaseEvent) -> str:
        """Return an hourly time bucket string for the event."""
        t: datetime | None = getattr(event, "time", None)
        if t is None:
            return "unknown_hour"
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return t.strftime("%Y-%m-%dT%H")

    @staticmethod
    def _extract_entity_uids(
        event: OCSFBaseEvent,
        result: AssessmentResult,
    ) -> list[str]:
        """
        Extract affected entity UIDs for dedup fingerprinting.
        Prefers DFKG refs; falls back to the event's own uid.
        """
        if result.dfkg_refs:
            return list(result.dfkg_refs)
        # Fallback: use the event's own deterministic uid.
        return [event.uid]

    def _validate_cypher_node_type(self, node_type: str) -> None:
        """
        Whitelist check for any Cypher parameter construction.
        Raises ValueError if node_type is not in ALLOWED_NODE_TYPES.
        Call this wherever this agent constructs Cypher parameters.
        """
        if node_type not in self._ALLOWED_NODE_TYPES:
            raise ValueError(
                f"Agent {self.ROLE} attempted to construct Cypher params for "
                f"forbidden node type {node_type!r}. "
                f"Allowed: {self._ALLOWED_NODE_TYPES}"
            )

    def _validate_cypher_edge_type(self, edge_type: str) -> None:
        """
        Whitelist check for edge types in Cypher parameter construction.
        Raises ValueError if edge_type is in FORBIDDEN_EDGE_TYPES.
        """
        if edge_type in self._FORBIDDEN_EDGE_TYPES:
            raise ValueError(
                f"Agent {self.ROLE} attempted to construct Cypher params for "
                f"forbidden edge type {edge_type!r}. "
                f"Forbidden: {self._FORBIDDEN_EDGE_TYPES}"
            )
        if edge_type not in self._ALLOWED_EDGE_TYPES:
            raise ValueError(
                f"Agent {self.ROLE}: edge type {edge_type!r} is not in the "
                f"allowed set {self._ALLOWED_EDGE_TYPES}."
            )

    def get_agent_traces(self) -> list[dict]:
        """Return the accumulated agent traces for this session."""
        return list(self._agent_traces)
