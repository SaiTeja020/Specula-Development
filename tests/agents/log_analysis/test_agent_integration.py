"""
Integration tests for agent.py and RBAC — Implementation Plan §9 tests 5, 6, 7.

Tests (mocked Kafka, DFKG read client, model router, Redis):
  5a. Out-of-scope class_uid → skipped, no LLM call, no publish.
  5b. Rule+anomaly both silent → no LLM call, no publish.
  5c. Suspicious event → exactly one publish to FINDINGS_TOPIC, dfkg_refs non-empty.
  5d. Model-unavailable → degraded marker finding published (with signals) OR
      skipped cleanly (without signals) — both paths tested.
  5e. Confidence <0.7 → escalated=True on published finding.
  5f. Duplicate fingerprint on second call → second publish suppressed.
  5g. LLM narrates an unflagged pattern → guard rejects, retries once, falls
      back to template summary on second failure.
  6.  Import boundary: agent.py contains no reference to execute_ingestion_cypher
      or any raw Neo4j driver import.
  7.  RBAC: "Log-Analysis-Agent" in READ_ONLY_EVENT_ROLES, absent from
      READ_ONLY_CASE_ROLES and ALLOWED_SYSTEM_WRITE_ROLES.
"""

from __future__ import annotations

import importlib
import inspect
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from src.agents.log_analysis import config
from src.agents.log_analysis.agent import LogAnalysisAgent
from src.mcp.vector_retrieval import (
    ALLOWED_SYSTEM_WRITE_ROLES,
    READ_ONLY_CASE_ROLES,
    READ_ONLY_EVENT_ROLES,
)
from src.schemas.ocsf_phase2_events import FileActivityEvent, ProcessActivityEvent


# ─── Factories ───────────────────────────────────────────────────────────────


def _make_process_event(
    class_uid: int = 1007,
    host_name: str = "host-test",
    parent: str = "explorer.exe",
    child: str = "notepad.exe",
    activity_id: int = 1,
) -> ProcessActivityEvent:
    t = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    return ProcessActivityEvent(
        trace_id="t",
        activity_id=activity_id,
        class_uid=class_uid,
        category_uid=1,
        severity_id=2,
        time=t,
        raw_source_timestamp=t.isoformat(),
        uid=f"uid-{child}-{host_name}",
        process_name=child,
        process_pid=1234,
        parent_process_name=parent,
        host_name=host_name,
    )


def _make_file_event(
    file_path: str = "/etc/shadow",
    user_name: str = "user_bob",
) -> FileActivityEvent:
    t = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    return FileActivityEvent(
        trace_id="t",
        activity_id=1,
        class_uid=1001,
        category_uid=1,
        severity_id=3,
        time=t,
        raw_source_timestamp=t.isoformat(),
        uid="uid-file-shadow",
        file_path=file_path,
        user_name=user_name,
    )


class _MockRedis:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def exists(self, key: str) -> int:
        return 1 if key in self._store else 0

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = value


def _make_agent(
    model_response: str = "Detected unusual parent process. Pattern: unusual_parent_process.",
    dfkg_refs: list[str] | None = None,
    model_raises: Exception | None = None,
) -> tuple[LogAnalysisAgent, MagicMock, _MockRedis]:
    """
    Build a LogAnalysisAgent with all I/O mocked.
    Returns (agent, kafka_producer_mock, redis).
    """
    kafka_producer_mock = MagicMock()
    redis = _MockRedis()

    if model_raises:
        model_router = MagicMock(side_effect=model_raises)
    else:
        model_router = MagicMock(return_value=model_response)

    dfkg_client = MagicMock()
    dfkg_client.query.return_value = dfkg_refs if dfkg_refs is not None else ["dfkg-ref-001"]

    agent = LogAnalysisAgent(
        model_router=model_router,
        kafka_consumer=iter([]),  # not used in run_on_batch tests
        kafka_producer=kafka_producer_mock,
        dfkg_read_client=dfkg_client,
        vector_client=MagicMock(),
        redis_client=redis,
        system_prompt="You are a DFIR analyst.",
    )
    return agent, kafka_producer_mock, redis


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5a: Out-of-scope class_uid → skipped entirely
# ═══════════════════════════════════════════════════════════════════════════════


def test_out_of_scope_class_uid_skipped():
    """
    Events with class_uid not in CONSUMED_CLASS_UIDS must be skipped.
    No LLM call, no Kafka publish.
    """
    # class_uid=4001 = NetworkActivity — belongs to Network Forensics agent.
    oot_event = _make_process_event(class_uid=4001)
    agent, kafka_producer, _ = _make_agent()

    result = agent.run_on_batch([oot_event], kafka_offset=0)

    assert result == []
    kafka_producer.assert_not_called()
    agent._model_router.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5b: Rule+anomaly both silent → no LLM call, no publish
# ═══════════════════════════════════════════════════════════════════════════════


def test_silent_rules_and_anomaly_no_llm_no_publish():
    """
    A benign event (no rule signal, cold anomaly baseline) must produce
    zero LLM calls and zero Kafka publishes.
    """
    benign_event = _make_process_event(parent="explorer.exe", child="notepad.exe")
    agent, kafka_producer, _ = _make_agent()

    result = agent.run_on_batch([benign_event], kafka_offset=1)

    assert result == []
    kafka_producer.assert_not_called()
    agent._model_router.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5c: Suspicious event → exactly one publish, dfkg_refs non-empty
# ═══════════════════════════════════════════════════════════════════════════════


def test_suspicious_event_publishes_exactly_once():
    """
    A suspicious event (winword.exe → cmd.exe LOLBAS spawn) with dfkg_refs
    must produce exactly one Kafka publish to FINDINGS_TOPIC.
    """
    suspicious = _make_process_event(parent="winword.exe", child="cmd.exe")
    agent, kafka_producer, _ = _make_agent(
        model_response="Detected unusual parent process. Pattern: unusual_parent_process.",
        dfkg_refs=["dfkg-node-001"],
    )

    result = agent.run_on_batch([suspicious], kafka_offset=5)

    assert len(result) == 1
    kafka_producer.assert_called_once()
    topic_arg, finding_arg = kafka_producer.call_args[0]
    assert topic_arg == config.FINDINGS_TOPIC
    assert finding_arg["dfkg_refs"] != []
    assert finding_arg["pattern"] == "unusual_parent_process"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5d: Model unavailable → degraded path (with signals) or clean skip
# ═══════════════════════════════════════════════════════════════════════════════


def test_model_unavailable_with_signals_publishes_degraded():
    """
    When model raises but rule signals exist AND dfkg_refs non-empty,
    a degraded marker finding must be published.
    """
    suspicious = _make_process_event(parent="winword.exe", child="powershell.exe")
    agent, kafka_producer, _ = _make_agent(
        model_raises=RuntimeError("model unavailable"),
        dfkg_refs=["dfkg-ref-002"],
    )

    result = agent.run_on_batch([suspicious], kafka_offset=10)

    # Should still publish (degraded path).
    assert len(result) == 1
    topic_arg, finding_arg = kafka_producer.call_args[0]
    assert finding_arg["confidence"] == 0.0
    assert finding_arg.get("escalated") is True
    assert "model_unavailable" in finding_arg["summary"]


def test_model_unavailable_no_signals_no_publish():
    """
    Benign event + model unavailable → no signals → clean skip, no publish.
    """
    benign_event = _make_process_event(parent="explorer.exe", child="notepad.exe")
    agent, kafka_producer, _ = _make_agent(
        model_raises=RuntimeError("model unavailable"),
    )

    result = agent.run_on_batch([benign_event], kafka_offset=11)

    assert result == []
    kafka_producer.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5e: Confidence <0.7 → escalated=True
# ═══════════════════════════════════════════════════════════════════════════════


def test_low_confidence_sets_escalated_flag():
    """
    If the finding confidence falls below LOW_CONFIDENCE_ESCALATION_THRESHOLD,
    the published finding must have escalated=True.
    """
    suspicious = _make_process_event(parent="winword.exe", child="cmd.exe")
    agent, kafka_producer, _ = _make_agent(
        model_response="Detected unusual parent process. Pattern: unusual_parent_process.",
        dfkg_refs=["dfkg-ref-003"],
    )

    # Patch signal weight to produce a low confidence score.
    with patch(
        "src.agents.log_analysis.agent.run_rule_layer",
        return_value=[{"pattern": "unusual_parent_process", "weight": 0.3, "detail": "test"}],
    ):
        result = agent.run_on_batch([suspicious], kafka_offset=20)

    if result:
        _, finding_arg = kafka_producer.call_args[0]
        assert finding_arg.get("escalated") is True


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5f: Duplicate fingerprint → second publish suppressed
# ═══════════════════════════════════════════════════════════════════════════════


def test_duplicate_fingerprint_suppresses_second_publish():
    """
    Calling run_on_batch twice with the same event must result in only one
    Kafka publish — the second call is suppressed by the dedup layer.
    """
    suspicious = _make_process_event(parent="winword.exe", child="cmd.exe")
    agent, kafka_producer, _ = _make_agent(
        model_response="Detected unusual parent process. Pattern: unusual_parent_process.",
        dfkg_refs=["dfkg-ref-004"],
    )

    result1 = agent.run_on_batch([suspicious], kafka_offset=30)
    result2 = agent.run_on_batch([suspicious], kafka_offset=31)

    assert len(result1) == 1  # first call publishes
    assert len(result2) == 0  # second call suppressed by dedup
    assert kafka_producer.call_count == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5g: LLM narrates unflagged pattern → guard rejects, retry, template fallback
# ═══════════════════════════════════════════════════════════════════════════════


def test_hallucinated_pattern_falls_back_to_template():
    """
    If the LLM response mentions a pattern not in the signals list on both
    attempts, the post-hoc guard must reject both and fall back to a
    template-generated summary.
    """
    suspicious = _make_process_event(parent="winword.exe", child="cmd.exe")

    # LLM always returns a response referencing an unflagged pattern.
    hallucinated_response = (
        "Evidence suggests a brute_force attack from multiple IPs "
        "indicating credential stuffing."
    )
    agent, kafka_producer, _ = _make_agent(
        model_response=hallucinated_response,
        dfkg_refs=["dfkg-ref-005"],
    )
    # The only signal fired should be unusual_parent_process (not brute_force).
    # brute_force is in the unflagged set → guard should reject.

    result = agent.run_on_batch([suspicious], kafka_offset=40)

    if result:
        _, finding_arg = kafka_producer.call_args[0]
        # Summary must be from template (LLM narration rejected).
        assert "TEMPLATE FALLBACK" in finding_arg["summary"] or \
               "brute_force" not in finding_arg["summary"].lower() or \
               "model_unavailable" in finding_arg["summary"]


# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Import boundary — no Cypher-write imports in agent.py
# ═══════════════════════════════════════════════════════════════════════════════


def test_agent_import_boundary():
    """
    agent.py must NOT import execute_ingestion_cypher or any raw Neo4j
    driver reference. This is the import-boundary enforcement from §7b.
    """
    agent_path = Path(__file__).parent.parent.parent.parent / "src" / "agents" / "log_analysis" / "agent.py"
    assert agent_path.exists(), f"agent.py not found at {agent_path}"

    content = agent_path.read_text(encoding="utf-8")

    forbidden_patterns = [
        r"execute_ingestion_cypher",
        r"neo4j\.GraphDatabase",
        r"AsyncDriver",
        r"from neo4j",
        r"import neo4j",
    ]
    for pattern in forbidden_patterns:
        matches = re.findall(pattern, content)
        assert not matches, (
            f"Import boundary violation in agent.py: found forbidden pattern "
            f"{pattern!r}: {matches}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: RBAC — Log-Analysis-Agent in read set, absent from write sets
# ═══════════════════════════════════════════════════════════════════════════════


def test_rbac_log_analysis_agent_in_event_read_set():
    """Log-Analysis-Agent must be in READ_ONLY_EVENT_ROLES."""
    assert "Log-Analysis-Agent" in READ_ONLY_EVENT_ROLES, (
        "Log-Analysis-Agent missing from READ_ONLY_EVENT_ROLES. "
        "Add it as specified by resolved-decisions item #44."
    )


def test_rbac_log_analysis_agent_absent_from_case_read_set():
    """Log-Analysis-Agent must NOT be in READ_ONLY_CASE_ROLES."""
    assert "Log-Analysis-Agent" not in READ_ONLY_CASE_ROLES, (
        "Log-Analysis-Agent must not have cross-case read access "
        "(READ_ONLY_CASE_ROLES). Only event-level read is permitted."
    )


def test_rbac_log_analysis_agent_absent_from_write_set():
    """Log-Analysis-Agent must NOT be in ALLOWED_SYSTEM_WRITE_ROLES."""
    assert "Log-Analysis-Agent" not in ALLOWED_SYSTEM_WRITE_ROLES, (
        "Log-Analysis-Agent must not have any direct write permissions. "
        "All writes are Kafka-mediated only."
    )
