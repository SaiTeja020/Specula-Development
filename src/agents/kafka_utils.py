"""Kafka topic creation, producer, and DFKG consumer — §5.1.

Topics follow Master_doc §9.1 naming convention. Agent nodes publish
findings to their topic (fire-and-forget, non-blocking). A separate
consumer reads findings.* and performs MERGE writes into Neo4j.

All Kafka operations silently degrade when Kafka is unavailable — graph
progression is never blocked by Kafka.
"""
from __future__ import annotations

import json
import logging
import os

log = logging.getLogger(__name__)

KAFKA_BROKER = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

TOPICS = [
    "findings.evidence_collection",
    "findings.log_analysis",
    "findings.network_forensics",
    "findings.timeline",
    "findings.attribution",
    "findings.dag",
    "findings.specialist.memory",
    "findings.specialist.identity",
    "findings.specialist.cloud_container",
    "findings.specialist.malware",
    "findings.specialist.insider",
    "findings.debate",
    "dfkg.writes",
    "dfkg.dead_letter",
    "logs.normalized.ocsf",
    "specula.cases.opened",
]

# Agent role -> Kafka topic
ROLE_TOPIC_MAP: dict[str, str] = {
    "evidence_collection":  "findings.evidence_collection",
    "log_analysis":         "findings.log_analysis",
    "network_forensics":    "findings.network_forensics",
    "timeline_reconstruction": "findings.timeline",
    "threat_attribution":   "findings.attribution",
    "dag":                  "findings.dag",                          # F23
    "memory_forensics":     "findings.specialist.memory",
    "identity":             "findings.specialist.identity",          # F13a
    "cloud_container":      "findings.specialist.cloud_container",   # F13b
    "malware_stylometry":   "findings.specialist.malware",
    "insider_threat":       "findings.specialist.insider",
    "proponent":            "findings.debate",
    "critic":               "findings.debate",
    "judge":                "findings.debate",
}

# ---------------------------------------------------------------------------
# Producer (lazy singleton, degrades gracefully)
# ---------------------------------------------------------------------------

_producer = None
_kafka_available: bool | None = None


def _get_producer():
    """Lazy-init Kafka producer. Returns None if unavailable."""
    global _producer, _kafka_available
    if _kafka_available is False:
        return None
    if _producer is not None:
        return _producer
    try:
        from confluent_kafka import Producer  # type: ignore[import-untyped]
        _producer = Producer({"bootstrap.servers": KAFKA_BROKER})
        _kafka_available = True
        return _producer
    except Exception:
        _kafka_available = False
        return None


def publish_finding(topic: str, finding: dict, trace_id: str | None = None) -> None:
    """Publish a finding dict to *topic*. Non-blocking, silent on failure."""
    producer = _get_producer()
    if producer is None:
        return
    try:
        headers = [("trace_id", (trace_id or "").encode("utf-8"))]
        producer.produce(
            topic,
            value=json.dumps(finding, default=str).encode("utf-8"),
            headers=headers,
        )
        producer.poll(0)  # trigger delivery callbacks without blocking
    except Exception as exc:
        log.debug("Kafka publish failed (non-blocking): %s", exc)


def flush_producer(timeout: float = 2.0) -> None:
    """Flush any buffered messages."""
    if _producer is not None:
        try:
            _producer.flush(timeout=timeout)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Topic creation
# ---------------------------------------------------------------------------

def create_topics() -> None:
    """Create all skeleton topics (idempotent)."""
    try:
        from confluent_kafka.admin import AdminClient, NewTopic  # type: ignore[import-untyped]
        admin = AdminClient({"bootstrap.servers": KAFKA_BROKER})
        new_topics = [
            NewTopic(t, num_partitions=1, replication_factor=1)
            for t in TOPICS
        ]
        futures = admin.create_topics(new_topics)
        for topic, future in futures.items():
            try:
                future.result()
                log.info("Created topic: %s", topic)
            except Exception as exc:
                # Topic already exists is fine
                if "TOPIC_ALREADY_EXISTS" not in str(exc):
                    log.warning("Topic creation issue for %s: %s", topic, exc)
    except Exception as exc:
        log.warning("Kafka topic creation skipped (Kafka unavailable): %s", exc)


# ---------------------------------------------------------------------------
# DFKG Consumer — reads findings.* topics, writes to Neo4j
# ---------------------------------------------------------------------------

def run_dfkg_consumer(*, max_messages: int | None = None) -> None:
    """Blocking consumer loop: read findings.* and MERGE into Neo4j.

    Args:
        max_messages: stop after N messages (for testing); None = run forever.
    """
    from confluent_kafka import Consumer  # type: ignore[import-untyped]
    import hashlib

    neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")

    try:
        from neo4j import GraphDatabase  # type: ignore[import-untyped]
        driver = GraphDatabase.driver(neo4j_uri)
    except Exception as exc:
        log.error("Cannot connect to Neo4j at %s: %s", neo4j_uri, exc)
        return

    consumer = Consumer({
        "bootstrap.servers": KAFKA_BROKER,
        "group.id": "specula-dfkg-writer",
        "auto.offset.reset": "earliest",
    })
    # Subscribe to all findings topics via regex
    consumer.subscribe(["^findings\\..*"])
    log.info("DFKG consumer started, subscribing to findings.* topics")

    count = 0
    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                log.warning("Consumer error: %s", msg.error())
                continue

            try:
                finding = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                log.warning("Bad message on %s: %s", msg.topic(), exc)
                # ponytail: dead-letter publish deferred, just log
                continue

            # Deterministic UID: hash of (agent_role, case_id, summary prefix)
            uid_seed = f"{finding.get('agent_role', '')}-{finding.get('timestamp', '')}"
            uid = hashlib.sha256(uid_seed.encode()).hexdigest()[:16]

            # Parameterized MERGE — no dynamic string interpolation (AGENTS.md rule)
            case_id = finding.get("case_id", "unknown")
            dfkg_refs = finding.get("dfkg_refs", [])
            with driver.session() as session:
                session.run(
                    "MERGE (e:AgentFinding {uid: $uid}) "
                    "SET e.agent_role = $role, e.summary = $summary, "
                    "    e.timestamp = $ts, e.topic = $topic, e.case_id = $case_id "
                    "MERGE (c:Case {case_id: $case_id}) "
                    "MERGE (e)-[:BELONGS_TO]->(c)",
                    uid=uid,
                    role=finding.get("agent_role", "unknown"),
                    summary=finding.get("summary", "")[:500],
                    ts=finding.get("timestamp", ""),
                    topic=msg.topic(),
                    case_id=case_id,
                )
                if dfkg_refs:
                    session.run(
                        "MATCH (e:AgentFinding {uid: $uid}) "
                        "UNWIND $refs AS ref_uid "
                        "MERGE (ev:Entity {uid: ref_uid}) "
                        "MERGE (e)-[:BASED_ON]->(ev)",
                        uid=uid,
                        refs=dfkg_refs
                    )

            count += 1
            if max_messages is not None and count >= max_messages:
                break
    finally:
        consumer.close()
        driver.close()
        log.info("DFKG consumer stopped after %d messages", count)
