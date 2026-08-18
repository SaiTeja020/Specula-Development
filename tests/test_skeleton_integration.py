"""Integration verification for the Specula LangGraph skeleton — §11 items 5 & 6.

These CANNOT be verified by unit tests using stub LLM + InMemorySaver, by
construction:
  - Item 5: Kafka topics receive expected messages; Neo4j consumer writes
    deduplicated nodes/edges via the Entity.uid uniqueness constraint.
  - Item 6: HITL interrupt survives an actual process restart, not just
    same-process resume.

Requires: docker-compose infra up (Kafka, Neo4j, Redis) per Stage 1 plan §5.
Run explicitly, NOT part of default CI:
    pytest tests/test_skeleton_integration.py -v -m integration

If any of these are skipped in your environment, that is a genuine unresolved
gap in Stage 1 exit criteria, not a passing state — do not treat a skip as
equivalent to a pass.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

os.environ["SPECULA_LLM_BACKEND"] = "stub"

pytestmark = pytest.mark.integration

KAFKA_BOOTSTRAP = os.environ.get("SPECULA_KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
NEO4J_URI = os.environ.get("SPECULA_NEO4J_URI", "bolt://localhost:7687")
NEO4J_AUTH = (os.environ.get("SPECULA_NEO4J_USER", "neo4j"),
              os.environ.get("SPECULA_NEO4J_PASSWORD", "test"))
REDIS_URL = os.environ.get("SPECULA_REDIS_URL", "redis://localhost:6379/0")


def _infra_available() -> bool:
    """Best-effort check so this file gives a clear skip reason instead of
    a confusing connection-refused stack trace when infra isn't up."""
    try:
        from confluent_kafka.admin import AdminClient
        admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP})
        # Try to fetch cluster metadata (timeout is in seconds)
        admin.list_topics(timeout=2.0)
    except Exception:
        return False
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        driver.verify_connectivity()
        driver.close()
    except Exception:
        return False
    return True


requires_infra = pytest.mark.skipif(
    not _infra_available(),
    reason="Kafka/Neo4j not reachable — bring up docker-compose infra before running integration tests",
)


# ---------------------------------------------------------------------------
# §11 item 5a — Kafka: a published finding is actually consumable
# ---------------------------------------------------------------------------

@requires_infra
class TestKafkaDelivery:
    def test_finding_published_and_consumable(self):
        from confluent_kafka import Consumer
        from src.agents.graph import build_graph
        from langgraph.checkpoint.memory import InMemorySaver
        from src.agents.kafka_utils import flush_producer

        consumer = Consumer({
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": f"test-kafka-delivery-{int(time.time())}",
            "auto.offset.reset": "earliest",
        })
        consumer.subscribe(["findings.evidence_collection"])

        graph = build_graph(checkpointer=InMemorySaver())
        case_id = f"KAFKA-TEST-{int(time.time())}"
        config = {"configurable": {"thread_id": case_id}}
        graph.invoke({
            "case_id": case_id, "trace_id": f"trace-{case_id}",
            "input_type": "siem_alert",
            "raw_input": "Kafka delivery integration probe",
            "case_status": "open", "findings": [], "agent_traces": [],
            "debate_round": 1, "debate_history": [], "specialists_completed": [],
            "dead_end_detected": False, "dead_end_categories": [],
        }, config)

        flush_producer(timeout=5.0)

        found = False
        # Poll up to 500 times to read through historical messages since we use 'earliest'
        for _ in range(500):
            msg = consumer.poll(0.5)
            if msg and not msg.error() and msg.headers():
                for k, v in msg.headers():
                    if k == 'trace_id' and v and case_id.encode() in v:
                        found = True
                        break
            if found:
                break

        assert found, (
            "No message for this case_id observed on findings.evidence_collection — "
            "either the producer isn't publishing, or the topic name has drifted "
            "from the walkthrough's documented naming"
        )
        consumer.close()


# ---------------------------------------------------------------------------
# §11 item 5b — Neo4j: deterministic UID + uniqueness constraint actually dedup
# ---------------------------------------------------------------------------

@requires_infra
class TestNeo4jDeduplication:
    def test_uid_uniqueness_constraint_exists(self):
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        with driver.session() as session:
            constraints = session.run("SHOW CONSTRAINTS").data()
        driver.close()
        matching = [
            c for c in constraints
            if "Entity" in str(c.get("labelsOrTypes", [])) and "uid" in str(c.get("properties", []))
        ]
        assert matching, (
            "No uniqueness constraint found on Entity.uid — schema_constraints.cypher "
            "may not have been applied to this Neo4j instance"
        )

    def test_replayed_write_does_not_duplicate_node(self):
        """This is the test that actually validates deterministic UID
        generation + MERGE, rather than trusting it by inspection."""
        from neo4j import GraphDatabase
        import hashlib

        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        test_uid = hashlib.sha256(b"integration-test-entity-dedup-check").hexdigest()

        with driver.session() as session:
            # Clean slate for this specific test node
            session.run("MATCH (n:Entity {uid: $uid}) DETACH DELETE n", uid=test_uid)

            # Simulate the same finding being written twice (replay scenario)
            for _ in range(2):
                session.run(
                    "MERGE (n:Entity {uid: $uid}) SET n += $props",
                    uid=test_uid,
                    props={"role": "integration-test", "case_id": "dedup-check"},
                )

            result = session.run(
                "MATCH (n:Entity {uid: $uid}) RETURN count(n) AS c", uid=test_uid
            ).single()
            count = result["c"]

            # Cleanup
            session.run("MATCH (n:Entity {uid: $uid}) DETACH DELETE n", uid=test_uid)

        driver.close()
        assert count == 1, f"Expected exactly 1 node after replayed write, found {count}"


# ---------------------------------------------------------------------------
# §11 item 6 — HITL resume survives an actual process restart
# ---------------------------------------------------------------------------

@requires_infra
class TestHITLCrossProcessResume:
    """Runs the interrupt in THIS process, then resumes from a freshly
    spawned subprocess — proving the checkpointer (not just Python object
    identity within one process) is what carries state across the pause.

    Requires a persistent checkpointer (Redis- or Postgres-backed) wired
    into build_graph(); InMemorySaver will make this test fail by design,
    which is the point — it should fail loudly if someone swaps the
    checkpointer back to in-memory without noticing.
    """

    def test_resume_from_separate_process(self, tmp_path):
        from src.agents.graph import build_graph
        # Adjust this import to whatever persistent checkpointer factory
        # the codebase actually exposes (Redis/Postgres-backed).
        try:
            from src.agents.checkpointer import build_persistent_checkpointer
        except ImportError:
            pytest.skip(
                "No persistent checkpointer factory found — Stage 1 exit "
                "criterion 6 cannot be verified until one is wired in. This "
                "skip should be treated as an open item, not a pass."
            )

        thread_id = f"cross-process-{int(time.time())}"
        checkpointer = build_persistent_checkpointer(REDIS_URL)
        graph = build_graph(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": thread_id}}

        graph.invoke({
            "case_id": thread_id, "trace_id": f"trace-{thread_id}",
            "input_type": "siem_alert",
            "raw_input": "Normal input FORCE_GUARDRAIL1_FAIL",
            "case_status": "open", "findings": [], "agent_traces": [],
            "debate_round": 1, "debate_history": [], "specialists_completed": [],
            "dead_end_detected": False, "dead_end_categories": [],
        }, config)

        state = graph.get_state(config)
        assert state.next, "graph did not pause at HITL as expected"

        # Resume from a fresh subprocess — this is the real test. If this
        # were InMemorySaver, the subprocess would have no knowledge of the
        # paused state at all and this call would fail outright rather than
        # silently succeeding for the wrong reason.
        script = f"""
import sys
sys.path.insert(0, {str(os.getcwd())!r})
import os
os.environ["SPECULA_LLM_BACKEND"] = "stub"
from src.agents.graph import build_graph
from src.agents.checkpointer import build_persistent_checkpointer
from langgraph.types import Command

checkpointer = build_persistent_checkpointer({REDIS_URL!r})
graph = build_graph(checkpointer=checkpointer)
config = {{"configurable": {{"thread_id": {thread_id!r}}}}}
result = graph.invoke(Command(resume="approve"), config)
print("RESUME_STATUS:", result.get("case_status"))
print("RESUME_REPORT_SET:", result.get("report_output") is not None)
"""
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, f"Subprocess resume failed:\n{proc.stderr}"
        assert "RESUME_STATUS: closed" in proc.stdout
        assert "RESUME_REPORT_SET: True" in proc.stdout
