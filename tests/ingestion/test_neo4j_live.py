"""
Live Integration Test Suite — Neo4j DFKG Graph Layer.

These tests require a real Neo4j instance running at bolt://localhost:7687.
They are SKIPPED in normal `pytest` runs and ONLY execute when explicitly
targeted with the live_infra marker:

    docker-compose up -d neo4j
    python scripts/neo4j_setup.py
    pytest tests/ingestion/test_neo4j_live.py -m live_infra -v

Reference: specula_ingestion_final_plan.md §8.1 & §8.4
"""

import uuid
import pytest

from src.graph.neo4j_client import Neo4jClient, Neo4jClientError, NEO4J_URI
from src.graph.cypher_builder import CypherBuilder, build_node_merge


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_neo4j_reachable() -> bool:
    """Quick connectivity probe — auto-skips tests if Neo4j is down."""
    try:
        client = Neo4jClient()
        client.close()
        return True
    except Exception:
        return False


def _unique_uid() -> str:
    return f"test-{uuid.uuid4().hex}"


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

@pytest.mark.live_infra
class TestNeo4jLiveIntegration:
    """
    Hits the real Neo4j Bolt endpoint at localhost:7687.
    Each test is fully independent — uses unique UIDs to prevent cross-test pollution.
    All test nodes use a :TestNode label and are cleaned up after each test.
    """

    @pytest.fixture(autouse=True)
    def require_neo4j(self):
        """Skip entire class if Neo4j is not reachable."""
        if not _is_neo4j_reachable():
            pytest.skip(
                f"Neo4j is not reachable at {NEO4J_URI}. "
                "Run: docker-compose up -d neo4j"
            )

    @pytest.fixture
    def client(self) -> Neo4jClient:
        c = Neo4jClient()
        yield c
        c.close()

    @pytest.fixture(autouse=True)
    def cleanup_test_nodes(self, client: Neo4jClient):
        """Delete all :TestNode nodes after each test to prevent pollution."""
        yield
        client.execute("MATCH (n:TestNode) DETACH DELETE n")

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def test_health_check_returns_connected(self, client: Neo4jClient):
        """health_check() must return status='connected' for a live Neo4j."""
        result = client.health_check()
        assert result["status"] == "connected"
        assert "server_info" in result

    # ------------------------------------------------------------------
    # Schema application
    # ------------------------------------------------------------------

    def test_apply_schema_is_idempotent(self, client: Neo4jClient):
        """apply_schema() called twice must not raise any error (IF NOT EXISTS)."""
        import os
        schema_path = os.path.abspath("src/graph/schema_constraints.cypher")
        if not os.path.exists(schema_path):
            pytest.skip("schema_constraints.cypher not found")
        client.apply_schema(schema_path)
        client.apply_schema(schema_path)  # second call must be silent

    # ------------------------------------------------------------------
    # Write + read roundtrip
    # ------------------------------------------------------------------

    def test_node_write_and_verify_roundtrip(self, client: Neo4jClient):
        """
        Write a :TestNode via execute(), read it back, verify properties round-trip.
        """
        uid = _unique_uid()
        write_q = "MERGE (n:TestNode {uid: $uid}) SET n.label = $label RETURN n"
        client.execute(write_q, {"uid": uid, "label": "specula_test"})

        read_q = "MATCH (n:TestNode {uid: $uid}) RETURN n.label AS label"
        rows = client.execute_read(read_q, {"uid": uid})

        assert len(rows) == 1
        assert rows[0]["label"] == "specula_test"

    def test_process_creation_cypher_writes_host_and_process(self, client: Neo4jClient):
        """
        CypherBuilder.build_process_creation() query writes Host + Process nodes
        and a SPAWNED relationship — verify all 3 are created in the live graph.
        """
        host_uid = _unique_uid()
        proc_uid = _unique_uid()
        parent_uid = _unique_uid()

        event = {
            "canonical_host_id": host_uid,
            "host_name": "TEST-HOST-01",
            "case_id": "CASE-LIVE-TEST",
            "time": "2026-08-11T10:00:00+00:00",
            "raw_source_timestamp": "2026-08-11T10:00:00Z",
            "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
            "parent_process_uid": parent_uid,
            "parent_process_name": "test_parent.exe",
            "parent_process_pid": 100,
            "uid": proc_uid,
            "process_name": "test_child.exe",
            "process_pid": 200,
            "command_line": "test_child.exe --flag",
        }

        query, params = CypherBuilder.build_process_creation(event)
        client.execute(query, params)

        # Verify Host node
        rows = client.execute_read(
            "MATCH (h:Host {uid: $uid}) RETURN h.hostname AS hn",
            {"uid": host_uid},
        )
        assert len(rows) == 1
        assert rows[0]["hn"] == "TEST-HOST-01"

        # Verify Process node
        rows = client.execute_read(
            "MATCH (p:Process {uid: $uid}) RETURN p.process_name AS pn",
            {"uid": proc_uid},
        )
        assert len(rows) == 1
        assert rows[0]["pn"] == "test_child.exe"

        # Verify SPAWNED relationship
        rows = client.execute_read(
            "MATCH (parent:Process {uid: $puid})-[:SPAWNED]->(child:Process {uid: $cuid}) "
            "RETURN count(*) AS cnt",
            {"puid": parent_uid, "cuid": proc_uid},
        )
        assert rows[0]["cnt"] == 1

    # ------------------------------------------------------------------
    # Deterministic UID — no duplicate nodes
    # ------------------------------------------------------------------

    def test_deterministic_uid_prevents_duplicate_nodes(self, client: Neo4jClient):
        """
        Writing the same UID twice via MERGE must produce exactly 1 node,
        not 2 duplicate entries.
        """
        uid = _unique_uid()
        q = "MERGE (n:TestNode {uid: $uid}) SET n.count = coalesce(n.count, 0) + 1 RETURN n.count AS c"

        client.execute(q, {"uid": uid})
        client.execute(q, {"uid": uid})

        rows = client.execute_read(
            "MATCH (n:TestNode {uid: $uid}) RETURN count(n) AS total", {"uid": uid}
        )
        assert rows[0]["total"] == 1  # exactly 1 node, not 2

    # ------------------------------------------------------------------
    # Failure handling
    # ------------------------------------------------------------------

    def test_wrong_port_raises_neo4j_client_error(self):
        """Connecting to a wrong port must raise Neo4jClientError, not hang silently."""
        with pytest.raises(Neo4jClientError):
            Neo4jClient(uri="bolt://localhost:9999")

    def test_neo4j_write_failure_is_non_fatal_in_pipeline(self):
        """
        Verifies the pipeline's non-fatal Neo4j design: if Neo4j is unreachable,
        run_pipeline_on_event() must log a warning and NOT raise.

        Uses a bad client pointed at a closed port to simulate Neo4j being down.
        """
        from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
        from src.schemas.entity_resolver import CanonicalEntityResolver
        from src.ingestion.normalization.time_normalizer import TimeNormalizer
        from src.ingestion.run_pipeline import run_pipeline_on_event

        # Create a bad client that will fail on execute()
        class AlwaysFailingClient:
            def execute(self, query, params):
                raise RuntimeError("Simulated Neo4j connection failure")

        raw_event = {
            "Id": 4688,
            "TimeCreated": "2026-08-11T10:00:00Z",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Message": "A new process has been created.",
        }

        # Must not raise — Neo4j write failure is non-fatal
        results = run_pipeline_on_event(
            raw_event,
            VCTAtomicChain(),
            CanonicalEntityResolver(),
            TimeNormalizer(dc_anchor_skew_ms=0),
            qw_client=None,
            source_type="evtx",
            neo4j_client=AlwaysFailingClient(),
        )
        validated_evt, cypher_query, neo4j_result = results[0]

        assert validated_evt is not None
        assert neo4j_result is None  # write failed, result is None — pipeline continued
