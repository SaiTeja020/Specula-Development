"""
Unit and Component Test Suite for Specula Vector Retrieval Layer.

Reference: vector_retrieval_implementation_plan.md §3, §4, & §5
"""

import pytest
from datetime import datetime, timezone

from src.schemas.vector_metadata import VectorFindingMetadata
from src.ingestion.indexing.vector_store import (
    ChromaVectorStore,
    EmbeddingGenerator,
    InMemoryVectorStore,
)
from src.mcp.vector_retrieval import VectorRetrievalMCPServer


def test_vector_metadata_validation():
    """Verify VectorFindingMetadata enforces schema rules and timestamp conversion."""
    now = datetime.now(timezone.utc)
    meta = VectorFindingMetadata(
        finding_id="FINDING-001",
        case_id="CASE-101",
        trace_id="trace-1234567890ab",
        agent_role="System",
        timestamp=now,
        source="dfkg_finding",
    )

    meta_dict = meta.to_dict()
    assert meta_dict["finding_id"] == "FINDING-001"
    assert meta_dict["case_id"] == "CASE-101"
    assert meta_dict["embedding_model_version"] == "mxbai-embed-large-v1"
    assert isinstance(meta_dict["timestamp"], str)


def test_embedding_generator_determinism_and_normalization():
    """Verify EmbeddingGenerator produces 384-dimensional normalized float vectors."""
    gen = EmbeddingGenerator(dimension=384)
    vec1 = gen.embed("powershell.exe -enc AAAA==")
    vec2 = gen.embed("powershell.exe -enc AAAA==")

    assert len(vec1) == 384
    assert vec1 == vec2  # Deterministic output

    # Check vector unit norm
    norm = sum(v * v for v in vec1) ** 0.5
    assert abs(norm - 1.0) < 1e-5


def test_in_memory_vector_store_crud():
    """Test InMemoryVectorStore CRUD and similarity scoring."""
    store = InMemoryVectorStore()
    gen = EmbeddingGenerator(dimension=384)

    v1 = gen.embed("Suspicious execution of cmd.exe via svchost")
    v2 = gen.embed("User logged in via RDP session")

    store.upsert(
        record_id="F-1",
        text="Suspicious execution of cmd.exe via svchost",
        vector=v1,
        metadata={"case_id": "C-1", "source": "dfkg_finding"},
    )
    store.upsert(
        record_id="F-2",
        text="User logged in via RDP session",
        vector=v2,
        metadata={"case_id": "C-1", "source": "dfkg_finding"},
    )

    assert store.count() == 2

    # Query for process execution similarity
    query_v = gen.embed("cmd.exe svchost process execution")
    res = store.query(query_vector=query_v, case_id="C-1", top_k=2)

    assert len(res) == 2
    assert res[0]["id"] == "F-1"  # F-1 should rank higher than F-2

    # Delete record
    assert store.delete("F-1") is True
    assert store.count() == 1


def test_chroma_vector_store_fallback():
    """Verify ChromaVectorStore works seamlessly with or without chromadb installed."""
    store = ChromaVectorStore(collection_name="test_collection")
    gen = EmbeddingGenerator(dimension=384)

    v1 = gen.embed("Memory dump injected code DLL")
    store.upsert(
        record_id="F-3",
        text="Memory dump injected code DLL",
        vector=v1,
        metadata={"case_id": "C-2", "source": "dfkg_finding"},
    )

    assert store.count() >= 1
    res = store.query(query_vector=v1, case_id="C-2", top_k=1)
    assert len(res) == 1
    assert res[0]["id"] == "F-3"


def test_mcp_server_upsert_and_retrieve_similar_events():
    """Test VectorRetrievalMCPServer event indexing and retrieval."""
    server = VectorRetrievalMCPServer()

    meta = {
        "finding_id": "FIND-100",
        "case_id": "CASE-999",
        "trace_id": "trace-abcdef123456",
        "agent_role": "System",
        "timestamp": "2026-08-08T12:00:00Z",
        "source": "dfkg_finding",
    }

    # Index finding via System role
    res = server.upsert_finding_embedding(
        finding_id="FIND-100",
        text="Mimikatz credential dumping detected in LSASS memory",
        metadata=meta,
        caller_role="System",
    )
    assert res["status"] == "success"

    # Query finding via Judge role
    query_res = server.retrieve_similar_events(
        query_text="LSASS credential dumping Mimikatz",
        case_id="CASE-999",
        caller_role="Judge",
    )

    assert query_res["status"] == "ok"
    assert query_res["count"] == 1
    assert query_res["results"][0]["id"] == "FIND-100"


def test_strict_case_isolation():
    """Verify querying for Case A strictly excludes findings belonging to Case B."""
    server = VectorRetrievalMCPServer()

    meta_a = {
        "finding_id": "F-A",
        "case_id": "CASE-ALPHA",
        "trace_id": "trace-aaa",
        "agent_role": "System",
        "timestamp": "2026-08-08T12:00:00Z",
        "source": "dfkg_finding",
    }
    meta_b = {
        "finding_id": "F-B",
        "case_id": "CASE-BETA",
        "trace_id": "trace-bbb",
        "agent_role": "System",
        "timestamp": "2026-08-08T12:00:00Z",
        "source": "dfkg_finding",
    }

    server.upsert_finding_embedding("F-A", "Phishing email with malicious attachment", meta_a, caller_role="System")
    server.upsert_finding_embedding("F-B", "Phishing email with malicious attachment", meta_b, caller_role="System")

    # Search scoped to CASE-ALPHA
    res_a = server.retrieve_similar_events(
        query_text="Phishing email",
        case_id="CASE-ALPHA",
        caller_role="Judge",
    )
    assert res_a["count"] == 1
    assert res_a["results"][0]["id"] == "F-A"

    # Search scoped to CASE-BETA
    res_b = server.retrieve_similar_events(
        query_text="Phishing email",
        case_id="CASE-BETA",
        caller_role="Timeline-Agent",
    )
    assert res_b["count"] == 1
    assert res_b["results"][0]["id"] == "F-B"


def test_scratchpad_anti_pollution_rbac():
    """Verify agent roles cannot write directly to vector store, preventing scratchpad pollution."""
    server = VectorRetrievalMCPServer()

    meta = {
        "finding_id": "SCRATCH-01",
        "case_id": "CASE-001",
        "trace_id": "trace-xyz",
        "agent_role": "Malware-Agent",
        "timestamp": "2026-08-08T12:00:00Z",
        "source": "dfkg_finding",
    }

    # Attempting to write using Malware-Agent role must raise PermissionError
    with pytest.raises(PermissionError) as exc_info:
        server.upsert_finding_embedding(
            finding_id="SCRATCH-01",
            text="Unconfirmed hypothesis: host might be infected",
            metadata=meta,
            caller_role="Malware-Agent",
        )

    assert "cannot write directly to vector store" in str(exc_info.value)


def test_retrieve_similar_cases_closed_archives():
    """Verify retrieve_similar_cases returns closed-case archive vectors."""
    server = VectorRetrievalMCPServer()

    meta_archive = {
        "finding_id": "ARCHIVE-2025-09",
        "case_id": "CLOSED-CASE-2025-09",
        "trace_id": "trace-closed-09",
        "agent_role": "System",
        "timestamp": "2025-09-01T00:00:00Z",
        "source": "closed_case_archive",
    }

    server.upsert_finding_embedding(
        finding_id="ARCHIVE-2025-09",
        text="Ransomware breach via compromised VPN credentials and PsExec lateral movement",
        metadata=meta_archive,
        caller_role="System",
    )

    res = server.retrieve_similar_cases(
        case_summary="VPN credential theft ransomware PsExec",
        top_k=1,
        caller_role="Report-Agent",
    )

    assert res["status"] == "ok"
    assert res["count"] == 1
    assert res["results"][0]["id"] == "ARCHIVE-2025-09"


def test_read_only_agent_permissions():
    """Verify role-based access controls on retrieval tools."""
    server = VectorRetrievalMCPServer()

    # Malware-Agent attempting to run cross-case retrieval should fail
    with pytest.raises(PermissionError):
        server.retrieve_similar_cases(
            case_summary="Ransomware analysis",
            caller_role="Malware-Agent",
        )

    # Judge role should succeed
    res = server.retrieve_similar_cases(
        case_summary="Ransomware analysis",
        caller_role="Judge",
    )
    assert res["status"] == "ok"


def test_mcp_health_check():
    """Verify health_check endpoint."""
    server = VectorRetrievalMCPServer()
    hc = server.health_check()

    assert hc["status"] == "healthy"
    assert "vector_store_backend" in hc
    assert hc["embedding_model_version"] == "mxbai-embed-large-v1"
