import pytest
from unittest.mock import MagicMock, patch
from src.agents.rag.dfkg_retriever import DFKGRetriever
from src.agents.rag.faiss_context_builder import build_faiss_threat_context
from src.agents.rag.qa_service import ForensicQAService


def test_combined_rag_retrieval():
    mock_neo4j = MagicMock()
    mock_vector_store = MagicMock()
    mock_embedder = MagicMock()

    # Setup mock to return a dummy vector result
    mock_embedder.embed.return_value = [0.1, 0.2, 0.3]
    mock_vector_store.query.return_value = [
        {"id": "dummy_uid", "score": 0.9, "text": "dummy text"}
    ]

    # Setup mock Neo4j to simulate a NODE anchor and empty graph
    mock_neo4j.execute_read.side_effect = [
        [{"c": 1}],  # Is Node? Yes
        [],          # Graph expansion returns empty
    ]

    retriever = DFKGRetriever(
        neo4j_client=mock_neo4j,
        vector_store=mock_vector_store,
        embedder=mock_embedder,
        max_hops=1,
        max_nodes=10,
    )
    query = "What file activity and network activity are associated with the suspicious process?"

    # The new API is `retrieve(query)` which returns a dict
    result = retriever.retrieve(query, top_k=1)

    assert isinstance(result, dict)
    assert result["query"] == query
    assert len(result["retrieved_uids"]) == 1
    assert result["retrieved_uids"][0]["uid"] == "dummy_uid"

    # Check if we retrieved anything
    print("Retrieved UIDs:", result["retrieved_uids"])
    print("Contexts length:", len(result["graph_contexts"]))


# ---------------------------------------------------------------------------
# Tests for FaissContextBuilder (ADR-036)
# ---------------------------------------------------------------------------

def _make_technique_result(tid="T1059", name="Command and Scripting Interpreter", tactic="Execution", score=0.92):
    return {
        "record_id": tid,
        "record_type": "attack_technique",
        "title": name,
        "score": score,
        "metadata": {"technique_id": tid, "name": name, "tactic": tactic, "record_type": "attack_technique"},
    }


def _make_group_result(gid="G0016", name="APT28", aliases=["Fancy Bear"], score=0.81):
    return {
        "record_id": gid,
        "record_type": "attack_group",
        "title": name,
        "score": score,
        "metadata": {"group_id": gid, "name": name, "aliases": aliases, "record_type": "attack_group"},
    }


def _make_cve_result(cve_id="CVE-2023-1234", cvss=9.8, desc="Remote code execution in FooService.", score=0.77):
    return {
        "record_id": cve_id,
        "record_type": "cve",
        "title": desc,
        "score": score,
        "metadata": {"cve_id": cve_id, "cvss_score": cvss, "description": desc, "record_type": "cve"},
    }


class _MockThreatIntelServer:
    """Minimal mock of ThreatIntelMCPServer for unit tests."""

    def __init__(self, techniques=None, groups=None, cves=None):
        self._techniques = techniques or []
        self._groups = groups or []
        self._cves = cves or []

    def query_attack_techniques(self, query_text, top_k=5):
        return {"results": self._techniques[:top_k], "status": "ok"}

    def query_attack_groups(self, query_text, top_k=3):
        return {"results": self._groups[:top_k], "status": "ok"}

    def query_cves(self, query_text, top_k=3):
        return {"results": self._cves[:top_k], "status": "ok"}


def test_faiss_context_builder_returns_formatted_string():
    server = _MockThreatIntelServer(
        techniques=[_make_technique_result()],
        groups=[_make_group_result()],
        cves=[_make_cve_result()],
    )
    ctx = build_faiss_threat_context("powershell lateral movement", server)

    assert "THREAT-INTEL CONTEXT" in ctx
    assert "T1059" in ctx
    assert "Command and Scripting Interpreter" in ctx
    assert "APT28" in ctx
    assert "CVE-2023-1234" in ctx
    # Must clearly label it as distinct from forensic evidence
    assert "NOT case evidence" in ctx or "threat-intelligence index" in ctx.lower() or "THREAT-INTEL" in ctx


def test_faiss_context_builder_empty_corpus_returns_empty_string():
    """When corpus returns no results, builder must return '' (non-fatal)."""
    server = _MockThreatIntelServer()
    ctx = build_faiss_threat_context("any query", server)
    assert ctx == ""


def test_faiss_context_builder_server_exception_is_non_fatal():
    """Exceptions from the server must produce an empty string, not raise."""
    class BrokenServer:
        def query_attack_techniques(self, *a, **kw):
            raise RuntimeError("corpus unavailable")
        def query_attack_groups(self, *a, **kw):
            raise RuntimeError("corpus unavailable")
        def query_cves(self, *a, **kw):
            raise RuntimeError("corpus unavailable")

    ctx = build_faiss_threat_context("any query", BrokenServer())
    assert ctx == ""


def test_faiss_context_builder_missing_methods_returns_empty():
    """Objects without the MCP interface methods must not crash."""
    ctx = build_faiss_threat_context("any query", object())
    assert ctx == ""


# ---------------------------------------------------------------------------
# ForensicQAService integration: FAISS threat-intel wired into ask()
# ---------------------------------------------------------------------------

def _make_qa_service_with_mocks(threat_intel_server=None):
    """Build a ForensicQAService with all external dependencies mocked out."""
    mock_neo4j = MagicMock()
    mock_neo4j.execute_read.return_value = []

    mock_vector_store = MagicMock()
    mock_vector_store.query.return_value = []

    mock_embedder = MagicMock()
    mock_embedder.embed.return_value = [0.0] * 16

    svc = ForensicQAService(
        neo4j_client=mock_neo4j,
        vector_store=mock_vector_store,
        embedder=mock_embedder,
        threat_intel_server=threat_intel_server,
    )
    return svc


def test_qa_service_faiss_context_included_in_dry_run():
    """dry_run=True must expose threat_intel_context key and populate it."""
    server = _MockThreatIntelServer(
        techniques=[_make_technique_result()],
        groups=[_make_group_result()],
        cves=[_make_cve_result()],
    )
    svc = _make_qa_service_with_mocks(threat_intel_server=server)
    result = svc.ask("What TTPs are associated with the lateral movement?", dry_run=True)

    assert "threat_intel_context" in result
    ti_ctx = result["threat_intel_context"]
    # In dry_run the raw string is returned
    assert isinstance(ti_ctx, str)
    assert "T1059" in ti_ctx or "THREAT-INTEL" in ti_ctx


def test_qa_service_no_faiss_server_does_not_crash():
    """When threat_intel_server is None and corpus not built, ask() must succeed."""
    svc = _make_qa_service_with_mocks(threat_intel_server=None)
    # Prevent lazy instantiation from hitting disk
    with patch.object(svc, "_get_threat_intel_server", return_value=None):
        result = svc.ask("some forensic question", dry_run=True)

    assert result["answer"] == "DRY RUN — graph context prepared successfully."
    # threat_intel_context must still be present (empty string) in dry_run
    assert "threat_intel_context" in result
    assert result["threat_intel_context"] == ""


def test_qa_service_full_ask_returns_threat_intel_summary():
    """Full (non-dry-run) ask() must include threat_intel_context summary dict."""
    server = _MockThreatIntelServer(
        techniques=[_make_technique_result()],
    )
    svc = _make_qa_service_with_mocks(threat_intel_server=server)

    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content="Finding: Powershell abuse detected.")

    with patch("src.agents.rag.qa_service.get_llm", return_value=mock_llm):
        result = svc.ask("Why was powershell flagged?")

    assert "threat_intel_context" in result
    assert isinstance(result["threat_intel_context"], dict)
    assert "available" in result["threat_intel_context"]
    assert result["threat_intel_context"]["available"] is True
    assert result["threat_intel_context"]["chars"] > 0
