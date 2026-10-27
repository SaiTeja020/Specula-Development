"""Tests for ForensicQAService and RAG Q&A endpoints."""
import pytest
from unittest.mock import MagicMock, patch

from src.agents.rag.qa_service import ForensicQAService
from src.agents.examination_reports import render_examination_report


def test_forensic_qa_service_dry_run():
    """Verify dry_run builds context and skips LLM call."""
    mock_neo4j = MagicMock()
    mock_vector_store = MagicMock()
    mock_embedder = MagicMock()

    mock_embedder.embed.return_value = [0.1, 0.2, 0.3]
    mock_vector_store.query.return_value = [
        {"id": "uid_event_001", "score": 0.95, "text": "powershell.exe executed with -enc"}
    ]
    mock_neo4j.execute_read.side_effect = [
        [{"1": 1}],  # Node anchor check
        [{"node_uid": "uid_event_001", "node_label": "Process", "node_props": {"process_name": "powershell.exe"}, "rel_type": None, "neighbor_uid": None, "neighbor_label": None, "neighbor_props": None}]
    ]

    qa = ForensicQAService(
        neo4j_client=mock_neo4j,
        vector_store=mock_vector_store,
        embedder=mock_embedder,
    )

    res = qa.ask("Why was powershell flagged?", dry_run=True)
    assert res["query"] == "Why was powershell flagged?"
    assert "DRY RUN" in res["answer"]
    assert "uid_event_001" in res["graph_context"]
    assert len(res["retrieved_evidence"]) == 1
    assert res["retrieved_evidence"][0]["uid"] == "uid_event_001"


def test_forensic_qa_service_with_stub_llm():
    """Verify end-to-end question answering with skeleton's StubLLM and UID validation."""
    mock_neo4j = MagicMock()
    mock_vector_store = MagicMock()
    mock_embedder = MagicMock()

    mock_embedder.embed.return_value = [0.1, 0.2, 0.3]
    mock_vector_store.query.return_value = [
        {"id": "proc_ps_001", "score": 0.88, "text": "powershell.exe connected to 185.220.101.34"}
    ]
    mock_neo4j.execute_read.side_effect = [
        [{"1": 1}],
        [{"node_uid": "proc_ps_001", "node_label": "Process", "node_props": {"process_name": "powershell.exe", "pid": 1100}, "rel_type": None, "neighbor_uid": None, "neighbor_label": None, "neighbor_props": None}]
    ]

    qa = ForensicQAService(
        neo4j_client=mock_neo4j,
        vector_store=mock_vector_store,
        embedder=mock_embedder,
    )

    res = qa.ask("What did powershell.exe do in case LOCAL-001?", case_id="LOCAL-001")
    assert res["query"] == "What did powershell.exe do in case LOCAL-001?"
    assert "Finding:" in res["answer"]
    assert "proc_ps_001" in res["answer"]
    assert res["validation"]["validation_passed"] is True
    assert "proc_ps_001" in res["validation"]["verified_uids"]
    assert res["graph_context"]["nodes_count"] >= 1


def test_examination_report_has_explainability_block():
    """Verify findings in court and technical reports contain explainability blocks and exhibit anchors."""
    state = {
        "case_id": "LOCAL-test-exp",
        "case_status": "open",
        "evidence_collection": {
            "case_id": "LOCAL-test-exp",
            "status": "complete",
            "records": [
                {
                    "uid": "ev_001",
                    "time": "2026-10-12T09:00:00+00:00",
                    "class_uid": 1007,
                    "process_name": "powershell.exe",
                }
            ],
            "degraded_flags": [],
        },
        "findings": [
            {
                "agent_role": "log_analysis",
                "summary": "Suspicious encoded command execution",
                "classification": "true_positive",
                "operation_outcome": "success",
                "dfkg_refs": ["ev_001"],
                "reasoning": "Encoded payload detected matching known obfuscation patterns.",
            }
        ],
        "agent_traces": [],
    }

    court_html, _ = render_examination_report(state, "court")
    assert "explainability-block" in court_html
    assert "DFKG Explainability & Evidence Provenance" in court_html
    assert '<a href="#exhibit-ev_001">ev_001</a>' in court_html
    assert 'id="exhibit-ev_001"' in court_html

    technical_html, _ = render_examination_report(state, "technical")
    assert "explainability-block" in technical_html
    assert '<a href="#exhibit-ev_001">ev_001</a>' in technical_html


@pytest.mark.asyncio
async def test_qa_api_endpoints(api_auth):
    """Test the FastAPI /api/qa and /api/investigations/{case_id}/qa endpoints."""
    import httpx
    from src.agents.visualizer_api import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Test global QA
        resp = await client.post("/api/qa", json={"query": "Why was 185.220.101.45 flagged?", "dry_run": True}, headers=api_auth)
        assert resp.status_code == 200
        data = resp.json()
        assert data["query"] == "Why was 185.220.101.45 flagged?"
        assert "DRY RUN" in data["answer"]
        assert "validation" in data

        # Test case-scoped QA
        resp2 = await client.post("/api/investigations/LOCAL-test-case/qa", json={"query": "Did powershell execute?", "dry_run": True}, headers=api_auth)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["case_id"] == "LOCAL-test-case"
        assert "DRY RUN" in data2["answer"]

