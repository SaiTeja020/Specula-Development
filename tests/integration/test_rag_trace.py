import os
import sys
import json
import pytest
from unittest import mock

sys.path.insert(0, os.path.abspath("."))

from src.agents import investigation_trace
from src.agents.react_tools import ForensicRAGSearchTool
from src.agents.rag.dfkg_retriever import DFKGRetriever

PROC3_UID = "test-uid-proc3"

@pytest.fixture
def mock_retriever():
    retriever = mock.Mock(spec=DFKGRetriever)
    
    # Mock semantic retrieval
    retriever.retrieve_entity_uids.return_value = [
        {"uid": PROC3_UID, "score": 0.95, "text": "suspicious.exe communicated with 185.220.101.45", "metadata": {"source": "test"}}
    ]
    
    # Mock graph expansion
    retriever.expand_from_uid.return_value = {
        "seed_uid": PROC3_UID,
        "nodes": {
            PROC3_UID: {"uid": PROC3_UID, "label": "Process", "properties": {"process_name": "suspicious.exe"}}
        },
        "edges": []
    }
    return retriever


def test_offline_rag_trace(mock_retriever, tmp_path):
    """
    Directly invokes ForensicRAGSearchTool to ensure tracing captures:
    query -> semantic retrieval -> UID -> graph expansion -> evidence payload -> trace event
    """
    case_id = "RAG-TRACE-OFFLINE-001"
    query = "Which process communicated with 185.220.101.45?"
    
    # Mock the trace dir to tmp_path
    original_init = investigation_trace.TraceRecorder.__init__
    
    def mock_init(self, cid, q):
        self.case_id = cid
        self.query = q
        self.run_dir = tmp_path / "investigation_runs" / cid
        self.run_dir.mkdir(parents=True, exist_ok=True)
        import threading
        self._lock = threading.Lock()
        self.json_path = self.run_dir / "investigation_trace.json"
        if not self.json_path.exists():
            with open(self.json_path, 'w', encoding='utf-8') as f:
                json.dump({"case_id": cid, "query": q, "events": []}, f, indent=2)
        self._write_readme_header()
        self._write_user_query()

    with mock.patch.object(investigation_trace.TraceRecorder, '__init__', mock_init):
        # 1. Start trace
        investigation_trace.start_trace(case_id, query)
        investigation_trace.set_active_agent("network_forensics")
        investigation_trace.record_event("network_forensics", "agent_start", {"model": "mock_model"})

        
        # 2. Instantiate real RAG tool (using mocked data from fixture)
        tool = ForensicRAGSearchTool(mock_retriever)
        
        # 3. Execute tool
        result = tool.run(query)
        
        assert result.ok is True, "RAG Tool failed"
        assert PROC3_UID in result.data["uids"], "Did not retrieve expected UID"
        assert "RETRIEVED FORENSIC GRAPH CONTEXT" in result.observation
        
        # Now check the trace
        investigation_trace.get_recorder()._compile_full_report()
        
    run_dir = tmp_path / "investigation_runs" / case_id
    
    # Verify JSON trace has the required events
    with open(run_dir / "investigation_trace.json", 'r', encoding='utf-8') as f:
        trace_data = json.load(f)
        
    event_types = [e["event_type"] for e in trace_data["events"]]
    assert "rag_query" in event_types, "Missing rag_query trace event"
    assert "rag_retrieval" in event_types, "Missing rag_retrieval trace event"
    
    # Verify the contents of the trace event
    rag_retrieval_events = [e for e in trace_data["events"] if e["event_type"] == "rag_retrieval"]
    assert len(rag_retrieval_events) == 1
    
    retrieval_data = rag_retrieval_events[0]["data"]
    retrieved_uids = [r["uid"] for r in retrieval_data["records"]]
    
    assert PROC3_UID in retrieved_uids, "Trace did not record the retrieved UID"
    assert "dfkg_expansion" in retrieval_data, "Trace did not record graph expansion metadata"
    assert retrieval_data["dfkg_expansion"]["nodes_retrieved"] > 0, "Graph expansion reported 0 nodes"

    # Verify Markdown trace compilation
    with open(run_dir / "full_trace_report.md", 'r', encoding='utf-8') as f:
        md_content = f.read()
        
    assert "RAG REQUEST" in md_content
    assert query in md_content
    assert "RAG RESPONSE" in md_content
    assert PROC3_UID in md_content
    assert "GRAPH EXPANSION" in md_content
