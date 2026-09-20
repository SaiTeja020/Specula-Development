"""Integration tests for the investigation trace system."""
import json
import os
import shutil
from pathlib import Path
from unittest import mock

import pytest
from langgraph.checkpoint.memory import InMemorySaver

from src.agents.config import AGENT_CONFIG
from src.agents.graph import build_graph
from src.agents.investigation_runner import run_investigation
from src.agents import investigation_trace


@pytest.fixture
def mock_neo4j():
    with mock.patch("neo4j.GraphDatabase.driver") as mock_driver:
        yield mock_driver


def test_trace_generation(mock_neo4j, tmp_path):
    """Test that running an investigation with tracing enabled generates the expected files."""
    case_id = "TRACE-TEST-001"
    query = "Test query for tracing"
    
    # Force test mode by patching the trace directory so we don't pollute the workspace
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
        # Enable tracing
        investigation_trace.start_trace(case_id, query)
        
        # Build graph and run
        # Force the supervisor to route to wait (so it terminates quickly)
        raw_input = "FORCE_SUPERVISOR_ROUTE: wait"
        
        # Run it
        graph = build_graph()
        config = {"configurable": {"thread_id": "test-trace-thread"}}
        
        initial_state = {
            "case_id": case_id,
            "raw_input": raw_input,
            "findings": [],
            "agent_traces": [],
        }
        
        investigation_trace.record_event("runner", "user_query", {"query": query, "case_id": case_id})
        result_state = graph.invoke(initial_state, config)
        investigation_trace.record_event("runner", "investigation_complete", {"case_id": case_id, "status": "completed"})

    # Verify trace directory
    run_dir = tmp_path / "investigation_runs" / case_id
    assert run_dir.exists()
    
    # Verify core files
    assert (run_dir / "00_user_query.md").exists()
    assert (run_dir / "01_supervisor.md").exists()
    assert (run_dir / "README.md").exists()
    assert (run_dir / "investigation_trace.json").exists()
    
    # Verify JSON content
    with open(run_dir / "investigation_trace.json", 'r', encoding='utf-8') as f:
        trace_data = json.load(f)
        
    assert trace_data["case_id"] == case_id
    assert trace_data["query"] == query
    assert len(trace_data["events"]) > 0
    
    # Verify events
    event_types = [e["event_type"] for e in trace_data["events"]]
    assert "user_query" in event_types
    assert "agent_start" in event_types
    assert "agent_action" in event_types
    assert "agent_observation" in event_types
    assert "supervisor_route" in event_types
    assert "investigation_complete" in event_types
