import json

from langgraph.checkpoint.memory import InMemorySaver

import src.agents.graph as graph_module
from tests.agents.test_threat_attribution_agent import FakeGraph, FakeIntel, FakeModel


def test_full_graph_carries_scored_attribution_and_citations(monkeypatch):
    monkeypatch.setenv("SPECULA_LLM_BACKEND", "stub")
    monkeypatch.setattr(graph_module, "make_evidence_collection_node", lambda *args: lambda state: {
        "evidence_collection": {"case_id": "case-one", "status": "complete", "records": [
            {"uid": "event-one", "time": "2026-10-03T00:01:00Z"},
            {"uid": "event-two", "time": "2026-10-03T00:02:00Z"}], "degraded_flags": []}})
    monkeypatch.setattr(graph_module, "make_log_analysis_node", lambda *args: lambda state: {})
    monkeypatch.setattr(graph_module, "make_network_forensics_node", lambda *args: lambda state: {})

    class Producer:
        def __init__(self): self.published = []
        def produce(self, **kwargs): self.published.append(kwargs)
        def poll(self, timeout): pass

    producer = Producer()
    graph = graph_module.build_graph(
        checkpointer=InMemorySaver(), neo4j_driver=FakeGraph(),
        kafka_producer=producer, threat_intel=FakeIntel(),
        attribution_llm_factory=lambda case_id: FakeModel(),
    )
    result = graph.invoke({
        "case_id": "case-one", "trace_id": "trace-one", "input_type": "siem_alert",
        "raw_input": "PowerShell then SMB movement", "case_status": "open",
        "findings": [
            {"agent_role": "network_forensics", "summary": "SMB movement",
             "timestamp": "2026-10-03T00:10:00Z", "event_time": "2026-10-03T00:02:00Z",
             "attacks": ["T1021.002"], "dfkg_refs": ["event-two"]},
            {"agent_role": "log_analysis", "summary": "PowerShell execution",
             "timestamp": "2026-10-03T00:01:00Z", "attacks": ["T1059.001"], "dfkg_refs": ["event-one"]},
        ],
        "agent_traces": [], "debate_round": 1, "debate_history": [],
        "specialists_completed": [], "dead_end_detected": False,
        "dead_end_categories": [],
    }, {"configurable": {"thread_id": "threat-attribution-integration"}})

    assert result["case_status"] == "closed"
    assert result["timeline"]["frozen"] is True
    assert result["attribution"]["top_candidate"]["actor_id"] == "G0001"
    assert result["attribution"]["dfkg_refs"] == ["event-one", "event-two"]
    assert any(f.get("agent_role") == "report_generation" and f.get("dfkg_refs") == ["event-one", "event-two"]
               for f in result["findings"])
    published = [item for item in producer.published if item["topic"] == "findings.attribution"]
    assert len(published) == 1
    assert json.loads(published[0]["value"])["dfkg_refs"] == ["event-one", "event-two"]


def test_visualizer_graph_entrypoint_injects_neo4j_driver(monkeypatch):
    from unittest.mock import patch
    import src.agents.visualizer_api as visualizer

    driver = object()
    monkeypatch.setattr(visualizer, "_specula_graph", None)
    monkeypatch.setattr(visualizer, "_get_neo4j_driver", lambda: driver)
    with patch("src.agents.graph.build_graph", return_value="compiled") as builder:
        assert visualizer._get_specula_graph() == "compiled"
    assert builder.call_args.kwargs["neo4j_driver"] is driver
