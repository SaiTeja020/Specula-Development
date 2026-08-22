import pytest
from src.agents.supervisor_agent import SupervisorState
from src.orchestration.supervisor_graph import build_supervisor_graph

def test_supervisor_graph_normal_flow():
    graph = build_supervisor_graph()
    
    initial_state: SupervisorState = {
        "case_id": "test_1",
        "trace_id": "trace_1",
        "control_flags": {},
        "active_tier": "",
        "dispatched_agents": [],
        "completed_agents": [],
        "dead_end_detected": False,
        "hitl_attempt_count": 0,
        "terminal_state": ""
    }
    
    # Run the graph
    final_state = graph.invoke(initial_state)
    
    # It should route through primary, not detect dead end, go to synthesis, then debate, and end
    assert final_state["active_tier"] == "DEBATE"
    assert "proponent" in final_state["dispatched_agents"]

def test_supervisor_graph_dead_end_flow():
    graph = build_supervisor_graph()
    
    initial_state: SupervisorState = {
        "case_id": "test_2",
        "trace_id": "trace_2",
        "control_flags": {"FORCE_DEAD_END": True},
        "active_tier": "",
        "dispatched_agents": [],
        "completed_agents": [],
        "dead_end_detected": False,
        "hitl_attempt_count": 0,
        "terminal_state": ""
    }
    
    # Run the graph
    final_state = graph.invoke(initial_state)
    
    # It should hit evaluate_dead_end, detect dead end, route to specialist, then synthesis, then debate
    assert final_state["dead_end_detected"] is True
    assert final_state["active_tier"] == "DEBATE"
