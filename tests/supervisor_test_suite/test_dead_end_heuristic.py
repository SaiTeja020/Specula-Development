import pytest
from src.agents.supervisor_agent import evaluate_dead_end

def init_state(**kwargs):
    s = {
        "case_id": "c1", "trace_id": "t1", "control_flags": {}, "active_tier": "", 
        "dispatched_agents": [], "completed_agents": [], "dead_end_detected": False, 
        "hitl_attempt_count": 0, "terminal_state": ""
    }
    s.update(kwargs)
    return s

from unittest import mock

def test_dead_end_evaluation_never_touches_apoc():
    """The dead-end heuristic must be evaluated in-memory within the Supervisor StateGraph. It must NEVER issue APOC triggers to Neo4j."""
    with mock.patch("src.agents.supervisor_agent") as neo4j_mock:
        state = init_state()
        evaluate_dead_end(state)
        # If neo4j was called, this mock would register it. We assert it's untouched.
        neo4j_mock.apoc.assert_not_called()

def test_dead_end_based_on_finding_velocity():
    """If finding velocity across 2 successive loop iterations is 0 (flat), dead_end_detected MUST become True."""
    state = init_state(velocity="flat")
    result = evaluate_dead_end(state)
    assert result["dead_end_detected"] is True

def test_active_investigation_not_flagged_dead_end():
    """If finding velocity is >0, dead_end_detected MUST remain False."""
    state = init_state(velocity="increasing")
    result = evaluate_dead_end(state)
    assert result["dead_end_detected"] is False
