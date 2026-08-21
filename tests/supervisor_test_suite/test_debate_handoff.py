import pytest
from src.agents.supervisor_agent import handoff_to_debate
from src.orchestration.supervisor_graph import _debate_router

def init_state(**kwargs):
    s = {
        "case_id": "c1", "trace_id": "t1", "control_flags": {}, "active_tier": "", 
        "dispatched_agents": [], "completed_agents": [], "dead_end_detected": False, 
        "hitl_attempt_count": 0, "terminal_state": ""
    }
    s.update(kwargs)
    return s

def test_debate_handoff_passes_only_uid_references():
    """The payload passed to the debate subgraph MUST contain only Neo4j UID references (pointers), NEVER the full text of the findings."""
    state = init_state()
    result = handoff_to_debate(state)
    assert "uid" in result["debate_state"]["proponent_argument_ref"]
    assert "uid" in result["debate_state"]["critic_argument_ref"]

def test_debate_non_convergence_after_three_rounds_escalates_hitl():
    """If debate_round >= 3 and confidence_delta > 0.05, it MUST route to HITL."""
    state = init_state(debate_round=3, confidence_delta=0.10)
    result = handoff_to_debate(state)
    assert result["active_tier"] == "HITL"
    assert _debate_router(result) == "hitl_feedback_loop"

def test_debate_converges_before_three_rounds_skips_hitl():
    """If confidence_delta <= 0.05 before round 3, it resolves the finding without HITL escalation."""
    state = init_state(debate_round=2, confidence_delta=0.02)
    result = handoff_to_debate(state)
    # The default if < 3 rounds is to resolve unless HITL thresholds hit
    assert result["active_tier"] == "RESOLVED"
