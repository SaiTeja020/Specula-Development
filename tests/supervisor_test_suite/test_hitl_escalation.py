import pytest
from src.agents.supervisor_agent import handoff_to_debate, hitl_feedback_loop
from src.orchestration.supervisor_graph import _hitl_router
from langgraph.graph import END

def init_state(**kwargs):
    s = {
        "case_id": "c1", "trace_id": "t1", "control_flags": {}, "active_tier": "", 
        "dispatched_agents": [], "completed_agents": [], "dead_end_detected": False, 
        "hitl_attempt_count": 0, "terminal_state": ""
    }
    s.update(kwargs)
    return s

@pytest.mark.parametrize("trigger_state, expected_hitl", [
    ({"confidence": 0.5}, True),
    ({"confidence": 0.9}, False),
    ({"containment_proposed": True}, True),
    ({"blast_radius": 105}, True),
    ({"blast_radius": 1}, False),
])
def test_hitl_router_thresholds(trigger_state, expected_hitl):
    """Verify exact thresholds for autonomous-vs-HITL routing in debate handoff."""
    state = init_state(**trigger_state)
    result = handoff_to_debate(state)
    assert (result["active_tier"] == "HITL") == expected_hitl

def test_hitl_payload_carries_trace_id():
    """The payload sent to the Web UI via Kafka MUST include the trace_id so the human verdict can be correlated."""
    state = init_state(containment_proposed=True, trace_id="trace_x")
    result = handoff_to_debate(state)
    assert result["hitl_payload"]["trace_id"] == "trace_x"

def test_hitl_attempt_count_increments_each_cycle():
    """Each time a case routes to HITL, hitl_attempt_count MUST increment by 1."""
    state = init_state(hitl_attempt_count=1)
    result = hitl_feedback_loop(state)
    assert result["hitl_attempt_count"] == 2

def test_hitl_forces_manual_override_at_cycle_cap():
    """If hitl_attempt_count reaches the cycle cap (e.g., 3), the system MUST force a MANUAL_OVERRIDE_REQUIRED terminal state."""
    state = init_state(hitl_attempt_count=2) # Enters as 2, gets incremented to 3
    result = hitl_feedback_loop(state)
    assert result["terminal_state"] == "MANUAL_OVERRIDE_REQUIRED"

def test_manual_override_halts_further_dispatch():
    """Once in MANUAL_OVERRIDE_REQUIRED, no further agents or synthesis nodes can be dispatched. Graph ends."""
    state = init_state(terminal_state="MANUAL_OVERRIDE_REQUIRED")
    assert _hitl_router(state) == END

def test_approve_at_any_cycle_does_not_increment_toward_override():
    """If the analyst APPROVES (e.g., on cycle 2), the state becomes RESOLVED, skipping the cycle cap."""
    state = init_state(hitl_attempt_count=2, hitl_verdict="APPROVE")
    result = hitl_feedback_loop(state)
    assert result["terminal_state"] == "RESOLVED"
    assert _hitl_router(result) == END
