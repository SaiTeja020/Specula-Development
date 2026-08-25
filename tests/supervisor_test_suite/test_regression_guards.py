import pytest
from src.agents.supervisor_agent import dispatch_synthesis, NotReadyError, hitl_feedback_loop

def init_state(**kwargs):
    s = {
        "case_id": "c1", "trace_id": "t1", "control_flags": {}, "active_tier": "", 
        "dispatched_agents": [], "completed_agents": [], "dead_end_detected": False, 
        "hitl_attempt_count": 0, "terminal_state": ""
    }
    s.update(kwargs)
    return s

@pytest.mark.asyncio
async def test_tr_ta_wait_condition_is_enforced_not_advisory():
    """Regression Guard: Ensure synthesis dispatch physically raises NotReadyError if agents are running, not just logging a warning."""
    state = init_state(dispatched_agents=["a1", "a2"], completed_agents=["a1"])
    with pytest.raises(NotReadyError):
        await dispatch_synthesis(state)

@pytest.mark.asyncio
async def test_hitl_cycle_cap_is_enforced_not_advisory():
    """Regression Guard: Ensure HITL cycle cap of 3 strictly transitions state to MANUAL_OVERRIDE_REQUIRED without exception."""
    state = init_state(hitl_attempt_count=2)
    result = hitl_feedback_loop(state)
    assert result["terminal_state"] == "MANUAL_OVERRIDE_REQUIRED"
