import pytest
from src.orchestration.supervisor_graph import build_supervisor_graph

graph = build_supervisor_graph()

def init_state(**kwargs):
    s = {
        "case_id": "c1", "trace_id": "t1", "control_flags": {}, "active_tier": "", 
        "dispatched_agents": [], "completed_agents": [], "dead_end_detected": False, 
        "hitl_attempt_count": 0, "terminal_state": ""
    }
    s.update(kwargs)
    return s

@pytest.mark.asyncio
async def test_primary_tier_dispatches_all_three_in_parallel():
    """Primary tier must dispatch log_analysis, evidence_collection, and network_forensics simultaneously (parallel node execution)."""
    from src.agents.supervisor_agent import dispatch_primary_tier
    state = init_state()
    result = await dispatch_primary_tier(state)
    assert "log_analysis" in result["dispatched_agents"]
    assert "evidence_collection" in result["dispatched_agents"]
    assert "network_forensics" in result["dispatched_agents"]
    assert result["active_tier"] == "PRIMARY"

@pytest.mark.asyncio
async def test_specialist_tier_not_dispatched_without_dead_end():
    """Specialist agents must NOT be dispatched in the primary tier."""
    from src.agents.supervisor_agent import dispatch_primary_tier
    state = init_state()
    result = await dispatch_primary_tier(state)
    assert "malware_analysis" not in result["dispatched_agents"]

@pytest.mark.asyncio
async def test_specialist_tier_dispatched_on_dead_end():
    """If dead_end_detected is True, _dead_end_router MUST route to specialist tier."""
    from src.orchestration.supervisor_graph import _dead_end_router
    state = init_state(dead_end_detected=True)
    assert _dead_end_router(state) == "dispatch_specialist_tier"

@pytest.mark.asyncio
async def test_force_dead_end_flag_triggers_specialist_dispatch():
    """If control_flags contains FORCE_DEAD_END, the dead end condition must trigger immediately."""
    from src.agents.supervisor_agent import evaluate_dead_end
    from src.orchestration.supervisor_graph import _dead_end_router
    state = init_state(control_flags={"FORCE_DEAD_END": True})
    # Node logic
    state = evaluate_dead_end(state)
    assert state["dead_end_detected"] is True
    # Router logic
    assert _dead_end_router(state) == "dispatch_specialist_tier"
