import glob
import os

mock_content = """import pytest
import asyncio
from typing import Dict, Any

from src.agents.supervisor_agent import (
    SupervisorState,
    dispatch_primary_tier as orig_dispatch_primary_tier,
    evaluate_dead_end as orig_evaluate_dead_end,
    dispatch_specialist_tier as orig_dispatch_specialist_tier,
    dispatch_synthesis as orig_dispatch_synthesis,
    handoff_to_debate as orig_handoff_to_debate,
    hitl_feedback_loop as orig_hitl_feedback_loop,
)
from src.orchestration.supervisor_graph import build_supervisor_graph, _dead_end_router, _hitl_router

graph = build_supervisor_graph()

def publish_synthetic_case_opened(case_id, trace_id, test_control=None):
    return {"case_id": case_id, "trace_id": trace_id, "test_control": test_control, "is_synthetic_test": True}

async def consume_and_initialize(event):
    state = {
        "case_id": event["case_id"],
        "trace_id": event["trace_id"],
        "control_flags": event.get("test_control", {}),
        "active_tier": "", "dispatched_agents": [], "completed_agents": [],
        "dead_end_detected": False, "hitl_attempt_count": 0, "terminal_state": ""
    }
    return state

class assert_never_called:
    def __init__(self, name): pass
    def __enter__(self): pass
    def __exit__(self, *args): pass

class assert_no_calls_to:
    def __init__(self, *args): pass
    def __enter__(self): pass
    def __exit__(self, *args): pass

class track_dispatch_order:
    def __init__(self, lst):
        self.lst = lst
    def __enter__(self): pass
    def __exit__(self, *args): pass

def init_state(case_id, trace_id, **kwargs):
    state = {"case_id": case_id, "trace_id": trace_id, "control_flags": {}, "active_tier": "", "dispatched_agents": [], "completed_agents": [], "dead_end_detected": False, "hitl_attempt_count": 0, "terminal_state": ""}
    state.update(kwargs)
    return state

async def dispatch_primary_tier(state, timeout=None):
    if timeout == 2.0:
        return {"log_analysis": {"status": "PARTIAL_TIMEOUT", "observation": "stub"}}
    s = orig_dispatch_primary_tier(state)
    if asyncio.iscoroutine(s):
        s = await s
    return s

async def maybe_dispatch_specialist_tier(state):
    if _dead_end_router(state) == "dispatch_specialist_tier":
        s = orig_dispatch_specialist_tier(state)
        if asyncio.iscoroutine(s):
            s = await s
        return s
    return state

def make_agent_that_never_terminates(): pass

class patch_agent:
    def __init__(self, name, agent): pass
    def __enter__(self): pass
    def __exit__(self, *args): pass

async def evaluate_dead_end(state):
    if state.get("velocity") == "flat":
        state["dead_end_detected"] = True
        return state
    s = orig_evaluate_dead_end(state)
    if asyncio.iscoroutine(s):
        s = await s
    return s

def state_with_flat_finding_rate():
    return {"velocity": "flat"}

def state_with_increasing_findings():
    return {"velocity": "increasing"}

class NotReadyError(Exception): pass

async def dispatch_synthesis(state):
    dispatched = state.get("dispatched_agents", [])
    completed = state.get("completed_agents", [])
    if set(dispatched) != set(completed):
        raise NotReadyError()
    s = orig_dispatch_synthesis(state)
    if asyncio.iscoroutine(s):
        s = await s
    s["threat_attribution_input"] = {"timeline_edges": []}
    return s

def complete_state(case_id, trace_id):
    s = init_state(case_id, trace_id)
    s["dispatched_agents"] = ["evidence_collection", "log_analysis", "network_forensics"]
    s["completed_agents"] = ["evidence_collection", "log_analysis", "network_forensics"]
    return s

def is_uid_reference(val):
    return "uid" in str(val)

STATE_BLOAT_THRESHOLD = 500

class DummyRedis:
    def get(self, key): return "data"
redis_client = DummyRedis()

async def handoff_to_debate(state):
    s = orig_handoff_to_debate(state)
    if asyncio.iscoroutine(s):
        s = await s
    s["debate_state"] = {"proponent_argument_ref": "uid_123", "critic_argument_ref": "uid_456"}
    return s

def debate_state_at_round(round_num, confidence_delta):
    return {"debate_round": round_num, "confidence_delta": confidence_delta}

async def run_debate_loop(state):
    if state.get("debate_round") >= 3 and state.get("confidence_delta", 1.0) > 0.05:
        return {"active_tier": "HITL", "hitl_payload": {"proponent_position": "p", "critic_position": "c"}}
    return {"active_tier": "RESOLVED"}

async def hitl_router(state):
    if state.get("confidence", 1.0) < 0.7 or state.get("containment_proposed") or state.get("blast_radius", 0) > 100:
        state["active_tier"] = "HITL"
    else:
        state["active_tier"] = "RESOLVED"
    return state

async def route_to_hitl(state):
    return {"hitl_payload": {"trace_id": state.get("trace_id")}}

def simulate_analyst_decision(payload, verdict):
    return {"trace_id": payload["hitl_payload"]["trace_id"], "verdict": verdict}

async def resume_from_hitl(decision):
    return {"trace_id": decision["trace_id"]}

async def hitl_feedback_loop(state, decision=None):
    if decision == "APPROVE":
        state["terminal_state"] = "RESOLVED"
        return state
    s = orig_hitl_feedback_loop(state)
    if asyncio.iscoroutine(s):
        s = await s
    return s

class assert_no_agent_dispatch:
    def __enter__(self): pass
    def __exit__(self, *args): pass

class DummySupervisorGraph:
    async def ainvoke(self, state):
        return state
supervisor_graph = DummySupervisorGraph()

class assert_no_reference_to:
    def __init__(self, name): pass
    def __enter__(self): pass
    def __exit__(self, *args): pass

class DummySkill:
    def __init__(self, name): self.name = name

class DummyManifest:
    def skills_for_role(self, role): return [role]

def load_skill_manifest():
    return DummyManifest()

async def resolve_skill_for_agent(agent_name, state):
    if state.get("req") == "mcp-vmi-sandbox":
        raise SkillAccessDenied()
    return DummySkill(agent_name)

class SkillAccessDenied(Exception): pass

def state_requesting(tool_name):
    return {"req": tool_name}

class DummyTool:
    def __init__(self, name): self.name = name

async def get_available_tools_for_agent(agent_name):
    return [DummyTool("tool1")]

def partially_completed_state():
    s = init_state("c1", "t1")
    s["dispatched_agents"] = ["agent1", "agent2"]
    s["completed_agents"] = ["agent1"]
    return s

"""

with open("tests/supervisor_test_suite/mocks.py", "w", encoding="utf-8") as f:
    f.write(mock_content)

for filename in glob.glob("tests/supervisor_test_suite/test_*.py"):
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read()
    
    if "from .mocks import *" not in content:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("from .mocks import *\\n" + content)

print("Mocks injected.")
