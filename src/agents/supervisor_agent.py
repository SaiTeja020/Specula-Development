from typing import TypedDict, List, Dict, Optional
import asyncio

class NotReadyError(Exception):
    pass
class SkillAccessDenied(Exception):
    pass

class SupervisorState(TypedDict):
    case_id: str
    trace_id: str
    control_flags: dict  # Extracted from test_control headers (e.g., FORCE_DEAD_END)
    active_tier: str     # 'PRIMARY', 'SPECIALIST', 'SYNTHESIS', 'DEBATE', 'HITL'
    dispatched_agents: List[str]
    completed_agents: List[str]
    dead_end_detected: bool
    hitl_attempt_count: int
    terminal_state: str  # e.g., 'MANUAL_OVERRIDE_REQUIRED', 'RESOLVED'


def dispatch_primary_tier(state: SupervisorState) -> SupervisorState:
    """Dispatches Evidence Collection, Log Analysis, and Network Forensics agents."""
    state['active_tier'] = 'PRIMARY'
    state['dispatched_agents'] = ['evidence_collection', 'log_analysis', 'network_forensics']
    state['completed_agents'] = []
    
    # Simulate execution where one agent times out if configured in control flags
    if state.get("control_flags", {}).get("PRIMARY_TIMEOUT"):
        # For testing, represent timeout in state or return partial
        pass

    return state


def evaluate_dead_end(state: SupervisorState) -> SupervisorState:
    """Evaluates returned observations to detect if the investigation has stalled."""
    if state.get('control_flags', {}).get('FORCE_DEAD_END', False):
        state['dead_end_detected'] = True
    elif state.get("velocity") == "flat":
        state['dead_end_detected'] = True
    else:
        state['dead_end_detected'] = False
        
    return state


def dispatch_specialist_tier(state: SupervisorState) -> SupervisorState:
    """Dispatches Memory, Identity, Malware, and Insider Threat agents."""
    state['active_tier'] = 'SPECIALIST'
    state['dispatched_agents'] = ['memory_forensics', 'identity_cloud', 'malware_stylometry', 'insider_threat']
    state['completed_agents'] = []
    return state


def dispatch_synthesis(state: SupervisorState) -> SupervisorState:
    """Sequentially dispatch Timeline Reconstruction (TR), then Threat Attribution (TA)."""
    dispatched = state.get("dispatched_agents", [])
    completed = state.get("completed_agents", [])
    if set(dispatched) != set(completed):
        raise NotReadyError("Synthesis cannot run until all dispatched agents complete.")

    state['active_tier'] = 'SYNTHESIS'
    state['dispatched_agents'] = ['timeline_reconstruction', 'threat_attribution']
    state['completed_agents'] = []
    state['threat_attribution_input'] = {"timeline_edges": []}
    return state


def handoff_to_debate(state: SupervisorState) -> SupervisorState:
    """Transitions control to the ACH Debate Tier."""
    state['active_tier'] = 'DEBATE'
    state['dispatched_agents'] = ['proponent', 'critic', 'judge']
    state['completed_agents'] = []
    state['debate_state'] = {"proponent_argument_ref": "uid_prop", "critic_argument_ref": "uid_crit"}

    # Simulate debate loop
    round_num = state.get("debate_round", 0)
    confidence_delta = state.get("confidence_delta", 1.0)
    
    if round_num >= 3 and confidence_delta > 0.05:
        state['active_tier'] = 'HITL'
        state['hitl_payload'] = {"trace_id": state.get("trace_id")}
    else:
        state['active_tier'] = 'RESOLVED'
        
    # Check HITL thresholds directly
    if state.get("confidence", 1.0) < 0.7 or state.get("containment_proposed") or state.get("blast_radius", 0) > 100:
        state['active_tier'] = 'HITL'
        state['hitl_payload'] = {"trace_id": state.get("trace_id")}
        
    return state


def hitl_feedback_loop(state: SupervisorState) -> SupervisorState:
    """Pauses graph execution to wait for dashboard callback."""
    state['active_tier'] = 'HITL'
    
    if state.get('hitl_verdict') == "APPROVE":
        state['terminal_state'] = 'RESOLVED'
        return state

    state['hitl_attempt_count'] = state.get('hitl_attempt_count', 0) + 1
    
    if state['hitl_attempt_count'] >= 3:
        state['terminal_state'] = 'MANUAL_OVERRIDE_REQUIRED'
        
    return state

def resolve_skill(agent_role: str, requested_tool: str, skill_manifest: dict) -> str:
    """
    Dynamically introspects a versioned skill manifest to route tools.
    Enforces least-privilege scoping (e.g., Report Generation cannot access mcp-vmi-sandbox).
    """
    # 1. Fetch allowed skills for this specific agent role
    allowed_skills = skill_manifest.get(agent_role, {}).get("allowed_skills", [])
    
    # 2. Enforce strict boundary checks
    if requested_tool not in allowed_skills:
        raise SkillAccessDenied(
            f"SECURITY BLOCK: Agent '{agent_role}' attempted to access out-of-scope tool '{requested_tool}'."
        )
        
    return requested_tool
