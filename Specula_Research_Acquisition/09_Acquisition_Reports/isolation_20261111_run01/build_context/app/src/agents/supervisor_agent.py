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
    nl_query: Optional[str]
    query_routing_decision: Optional[str]
    degraded_capability_mode: Optional[bool]


async def dispatch_primary_tier(state: SupervisorState) -> SupervisorState:
    """Dispatches Evidence Collection, Log Analysis, and Network Forensics agents."""
    state['active_tier'] = 'PRIMARY'
    state['dispatched_agents'] = ['evidence_collection', 'log_analysis', 'network_forensics']
    
    # BUDGET ENFORCEMENT: Wrap ReAct loops in asyncio.wait_for to prevent infinite hangs.
    # Checkpointing constraint: catch TimeoutError and return partial state so progress survives container restart.
    try:
        # await asyncio.wait_for(invoke_agents(state['dispatched_agents']), timeout=300)
        state['completed_agents'] = list(state['dispatched_agents'])
    except asyncio.TimeoutError:
        state['terminal_state'] = 'INCOMPLETE: Loop budget exceeded'
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


async def dispatch_specialist_tier(state: SupervisorState) -> SupervisorState:
    """Dispatches Memory, Identity, Malware, and Insider Threat agents."""
    state['active_tier'] = 'SPECIALIST'
    state['dispatched_agents'] = ['memory_forensics', 'identity', 'cloud_container', 'malware_stylometry', 'insider_threat']
    
    try:
        # await asyncio.wait_for(invoke_agents(state['dispatched_agents']), timeout=300)
        state['completed_agents'] = list(state['dispatched_agents'])
    except asyncio.TimeoutError:
        state['terminal_state'] = 'INCOMPLETE: Loop budget exceeded'
        state['completed_agents'] = []

    return state


async def dispatch_synthesis(state: SupervisorState) -> SupervisorState:
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


def route_nl_query(state: SupervisorState) -> SupervisorState:
    """Uses Nemotron-3 Ultra to classify the nl_query intent and map it to the correct specialist agent."""
    query = state.get('nl_query')
    if not query:
        return state
    
    # Prompt Nemotron-3 Ultra to route the query
    # Mocking the LLM behavior for the skeleton:
    query_lower = query.lower()
    if 'lateral movement' in query_lower or 'network' in query_lower:
        decision = 'network_forensics'
    elif 'memory' in query_lower or 'process' in query_lower:
        decision = 'memory_forensics'
    else:
        decision = 'log_analysis'
        
    state['query_routing_decision'] = decision
    state['active_tier'] = 'SPECIALIST'
    state['dispatched_agents'] = [decision]
    state['completed_agents'] = [decision]
    return state


def handoff_to_debate(state: SupervisorState) -> SupervisorState:
    """Transitions control to the ACH Debate Tier.

    Routing priority (highest to lowest):
      1. HITL safety thresholds (confidence, containment, blast radius) — always escalate.
      2. Debate non-convergence after max rounds — escalate to human.
      3. Debate converged (low delta, past round 0) — resolve autonomously.
      4. Default — debate is starting or ongoing, continue.

    BUG-2 FIX: debate_state (uid refs) is always prepared for the Blackboard pattern, but
    dispatched_agents is only set to debate agents when we are actually entering the DEBATE
    tier. On HITL paths, those agents were never dispatched and must not appear in state.
    """
    # Always prepare the debate payload — uid-only references per ADR-001 Blackboard pattern.
    state['debate_state'] = {"proponent_argument_ref": "uid_prop", "critic_argument_ref": "uid_crit"}

    round_num = state.get("debate_round", 0)
    confidence_delta = state.get("confidence_delta", 1.0)

    # --- Priority 1: Safety thresholds always require human oversight (intentional design). ---
    hitl_threshold_triggered = (
        state.get("confidence", 1.0) < 0.7
        or state.get("containment_proposed")
        or state.get("blast_radius", 0) > 100
        or state.get("degraded_capability_mode")
    )

    if hitl_threshold_triggered:
        # Intentional: human must review high-risk or low-confidence outcomes.
        state['active_tier'] = 'HITL'
        state['hitl_payload'] = {"trace_id": state.get("trace_id")}
        # Do NOT set dispatched_agents to debate agents — they were never sent out.

    elif round_num >= 3 and confidence_delta > 0.05:
        # --- Priority 2: Debate did not converge after max rounds — escalate. ---
        state['active_tier'] = 'HITL'
        state['hitl_payload'] = {"trace_id": state.get("trace_id")}

    elif round_num > 0 and confidence_delta <= 0.05:
        # --- Priority 3: Debate converged, resolve autonomously. ---
        state['active_tier'] = 'RESOLVED'
        state['dispatched_agents'] = ['proponent', 'critic', 'judge']
        state['completed_agents'] = []

    else:
        # --- Priority 4: Debate is starting or mid-flight, continue. ---
        state['active_tier'] = 'DEBATE'
        state['dispatched_agents'] = ['proponent', 'critic', 'judge']
        state['completed_agents'] = []

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

def resolve_skill(agent_role: str, requested_tool: str, skill_manifest: dict, state: Optional[SupervisorState] = None) -> str:
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
        
    # 3. Capability Fallback Governance
    if state is not None:
        import os
        min_tier = skill_manifest.get(agent_role, {}).get("min_capability_tier", "light")
        deployed_tier = os.getenv("SPECULA_DEPLOYMENT_MODE", "full")
        
        # Override with control flag if present for testing
        if "DEPLOYED_MODEL_TIER" in state.get("control_flags", {}):
            deployed_tier = state["control_flags"]["DEPLOYED_MODEL_TIER"]
            
        if min_tier == "full" and deployed_tier == "light":
            state["degraded_capability_mode"] = True
            
    return requested_tool
