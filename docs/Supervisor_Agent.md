Supervisor Agent Implementation Plan: Specula **DFIR** Framework1. Project Context & Architectural RoleSpecula (Specula-Agent) is an autonomous multi-agent Digital Forensics and Incident Response (**DFIR**) framework designed to reconstruct cyber-incident crime scenes from fragmented, heterogeneous evidence into a unified Digital Forensic Knowledge Graph (**DFKG**) hosted on Neo4j. The framework coordinates 13 specialized AI agent roles to achieve sub-5-minute investigation times while maintaining Daubert legal admissibility standards.  The Supervisor Agent is the central orchestrator of Specula. It enforces a hybrid governance model:  Deterministic LangGraph Execution: State transitions, stage completion barriers, human-in-the-loop limits, and test overrides are governed deterministically by a compiled StateGraph without prompt-based routing hallucinations.Bounded **LLM** Inactivity Reasoning: Specialized semantic evaluations (e.g., assessing stalled investigation telemetry during dead-end evaluations) are powered by Nemotron-3 Ultra.  2. Component Deliverables & State SchemaFile Targetssrc/agents/supervisor_agent.py: Agent node functions, custom exceptions, state mutations, and dynamic skill resolvers.src/orchestration/supervisor_graph.py: LangGraph StateGraph structure, transition edges, and routing predicates.tests/supervisor_test_suite/test_supervisor_entry.py: Full regression and unit test suite enforcing deterministic contracts.Runtime State Contract (SupervisorState)The orchestration state tracks references, metrics, and lifecycle flags; raw forensic payloads are strictly excluded to prevent graph serialization overhead.Pythonfrom typing import TypedDict, List, Dict, Any, Optional

class SupervisorState(TypedDict):
    case_id: str
    trace_id: str
    control_flags: Dict[str, Any]      # Extracted from test_control headers (e.g., FORCE_DEAD_END)
    active_tier: str                  # '**PRIMARY**', '**SPECIALIST**', '**SYNTHESIS**', '**DEBATE**', '**HITL**', '**RESOLVED**'
    dispatched_agents: List[str]
    completed_agents: List[str]
    dead_end_detected: bool
    hitl_attempt_count: int
    terminal_state: str               # 'MANUAL_OVERRIDE_REQUIRED', '**RESOLVED**', or empty
    confidence: Optional[float]
    confidence_delta: Optional[float]
    debate_round: Optional[int]
    containment_proposed: Optional[bool]
    blast_radius: Optional[int]
    hitl_verdict: Optional[str]        # '**APPROVE**', '**REJECT**', 'REQUEST_CLARIFICATION'
    hitl_payload: Optional[Dict[str, Any]]
    debate_state: Optional[Dict[str, str]]
    threat_attribution_input: Optional[Dict[str, Any]]
    velocity: Optional[str]           # Finding velocity: 'flat', 'increasing'
(All fields are managed via explicit single-writer or append semantics).  3. Event-Driven Ingestion ContractThe Supervisor does not accept direct raw input injections. It initializes execution via an asynchronous Kafka message broker listener:  Kafka Trigger Topic: specula.cases.opened.Payload Structure: Must contain case_id, trace_id, and a **URI** pointer to the initialized **DFKG** subgraph.Test Control Parsing: Header values from test_control (e.g., FORCE_DEAD_END, FORCE_JUDGE_REJECT, FORCE_GUARDRAIL_FAIL_TIER:N, PRIMARY_TIMEOUT) or trace-embedded control tokens are parsed into SupervisorState[*control_flags*] before invoking the graph.Graph Invocation: Initialized via build_supervisor_graph().invoke(initial_state) seeded exclusively with case_id and trace_id to maintain distributed tracing across the **DFKG** and Kafka.4. LangGraph Node Specifications & Stage Transitions [**START**]
    │
    ▼
[dispatch_primary_tier] ──► [evaluate_dead_end]
    │
    ┌───────────────┴───────────────┐
    ▼ (dead_end == True)            ▼ (dead_end == False)
    [dispatch_specialist_tier]                  │
    │                               │
    └───────────────┬───────────────┘
    ▼
    [dispatch_synthesis]
    │
    ▼
    [handoff_to_debate]
    │
    ┌───────────────┴───────────────┐
    ▼ (Escalation Triggered)         ▼ (Consensus / Resolved)
    [hitl_feedback_loop]                    [**END**]
    │
    ┌─────────┴─────────┐
    ▼ (Resolved / Cap)  ▼ (Resume / Retry)
    [**END**]        [dispatch_synthesis]
Stage 1: Primary Tier Dispatch (dispatch_primary_tier)Dispatched Subordinates: evidence_collection, log_analysis, network_forensics executed concurrently.  Execution Contract: Subordinate agents run bounded ReAct loops. If an agent hits its loop budget or timeout, it returns a partial observation back to the Supervisor.  State Updates: active_tier = '**PRIMARY**', dispatched_agents = ['evidence_collection', 'log_analysis', 'network_forensics'], completed_agents = [].Stage 2: Dead-End Evaluation Heuristic (evaluate_dead_end)Evaluation Mechanism: Purely an in-memory **LLM** inactivity and finding-velocity heuristic. It measures whether finding generation has plateaued ($velocity = 0$).Decoupling Constraint: Strictly forbids Neo4j **APOC** triggers for dead-end determination. **APOC** triggers are isolated to milestone graph events with an independent 5-second debounce window.  State Updates: Sets dead_end_detected = True if control_flags['FORCE_DEAD_END'] is active or if velocity == 'flat'; otherwise False.Stage 2 (Conditional): Specialist Tier Dispatch (dispatch_specialist_tier)Trigger: Invoked exclusively when dead_end_detected == True.  Dispatched Subordinates: memory_forensics, identity_cloud, malware_stylometry, insider_threat.  State Updates: active_tier = '**SPECIALIST**', dispatched_agents = ['memory_forensics', 'identity_cloud', 'malware_stylometry', 'insider_threat'], completed_agents = [].Stage 3: Synthesis Tier (dispatch_synthesis)Completion Barrier: Enforces a rigid completion prerequisite:$$\text{dispatched\_agents} \equiv \text{completed\_agents}$$
Raises NotReadyError if any dispatched agent from the Primary or Specialist tier has not returned its final observation.Dispatched Subordinates: Sequentially dispatches Timeline Reconstruction (TR) (powered by DeepSeek-V3.2) followed by Threat Attribution (TA) (powered by Kimi K2.6).  State Updates: active_tier = '**SYNTHESIS**', dispatched_agents = ['timeline_reconstruction', 'threat_attribution'], completed_agents = [].Stage 4: Analysis of Competing Hypotheses Debate (handoff_to_debate)Subordinates: proponent, critic, judge executing an iterative debate cycle (max 3 rounds).  Memory Management: Passes only 8-byte **UID** references (e.g., uid_prop, uid_crit) through the LangGraph state; full evidentiary transcripts and claim matrices are stored in the ephemeral Redis scratchpad.  Escalation Routing Check: Evaluates state conditions against **HITL** risk boundaries.  5. Escalation Thresholds & Anti-Ping-Pong **HITL** LogicAutomatic **HITL** Escalation TriggersThe handoff_to_debate node routes directly to hitl_feedback_loop if any of the following conditions evaluate to True:  Low Confidence: Subordinate finding confidence $< 0.70$.  Active Containment: containment_proposed == True (e.g., host isolation, credential revocation).  Blast Radius Threshold: Calculated impact blast radius $> **100**$ affected graph nodes.  Debate Non-Convergence: Debate reaches round 3 with confidence score delta between Proponent and Critic $> 0.05$.  **HITL** Node & Router Logic (hitl_feedback_loop & _hitl_router)Trace Propagation: The hitl_payload must encapsulate the original trace_id to allow bi-directional correlation with analyst decisions from the dashboard.Approval Handling: If hitl_verdict == *APPROVE*, sets terminal_state = '**RESOLVED**', which the router directs to **END**.Anti-Ping-Pong Cycle Cap: Increments hitl_attempt_count by 1 on each entry. If hitl_attempt_count >= 3, the system sets terminal_state = 'MANUAL_OVERRIDE_REQUIRED' and halts autonomous execution to prevent infinite agent-analyst loops.6. Dynamic Tool Resolution & Least-Privilege GovernanceTo eliminate static attack vectors and comply with zero-trust mandates, the Supervisor contains no hardcoded AGENT_TOOL_MAPPING. Tool assignments are validated dynamically at runtime:Pythonclass SkillAccessDenied(Exception):
    """Raised when an agent attempts to invoke a tool outside its authorized scope."""
    pass

def resolve_skill(agent_role: str, requested_tool: str, skill_manifest: dict) -> str:
    """
    Dynamically introspects a versioned skill manifest to validate tool authorization.
    Prevents unauthorized lateral capability escalation.
    """
    allowed_skills = skill_manifest.get(agent_role, {}).get(*allowed_skills*, [])
    if requested_tool not in allowed_skills:
    raise SkillAccessDenied(
    f"**SECURITY** **BLOCK**: Agent '{agent_role}' attempted to access unauthorized tool '{requested_tool}'."
    )
    return requested_tool
(Prevents privilege escalation, such as Report Generation calling mcp-vmi-sandbox).7. Complete Reference Implementationsrc/agents/supervisor_agent.pyPythonfrom typing import TypedDict, List, Dict, Any, Optional
import asyncio

class NotReadyError(Exception):
    """Raised when downstream nodes fire before prerequisite tier agents complete."""
    pass

class SkillAccessDenied(Exception):
    """Raised when an agent requests out-of-scope capabilities."""
    pass

class SupervisorState(TypedDict):
    case_id: str
    trace_id: str
    control_flags: Dict[str, Any]
    active_tier: str
    dispatched_agents: List[str]
    completed_agents: List[str]
    dead_end_detected: bool
    hitl_attempt_count: int
    terminal_state: str
    confidence: Optional[float]
    confidence_delta: Optional[float]
    debate_round: Optional[int]
    containment_proposed: Optional[bool]
    blast_radius: Optional[int]
    hitl_verdict: Optional[str]
    hitl_payload: Optional[Dict[str, Any]]
    debate_state: Optional[Dict[str, str]]
    threat_attribution_input: Optional[Dict[str, Any]]
    velocity: Optional[str]

def dispatch_primary_tier(state: SupervisorState) -> SupervisorState:
    state[*active_tier*] = *PRIMARY*
    state[*dispatched_agents*] = [*evidence_collection*, *log_analysis*, *network_forensics*]
    state[*completed_agents*] = []
    return state

def evaluate_dead_end(state: SupervisorState) -> SupervisorState:
    if state.get(*control_flags*, {}).get(*FORCE_DEAD_END*, False):
    state[*dead_end_detected*] = True
    elif state.get(*velocity*) == *flat*:
    state[*dead_end_detected*] = True
    else:
    state[*dead_end_detected*] = False
    return state

def dispatch_specialist_tier(state: SupervisorState) -> SupervisorState:
    state[*active_tier*] = *SPECIALIST*
    state[*dispatched_agents*] = [*memory_forensics*, *identity_cloud*, *malware_stylometry*, *insider_threat*]
    state[*completed_agents*] = []
    return state

def dispatch_synthesis(state: SupervisorState) -> SupervisorState:
    dispatched = state.get(*dispatched_agents*, [])
    completed = state.get(*completed_agents*, [])
    if set(dispatched) != set(completed):
    raise NotReadyError("Synthesis cannot run until all dispatched agents complete.*)

    state[*active_tier*] = *SYNTHESIS*
    state[*dispatched_agents*] = [*timeline_reconstruction*, *threat_attribution*]
    state[*completed_agents*] = []
    state[*threat_attribution_input*] = {*timeline_edges": []}
    return state

def handoff_to_debate(state: SupervisorState) -> SupervisorState:
    state[*active_tier*] = *DEBATE*
    state[*dispatched_agents*] = [*proponent*, *critic*, *judge*]
    state[*completed_agents*] = []
    state[*debate_state*] = {*proponent_argument_ref*: *uid_prop*, *critic_argument_ref*: *uid_crit*}

    round_num = state.get(*debate_round*, 0)
    confidence_delta = state.get(*confidence_delta*, 1.0)

    # Check non-convergence at round cap
    if round_num >= 3 and confidence_delta > 0.05:
    state[*active_tier*] = *HITL*
    state[*hitl_payload*] = {*trace_id*: state.get(*trace_id*)}
    return state

    # Check primary escalation thresholds
    if (
    state.get(*confidence*, 1.0) < 0.7
    or state.get(*containment_proposed*) is True
    or state.get(*blast_radius*, 0) > **100**
    ):
    state[*active_tier*] = *HITL*
    state[*hitl_payload*] = {*trace_id*: state.get(*trace_id*)}
    else:
    state[*active_tier*] = *RESOLVED*

    return state

def hitl_feedback_loop(state: SupervisorState) -> SupervisorState:
    state[*active_tier*] = *HITL*
    if state.get(*hitl_verdict*) == *APPROVE*:
    state[*terminal_state*] = *RESOLVED*
    return state

    state[*hitl_attempt_count*] = state.get(*hitl_attempt_count*, 0) + 1
    if state[*hitl_attempt_count*] >= 3:
    state[*terminal_state*] = *MANUAL_OVERRIDE_REQUIRED*

    return state

def resolve_skill(agent_role: str, requested_tool: str, skill_manifest: dict) -> str:
    allowed_skills = skill_manifest.get(agent_role, {}).get(*allowed_skills*, [])
    if requested_tool not in allowed_skills:
    raise SkillAccessDenied(
    f"**SECURITY** **BLOCK**: Agent '{agent_role}' attempted to access unauthorized tool '{requested_tool}'."
    )
    return requested_tool
src/orchestration/supervisor_graph.pyPythonfrom langgraph.graph import StateGraph, **START**, **END**
from src.agents.supervisor_agent import (
    SupervisorState,
    dispatch_primary_tier,
    evaluate_dead_end,
    dispatch_specialist_tier,
    dispatch_synthesis,
    handoff_to_debate,
    hitl_feedback_loop,
)

def _dead_end_router(state: SupervisorState) -> str:
    if state.get(*dead_end_detected*):
    return *dispatch_specialist_tier*
    return *dispatch_synthesis*

def _hitl_router(state: SupervisorState) -> str:
    if state.get(*terminal_state*) in [*MANUAL_OVERRIDE_REQUIRED*, *RESOLVED*]:
    return **END**
    return *dispatch_synthesis*

def _debate_router(state: SupervisorState) -> str:
    if state.get(*active_tier*) == *HITL*:
    return *hitl_feedback_loop*
    return **END**

def build_supervisor_graph():
    builder = StateGraph(SupervisorState)

    # Register Nodes
    builder.add_node(*dispatch_primary_tier*, dispatch_primary_tier)
    builder.add_node(*evaluate_dead_end*, evaluate_dead_end)
    builder.add_node(*dispatch_specialist_tier*, dispatch_specialist_tier)
    builder.add_node(*dispatch_synthesis*, dispatch_synthesis)
    builder.add_node(*handoff_to_debate*, handoff_to_debate)
    builder.add_node(*hitl_feedback_loop*, hitl_feedback_loop)

    # Register Edges & Conditional Routes
    builder.add_edge(**START**, *dispatch_primary_tier*)
    builder.add_edge(*dispatch_primary_tier*, *evaluate_dead_end*)

    builder.add_conditional_edges(
    *evaluate_dead_end*,
    _dead_end_router,
    {
    *dispatch_specialist_tier*: *dispatch_specialist_tier*,
    *dispatch_synthesis*: *dispatch_synthesis*,
    },
    )

    builder.add_edge(*dispatch_specialist_tier*, *dispatch_synthesis*)
    builder.add_edge(*dispatch_synthesis*, *handoff_to_debate*)

    builder.add_conditional_edges(
    *handoff_to_debate*,
    _debate_router,
    {
    *hitl_feedback_loop*: *hitl_feedback_loop*,
    **END**: **END**,
    },
    )

    builder.add_conditional_edges(
    *hitl_feedback_loop*,
    _hitl_router,
    {
    **END**: **END**,
    *dispatch_synthesis*: *dispatch_synthesis*,
    },
    )

    return builder.compile()
## Verification Matrix & Test StrategyThe test suite validates every boundary condition without relying on arbitrary prompt mocks:Test IdentifierValidated RequirementAssertion Conditiontest_hitl_router_thresholdsConfidence $< 0.7$, Containment, Blast Radius $> 100$result[*active_tier*] == *HITL*test_hitl_payload_carries_trace_idEnd-to-end distributed tracing across HITL payloadresult[*hitl_payload*][*trace_id*] == state[*trace_id*]test_hitl_attempt_count_incrementsAnti-ping-pong cycle trackingstate[*hitl_attempt_count*] increments by 1test_hitl_forces_manual_overrideCycle cap enforcement ($N \ge 3$)terminal_state == *MANUAL_OVERRIDE_REQUIRED*test_manual_override_halts_dispatchPermanent halting on override required_hitl_router(state) == ENDtest_dead_end_never_touches_apocAPOC decoupling from dead-end detectionneo4j_mock.apoc.assert_not_called()test_synthesis_completion_barrierTR/TA awaits all dispatched agentsRaises NotReadyError if agents incompletetest_supervisor_blocks_out_of_scopeZero-trust dynamic skill resolutionRaises SkillAccessDenied on invalid toolExecution verification command:Bashpytest tests/supervisor_test_suite/ -v