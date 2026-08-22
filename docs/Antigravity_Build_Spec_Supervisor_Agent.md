# Antigravity Build Spec: Supervisor Agent (Orchestrator)

**Target Component:** `src/agents/supervisor_agent.py` & `src/orchestration/supervisor_graph.py`
**Frameworks:** LangGraph, Kafka (confluent-kafka), LangChain, Redis
**Model Assignment:** `Nemotron-3 Ultra` (via Together AI / Hugging Face endpoint)

## 1. State Schema Definition (`SupervisorState`)
Antigravity must define the LangGraph state for the Supervisor with the following typed schema. Do NOT inject raw evidence here.

```python
class SupervisorState(TypedDict):
    case_id: str
    trace_id: str
    control_flags: dict  # Extracted from test_control headers (e.g., FORCE_DEAD_END)
    active_tier: str     # 'PRIMARY', 'SPECIALIST', 'SYNTHESIS', 'DEBATE', 'HITL'
    dispatched_agents: list[str]
    completed_agents: list[str]
    dead_end_detected: bool
    hitl_attempt_count: int
    terminal_state: str  # e.g., 'MANUAL_OVERRIDE_REQUIRED', 'RESOLVED'
```

## 2. Event-Driven Entry Contract (Kafka Consumer)
Generate a listener process that acts as the entry point for the graph.

* **Topic:** `specula.cases.opened`
* **Payload Schema Requirement:** Must expect `case_id`, `trace_id`, and a URI pointer to the DFKG/Evidence. **Never** raw logs.
* **Test Controls:** The consumer must read the `test_control` Kafka header (or embedded trace_id flags). If flags like `FORCE_DEAD_END` or `FORCE_GUARDRAIL_FAIL_TIER:N` exist, they must be parsed and injected into `SupervisorState.control_flags` to guarantee Stage 1 deterministic test passes.
* **Action:** On message consume, initialize `SupervisorState` and call `supervisor_graph.invoke(state)`.

## 3. LangGraph Node Definitions & Routing Logic
Implement the orchestration loop using the following nodes and conditional edges.

### Node: `dispatch_primary_tier`
* **Action:** Dispatches the **Evidence Collection**, **Log Analysis**, and **Network Forensics** agents in parallel using the Blackboard pattern.
* **Constraint (Phase 5):** Enforce strict loop budgets (max iterations/tool calls) on these agents. Implement a graceful timeout (`asyncio.wait_for` equivalent) that forces partial observation return rather than indefinite blocking.

### Node: `evaluate_dead_end` (Supervisor Inactivity Heuristic)
* **Action:** Evaluates returned observations. Detects if the investigation has stalled.
* **Anti-Pattern to Avoid:** Do NOT use Neo4j APOC triggers (the 5s debounce) for this logic. Dead-end evaluation is purely an LLM reasoning heuristic based on agent output velocity and finding relevance.

### Node: `dispatch_specialist_tier` (Conditional)
* **Trigger:** Only fires if `evaluate_dead_end` returns `True` (or if `FORCE_DEAD_END` is set in `control_flags`).
* **Action:** Dispatches Memory, Identity, Malware, and Insider Threat agents.

### Node: `dispatch_synthesis` (TR & TA)
* **Wait Condition (Master_doc §14.3.9 constraint):** This node MUST explicitly await the completion of ALL dispatched Stage 1 and Stage 2 (Specialist) agents before firing.
* **Action:** Sequentially dispatch **Timeline Reconstruction (TR)**, then **Threat Attribution (TA)**.

### Node: `handoff_to_debate`
* **Action:** Transitions control to the ACH Debate Tier (Proponent → Critic → Judge).
* **State Constraint:** Pass ONLY UID references through the LangGraph state. Push the actual argument payloads into the Redis ephemeral scratchpad to prevent LangGraph state bloat.

## 4. HITL Escalation & Guardrail Router
Implement a conditional router that interrupts normal graph flow and routes to a `hitl_escalation` node if ANY of the following thresholds are breached:

1.  **Confidence:** Any agent reports a confidence score `< 0.7`.
2.  **Containment:** An active containment action is proposed.
3.  **Debate Failure:** Debate reaches the 3-round cap without the confidence delta dropping below `0.05`. (Force-escalate with both final Proponent/Critic positions attached).
4.  **Blast Radius:** Calculated impact exceeds predefined thresholds.

### Node: `hitl_feedback_loop`
* **Action:** Pauses graph execution to wait for dashboard callback (`APPROVE`, `REJECT`, `REQUEST_CLARIFICATION`).
* **Tracing Requirement:** Attach the `trace_id` to the HITL payload and ensure it is parsed from the returning human decision.
* **Cycle Bound (Master_doc §14.3.10 fix):** Increment `hitl_attempt_count`. If `hitl_attempt_count >= 3` (or configurable $N$), set `terminal_state = 'MANUAL_OVERRIDE_REQUIRED'` and permanently halt autonomous dispatch. Do not allow infinite Supervisor ↔ HITL ping-ponging.

## 5. Tool/Skill Governance
* When the Supervisor routes tasks to subordinates, it must **dynamically introspect a versioned skill manifest** rather than using hardcoded `agent -> tool` arrays. 

***

**Instructions for Antigravity:** *Treat this specification as absolute. Do not inject default LangChain tools (like Wikipedia/Search). Do not alter the wait-conditions for TR/TA. Begin by scaffolding `supervisor_graph.py` with the nodes and edges defined in Section 3.*
