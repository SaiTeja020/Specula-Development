# Specula Evidentiary Adversarial Debate (ACH) Subsystem — Implementation Plan v2

## 1. Introduction and Architectural Alignment
The Evidentiary Adversarial Debate subsystem executes an Analysis of Competing Hypotheses (ACH) protocol to mathematically eliminate hallucinations and anchor conclusions to the Digital Forensic Knowledge Graph (DFKG). This implementation plan is designed to be integrated directly with the framework defined in the file named **Specula**. The subsystem receives a frozen causal timeline and MITRE ATT&CK attributions, treating the synthesized narrative as a binary conflict between a primary hypothesis and an alternative counter-argument.

**Gate Condition:** The debate subgraph is only invoked if `case_state == "FROZEN"` and all dispatched primary and specialist agents have completed execution without lagging consumer writes.

---

## 2. Agent Configuration & Operational Boundaries
All agents operate as strict ReAct architectures with explicitly bounded loops (max 5 iterations, 40s timeout) implemented via `asyncio.wait_for`.

*   **Proponent Agent (Nemotron-3 Super 120B):** Constructs the primary hypothesis $H_1$. 
    *   *Tools:* `mcp-dfkg-cypher:read_query`, `mcp-vct-ledger:append_interaction`.
*   **Critic Agent (Llama-3.3-70B-Instruct):** Hunts for timeline contradictions and constructs alternative explanations $H_2$. Deliberately utilizes a different model family to avoid correlated blind spots.
    *   *Tools:* `mcp-dfkg-cypher:read_query`, `mcp-dataset-eval:query_baseline`, `mcp-vct-ledger:append_interaction`.
*   **Judge Agent (Nemotron-3 Ultra 550B):** Acts as the arbitrator evaluating raw evidence entailment in a single batched pass.
    *   *Tools:* `mcp-vct-ledger:append_interaction` (Math delegated to deterministic skill).

*Note: For air-gapped deployments or API failures, model routing falls back to a local quantized 7B model, appending a `degraded_capability_mode: true` flag to the final report and HITL payload.*

---

## 3. Rejected Architectural Approaches & Decisions
To prevent regressions during development, the following alternative designs were explicitly evaluated and rejected:

1.  **Rejected: Pure ReAct for the Judge Agent**
    *   *Reason:* The Judge must act as a strict evidentiary arbitrator. Giving it exploratory tool-use capabilities (like the Proponent/Critic) risks hallucinating new investigative paths or suffering from ReAct wandering. It is strictly constrained to an Agent-Eval rubric.
2.  **Rejected: Calculating the ACH Matrix inside the LLM Context**
    *   *Reason:* LLMs exhibit high hallucination rates when performing deterministic Laplace smoothing and softmax calculations. The math has been offloaded to a deterministic Python tool (`calculate_ach_matrix`).
3.  **Rejected: Judge Evaluating Agent Rationale instead of Raw Evidence**
    *   *Reason:* Allowing the Judge to score entailment based on the Proponent/Critic's persuasive text creates a parametric-trust failure. The Judge is now blinded to agent labels and evaluates *raw node content* retrieved deterministically via `mcp-dfkg-cypher`.
4.  **Rejected: Failing Open on Debate Ties ($\Delta < 0.05$)**
    *   *Reason:* Earlier drafts terminated the debate if hypotheses tied, without declaring a winner. A tie means the system cannot mathematically distinguish the truth. This now correctly routes to a `DEADLOCK_TIE` state and force-escalates to the Human-in-the-Loop (HITL) dashboard.
5.  **Rejected: Passing Full Argument Text in LangGraph State**
    *   *Reason:* Passing full text scales memory linearly and causes severe network overhead. LangGraph passes only 8-byte/SHA-256 UIDs, while the heavy text payloads are stored in an ephemeral Redis scratchpad.
6.  **Rejected: Unbounded Fast-Fail Retries for Citation Errors**
    *   *Reason:* An LLM caught in a hallucination loop could retry forever, burning API tokens. The system now enforces a strict 3-attempt validation budget before escalating to HITL via `VALIDATION_EXHAUSTED`.
7.  **Rejected: Raw Neo4j Driver Queries for Citation Validation**
    *   *Reason:* Bypassing the MCP layer for validation means those reads bypass the Verifiable Conversation Transcripts (VCT) Merkle chain. All validation must route through `mcp-dfkg-cypher:verify_uids`.

---

## 4. State Schemas & Data Contracts

### 4.1 LangGraph State (Lightweight Routing)
Passes only scalar metadata and SHA-256 hex UIDs.

```python
from typing import TypedDict, Literal, Optional

class DebateGraphState(TypedDict):
    case_id: str
    trace_id: str
    round_index: int                       # Code-managed (1 to 3)
    validation_attempts: int               # Code-managed (Max 3 per turn)
    active_turn: Literal["PROPONENT", "CRITIC", "JUDGE"]
    proponent_payload_uid: str             # SHA-256 hash pointer to Redis
    critic_payload_uid: str                # SHA-256 hash pointer to Redis
    p_h1: Optional[float]                  # Code-managed derived probability
    p_h2: Optional[float]                  # Code-managed derived probability
    convergence_status: Literal[
        "PENDING", "CONVERGED_DOMINANT", "CONVERGED_STABLE", 
        "DEADLOCK_TIE", "VALIDATION_EXHAUSTED", "TOOL_TIMEOUT"
    ]
```

### 4.2 Redis Storage Contract (Durable Payloads)
Payloads are persisted durably on commit and hashed into the VCT atomic chain. Ephemeral TTLs (86400s) are dynamically suspended while `case_state == "HITL"`.

```python
from pydantic import BaseModel, Field
from typing import List, Literal

class CitedClaim(BaseModel):
    assertion: str
    cited_uids: List[str] = Field(min_length=1)  # Reject empty citations

class AgentPayload(BaseModel):
    case_id: str
    round_index: int
    hypothesis: str
    claims: List[CitedClaim]
    retrieved_uids: List[str]  # Must contain all cited_uids (Provenance check)

class EvidenceEvaluation(BaseModel):
    evidence_uid: str
    relation_to_A: Literal["CONFIRMS", "CONTRADICTS", "NEUTRAL"]
    relation_to_B: Literal["CONFIRMS", "CONTRADICTS", "NEUTRAL"]
```

---

## 5. Middleware, Validation & Context Hydration

### 5.1 Context Compaction & Judge Blinding
*   **Compaction:** Active round payloads are loaded fully. Closed rounds undergo context compaction: exact citation UIDs are pinned, while rhetorical rationale text is summarized.
*   **Crash Prevention:** `model_validate_json` is wrapped in try/except blocks to fallback to empty schemas if Redis pointers break.
*   **Judge Blinding:** The Judge must never know which hypothesis belongs to which agent. Middleware randomly maps $H_1 \to \text{Hypothesis A}$ and $H_2 \to \text{Hypothesis B}$, passing this blinded mapping strictly to the Judge's prompt to eliminate model position bias.

### 5.2 Judge Evidence Retrieval
Before Judge execution, a deterministic Python step queries the union of all UIDs:
```cypher
MATCH (n:Entity {case_id: $case_id}) 
WHERE n.uid IN $all_cited_uids 
RETURN n.uid, n.content, n.summary
```
This raw content is injected as untrusted text into the Judge's prompt.

### 5.3 Strict Citation Enforcement
Executed via `mcp-dfkg-cypher:verify_uids` (ensuring ACL and AST safety).
1.  **Empty Check:** Reject any claim where `len(cited_uids) == 0`.
2.  **Provenance Check:** Ensure every cited UID exists in the agent's `retrieved_uids` for that turn.
3.  **Existence Check:** Verify via `MATCH (n:Entity {uid: $uid, case_id: $case_id})`.
4.  **Rejection:** If failed, emit `PARAMETRIC_KNOWLEDGE_REJECTED`, hash the failure to the VCT ledger under `VCT_REJECTED_RETRY_EVENT`, and feed the missing/invalid UIDs back to the agent in the retry prompt.
5.  **Exhaustion:** 3 consecutive failures sets `convergence_status = "VALIDATION_EXHAUSTED"`, routing directly to HITL.

---

## 6. Deterministic ACH Matrix Computation

The ACH matrix tool is invoked by code, not the LLM. It applies a uniform weight ($W=1.0$) for v1, penalizing inconsistencies.

```python
def compute_ach_verdict(evaluations: List[Dict], round_index: int, prev_p_h1: float) -> Dict:
    # 1. Empty Evidence Guard
    non_neutral = sum(1 for e in evaluations if e["relation_to_A"] != "NEUTRAL" or e["relation_to_B"] != "NEUTRAL")
    if non_neutral < 3:
        return {"status": "DEADLOCK_TIE", "p_h1": 0.5, "p_h2": 0.5}

    # 2. Contradiction Penalty Accumulation
    score_A, score_B = 0.0, 0.0
    for ev in evaluations:
        if ev["relation_to_A"] == "CONTRADICTS": score_A += 1.0
        if ev["relation_to_B"] == "CONTRADICTS": score_B += 1.0
        
    # Apply softmax inversion (Lower penalty = Higher confidence)
    import numpy as np
    penalties = np.array([score_A, score_B], dtype=np.float64)
    probs = np.exp(-penalties) / np.sum(np.exp(-penalties))
    p_A, p_B = float(probs[0]), float(probs[1])
    
    # Reverse the blind to map A/B back to H1(Prop) and H2(Crit)
    p_h1, p_h2 = unblind_scores(p_A, p_B)

    # 3. Convergence Logic
    # Dominance check
    if max(p_h1, p_h2) >= 0.85:
        return {"status": "CONVERGED_DOMINANT", "p_h1": p_h1, "p_h2": p_h2}
    
    # Stable margin cross-round check
    if round_index > 1 and abs(p_h1 - prev_p_h1) < 0.02 and abs(p_h1 - p_h2) >= 0.15:
        return {"status": "CONVERGED_STABLE", "p_h1": p_h1, "p_h2": p_h2}

    # Round 3 tie goes to HITL
    if round_index == 3:
        return {"status": "DEADLOCK_TIE", "p_h1": p_h1, "p_h2": p_h2}

    return {"status": "PENDING", "p_h1": p_h1, "p_h2": p_h2}
```

---

## 7. LangGraph State Machine & Orchestration

The router relies entirely on deterministically derived state variables, completely ignoring any hallucinated control flow outputs from the LLM.

```python
from langgraph.graph import StateGraph, END

def router_after_proponent(state: DebateGraphState) -> str:
    if state["convergence_status"] == "VALIDATION_EXHAUSTED": return "escalate_to_hitl"
    if state["validation_attempts"] > 0: return "proponent_node" # Retry
    return "critic_node"

def router_after_critic(state: DebateGraphState) -> str:
    if state["convergence_status"] == "VALIDATION_EXHAUSTED": return "escalate_to_hitl"
    if state["validation_attempts"] > 0: return "critic_node" # Retry
    return "judge_node"

def router_after_judge(state: DebateGraphState) -> str:
    if state["convergence_status"] in ["CONVERGED_DOMINANT", "CONVERGED_STABLE"]:
        return "route_to_guardrails"
    if state["convergence_status"] in ["DEADLOCK_TIE", "TOOL_TIMEOUT"]:
        return "escalate_to_hitl"
    
    # Increment round and continue loop
    return "proponent_node"
```

### 7.1 Graph Constraints & Guardrails
*   **APOC Cypher Limits:** All `mcp-dfkg-cypher` queries enforce strict APOC BFS constraints (max 3 hops, 100 nodes, 300 relationships) to prevent graph scanning timeouts that would disrupt the 40s loop budget.
*   **Degradation Policy:** If an agent times out on tool use, `state["convergence_status"]` is set to `TOOL_TIMEOUT` and routed to HITL. 