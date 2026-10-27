# Specula Evidentiary Adversarial Debate (ACH) Subsystem — Implementation Plan v3

## 1. Introduction and Architectural Alignment
The Evidentiary Adversarial Debate subsystem executes an Analysis of Competing Hypotheses (ACH) protocol to mathematically eliminate hallucinations and anchor conclusions to the Digital Forensic Knowledge Graph (DFKG). The subsystem receives a frozen causal timeline and MITRE ATT&CK attributions, treating the synthesized narrative as a binary conflict between a primary hypothesis and an alternative counter-argument.

**Gate Condition & Readiness Invariant (§1):**
1. The debate subgraph is only invoked if `case_state == "FROZEN"`: zero consumer lag and all dispatched primary (`evidence_collection`, `log_analysis`, `network_forensics`), specialist (if dead-end detected), and sequential synthesis agents (`timeline_reconstruction`, `threat_attribution`, `dag`) have completed execution and emitted findings.
2. The readiness gate is wired directly into the main orchestration StateGraph between Sequential Synthesis (`dag`) and the debate entry (`debate_gate` -> `proponent`).
3. **Kafka Consumer Lag & Bounded Wait:** Consumer lag is read from the Kafka consumer group (`specula-dfkg-writer`). If lag is temporarily positive, `debate_gate_node` executes a bounded retry loop (up to 3 retries with short backoff) before escalating to `hitl` with `entry_reason == "gate_blocked"`. Analyst approval re-evaluates the gate rather than bypassing it.
4. **Mid-Debate Late-Write Detection:** The `FROZEN` invariant is verified after each debate round. If a late write reopens the case (`case_state == "OPEN"`), the in-flight debate is aborted (`CASE_REOPENED`), round history for the voided round is discarded, and the debate is restarted under an incremented attempt counter (bounded by `MAX_DEBATE_RESTARTS = 2` before escalating to HITL).

---

## 2. Agent Configuration & Operational Boundaries
All agents operate as strict ReAct architectures with explicitly bounded loops (max 5 iterations, 40s default turn timeout) implemented via `asyncio.wait_for`.

*   **Proponent Agent (Nemotron-3 Super 120B):** Constructs primary hypothesis $H_1$.
    *   *Tools:* `mcp-dfkg-cypher:read_query`. (Ledger writing is automatic in middleware; agents have no ledger tool).
*   **Critic Agent (Llama-3.3-70B-Instruct):** Hunts for timeline contradictions and constructs alternative explanations $H_2$. Deliberately utilizes a different model family to avoid correlated blind spots.
    *   *Tools:* `mcp-dfkg-cypher:read_query`, `mcp-dataset-eval:query_baseline`.
*   **Judge Agent (Nemotron-3 Ultra 550B):** Acts as the arbitrator evaluating raw evidence entailment and hypothesis contradictions in a single batched pass.
    *   *Tools:* Raw node content fetching (capped to 500 chars per node) and evaluation are handled deterministically through the MCP and Python matrix layers.

**Model Degradation & HITL Policy (M5):**
Primary debate models are pinned per role:
- Proponent: `nemotron-3-super-120b`
- Critic: `llama-3.3-70b-instruct`
- Judge: `nemotron-3-ultra-550b`

If ANY debate role uses a non-primary model (whether local quantized `local-quantized-7b` or a cloud-to-cloud fallback e.g. switching Judge to GPT-4o or another model), or if a mid-run fallback occurs, `degraded_capability_mode` is set to `True`. Any degraded debate run **forces escalation to HITL across all exit paths**, even if the mathematical verdict converged.

**SLO & Budget Policy (M6):**
`TOTAL_DEBATE_BUDGET_SECONDS = 60.0` is strictly enforced as the debate sub-pipeline allocation within the 300s (5-minute) system SLO.
- Turns dynamically calculate remaining budget: `remaining = max(5.0, TOTAL_DEBATE_BUDGET_SECONDS - elapsed)`.
- If wall-clock elapsed time reaches 60.0s, the debate immediately terminates with `TOOL_TIMEOUT` and escalates to HITL.

---

## 3. Core Review Findings & Architectural Resolutions (v3 Final)

1.  **M4 — Judge Independent Claim Entailment (Raw Content):**
    Agents do NOT self-report support labels (removing self-reporting loopholes). Instead:
    - Agents emit `CitedClaim(assertion=..., cited_uids=[...], justification=...)`. Justification is stored for human review, not scored in the matrix.
    - The Judge independently inspects raw node content (truncated to 500 characters) and evaluates each claim as `SUPPORTED` or `UNSUPPORTED`.
    - If ANY claim is labeled `UNSUPPORTED`, the Judge maps the claim back to the responsible agent, records `PARAMETRIC_KNOWLEDGE_REJECTED` in feedback and ledger, increments `validation_attempts`, and routes to agent retry (or `VALIDATION_EXHAUSTED` after 3 attempts).
2.  **K1 / M1 / M3 — Heuer Contradiction Elimination & Volume Bias Mitigation:**
    Winner determination is based strictly on Richards Heuer's contradiction elimination protocol on diagnostic items ($\text{relation\_to\_A} \ne \text{relation\_to\_B}$):
    - Volume cap: citations per side are capped at `max_citations_per_side = 10` in `enforce_citations` and `AchConfig`, preventing a party from overpowering contradictions by citing endless confirming nodes (M3).
    - Winner criteria: leader must have fewer diagnostic contradictions ($\text{dx}_{\text{leader}} < \text{dx}_{\text{trailer}}$), net contradiction margin $\ge 2$ (M1), AND leader diagnostic contradictions capped at $\le 1$ ($\text{max\_winner\_contradictions} = 1$).
    - (0, 2) contradictions converges dominant; (5, 7) contradictions fails the absolute leader cap and results in `INSUFFICIENT_EVIDENCE` at the round cap (K1).
    - Fewer than 3 diagnostic items returns `PENDING` (or `INSUFFICIENT_EVIDENCE` at round cap). Equal contradictions or margin $< 2$ returns `DEADLOCK_TIE`.
    - All thresholds are encapsulated in `AchConfig` and pinned by `RULES_VERSION = "ach-rules-v3-uncalibrated"` with `calibrated = False`.
3.  **K2 & M8 — Middleware Provenance & Automatic Audit:**
    `retrieved_uids` is recorded by `DfkgCypherMCP` per turn and per agent (`TurnScope`), keyed by `(case, run, round, role, attempt)`. Self-reported agent lists are discarded. The Critic cannot inherit the Proponent's retrievals. DFKG reads automatically audit to `mcp-vct-ledger`.
4.  **K3 — Fail-Closed Payload Retrieval:**
    `load_payload` raises `PayloadMissingError` on missing or corrupt Redis keys, setting `convergence_status = "PAYLOAD_MISSING"` and routing to HITL. It never returns empty dummy schemas.
5.  **M5 — Comprehensive Fallback Detection:**
    Catches local-quantized fallbacks and cloud-to-cloud model switches; mid-run fallbacks are caught; forced HITL review across all paths.
6.  **M7 — Scoped Run ID, Bounded Attempts & Durable Store Roadmap:**
    `debate_run_id = sha256(case_id | trace_id | attempt)[:16]`.
    `attempt` increments on mid-debate restarts and on HITL re-dispatches, preventing Redis key collisions.
    Redis TTL is suspended during HITL escalation so analysts can review payloads.
    *Durable Store Roadmap:* Stage 1 uses Redis key-value storage; Stage 12 migrates to Postgres JSONB / S3 by swapping the backend adapter without altering the `DebatePayloadStore` interface.

---

## 4. State Schemas & Data Contracts

### 4.1 LangGraph State (Lightweight Routing)
```python
from typing import TypedDict, Literal, Optional, Dict

class DebateGraphState(TypedDict):
    case_id: str
    trace_id: str
    debate_run_id: str                     # Deterministic per (case, trace, attempt)
    round_index: int                       # Code-managed (1 to 3); advanced only by Judge
    validation_attempts: int               # Code-managed (Max 3 per turn)
    active_turn: Literal["PROPONENT", "CRITIC", "JUDGE"]
    proponent_payload_uid: str             # SHA-256 hash pointer to Redis
    critic_payload_uid: str                # SHA-256 hash pointer to Redis
    p_h1: Optional[float]                  # Previous judge round P(H1); None in round 1
    p_h2: Optional[float]                  # Derived probability
    degraded_capability_mode: bool         # True if any role used fallback model
    models_used: Dict[str, str]            # Map role -> model actually invoked
    start_time: float                      # Wall-clock timestamp for 60s budget enforcement
    convergence_status: Literal[
        "PENDING", "CONVERGED_DOMINANT", "CONVERGED_STABLE", 
        "DEADLOCK_TIE", "VALIDATION_EXHAUSTED", "TOOL_TIMEOUT",
        "INSUFFICIENT_EVIDENCE", "PAYLOAD_MISSING", "CASE_REOPENED"
    ]
    debate_result: Optional[dict]          # Populated upon convergence per DebateResult schema
```

### 4.2 Durable Storage Contract & Downstream Result Contract
```python
from pydantic import BaseModel, Field
from typing import List, Literal

class CitedClaim(BaseModel):
    assertion: str
    cited_uids: List[str] = Field(min_length=1)
    justification: str = ""                # Stored for audit, not scored in ACH matrix

class ClaimEntailment(BaseModel):
    claim_index: int
    hypothesis_label: Literal["A", "B"]
    status: Literal["SUPPORTED", "UNSUPPORTED"]
    reason: str = ""

class AgentPayload(BaseModel):
    case_id: str
    round_index: int
    hypothesis: str
    claims: List[CitedClaim]
    retrieved_uids: List[str]              # Middleware-recorded provenance

class EvidenceEvaluation(BaseModel):
    evidence_uid: str
    relation_to_A: Literal["CONFIRMS", "CONTRADICTS", "NEUTRAL"]
    relation_to_B: Literal["CONFIRMS", "CONTRADICTS", "NEUTRAL"]

class DebateResult(BaseModel):
    winning_hypothesis: str
    winning_role: Literal["PROPONENT", "CRITIC", "TIE", "INSUFFICIENT"]
    confidence: float
    status: str
    rules_version: str
    claims: List[CitedClaim]
    cited_uids: List[str]
    evaluations: List[EvidenceEvaluation]
    claim_entailments: List[ClaimEntailment]
    degraded_capability_mode: bool
```

---

## 5. Verification Oracles & Suite Coverage
The test suite validates all requirements without shortcuts:
- `tests/debate/test_ach_debate.py`: 53 tests (Heuer contradiction elimination, (0,2) vs (5,7) distinction, volume cap enforcement, M4 Judge entailment rejection & retry, M5 cloud fallback, fail-closed Redis store, MCP provenance & audit, label-swap invariance, TTL suspension).
- `tests/test_debate_gate.py`: 17 tests (readiness gate checking primary + synthesis agents, transient Kafka lag retry, persistent lag HITL escalation, mid-debate reopen & bounded restart).
- `tests/test_skeleton_graph.py`: 28 regression tests verifying zero graph breakage.
- Total verification pass: **98/98 green**.

---

## 6. Explicit Known Limitations & Architectural Bounds (Items 5–7)
Per reviewer guidance, items 5–7 are formally recorded as bounded operational constraints and known limitations:
1. **Item 5 (M6 — Pipeline SLO & Budget Enforcement):**
   - *Status:* Derived and enforced via `TOTAL_DEBATE_BUDGET_SECONDS = 60.0` within the overall 300s (5-minute) pipeline SLO.
   - *Known Limitation:* 60.0s is a hard wall-clock ceiling across the entire debate (proponent, critic, judge across all rounds and retries). Under slow LLM inference or network degradation, 60s is insufficient for 3 full rounds (40s default per turn). When the 60s ceiling is hit, the debate cuts off immediately with `TOOL_TIMEOUT` and escalates to HITL rather than running to round completion.
2. **Item 6 (M1 — Evidence Aggregation & Contradiction Margins):**
   - *Status:* Evidence is evaluated **cumulatively** across rounds by taking the deterministic union of all cited UIDs (current round + pinned UIDs from closed rounds). Margin requirement requires $\ge 2$ net diagnostic contradictions and leader contradictions $\le 1$.
   - *Known Limitation:* While cumulative evaluation makes cross-round stability testing meaningful, the thresholds (`min_contradiction_margin = 2`, `dominance_threshold = 0.85`, `stable_delta = 0.02`, `max_citations_per_side = 10`) are uncalibrated empirically on live benchmark datasets. They are explicitly tagged as `RULES_VERSION = "ach-rules-v3-uncalibrated"` with `calibrated = False` until calibrated against real DFIR benchmark corpora.
3. **Item 7 (M7 — Storage Architecture & Lifecycle):**
   - *Status:* Redis is currently the primary operational store (Stage 1). `attempt` in `debate_run_id` increments on mid-debate restarts and on HITL re-dispatch to prevent Redis key collisions. Ephemeral TTL is explicitly suspended (`deps.store.suspend_ttl(case_id)`) upon any HITL escalation.
   - *Known Limitation:* Redis remains the sole backing store in this phase. Permanent durable persistence to Postgres JSONB / S3 object storage is deferred to Stage 12, where `DebatePayloadStore` will be adapted to dual-write or swap backend implementations without changing interface contracts.

