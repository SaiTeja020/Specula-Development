# Specula — LangGraph Orchestration Skeleton: Implementation Plan

## 0. Scope Statement

This plan covers **only** the multi-agent orchestration graph — the control-flow skeleton that proves all agents (per Master_doc §2.5's Agent-Model Rationale Matrix, which is authoritative over the 13-agent narrative count and over `architecture_v3.html`'s node list) are reachable, dispatchable, and can pass state to one another correctly. It does not implement real forensic reasoning, real ingestion, or the full runtime harness/optimization layers — those are enumerated as deferred in Section 9.

**Authoritative source for control-flow mechanics:** Master_doc.docx §9–10 — Kafka-mediated writes, Supervisor-side inactivity heuristic for dead-end detection. `Specula_runtime_harness.md` and `architecture_v3.html` are treated as historical/superseded wherever they conflict.

---

## 1. Agent Count Clarification & Skeleton Scope

### 1.0 Authoritative Agent Roster (15 core agents)

Per Master_doc §2.5 Agent-Model Rationale Matrix (the single source of truth for agent roles):

1. **Supervisor** — Orchestration
2. **Evidence Collection** — Primary tier
3. **Log Analysis** — Primary tier
4. **Network Forensics** — Primary tier
5. **Timeline Reconstruction** — Sequential synthesis
6. **Threat Attribution** — Sequential synthesis
7. **Memory Forensics** — Specialist (conditional)
8. **Identity & Cloud** — Specialist (conditional)
9. **Malware & Stylometry** — Specialist (conditional)
10. **Insider Threat** — Specialist (conditional)
11. **Proponent** — Debate
12. **Critic** — Debate
13. **Judge** — Debate
14. **Guardrail Tier 3** — Semantic validation (agent #14)
15. **Report Generation** — Final output

**Timeline Artifact Generation** is a **16th skeleton-only agent**, added for this orchestration phase to decouple timeline visualization from report generation. This is not in the Master_doc's authoritative 15-agent roster. **Decision pending:** in a production build, either fold this back into Timeline Reconstruction's output (reducing to 15 nodes) or formally add it to Master_doc §2.5 with its own model assignment (promoting to 16 permanent agents).

### 1.1 Skeleton Scope & Foundation Reliability

**What this skeleton WILL provide** (solid foundation for the full system):
- Control-flow topology — all 16 agent node roles (including the 15 core + 1 skeleton-only), their dispatch pattern, conditional branching, fan-out/fan-in, loops, and terminal states
- State schema with correct reducer semantics for parallel-stage concurrency (append-reducers for multi-writer fields, single-writer for deterministic fields)
- Kafka-Neo4j-Redis infrastructure layout, integration, and consumer logic
- HITL interrupt/resume pattern proof-of-concept with dual-entry-path routing
- Verification test suite covering all major control-flow paths and edge cases
- Agent-to-model configuration structure that decouples node identity from model assignment

**What this skeleton WILL NOT provide** (minimal stubs only, not production-ready):
- Real ReAct loop logic in any agent — each agent runs a **single-pass LLM call**, not iterative Thought→Action→Observation→revised-Thought loops
- Real dead-end detection heuristic — uses an injectable flag in `raw_input` instead of a timeout/iteration-count detector
- Real forensic reasoning in any agent — all produce generic stub findings with template content; no actual log analysis, network forensics, malware detonation, threat attribution, etc.
- Real Kafka schema registry (Confluent/Avro/Protobuf) — messages are plain JSON, not schema-enforced
- Circuit breakers, retry/backoff, multi-provider fallback — model routing is simple single-model, single-provider
- MCP abstraction layer — DFKG writes go through plain Neo4j driver, not `mcp-dfkg-cypher` or other MCP servers
- Vector retrieval (FAISS/ChromaDB) — Threat Attribution's RAG step is a stub call with no real corpus
- Any analytical skills (timestomping detection, code stylometry, blast radius, attack graph, etc.) — all are stubbed or deferred
- Redis-backed debate-history mirroring — held purely in-graph state

**Transition plan to full architecture:**
The skeleton's orchestration wiring (§3–5 on node topology, edges, and infra layout) is directly reusable into the full system. Each agent node's **internal logic** (the LLM call function, state update, finding generation) will be rewritten almost entirely with real ReAct loops, tool-calling, error recovery, and domain-specific reasoning — but the node names, dispatch edges, and state schema survive unchanged. The Kafka-Neo4j-Redis infrastructure survives as-is; the MCP abstraction layer and analytical skills are additions on top, not replacements.

---

## 1.1 Locked-In Decisions (recap)

| Decision point | Resolution |
|---|---|
| DFKG write path | Kafka-mediated only (no specialist direct-write) |
| Dead-end detection | Supervisor-side inactivity heuristic, not APOC trigger |
| Agent count | 15 core agents (includes Guardrail Tier 3 as a distinct LLM-backed agent, per §2.5) + 1 lightweight Timeline Artifact Generation agent (16 total ReAct-stub nodes) |
| ReAct fidelity | Real single-pass LLM call per agent (not pure plumbing) |
| Infra | Kafka + Neo4j/APOC + Redis stood up for real; MCP/skills/harness/Quickwit/Chroma/FAISS/DuckDB/Hyperledger excluded |
| Model routing | Config-driven agent→model mapping, all roles pointed at one cheap model for now |
| Guardrail Tier 1/2 | Real minimal implementations, not pass-through stubs |
| HITL | Minimal real HTTP endpoint using LangGraph's interrupt pattern |
| Kafka topics | Real topic naming/structure per Master_doc §9.1, even though upstream ingestion isn't built |
| Agent-to-agent communication | Both direct LangGraph edges (control flow) **and** Kafka (DFKG data path) |
| Timeline Artifact Generation | Implemented as its own lightweight ReAct-stub agent, separate from Timeline Reconstruction |
| Redis for debate-round prose mirroring | Deferred — not implemented in this phase (see §9) |

---

## 2. State Schema Design

This is the highest-leverage design decision in the whole skeleton — every node reads and writes it, and getting the reducer semantics wrong silently corrupts state under the parallel fan-out stages (primary tier, specialist tier). Designed as a single shared graph state object with explicit merge strategies per field.

### 2.1 Core case metadata (single-writer, no merge needed)
- `case_id` — set once at graph entry, immutable thereafter
- `trace_id` — set once, propagated as a Kafka header on every publish (even without full OpenTelemetry, this is cheap to include now and expensive to retrofit later)
- `input_type` — `siem_alert` | `investigator_query`
- `raw_input` — the seed text/payload (since ingestion is out of scope, this is injected directly, not derived from Filebeat/OCSF)
- `case_status` — enum: `open`, `primary_tier`, `specialist_tier`, `synthesis`, `debate`, `guardrail`, `hitl_review`, `report`, `closed`

### 2.2 Findings (multi-writer, append-only reducer)
- `findings` — list, each entry `{agent_role, summary, dfkg_refs: [], timestamp, kafka_offset}`. Must use an **append reducer** (LangGraph `Annotated[list, operator.add]` or equivalent), because Evidence Collection, Log Analysis, and Network Forensics write concurrently in the parallel primary-tier fan-out, and later Memory Forensics/Identity & Cloud/Malware/Insider Threat write concurrently in the conditional specialist fan-out. A last-write-wins field here would silently drop findings — this is exactly the kind of bug the plan needs to prevent structurally, not by convention.

### 2.3 Dead-end / dispatch control
- `dead_end_detected` — bool, set by Supervisor's inactivity-heuristic check (single-writer)
- `dead_end_categories` — list of which specialist domains are implicated (e.g. `["memory", "identity"]`); an empty list is the explicit "no dead end" state (distinct from the list being unset), so the routing conditional has one unambiguous signal to check rather than two — drives conditional specialist dispatch — Supervisor is the sole writer
- `specialists_dispatched` — list, set once by Supervisor before fan-out
- `specialists_completed` — append-reducer list, so the fan-in/join node can check completion by comparing against `specialists_dispatched` rather than relying on a fragile count

### 2.4 Sequential synthesis
- `timeline` — single-writer (Timeline Reconstruction agent only)
- `attribution` — single-writer (Threat Attribution agent only, and only after `timeline` is non-null — enforced by edge ordering, not by the state schema itself)

### 2.5 Debate subsystem
- `debate_round` — int, incremented by the routing edge after a Judge rejection, capped at 3
- `proponent_argument` — overwritten each round (single-writer, current round only)
- `critic_argument` — overwritten each round
- `judge_verdict` — enum `accept | reject`, overwritten each round
- `confidence_delta` — float or `null`, overwritten each round; **undefined on round 1** (there is no prior round to compare against), so the early-exit conditional in §4 must not evaluate this field until `debate_round >= 2` — treating `null` as `0.0` would incorrectly allow a false early exit on the very first round
- `debate_history` — append-reducer list, one entry per closed round, so nothing is lost even though the "live" fields above are overwritten (this mirrors the real system's Redis-backed full-prose retention pattern, held purely in-state for this phase since Redis mirroring is deferred — see §9)
- `debate_outcome` — set once loop exits: `converged` | `round_cap_exhausted`

### 2.6 Guardrail subsystem
- `guardrail_tier1_result` / `_tier2_result` / `_tier3_result` — each `pass | fail`, single-writer, sequential
- `guardrail_fail_tier` — which tier failed, if any, used for HITL context

### 2.7 HITL
- `hitl_required` — bool
- `hitl_case_snapshot` — the subset of state exposed to the minimal endpoint
- `hitl_decision` — `approve | reject | clarify`, written externally via the endpoint, resumes the interrupted graph

### 2.8 Output
- `report_output` — single-writer (Report Generation)
- `timeline_artifact` — single-writer (Timeline Artifact Generation agent — separate node and separate field from `timeline`, which holds the raw sequencing)
- `final_output_ref` — set once both converge

### 2.9 Per-agent ReAct scratch (for skeleton verification only)
- `agent_traces` — append-reducer list of `{agent_role, thought, action, observation, model_used, latency_ms}`. This is the field you'll actually inspect to confirm "every agent fired and produced something coherent" — it's the primary verification surface for this phase, standing in for the real system's Redis scratchpad + observability logging, both of which are deferred.

**Design rule applied throughout:** every field written by more than one node in the same graph "layer" (parallel fan-out) gets an append-reducer. Every field written by exactly one node gets plain overwrite. Fields spanning sequential stages are never touched by two different nodes without an explicit edge-order dependency.

---

## 3. Node Inventory

**23 nodes total**, broken down by type:
- **16 ReAct-stub LLM agent nodes** — the 15 core agents from Master_doc §2.5 (including Guardrail Tier 3) plus the Timeline Artifact Generation agent
- **2 non-LLM real nodes** — Guardrail Tier 1, Guardrail Tier 2
- **1 real HTTP node** — HITL
- **4 control-only nodes** — Primary-tier join, Specialist join, Final output join, and a terminal Case-Closed-Rejected node — these carry no agent identity, produce no `agent_traces` entry, and exist purely to satisfy LangGraph's fan-in/termination semantics

| Node | Type | Notes |
|---|---|---|
| Supervisor | ReAct-stub, LLM | Entry point, dispatch decisions, dead-end heuristic, HITL re-dispatch target |
| Evidence Collection | ReAct-stub, LLM | Primary tier, parallel |
| Log Analysis | ReAct-stub, LLM | Primary tier, parallel |
| Network Forensics | ReAct-stub, LLM | Primary tier, parallel |
| *Primary-tier join* | Control-only | Waits for all 3 primary findings before evaluating dead-end |
| Timeline Reconstruction | ReAct-stub, LLM | Sequential synthesis, step 1 |
| Threat Attribution | ReAct-stub, LLM | Sequential synthesis, step 2 — edge-gated on Timeline completing |
| Memory Forensics | ReAct-stub, LLM | Specialist, conditional, parallel-if-multiple |
| Identity & Cloud | ReAct-stub, LLM | Specialist, conditional |
| Malware & Stylometry | ReAct-stub, LLM | Specialist, conditional |
| Insider Threat | ReAct-stub, LLM | Specialist, conditional |
| *Specialist join* | Control-only | Waits for all dispatched specialists before proceeding |
| Proponent | ReAct-stub, LLM | Debate loop |
| Critic | ReAct-stub, LLM | Debate loop |
| Judge | ReAct-stub, LLM | Debate loop, drives loop-back or exit |
| Guardrail Tier 1 | Real, non-LLM | Regex/AST-style pattern check — see §7 |
| Guardrail Tier 2 | Real, non-LLM | Lightweight embedding-similarity classifier — see §7 |
| Guardrail Tier 3 | ReAct-stub, LLM | Semantic validation — this is agent #15 |
| HITL | Real, minimal HTTP | Interrupt/resume pattern — see §8 |
| Report Generation | ReAct-stub, LLM | Final stage, parallel with Timeline Artifact Generation |
| Timeline Artifact Generation | ReAct-stub, LLM (lightweight) | Separate, lightweight agent — consumes `timeline` + `attribution`, produces `timeline_artifact`. Kept intentionally minimal in both prompt complexity and expected output size, distinct from Report Generation's fuller stub. |
| *Final output join* | Control-only | Converges report + timeline artifact |
| *Case Closed — Rejected* | Control-only, terminal | Reached only via HITL `reject`. Terminal state distinct from the normal final-output join — a run ending here has no `report_output`/`timeline_artifact`, and verification logic must not expect them. |

---

## 4. Graph Topology & Conditional Routing

**Stage 0 → Supervisor:** entry edge, unconditional.

**Supervisor → fan-out (Evidence Collection, Log Analysis, Network Forensics):** parallel dispatch, three simultaneous edges.

**Fan-in at primary-tier join:** waits on `findings` containing entries from all three primary agents. LangGraph handles this via multiple incoming edges to one node with a superstep barrier — exact join semantics should be confirmed against the LangGraph version in use, since join-node behavior differs between LangGraph's `Send` API (dynamic fan-out) and static parallel edges. **Recommendation:** use `Send` for the primary-tier dispatch specifically because it lets the Supervisor node's own logic decide the fan-out set, which sets up the same pattern reused for the truly dynamic specialist fan-out later.

**Conditional edge — dead-end check (Supervisor, inactivity heuristic):**
- Since there's no real "inactivity" to measure with stub agents that return instantly, the skeleton needs an explicit **injectable dead-end signal** — e.g., a field in `raw_input` or a config flag the test harness sets, so both branches (dead-end vs. no dead-end) can be exercised deterministically rather than relying on timing that won't naturally occur in a skeleton run.
- If dead-end → conditional `Send` to the relevant subset of specialists per `dead_end_categories`.
- If no dead-end → skip directly to Timeline Reconstruction.

**Specialist join → Timeline Reconstruction:** both the "dead-end" and "no dead-end" paths converge here.

**Timeline Reconstruction → Threat Attribution:** strict sequential edge, no fan-out.

**Threat Attribution → Proponent:** enters debate subgraph.

**Debate loop:**
- Proponent → Critic → Judge (linear within a round)
- Judge conditional edge evaluates, in this order:
  1. `judge_verdict == accept` → exit loop, `debate_outcome = converged`, proceed to Guardrail Tier 1
  2. `debate_round >= 2` AND `confidence_delta < 0.05` → exit loop, `debate_outcome = converged`, proceed to Guardrail Tier 1 (this is the source docs' independent early-exit signal — distinct from an outright Judge `accept`, and only evaluable from round 2 onward per §2.5's note on `confidence_delta`)
  3. `judge_verdict == reject` AND `debate_round < 3` → increment round, loop back to Proponent
  4. `debate_round == 3` and neither (1) nor (2) fired → exit loop, `debate_outcome = round_cap_exhausted`, route to HITL (not Guardrail Tier 1 — see below)
- **Open item carried from Master_doc §14.3 item 1** (round-cap-with-no-convergence has no defined outcome): the skeleton implements the documented proposed fix — force-route to HITL with both final positions attached if round 3 ends without convergence, rather than silently treating exhaustion as acceptance.
- **Correctness note on the round-cap-exhausted path:** this HITL detour happens *before* the guardrail chain has run at all. Do not treat this the same as a guardrail-triggered HITL escalation when wiring the HITL resume edges — see the routing distinction under **HITL** below. Collapsing these two cases would let a debate-exhausted case skip Guardrail entirely on analyst approval, which is a real safety gap, not a cosmetic one.

**Guardrail chain:**
- Tier 1 → conditional: `fail` → HITL; `pass` → Tier 2
- Tier 2 → conditional: `fail` → HITL; `pass` → Tier 3
- Tier 3 → conditional: `fail` → HITL; `pass` → Report Generation + Timeline Artifact Generation (parallel fan-out)

**HITL:**
- Graph interrupts here (LangGraph's `interrupt()`), exposing `hitl_case_snapshot` via the minimal endpoint.
- **HITL can be entered from two structurally different states, and the resume routing must not treat them identically:**
  - **Entry via guardrail failure** (Tier 1/2/3 `fail`) — guardrail has partially or fully run; `guardrail_fail_tier` is set.
  - **Entry via debate round-cap exhaustion** — guardrail has **not run at all yet**; `guardrail_fail_tier` is unset.
- On resume with `hitl_decision`, routing branches on which entry path produced the interrupt:
  - `approve`, entered via **guardrail failure** → routes to Report Generation, skipping the remainder of the guardrail chain (this matches "analyst decision routes back to Supervisor" in the source docs, simplified here to route directly forward rather than re-entering the full Supervisor dispatch logic, since the real re-dispatch semantics are explicitly left unspecified in Master_doc §14.3 item 10 and `Our_view_on_architecture` Stage 7)
  - `approve`, entered via **debate round-cap exhaustion** → routes to **Guardrail Tier 1** (the chain has not run yet; skipping straight to Report Generation here would let an unresolved, non-converged debate outcome bypass every safety check — this is the gap flagged in §4 above, closed here rather than left implicit)
  - `reject` (either entry path) → routes to the terminal **Case Closed — Rejected** node
  - `clarify` (either entry path) → loops back to Supervisor (this is the "only edge that re-enters the top of the graph," per Master_doc §8 — worth preserving in the skeleton specifically to prove LangGraph handles a genuine cycle back to the entry node, not just forward-only flow)
- **Dependency on §5.3:** the interrupt/resume pattern only works correctly across the real process boundary (external HTTP call arriving after the graph process may have cycled) if the LangGraph checkpointer is active. The Redis checkpointing in §5.3 is not optional infrastructure for this node — it is a hard prerequisite for HITL functioning at all in this skeleton. If checkpointing is skipped, HITL testing must run within a single uninterrupted process and the "survives restart" property in the verification list (§10, item 4) cannot actually be demonstrated.

**Report Generation + Timeline Artifact Generation → final output join → end.**

---

## 5. Infra Components

### 5.1 Kafka (real, docker-compose)
Topics stood up per Master_doc §9.1 naming convention, even though no ingestion pipeline feeds them in this phase:
- `findings.evidence_collection`, `findings.log_analysis`, `findings.network_forensics`, `findings.timeline`, `findings.attribution`, `findings.specialist.memory`, `findings.specialist.identity`, `findings.specialist.malware`, `findings.specialist.insider`, `findings.debate`
- `dfkg.writes` — the topic a consumer reads to perform the actual Neo4j write (this is the mechanism that keeps writes uniform/audited per the Kafka-mediated decision)
- `dfkg.dead_letter` — for any finding message that fails a basic shape check before writing

Each agent node, on producing a finding, publishes to its topic **and** updates `findings` in LangGraph state directly — the direct edge carries control flow forward immediately rather than waiting on Kafka round-trip latency; Kafka is the audit/DFKG path running alongside, not blocking graph progression. This matches the "Kafka is mainly for DFKG" direction.

A single lightweight consumer process reads `findings.*` topics and performs the actual `MERGE` write into Neo4j — this is the skeleton's stand-in for the real `mcp-dfkg-cypher` abstraction, implemented as a plain Neo4j driver call for now (not an MCP-wrapped tool call, since MCP itself is out of scope).

**Left out here:** schema registry / Avro-Protobuf enforcement — messages are plain JSON with no wire-level validation for this phase. This is a real gap versus the production design and should be flagged as technical debt, not silently accepted.

### 5.2 Neo4j + APOC (real, docker-compose)
- Deterministic UID generation implemented (hash of a small identifying tuple) so repeated skeleton runs don't create duplicate nodes.
- Parameterized `MERGE` only, per Master_doc §10's corrected pipeline.
- **A uniqueness constraint on `Entity.uid` must be created at schema-init time** (`CREATE CONSTRAINT ... FOR (n:Entity) REQUIRE n.uid IS UNIQUE` or the APOC/Neo4j-version-appropriate equivalent). Deterministic UID generation alone only prevents duplicates if the database *enforces* uniqueness — without the constraint, a race between the consumer process and a retried/replayed message can still produce two nodes with logically-the-same UID before the application-level `MERGE` check resolves. This is a one-line addition with an outsized correctness payoff and should not be skipped.
- **Not implemented:** debounced APOC triggers, supernode/degree pre-checks, milestone pattern detection. Dead-end detection correctly does not touch Neo4j at all per the locked-in decision — it's a state-only heuristic in the Supervisor node.

### 5.3 Redis (real, docker-compose)
Used narrowly in this phase:
- LangGraph checkpointing (mid-run persistence/resume for testing), since it directly exercises the "survives restart" property mentioned in harness §9.5, even though the rest of that section isn't built.

**Deferred:** mirroring `debate_history` prose into Redis to rehearse the real architecture's Redis-backed debate-cache pattern. For this phase, `debate_history` is held purely in-graph state. This will be revisited when the skeleton is upgraded into a working architecture.

---

## 6. Agent-to-Model Configuration

A single external configuration artifact (structured as agent-role → model settings) drives which model each node calls. Design requirements:

- Keys: the canonical agent role identifiers (matching Master_doc §2.5's exact role names, plus `timeline_artifact_generation`), so a future swap is a pure config edit
- Per-role fields: `model_id`, `provider`, `system_prompt_template` (a short role-flavored instruction, since even a skeleton run should produce *distinguishable* stub outputs per agent rather than identical responses across all nodes — this is what makes `agent_traces` actually useful for verification)
- For this phase: every role points at the same single cheap/fast model and provider. Swapping to the real per-agent matrix later is a config change only, no code change — this is the direct payoff of building it this way now.

**Left out:** actual multi-provider fallback/circuit-breaker logic, cost/latency tracking per call, confidence flagging on fallback. The config structure is designed to *accommodate* these later (e.g., a `fallback_model_id` field can be added without restructuring), but none of that logic is implemented now.

---

## 7. Guardrail Tier 1 / Tier 2 — Real Minimal Implementations

**Tier 1 (regex/AST-style):** implement a small set of real deterministic checks against agent output text — e.g., presence of raw Cypher-injection-shaped strings, suspicious command-execution patterns, or obviously malformed output shape. This is not the full regex/AST signature library from the real system, but it's a genuine pass/fail check on content, not a hardcoded `return pass`. Design it as a short, explicit, inspectable rule list so its behavior is auditable in review.

**Tier 2 (lightweight classifier):** since a fully trained MiniLM SAFE/UNSAFE classifier is out of reach for a skeleton phase, implement a real-but-simple embedding-similarity check: embed the agent's proposed output against a small hardcoded set of "known-unsafe" example phrases using an off-the-shelf small sentence-embedding model, and fail if cosine similarity exceeds a threshold. This is genuinely functional (not decorative) while being honest that it has no training data behind it and will need real fine-tuning later — that limitation should be stated plainly wherever this tier is documented, not glossed over.

**Tier 3** is agent #15 — a real LLM call performing semantic validation, using the same config-driven model as everything else in this phase.

---

## 8. HITL — Minimal Endpoint

A single, very small HTTP service exposing:
- One endpoint to fetch the current `hitl_case_snapshot` for a paused case
- One endpoint to submit `hitl_decision` (approve/reject/clarify), which resumes the interrupted LangGraph run

No React frontend, no analyst-facing UI, no tiered auto-approval timeout logic (4h/2h/8h thresholds from Master_doc §2.4 feature 9), no agreement-rate tracking. This is purely a mechanism to prove LangGraph's interrupt/resume pattern works correctly across a real process boundary (an external HTTP call resuming a paused graph), which is the one thing worth validating now — everything else about HITL is a UI/policy layer that can be built later without touching the graph's control-flow design.

---

## 9. Explicitly Deferred / Out of Scope

Stated plainly so there's no ambiguity about what this phase does *not* deliver.

### 9.1 From the runtime harness

| Harness component | Status this phase |
|---|---|
| Schema registry (Confluent/Avro), enforced wire-level validation | Not implemented — topics carry unvalidated JSON |
| Dead-letter topic *consumer logic* | Topic created; no reconciliation/quarantine handling built |
| Debounced APOC triggers, milestone pattern detection | Not implemented at all |
| Distributed tracing (OpenTelemetry spans) | Not implemented — `trace_id` field exists in state/Kafka headers but nothing consumes it as real tracing |
| All MCP servers (`mcp-dfkg-cypher`, `mcp-vmi-sandbox`, `mcp-threat-intel`, `mcp-vct-ledger`, `mcp-dataset-eval`) | None built — DFKG writes go through a plain driver call, not an MCP abstraction |
| Circuit breakers, retry/backoff, provider fallback | Not implemented |
| Vault-backed secrets management | Not implemented — any credentials used in this phase are handled as plain local config, which is **not acceptable for anything beyond a local dev skeleton** |
| Skill manifest/registry, least-privilege scoping | Not implemented — agent nodes carry no formal tool-access restrictions in this phase |
| All named skills (`Timestomping_XGBoost_Skill`, `Entropy_Distillation_Skill`, `Code_AST_Extraction_Skill`, `Smith_Waterman_Attribution_Skill`, `Dijkstra_Attack_Graph_Skill`, `Calculate_Blast_Radius`, `OCSF_Normalizer_Skill`, `Temporal_Drift_Calculator`) | None implemented — no real forensic logic exists in this phase, only stub LLM calls |
| Golden-fixture unit tests for deterministic skills | Not applicable yet — no deterministic skills exist to test |
| Per-role rule engine, hot-reload, degradation policy | Not implemented — no explicit "what happens when a tool times out" rule exists; a timeout will surface as an unhandled error for now |
| Loop budget enforcement (max iterations/tool calls per agent) | Not needed yet since each stub agent runs a single-pass ReAct call, not an iterative loop |
| Context-compaction skill (general) | Not applicable — context volume in a skeleton run is trivial |
| Full observability harness (per-call cost/latency logging, deterministic replay harness, live DFIR-Metric scoreboard) | Not implemented — `agent_traces` gives basic per-node visibility only |
| Sandboxed skill execution (gVisor) | Not applicable — no skills parse attacker-controlled input yet |
| Immutable VCT-anchored audit log of every tool call | Not implemented — no VCT chain exists in this phase at all |
| Redis-backed debate-round prose mirroring | Deferred — `debate_history` held purely in LangGraph state for now |

### 9.2 From the optimization/caching layer

| Optimization component | Status this phase |
|---|---|
| Ingestion-side entropy distillation (Drain3/SimHash/MiniBatchKMeans) | Not applicable — ingestion pipeline itself is out of scope for this task |
| `Debate_Context_Compaction_Skill` | Not implemented — debate rounds pass full raw prose each time, fine at 3-round scale |
| Prompt compression (LongLLMLingua / LLMLingua-2) | Not implemented |
| DFKG subgraph serialization (triple-based NL templates, ranking, hop-distance annotation) | Not implemented — any DFKG reads in this phase use raw, unoptimized output |
| Reranking (cross-encoder) | Not implemented — no multi-source retrieval exists yet to rerank |
| Token budgeting, capital/consumable split, prompt caching | Not implemented |
| Context eviction for constrained-context models | Not implemented |
| Latency SLO instrumentation against the 5-minute target | Not implemented — `agent_traces` includes raw latency per call but nothing aggregates or gates against a target |
| ChromaDB / FAISS vector indexing | Not implemented — Threat Attribution's RAG step is a stub call with no real corpus behind it |
| DuckDB EPSS cache | Not applicable — Dynamic Attack Graph is a skill/feature, not one of the core agents, and isn't built in this phase |

### 9.3 Other explicit exclusions
- **Ingestion pipeline** — completely out of scope for this task. A case is seeded by directly injecting `raw_input` into state; no Filebeat, no OCSF normalization, no Security Gate (NFKC/Rebuff), no Quickwit/VCT atomic hashing.
- **Cryptographic provenance** — no VCT Merkle chain, no Hyperledger Fabric anchoring, no case-level signing. Legal-admissibility claims cannot be made about anything produced in this phase.
- **Report/timeline content fidelity** — Report Generation and the Timeline Artifact Generation node produce placeholder/stub content confirming they ran and received upstream state correctly, not the real 17-section report or an interactive DFKG-grounded visualization.
- **All domain-specific reasoning** — blast radius scoring, Smith-Waterman attribution, Dijkstra attack-graph traversal, timestomping classification, code stylometry, LSTM-based insider-threat scoring, tiered malware sandboxing. Every agent node in this phase does a generic single-pass "receive state → produce a labeled stub finding" call; none of them do real forensic work.
- **Guardrail Tier 1/2 production accuracy** — both are real but intentionally minimal; neither should be treated as a validated security control yet.

---

## 10. Feature-to-Skeleton-Implementation Matrix

This matrix cross-references the 36 features defined in `architecture_v3.html` (F1–F36) against what this skeleton actually implements vs. stubs. Use this to understand which features an implementer can rely on being correct vs. which are placeholders awaiting the full system build.

| Feature Code | Feature Name | Master_doc section | Skeleton implementation | Status | Notes |
|---|---|---|---|---|---|
| F1 | Evidence capture + OCSF normalization, schema-validated ingestion | §6 | Not implemented — ingestion pipeline is out of scope; evidence is injected directly as `raw_input` into state | Deferred | Will be added when the upstream ingestion pipeline (Filebeat, FastMCP gateways, Pydantic validation) is built |
| F2 | Evidence collection & correlation agent | §2.5 (Evidence Collection row) | Implemented as a node; runs a single-pass stub LLM call | Partial | Agent exists and is correctly wired into the orchestration; logic is a stub |
| F3 | Log analysis — suspicious activity detection | §2.5 (Log Analysis row) | Implemented as a node; runs a single-pass stub LLM call | Partial | Agent exists and is correctly wired; no real log parsing, pattern matching, or anomaly detection |
| F4 | Network forensics — traffic anomalies, C2 detection | §2.5 (Network Forensics row) | Implemented as a node; runs a single-pass stub LLM call | Partial | Agent exists and is correctly wired; no real PCAP parsing, flow analysis, or signature matching |
| F5 | Timeline reconstruction agent | §2.5 (Timeline Reconstruction row) | Implemented as a node; runs a single-pass stub LLM call | Partial | Agent exists and is correctly wired; no real temporal ordering logic or conflict resolution |
| F6 | RAG-enhanced threat attribution, ATT&CK mapping | §2.5 (Threat Attribution row) + §4.2 (retrieval) | Implemented as a node; runs a single-pass stub LLM call with no real corpus or retrieval | Partial | Agent exists and is correctly wired; RAG step is stubbed (no ChromaDB, no FAISS, no actual ATT&CK corpus querying) |
| F7 | Forensic knowledge graph — shared memory, entity correlation | §2.4 (DFKG) | Implemented real Neo4j + APOC setup with deterministic UIDs, parameterized MERGE, uniqueness constraints | Full | Fully implemented in the skeleton; ready for production use with appropriate testing |
| F8 | Topological GraphRAG (FAISS IndexIVFPQ + APOC bounded BFS) | §2.4, §4.2 | Neo4j + APOC BFS part is implemented (max 3 hops, max 100 nodes, max 300 edges pre-check); FAISS vector retrieval is deferred | Partial | Graph retrieval is correct and tested; vector-based similarity search will be added when ChromaDB/FAISS are stood up |
| F9 | Hybrid / RAG-based forensic memory | §2.4 | Vector retrieval (ChromaDB + FAISS) is deferred; DFKG reads work natively | Partial | Graph-based retrieval functional; vector-hybrid layer is deferred infrastructure |
| F10 | Multi-agent orchestration (Supervisor / Blackboard) | §2.5 (Supervisor row) + §8 | Fully implemented — Supervisor node dispatches primary tier in parallel, evaluates dead-end signal, re-dispatches specialists, re-enters on HITL clarify | Full | Supervisor's control logic is fully implemented; core orchestration is correct and tested |
| F11 | Selective agent dispatch / cost pruning (dead-end-triggered, not unconditional) | §2.5, §4 | Implemented — specialists are only dispatched if `dead_end_detected == true`; injectable flag in skeleton; will be replaced with timeout heuristic in full system | Full | Skeleton uses injectable flag; production will replace with iteration-count/timeout detector |
| F12 | Memory forensics specialist | §2.5 (Memory Forensics row) | Implemented as a node; runs a single-pass stub LLM call | Partial | Agent exists and is correctly wired as conditional specialist; no real Volatility parsing or memory artifact analysis |
| F13 | Identity & cloud/container specialist | §2.5 (Identity & Cloud row) | Implemented as a node; runs a single-pass stub LLM call | Partial | Agent exists and is correctly wired as conditional specialist; no real AD/cloud audit parsing |
| F14 | Tiered malware sandboxing (YARA → Speakeasy → CAPE/DRAKVUF) | §2.5 (Malware & Stylometry row) | Implemented as a node; runs a single-pass stub LLM call; no actual sandbox integration | Deferred | Agent exists and is wired correctly; all three tiers (YARA, Speakeasy, CAPE) are deferred infrastructure |
| F15 | LLM code stylometry / authorship attribution | §2.5 (Malware & Stylometry row) | Implemented as a node; runs a single-pass stub LLM call; no actual AST parsing or feature extraction | Deferred | Agent exists and is wired correctly; all AST parsing and classifier logic is deferred |
| F16 | Insider threat agent (LSTM autoencoder, sentiment) | §2.5 (Insider Threat row) | Implemented as a node; runs a single-pass stub LLM call; no actual LSTM or sentiment model | Deferred | Agent exists and is wired correctly; behavioral baseline and LSTM logic is deferred |
| F17 | Timestomping detection / temporal normalization (XGBoost) | §6.2, §10 | Not implemented — ingestion pipeline is out of scope; no XGBoost classifier or MFT delta checks | Deferred | Will be implemented as part of ingestion and specialist tier when those are built |
| F18 | Argumentative agents / Evidentiary Adversarial Debate (ACH) | §2.5 (Proponent, Critic, Judge rows) + §4 | Fully implemented — three-agent loop with mandatory DFKG citations, ACH-style verdict, early-exit on confidence delta, round-cap with HITL escalation | Full | Debate topology and control flow are fully correct; Judge's citation validation is stubbed (always accepts DFKG refs without real validation logic) |
| F19 | Confidence scoring / multi-agent verification | §2.5 (Judge row) + §4 | Implemented — confidence_delta field in state, Judge computes and drives early exit; no actual Bayesian/softmax scoring | Partial | State machinery for confidence tracking is fully implemented; actual scoring algorithm is stubbed |
| F20 | Cryptographic provenance — VCT, Merkle trees, Hyperledger anchor | Master_doc §2.4 (feature 5) | Not implemented — no VCT hash chain, no Merkle aggregation, no Hyperledger Fabric | Deferred | No legal-admissibility claims can be made about skeleton output; VCT will be added when cryptographic layer is built |
| F21 | Zero-trust guardrail — 3-tier escalation | Master_doc §2.4 (feature 7) + §9.6 | Fully implemented — Tier 1 (real regex checks), Tier 2 (real embedding-similarity classifier), Tier 3 (real LLM call), all-or-fail routing to HITL on any tier failure | Full | All three tiers are implemented with real logic (though minimal); routing and escalation are correct |
| F22 | Human-in-the-loop approval gate | Master_doc §2.4 (feature 9) + §8 | Minimal HTTP endpoint implemented — fetch snapshot, submit decision (approve/reject/clarify), resume graph; no UI, no tiered timeouts, no agreement tracking | Partial | Interrupt/resume pattern is proven; analyst dashboard and timeout policy are deferred |
| F23 | Dynamic attack graph (Dijkstra, EPSS/CVSS weighting) | Master_doc §2.4 (feature 12) + §10 | Not implemented — no Dijkstra traversal, no EPSS/CVSS scoring, no DuckDB cache | Deferred | Dynamic attack graph is a skill/feature, not one of the 15 core agents; will be implemented as an analytical tool |
| F24 | Blast radius quantification + Smith-Waterman sequence-aligned attribution | Master_doc §2.4 (feature 12) | Not implemented — no blast radius formula, no Smith-Waterman scoring, no Jaccard similarity computation | Deferred | Implements as specialized skills in the full system; not part of this orchestration skeleton |
| F25 | Automated explainable, court-ready report generation | Master_doc §2.4 (feature 6) + §11 | Implemented as a node; runs a single-pass stub LLM call producing a placeholder report; no 17-section template population, no DFKG citation resolution | Partial | Agent exists and is correctly wired; report content is a stub; full 17-section template will be implemented with the Report Generation skill |
| F26 | Dynamic, interactive attack timeline artifact | Master_doc §12 + §3 (Timeline Artifact Generation node) | Implemented as a separate lightweight node; runs a single-pass stub LLM call; no interactive visualization, no DFKG-grounded rendering | Partial | Timeline Artifact node exists and is correctly wired as a separate agent; visualization logic is deferred to frontend/interactive tooling |
| F27 | Sandbox/AutoBnB-RAG simulation validation of team strategy | Master_doc §2.4 (feature 11) + harness §6 | Not implemented — no replay harness, no simulation environment, no evaluation framework | Deferred | Observability and deterministic replay infrastructure is deferred |
| F28 | Advanced breach scenario benchmarking (supply chain, cloud) | Master_doc §2.4 (feature 11) | Not implemented — no scenario datasets, no multi-stage attack templates, no scoring against DFIR-Metric TUS | Deferred | Evaluation framework and scenario libraries are deferred |
| F29 | Collaborative timeline export (Timesketch-style) | Master_doc §2.4 (feature 10) + §12 | Implemented as timeline edges in DFKG; no actual Timesketch export, no interactive UI | Partial | Timeline edges are generated and stored in DFKG correctly; export/visualization layer is deferred |
| F30 | Event backbone hardening — schema registry, dead-letter topics, debounced triggers | Harness §9.1 | Kafka topics are created with correct names; schema registry is not implemented; dead-letter topic has no consumer logic; APOC triggers are deferred | Partial | Infrastructure is in place; schema enforcement and trigger logic are deferred |
| F31 | MCP server abstraction layer with circuit breakers / vault secrets | Harness §9.2 | Not implemented — DFKG writes go through plain Neo4j driver; no MCP wrappers, no circuit breakers, no vault integration | Deferred | MCP layer is deferred infrastructure; plain driver calls work for skeleton phase |
| F32 | Skill library governance — manifest, least-privilege scoping, golden fixtures | Harness §9.3 | Not implemented — no skill manifest, no access-control model, no golden-fixture tests | Deferred | Skills and governance are deferred; orchestration skeleton doesn't require them |
| F33 | Rule engine — per-role scoping, hot-reload, degradation policy | Harness §9.4 | Not implemented — no rule engine, no degradation policy; timeouts will surface as unhandled errors | Deferred | Rule engine is deferred operational infrastructure |
| F34 | ReAct loop runtime — checkpointing, loop budgets, context compaction, scratchpad | Harness §9.5 | Checkpointing is implemented (Redis-backed for HITL interrupt/resume); loop budgets, context compaction, and scratchpad are not needed since each agent runs a single-pass call | Partial | Checkpointing works for this skeleton's single-pass architecture; full loop infrastructure is deferred for when ReAct loops are added |
| F35 | Observability, replay harness, model routing with fallback confidence flagging | Harness §9.6 + §6 | Model routing is implemented (config-driven); observability is minimal (`agent_traces` field in state); deterministic replay harness, live scoreboard, and fallback flagging are deferred | Partial | Basic observability and config-driven routing work; advanced observability is deferred |
| F36 | Harness security hardening — sandboxed skill execution, immutable tool-call audit log | Harness §9.6 | Not implemented — no sandboxed execution, no tool-call audit log in VCT chain | Deferred | Security hardening is deferred infrastructure; not part of this orchestration skeleton |

**Key takeaway:** 
- **Fully implemented (green-light):** F7 (DFKG), F10 (Supervisor orchestration), F11 (selective dispatch), F18 (debate topology), F21 (guardrail chain) — these are the control-flow and state-management foundations.
- **Partial (yellow-light):** F2–F6, F12–F16, F19, F22, F25–F26, F29, F30, F34–F35 — node wiring is correct, but agent logic or infrastructure dependencies are stubbed.
- **Deferred (red-light):** F1, F8 (vector part), F14–F17, F20, F23–F24, F27–F28, F31–F33, F36 — not implemented in this phase; full infrastructure or algorithmic logic required.

An implementer should treat "Fully implemented" features as production-ready and correctly integrated. "Partial" features should be re-implemented with real logic while keeping the wiring intact. "Deferred" features require new infrastructure or skills to be built separately.

---

## 11. Verification Approach for This Phase

The success criterion for the skeleton is narrow and should be tested as such:
1. A synthetic case run (with the dead-end flag toggled both ways) reaches the final output join.
2. `agent_traces` contains exactly one entry per node that should have fired given the path taken, in the correct order, with distinguishable (non-identical) content per role.
3. The debate loop is exercised at least once with a forced `reject` to confirm the cycle back to Proponent works, and once with a forced round-3 exhaustion to confirm the HITL-escalation fallback fires — and in the round-3-exhaustion case specifically, confirm an `approve` decision routes to **Guardrail Tier 1**, not directly to Report Generation (this is the distinction fixed in §4/§8; a test that only checks "did it reach Report Generation eventually" would not catch a regression here).
4. At least one guardrail failure at each tier is forced to confirm all three fail→HITL edges route correctly, and the HITL endpoint correctly resumes the graph on each of `approve`/`reject`/`clarify` — including confirming that a `reject` decision (from either HITL entry path) lands on the **Case Closed — Rejected** terminal node with no `report_output` or `timeline_artifact` set, rather than a partially-populated final state.
5. Kafka topics receive the expected messages and the Neo4j consumer writes corresponding nodes/edges with correctly deduplicated UIDs across a repeated run — including a check that the `Entity.uid` uniqueness constraint (§5.2) actually rejects/merges a manually-replayed duplicate write rather than relying solely on application-level `MERGE` logic.
6. A HITL interrupt is triggered, the graph process is restarted (or the resume call is issued from a separate process), and the resume still succeeds — this is the only test that actually validates the Redis-checkpointer dependency noted in §8, as opposed to a same-process interrupt/resume which would pass even if checkpointing were silently broken.

This is deliberately a control-flow/plumbing test, not an accuracy or content-quality test — nothing in this phase should be judged against the project's real performance targets (95% correlation, etc.), since none of the logic those targets depend on exists yet.

---

## 12. Summary: Skeleton as Foundation

This implementation plan provides a **complete, correctly-wired control-flow skeleton** that serves as the foundation for the full Specula architecture. The orchestration topology, state management, and infrastructure layout are production-ready and will survive into the full system with minimal changes. Agent node implementations are stubs and will be rewritten with real forensic logic while keeping the wiring intact.

**What to build next (in order):**
1. Replace single-pass agent stubs with real ReAct loops and tool-calling (keeping node names and state schema unchanged)
2. Implement real forensic logic in each agent role (log analysis patterns, network anomaly detection, etc.)
3. Build the ingestion pipeline (Filebeat, FastMCP gateways, OCSF validation, Quickwit/VCT hashing)
4. Add vector retrieval infrastructure (ChromaDB, FAISS, graph-vector hybrid retrieval)
5. Implement MCP abstraction layer and analytical skills (sandboxing, stylometry, attack graph, etc.)
6. Add observability, replay harness, and deterministic testing framework
7. Implement cryptographic provenance (VCT Merkle chain, Hyperledger Fabric anchoring)

The skeleton unblocks all of these build streams in parallel — each can proceed independently while the orchestration wiring remains stable.
