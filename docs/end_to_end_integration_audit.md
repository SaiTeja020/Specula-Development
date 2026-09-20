# End-to-End Integration Audit — Specula

## Audit Date
2026-09-20

## Purpose
This document captures the findings of the Phase 1 audit performed before implementing
the end-to-end investigation workflow (User Text → Supervisor → Agents → DFKG/GraphRAG
→ HITL/Debate → Plain-English answer).

---

## 1. Current Entrypoints (Pre-Integration)

| File | Type | Accepts | Invokes |
|---|---|---|---|
| `src/agents/hitl_api.py` | FastAPI (port 8200) | GET/POST `/hitl/{thread_id}` | Graph resume only |
| `src/agents/visualizer_api.py` | FastAPI (port 8300) | POST `/api/graph/run_mock` | Mock simulation only |
| `scripts/run_e2e_simulation.py` | CLI | OCSF events from disk | Evidence collection triage only |
| `scripts/run_rag_agent.py` | CLI | `--query` flag | RAG retriever directly (bypasses Supervisor) |

**GAP**: No entrypoint accepted `(query, case_id)` and invoked the full LangGraph.

---

## 2. Supervisor Behavior

### Active Supervisor: `make_supervisor_node()` in `src/agents/nodes.py`
- Wired into `graph.py` via `build_graph()`
- Queries Neo4j DFKG for existing `AgentFinding` nodes via parameterized Cypher
- Runs `_run_agent("supervisor", state, findings_summary=dfkg_summary)` using `StubLLM` or `ChatGoogleGenerativeAI`
- Parses `ROUTE: agent1, agent2` from the LLM output to drive dynamic dispatch
- Falls back to `["evidence_collection", "log_analysis", "network_forensics"]` if no ROUTE found

### Disconnected Code: `supervisor_agent.py`
- Contains `route_nl_query()` with keyword-based routing — **NOT wired into the graph**
- A standalone class (`SupervisorState`, `dispatch_primary_tier`, etc.) — **entirely disconnected**
- Resolution: left in place; the active Supervisor in `nodes.py` handles NL routing via the LLM

---

## 3. Agent Dispatch

```
START
  ↓
supervisor (queries DFKG, determines ROUTE)
  ↓ [Send() fan-out based on next_agents]
evidence_collection | log_analysis | network_forensics
  ↓ [all → primary_tier_join]
dead_end_route:
  → no dead-end: timeline_reconstruction
  → dead-end:    memory_forensics | identity_cloud | malware_stylometry | insider_threat
                   ↓ specialist_join → timeline_reconstruction
  ↓
threat_attribution
  ↓
proponent → critic → judge [Command loop]
  ↓ (accept → guardrail_tier1)
guardrail_tier1 → guardrail_tier2 → guardrail_tier3 [Command chain]
  ↓ (pass → [report_generation, timeline_artifact_generation])
final_output_join
  ↓
END
```

All nodes except `memory_forensics`, `identity_cloud`, `malware_stylometry`, and `insider_threat`
use real ReAct loops. The three remaining H.7 legacy nodes use `_run_agent()` single-pass calls.

---

## 4. GraphRAG Path

### Existing components (all functional):
- `src/agents/rag/dfkg_retriever.py` — `DFKGRetriever`: vector search + Neo4j graph expansion
- `src/agents/react_tools.py` — `ForensicRAGSearchTool`: wraps `DFKGRetriever` as a ReAct tool
- `src/agents/react_tools.py` — `TrackingDFKGQueryTool`: direct parameterized Cypher queries
- `src/agents/rag/graph_context_builder.py` — `build_graph_context()`: formats subgraph for LLM
- `src/agents/rag/forensic_prompt.py` — `build_forensic_prompt()`: prompt with injection guard

### Wiring status:
- `evidence_collection_agent.py` — uses `TrackingDFKGQueryTool` (Cypher) + `ForensicRAGSearchTool` (semantic RAG)
- `network_forensics_agent.py` — uses `TrackingDFKGQueryTool` only (Cypher)
- `log_analysis_agent.py` — uses `TrackingDFKGQueryTool` only
- `timeline_reconstruction_agent.py` — uses `TrackingDFKGQueryTool` only
- `threat_attribution_agent.py` — uses `TrackingDFKGQueryTool` only
- `memory_forensics_agent.py` — uses `TrackingDFKGQueryTool` only
- `debate_agents.py` — uses `TrackingDFKGQueryTool` + `ForensicThreatContextSearchTool`

**Semantic RAG** (`ForensicRAGSearchTool`) is fully available and already used in evidence collection.
Specialist agents use direct Cypher queries which are sufficient for DFKG-driven context retrieval.

---

## 5. HITL Path

### Implementation:
- `src/agents/nodes.py` → `hitl_node()` — calls LangGraph `interrupt()` — functional
- `src/agents/hitl_api.py` — GET/POST `/hitl/{thread_id}` — functional
- HITL is triggered by: guardrail failure (tier 1/2/3) OR debate round-cap exhaustion

### Limitation:
- The HITL API requires a **shared checkpointer** between the run-invocation and the resume call.
- Post-integration: the shared `_checkpointer = InMemorySaver()` in `hitl_api.py` is used by
  both `POST /investigate` and `POST /hitl/{thread_id}`, enabling seamless resume.
- In CLI mode (`scripts/run_investigation.py`), HITL is handled interactively via stdin.

---

## 6. Debate Path

- `src/agents/debate_agents.py` — `make_proponent_node`, `make_critic_node`, `make_judge_node`
- All factory-based, use ReAct loops, fully wired in `graph.py`
- Judge routes via `Command` to `guardrail_tier1` (accept) or loops back (reject, round < 3) or `hitl` (exhausted)
- **Status: FUNCTIONAL — no changes required**

---

## 7. AgentFinding / Blackboard Path

- Each ReAct agent publishes findings via `KafkaPublishFindingTool` → `publish_finding()` in `kafka_utils.py`
- `run_dfkg_consumer()` in `kafka_utils.py` — consumes findings.* and MERGEs `AgentFinding` nodes into Neo4j
- `dfkg_refs` list on each finding carries UID provenance (`TrackingDFKGQueryTool.collected_uids`)
- **Status: FUNCTIONAL — consumer must run as a separate process for live writes**

---

## 8. Final Output Path (Pre-Integration)

- `report_generation_node` → `state["report_output"]` — raw LLM response from template prompt
- `timeline_artifact_generation_node` → `state["timeline_artifact"]`
- `final_output_join_node` → `state["final_output_ref"]`
- **GAP: No plain-English synthesis. `report_output` is the template LLM's direct output.**

Post-integration: `synthesis.py` → `synthesize_plain_english()` reads the final state and produces
a formatted `InvestigationResult` with `answer`, `evidence_uids`, `agents_used`, `limitations`.

---

## 9. Model Configuration

| Config Path | Value | Used By |
|---|---|---|
| `.env` → `SPECULA_LLM_BACKEND` | `stub` (default) / `gemini` | All agents via `config.py::get_llm()` |
| `config.py` → `AGENT_CONFIG["*"]["model_id"]` | `gemini-3.6-flash` (declared) | Resolved at runtime via `_get_gemini_model()` |
| `rag/gemini_client.py` → `GEMINI_MODEL` | `gemini-3.1-pro-preview` (default) | RAG-only path via `google-genai` SDK |

**Two separate LLM call paths exist:**
1. Agents: `langchain_google_genai.ChatGoogleGenerativeAI` via `get_llm()`
2. RAG (`dfkg_retriever.py` when used standalone): `google-genai` `GeminiClient`

In the integrated flow, agents use path (1) exclusively. Path (2) is only used when
`scripts/run_rag_agent.py` or `GeminiClient` is called directly.

---

## 10. Missing Connections (Pre-Integration)

| Gap | Resolution |
|---|---|
| No `(query, case_id)` → graph entrypoint | Created `src/agents/investigation_runner.py` + `scripts/run_investigation.py` |
| No plain-English synthesis | Created `src/agents/synthesis.py` |
| No unified API gateway | Extended `src/agents/hitl_api.py` with `POST /investigate` |
| `supervisor_agent.py` disconnected | Documented; active Supervisor is in `nodes.py` |
| HITL requires shared checkpointer | `hitl_api.py` now uses a module-level `InMemorySaver()` |
