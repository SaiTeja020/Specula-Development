# Phase H.7.2 — Memory Forensics Migration

## Objective
Convert the existing Memory Forensics legacy stub into the ReAct/DFKG-driven architecture used by other H.7 specialist agents. 
The goal is to eliminate its dependency on the large ephemeral `SpeculaState` payload (`state.get("findings")`, `state.get("timeline")`, `state.get("attribution")`) as its primary evidence source, and replace it with bounded, case-scoped queries to the Neo4j Blackboard.

## Architecture

### Previous Architecture (Stub)
- The memory forensics agent was a simple stub function (`memory_forensics_node` in `src/agents/nodes.py`).
- It used a single-pass LLM call (`_run_agent`) which injected the entire `SpeculaState` stringified content (including `findings`, `timeline`, and `attribution`) directly into the prompt.
- It did not possess independent reasoning or tool usage capabilities.

### New Architecture (ReAct)
- Migrated to `src/agents/memory_forensics_agent.py`.
- Follows the factory pattern (`make_memory_forensics_node`) used by `network_forensics_agent.py` and others.
- **ReAct Loop:** Incorporates Thought → Action → Observation loop powered by the LangGraph ReAct engine.
- **Independent Querying:** The agent dynamically forms its own Cypher queries using the `TrackingDFKGQueryTool`.

## DFKG Query Design
- **Tool:** `TrackingDFKGQueryTool` is provided to the agent to query the Neo4j instance.
- **Bounded:** The system prompt instructs the agent to limit its queries to memory-forensics-relevant evidence (e.g., process hollowing, code injection, rootkits).
- **Case Isolation:** The `TrackingDFKGQueryTool` internally ensures all queries are strictly case-scoped to the current `case_id`. The agent cannot accidentally retrieve data from another case.

## State Dependencies
- **Removed:** The agent no longer relies on `state.get("findings")`, `state.get("timeline")`, or `state.get("attribution")`. All logic related to these legacy payloads was completely excluded from the new implementation.
- **Remaining:** No legacy state dependencies remain in `memory_forensics_agent.py`. The arrays remain in `SpeculaState` because other downstream nodes (like Debate and Reporting) still require them.

## UID / Provenance Behavior
- `TrackingDFKGQueryTool` automatically intercepts and logs all DFKG `uid` values retrieved during the ReAct session.
- When the agent produces its `FINAL_ANSWER`, the collected UIDs are appended to the `dfkg_refs` list in the resulting `AgentFinding`.
- This ensures proper upstream provenance linking (e.g. `AgentFinding -[:BASED_ON]-> DFKG evidence`) in the Blackboard.

## Security & Prompt Injection
- Extracted memory strings and hostnames are treated strictly as **DATA**.
- Explicit instructions in the system prompt guard against prompt injection (e.g. strings like "ignore previous instructions"). The agent will log the anomaly but will not execute the embedded commands.

## Tests & Validation

### Exact Test Counts
- `test_memory_forensics_from_dfkg` (PASSED)
- `test_prompt_injection_in_dfkg_evidence` (PASSED)
- Total New Memory Forensics Tests: **2/2**
- Total Regression Tests: **19/19** (Across Supervisor, Timeline, Threat Attribution, Log Analysis, Network Forensics, and Debate agents)

### Live Validation Status
- **CODE / TEST VALIDATION ONLY (PASS WITH LIMITATION).**
- Due to the `SPECULA_DISABLE_NEURAL=1` fallback limitation in the testing environment, tests were executed using `StubLLM` and component stubs. No actual LLM call was executed against the Gemini API. Functional routing, architecture, UID collection, and state mutations are fully verified deterministically.

## Known Limitations
- The agent currently uses a mock/stub model in CI. Real efficacy against malicious memory dumps relies on the production LLM (Gemini).
- Identity & Cloud, Malware Stylometry, and Insider Threat agents remain on the legacy architecture.
