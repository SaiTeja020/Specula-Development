# Phase H.7.1 — Threat Attribution Context Migration

## Objective
Remove the Threat Attribution agent's dependency on the large ephemeral `SpeculaState` payload (`state.get("timeline")`) and replace it with a direct, bounded DFKG query using the `TrackingDFKGQueryTool`. This ensures the agent pulls investigation context directly from the Neo4j graph while preserving UID tracking, and moves us closer to deprecating legacy LangGraph arrays.

## Architecture

### Old Architecture
- The agent's `_build_system_prompt()` extracted the `timeline_summary` directly from `state.get("timeline", {})`.
- The `timeline` state was a large JSON array passed through the entire LangGraph orchestration cycle.
- Modifying or clearing this state payload risked breaking downstream consumers (Debate, Reporting, Guardrails).

### New Architecture
- `_build_system_prompt()` now receives `timeline_summary` as an explicit string argument and no longer accesses `state` directly.
- The `make_threat_attribution_node()` factory intercepts the initialization phase and uses the existing `TrackingDFKGQueryTool` to issue a targeted, case-scoped Cypher query for recent `timeline_reconstruction` AgentFindings.
- Because `TrackingDFKGQueryTool` tracks the UIDs of retrieved records, any `uid` returned by the timeline query is automatically appended to the Threat Attribution agent's `dfkg_refs` list, properly sourcing its conclusions back to the DFKG.

**Exact State Dependency Removed:**
- `state.get("timeline", {})` was completely removed from `src/agents/threat_attribution_agent.py`.

**DFKG Query Used:**
```cypher
MATCH (f:AgentFinding)-[:BELONGS_TO]->(c:Case {case_id: $case_id})
WHERE f.agent_role = 'timeline_reconstruction'
RETURN f.summary AS summary, f.uid AS uid
ORDER BY f.timestamp DESC LIMIT 1
```

## Testing & Validation

### Code/Test Validation (PASS)
A new integration test suite was created (`test_threat_attribution_context_migration.py`) and existing tests were updated to cover the new architectural pattern.

**Tests Run:**
- `tests/agents/test_threat_attribution_rag.py` (7/7 passed)
- `tests/agents/test_threat_attribution_context_migration.py` (3/3 passed)

**Test Coverage Verified:**
- [x] A. Timeline state absent from payload entirely (simulated)
- [x] B. DFKG context retrieved successfully via Cypher
- [x] C. Query is case-scoped (handled inherently by `TrackingDFKGQueryTool`)
- [x] D. UID citations remain present (verified via `dfkg_refs` extraction)
- [x] E. Threat-intel retrieval still works
- [x] F. Prompt injection in DFKG evidence remains data
- [x] G. AgentFinding publication remains functional

### Live LLM Validation (LIMITATION)
Validation was performed strictly via Pytest using `StubLLM` and MagicMock stubs for the MCP server and Neo4j driver. Due to local testing environment constraints (`SPECULA_DISABLE_NEURAL=1`), a full live LLM test against the real Gemini API was not executed. The functional logic is verified through deterministic unit testing.

## Known Limitations
- The fallback logic limits timeline context to `LIMIT 1` for now, assuming the most recent `timeline_reconstruction` finding contains the complete chronological summary.
- The other legacy specialist agents (`Memory`, `Identity`, `Malware`, `Insider`) are still unmigrated.
