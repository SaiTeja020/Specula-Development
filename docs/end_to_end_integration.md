# End-to-End Integration — Specula Investigation Guide

## Overview

Phase E2E connects all existing Specula components into a single cohesive user-facing investigation workflow:

```
User Text Query
      ↓
run_investigation() / POST /investigate
      ↓
build_graph() — LangGraph Orchestration
      ↓
Supervisor → primary agents (Evidence Collection, Log Analysis, Network Forensics)
      ↓ [DFKG / GraphRAG queries]
Specialists if needed (Memory Forensics, etc.)
      ↓
Timeline Reconstruction → Threat Attribution
      ↓
Debate (Proponent ↔ Critic ↔ Judge)
      ↓
Guardrails (Tier 1 / 2 / 3)
      ↓  [HITL interrupt if guardrail fails or debate exhausted]
Report Generation + Timeline Artifact
      ↓
synthesize_plain_english()
      ↓
InvestigationResult (plain English, no traces, no Cypher)
```

---

## Entrypoints

### CLI
```powershell
python scripts/run_investigation.py \
  --case-id case-001 \
  --query "Investigate whether there was suspicious communication from this host." \
  --no-hitl
```

**Flags:**
- `--case-id` — Case identifier (auto-generated UUID if omitted)
- `--query` — Investigation question (required)
- `--json` — Output full result as JSON
- `--no-hitl` — Auto-approve HITL pauses (non-interactive, useful for CI)
- `--neo4j-uri` — Override Neo4j URI

**Environment variables honoured:**
- `SPECULA_LLM_BACKEND` — `stub` (default) or `gemini`
- `GEMINI_API_KEY` — Required when backend is `gemini`
- `SPECULA_NEO4J_ENABLED=true` — Enable live Neo4j queries
- `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`
- `SPECULA_DISABLE_NEURAL=1` — Disable sentence-transformers (process-local, test use only)

### HTTP API (FastAPI, port 8200)
```bash
# Start the gateway
uvicorn src.agents.hitl_api:app --port 8200

# Submit an investigation
curl -X POST http://localhost:8200/investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "Investigate suspicious network activity.", "case_id": "case-001"}'

# If HITL is triggered (status: paused_hitl), retrieve thread_id from response, then:
curl -X POST http://localhost:8200/hitl/{thread_id} \
  -H "Content-Type: application/json" \
  -d '{"decision": "approve"}'

# Retrieve result after completion
curl http://localhost:8200/investigation/thread-case-001/result
```

### Programmatic (Python)
```python
from src.agents.investigation_runner import run_investigation, HITLPausedResult

result = run_investigation(
    query="Was there lateral movement from host DESKTOP-ABC?",
    case_id="case-002",
)

if isinstance(result, HITLPausedResult):
    print(f"HITL required — thread: {result.thread_id}")
else:
    print(result["answer"])
    print("Agents used:", result["agents_used"])
    print("Evidence UIDs:", result["evidence_uids"])
```

---

## Output Contract (`InvestigationResult`)

| Field | Type | Description |
|---|---|---|
| `case_id` | str | Case identifier |
| `query` | str | Original investigation query |
| `status` | str | `completed` / `partial` / `rejected` |
| `answer` | str | Plain-English answer (no traces, no Cypher) |
| `evidence_uids` | list | DFKG UIDs from agent findings (provenance) |
| `agents_used` | list | Agent roles that contributed findings |
| `human_intervention` | bool | True if HITL was triggered |
| `debate_outcome` | str | `converged` / `round_cap_exhausted` / None |
| `validation_passed` | bool | UID hallucination check (None if not run) |
| `limitations` | list | Known gaps in the investigation |

---

## Security Model

1. **Prompt injection protection**: `forensic_prompt.py` wraps all evidence in `[BEGIN FORENSIC EVIDENCE (UNTRUSTED DATA)]` delimiters. The synthesis prompt uses `MANDATORY RULES` that explicitly forbid following any instructions found in the evidence.
2. **UID hallucination detection**: `response_validator.py` verifies all uid= citations against the known graph context. Unverified UIDs are logged with `HALLUCINATION RISK` warning.
3. **Case-scoped DFKG queries**: `DFKGQueryTool` injects `case_id` into every query — an agent cannot read another case's graph even under prompt injection.
4. **Read-only tools**: `DFKGQueryTool` rejects any Cypher containing write keywords (CREATE, MERGE, DELETE, SET, REMOVE, DROP, DETACH).
5. **Epistemic language enforced**: `synthesis.py` system prompt mandates `observed` / `consistent with` / `does not establish` vocabulary distinctions.

---

## HITL Workflow

If the graph pauses at a HITL checkpoint (guardrail failure or debate exhaustion):

**CLI mode**: The CLI prints the pause reason and reads a decision from stdin:
```
SPECULA HITL — HUMAN REVIEW REQUIRED
Case: case-001
Thread: thread-case-001
Options: approve / reject / clarify
Your decision: approve
```

**API mode**: The `/investigate` response returns `{"status": "paused_hitl", "thread_id": ...}`. The client then POSTs to `/hitl/{thread_id}` with `{"decision": "approve"|"reject"|"clarify"}`.

---

## Running Tests

```powershell
# E2E integration tests (mocked, no infrastructure required)
$env:SPECULA_DISABLE_NEURAL="1"; python -m pytest tests/integration/test_end_to_end_investigation.py -v

# Full regression suite
$env:SPECULA_DISABLE_NEURAL="1"; python -m pytest tests/ --ignore=tests/ingestion/test_neo4j_live.py -q
```

---

## Known Limitations

1. **HITL resume across processes**: The shared `InMemorySaver` in `hitl_api.py` is in-process only. For cross-process HITL resume, replace with a `SqliteSaver` or Redis-based checkpointer.
2. **Kafka consumer is a separate process**: Agent findings are published to Kafka fire-and-forget. The consumer (`run_dfkg_consumer()`) must run as a separate process to write findings back to Neo4j.
3. **H.7.3+ specialists still use `_run_agent`**: Identity & Cloud, Malware Stylometry, and Insider Threat use single-pass LLM calls without DFKG context retrieval. Migration is planned for future phases.
4. **FAISS threat intel index**: Not built in this environment. The `ForensicThreatContextSearchTool` in debate agents degrades gracefully with a logged warning.
