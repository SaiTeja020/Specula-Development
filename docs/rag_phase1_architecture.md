# Specula RAG Phase 1 — Architecture & Usage

## Overview

This document describes the Phase 1 RAG prototype for Specula.
The goal is to prove end-to-end forensic retrieval-augmented generation
using the existing DFKG (Neo4j), a controlled test dataset, and Gemini 2.5 Flash.

This is **NOT** integrated into the 13 LangGraph agents yet.

---

## Architecture

```
User Query
    ↓
InMemory/ChromaDB Vector Store  ←── EmbeddingGenerator (hash-based fallback or SentenceTransformers)
    ↓
Relevant DFKG entity UIDs + similarity scores
    ↓
DFKGRetriever.expand_from_uid()
    ↓
Bounded Neo4j subgraph (max_hops=3, max_nodes=100, max_rels=300)
    ↓
GraphContextBuilder  →  Structured forensic context text
    ↓
ForensicPrompt  →  Injection-resistant RAG prompt (system + evidence + query)
    ↓
GeminiClient (gemini-2.5-flash)
    ↓
Grounded forensic answer (cites DFKG UIDs)
```

---

## Files Created

| File | Purpose |
|------|---------|
| `scripts/seed_rag_test_data.py` | Seeds controlled forensic scenario into Neo4j |
| `scripts/run_rag_agent.py` | End-to-end RAG test agent CLI |
| `src/agents/rag/__init__.py` | RAG package |
| `src/agents/rag/dfkg_retriever.py` | Two-stage retriever (vector → graph) |
| `src/agents/rag/graph_context_builder.py` | Subgraph → LLM context formatter |
| `src/agents/rag/gemini_client.py` | Isolated Gemini API client |
| `src/agents/rag/forensic_prompt.py` | Injection-resistant forensic prompt builder |
| `tests/test_rag_pipeline.py` | 7-test RAG test suite |

---

## Neo4j Schema Used (Existing — Not Modified)

| Label | Key Property | Description |
|-------|-------------|-------------|
| `Host` | `uid`, `hostname` | Compromised endpoint |
| `User` | `uid`, `user_name` | User account |
| `Process` | `uid`, `process_name`, `pid`, `command_line` | Executed process |
| `NetworkEndpoint` | `uid`, `ip` | IP address |
| `File` | `uid`, `file_name`, `file_path` | File artifact |

| Relationship | Meaning |
|-------------|---------|
| `LOGGED_INTO` | User → Host |
| `LAUNCHED` | User → Process (initial launch) |
| `SPAWNED` | Process → Process (child) |
| `RUNS_ON` | Process → Host |
| `COMMUNICATED_WITH` | Process → NetworkEndpoint, NetworkEndpoint → NetworkEndpoint |
| `ACCESSED` | Process → File (read) |
| `CREATED` | Process → File (written/dropped) |

---

## Controlled Test Scenario

```
alice (User)
  ↓ LOGGED_INTO
workstation-01 (Host)

alice
  ↓ LAUNCHED
powershell.exe PID=1100
  ↓ SPAWNED
cmd.exe PID=1200
  ↓ SPAWNED
suspicious.exe PID=1300
  ├─ COMMUNICATED_WITH → 10.10.10.50 → 185.220.101.45 (C2)
  ├─ ACCESSED → invoice.pdf (lure document)
  └─ CREATED  → suspicious.exe in AppData/Roaming (persistence)
```

---

## ChromaDB vs FAISS Difference

| Aspect | Current Code | Master Document |
|--------|-------------|-----------------|
| DFKG Evidence Vectors | ChromaDB (`case_evidence_embeddings`) | FAISS |
| Threat Intel Vectors | FAISS (`build_threat_intel_index.py`) | FAISS |

The RAG retriever is isolated behind `VectorStoreAdapter` so ChromaDB can be replaced
with FAISS without modifying graph traversal or LLM code.

For Phase 1, the test agent uses **InMemoryVectorStore** seeded with the controlled
scenario, making it reproducible without depending on whether the live ingestion pipeline
has run.

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | **YES** | — | Gemini API key from aistudio.google.com |
| `NEO4J_URI` | No | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | No | `neo4j` | Neo4j user |
| `NEO4J_PASSWORD` | No | (empty) | Neo4j password |

Never commit `GEMINI_API_KEY`. It is already in `.env` (gitignored).

---

## How to Run

### 1. Start infrastructure
```powershell
docker-compose up -d
```

### 2. Seed the test dataset
```powershell
python scripts/seed_rag_test_data.py
```

### 3. Run the RAG agent
```powershell
# Default question
python scripts/run_rag_agent.py

# Custom question
python scripts/run_rag_agent.py "What process communicated with 185.220.101.45?"

# Dry-run (no Gemini, prints graph context only)
python scripts/run_rag_agent.py --dry-run "What process communicated with 185.220.101.45?"

# Direct UID expansion (bypass vector retrieval)
python scripts/run_rag_agent.py --uid <UID> "What did this process do?"
```

### 4. Run the test suite
```powershell
pytest tests/test_rag_pipeline.py -v
```

---

## Graph Traversal Limits

| Limit | Default | Configurable |
|-------|---------|-------------|
| Max hops | 3 | `DFKGRetriever(max_hops=N)` |
| Max nodes | 100 | `DFKGRetriever(max_nodes=N)` |
| Max relationships | 300 | `DFKGRetriever(max_rels=N)` |

---

## Example Query & Response

**Query:**
```
What process communicated with 185.220.101.45 and what evidence connects it to the user?
```

**Expected Response (paraphrased):**
```
Finding:
suspicious.exe (PROC-003) communicated with external C2 server 185.220.101.45 via
pivot host 10.10.10.50. The process chain traces back to user alice via powershell.exe
and cmd.exe.

Evidence:
- uid=<PROC3_UID>: suspicious.exe spawned by cmd.exe, communicated with 185.220.101.45
- uid=<IP2_UID>: 185.220.101.45 — C2 NetworkEndpoint
- uid=<USER_UID>: alice launched powershell.exe → cmd.exe → suspicious.exe

Reasoning:
Multi-hop traversal: alice → powershell.exe → cmd.exe → suspicious.exe →
10.10.10.50 → 185.220.101.45 shows a 5-hop chain connecting the user to the C2.

Confidence:
HIGH — all relationships are observed facts in the DFKG graph.
```

---

## Known Limitations (Phase 1)

1. **Vector store**: Phase 1 uses InMemoryVectorStore for reproducibility.
   The live pipeline uses ChromaDB. To use ChromaDB, replace the store
   in `run_rag_agent.py::build_retriever_from_seed()`.
2. **Embedding quality**: The default `EmbeddingGenerator` uses a hash-based
   fallback embedding. Install `sentence-transformers` for semantic accuracy.
3. **Not integrated into existing agents**: This is a standalone prototype.
4. **No LangGraph state**: The test agent does not use checkpointing or memory.
5. **ChromaDB/FAISS divergence**: Tracked — replaceable via VectorStoreAdapter.

---

## What Remains Before Integrating into Real Agents

1. Wire `DFKGRetriever` into the Evidence Collection Agent's tool calls.
2. Wire `GeminiClient` as the LLM for the Log Analysis Agent.
3. Replace hash-based embeddings with `sentence-transformers` in production.
4. Decide ChromaDB vs FAISS for DFKG vectors (tracked as open ADR).
5. Add retry/backoff for Gemini rate limiting.
6. Evaluate whether bounded traversal limits need tuning for large graphs.
