# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Update this file **immediately** whenever a task status changes, code is added/modified, or dependencies are flagged. Make sure the logs are brief and understandable.

---

## Current Build Status
- **Active Phase:** Visualization Layer (Phase 5)
- **Current Objective:** Build real-time LangGraph visualization using React Flow and FastAPI WebSockets.
- **Last Updated:** 2026-08-14

---

## Architectural Decisions (ADRs)
Central Architecture Decision Records are maintained in [DECISIONS.md](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md).

| ADR ID | Title | Status | Governed Phase |
| :--- | :--- | :--- | :--- |
| [ADR-001](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-001-blackboard-coordination--supervisor-governance-model) | Blackboard Coordination + Supervisor Governance Model | Accepted | Phase 4 |
| [ADR-002](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-002-ingestion-pipeline-bifurcation-preservation-vs-abstraction) | Ingestion Pipeline Bifurcation (Preservation vs. Abstraction) | Accepted | Phase 1 |
| [ADR-003](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-003-model-distribution--deployment-topology) | Model Distribution & Deployment Topology | Accepted | Phase 4 & Phase 5 |
| [ADR-004](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-004-three-tier-cryptographic-provenance-architecture-vct) | Three-Tier Cryptographic Provenance Architecture (VCT) | Accepted | Phase 1 & Phase 2 |
| [ADR-005](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-005-adversarial-quality-control-via-ach-debate-loop) | Adversarial Quality Control via ACH Debate Loop | Accepted | Phase 4 |
| [ADR-006](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-006-dynamic-attack-graph-weighting-via-negative-log-transformation) | Dynamic Attack Graph Weighting via Negative Log Transformation | Accepted | Phase 2 & Phase 3 |
| [ADR-007](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-007-mcp-integration-scope) | MCP Integration Scope | Accepted | Phase 5 |

---

## Task Roadmap & Status

### Phase 1: Local Sandbox & Data Schemas (`ADR-002`, `ADR-004`)
- [x] Task 1.1: Create `docker-compose.yml` (Neo4j, Kafka/Redpanda, Redis, Quickwit, Qdrant).
- [x] Task 1.2: Define base Pydantic schemas for OCSF/OSSEM log ingestion.
- [x] Task 1.3: Create mock log pump (`mock_telemetry_pump.py`) for synthetic events.

### Phase 2: Forensic Preservation & VCT Layer (`ADR-004`, `ADR-006`)
- [x] Task 2.1: Implement atomic hashing for incoming raw logs (Preservation Layer).
- [x] Task 2.2: Implement Merkle tree generation for VCT session roots.
- [x] Task 2.3: Build immutable append-only WORM datastore handler.

### Phase 3: Graph Streaming, Ingestion & Vector Retrieval (`ADR-006`)
- [x] Task 3.1: Create Kafka stream consumer for normalized OCSF events & ActiveCasesCache.
- [x] Task 3.2: Write deterministic Cypher `MERGE` query builder for Neo4j.
- [x] Task 3.3: Implement Neo4j APOC triggers for Blackboard event dispatching.
- [x] Task 3.4: Implement Phase 2 & Phase 3 OCSF Event Schemas and Normalizers.
- [x] Task 3.5: Implement Vector Retrieval Layer (`mcp-vector-retrieval`), ChromaDB/InMemory adapter, metadata validation, and RBAC tools.

### Phase 4: LangGraph Orchestration Skeleton (`ADR-001`, `ADR-003`, `ADR-005`)
- [x] Task 4.1: Define SpeculaState schema with append-reducers for parallel fan-out (§2).
- [x] Task 4.2: Implement 16 ReAct-stub LLM agent nodes with config-driven model mapping (§3, §6).
- [x] Task 4.3: Implement Guardrail Tier 1 (regex), Tier 2 (embedding similarity), Tier 3 (LLM) (§7).
- [x] Task 4.4: Implement HITL interrupt/resume with dual-entry routing (§8).
- [x] Task 4.5: Wire 23-node StateGraph with Send fan-out, Command routing, debate loop (§4).
- [x] Task 4.6: Implement Kafka topic layout, producer helpers, DFKG consumer (§5.1).
- [x] Task 4.7: Add Entity.uid uniqueness constraint (§5.2).
- [x] Task 4.8: Create FastAPI HITL endpoint on uvicorn (§8).
- [x] Task 4.9: Write verification test suite (§11).
- [x] Task 4.10: Run test suite after dependency install.

### Phase 5: Visualization Layer (`ADR-003`, `ADR-007`)
- [ ] Task 5.1: Create `src/agents/visualizer_api.py` standalone FastAPI on port 8300.
- [ ] Task 5.2: Implement WebSocket streaming of LangGraph data flow.
- [ ] Task 5.3: Scaffold Vite + React application with React Flow.
- [ ] Task 5.4: Verify real-time tracking of graph execution in UI.

---

## Pending Dependency Requests (Awaiting Human Action)
- **Required:** `pip install langgraph langchain-core langchain-google-genai python-dotenv neo4j fastapi uvicorn httpx` for LangGraph skeleton with Gemini.
- Optional: `pip install chromadb>=0.4.22` for live ChromaDB integration runs.
- Optional: `pip install sentence-transformers` for neural Tier 2 guardrail.


---

## Recent Execution Log
| Date | Component / File Modified | Changes Made | Verification Result |
| :--- | :--- | :--- | :--- |
| 2026-07-25 | `AGENTS.md`, `PROGRESS.md` | Initialized development harness and tracking rules | Verified |
| 2026-07-28 | `.agents/skills/mcp-builder`, `.agents/skills.json` | Downloaded and added `mcp-builder` skill from GitHub | Verified |
| 2026-07-28 | `specula_ingestion_final_plan.md` | Adopted authoritative v6 implementation plan | Approved for Execution |
| 2026-07-28 | `src/schemas/*`, `src/ingestion/preservation/*` | Implemented Component 1 (Schemas) & Component 2 (Forensic Preservation) | Verified |
| 2026-07-28 | `src/ingestion/security_gate/*` | Implemented Component 3 (Security Gate) | Verified |
| 2026-07-28 | `src/ingestion/normalization/*`, `src/mcp/*` | Implemented Component 4 (OCSF Normalization & Time Baseline) | Verified |
| 2026-07-28 | `src/ingestion/validation/*`, `src/ingestion/broker/*` | Implemented Component 5 (Validation, Wire Serialization & Case Tagging) | Verified |
| 2026-07-28 | `src/ingestion/abstraction/*`, `src/ingestion/broker/reconcile_degraded_windows.py` | Implemented Component 6 (Analytical Abstraction & Compression) | Verified |
| 2026-07-28 | `src/graph/*`, `src/mcp/dfkg_cypher.py` | Implemented Component 7 (Knowledge Graph Ingestion) | Verified |
| 2026-07-28 | `src/ingestion/indexing/*`, `requirements.txt`, `docker-compose.yml` | Implemented Component 8 (Vector Indexing) & Infrastructure | Verified |
| 2026-07-31 | `tests/conftest.py`, `tests/ingestion/*` | Merged all 8 component test suites from `additional tests/` into `tests/ingestion/`. Updated `conftest.py` with mock fixtures (`FakeRedisPersistent`, `FakeQuickwit`, `FakeNeo4j`, `synthetic_evtx_batch`, `poison_cluster`). | Verified |
| 2026-07-31 | `dist/Specula_Ingestion_Pipeline_and_Tests.zip` | Packaged complete source pipeline (`src/`), full test suite (`tests/`), `PROGRESS.md`, `pytest.ini`, and `specula_ingestion_final_plan.md` into zip archive without altering source files. | Verified |
| 2026-08-01 | `.gitignore`, `src/*`, `tests/*` | Updated `.gitignore` (excluding `data/`, `quarantine/`, `dist/`, `*.bin`, `*.zip`) and committed all implementation modules and 99/99 passing unit tests to local Git (`main`). | Committed (`42690bf`) |
| 2026-08-08 | `ocsf_phase2_phase3_implementation_plan_FINAL.md` | Adopted final approved implementation plan for Phase 2 & 3 OCSF normalizers | Approved for Execution |
| 2026-08-08 | `src/schemas/ocsf_phase2_events.py`, `src/schemas/ocsf_phase3_events.py` | Implemented Pydantic v2 schemas for `ProcessActivityEvent`, `FileActivityEvent`, `NetworkActivityEvent`, `AuthenticationEvent`, `DetectionFindingEvent`, `IncidentFindingEvent`, `EmailActivityEvent`, `VulnerabilityFindingEvent`, `HTTPActivityEvent`, `DeviceInventoryInfoEvent` | Verified |
| 2026-08-08 | `src/ingestion/normalization/*` | Built 8 normalizers (`edr_normalizer.py`, `malware_normalizer.py`, `email_normalizer.py`, `memory_dump_normalizer.py`, `container_normalizer.py`, `vuln_scan_normalizer.py`, `ueba_browser_normalizer.py`, `cloud_topology_normalizer.py`) | Verified |
| 2026-08-08 | `src/mcp/fastmcp_gateway.py` | Registered FastMCP gateway port routing for ports `8106`–`8113` | Verified |
| 2026-08-08 | `tests/ingestion/test_phase2_phase3_normalizers.py` | Added test suite covering sub-event branching, UID determinism, time baseline/unverified flags, gateway port routing, and threat intel boundary isolation. | 111/111 Passed |
| 2026-08-08 | `vector_retrieval_implementation_plan.md`, `src/schemas/vector_metadata.py`, `src/ingestion/indexing/vector_store.py`, `src/mcp/vector_retrieval.py`, `src/mcp/fastmcp_gateway.py`, `tests/ingestion/test_vector_retrieval.py` | Implemented Vector Retrieval Layer (`mcp-vector-retrieval`), metadata schema, ChromaDB & InMemory adapters, FastMCP port 8114 registration, and comprehensive test suite. | 10/10 Passed |
| 2026-08-09 | `docs/*`, `.gitignore` | Reorganized documentation files into `docs/` folder, updated `.gitignore` to ignore `.agents/`, staged, and pushed changes to remote `main`. | Pushed |
| 2026-08-09 | `src/agents/*` | Built full 23-node LangGraph orchestration skeleton: state schema (state.py), 16 agent configs (config.py), guardrails T1/T2 (guardrails.py), Kafka utils (kafka_utils.py), all node functions (nodes.py), graph assembly (graph.py), HITL API (hitl_api.py). | Code Complete |
| 2026-08-09 | `tests/test_skeleton_graph.py` | Verification suite: 10 test classes covering normal/dead-end paths, debate loop, guardrail failures, HITL dual-entry routing. | 19/19 Passed |
| 2026-08-09 | `requirements.txt`, `schema_constraints.cypher` | Added langgraph/fastapi/neo4j/google-genai deps. Added Entity.uid uniqueness constraint (§5.2). | Updated |
| 2026-08-11 | `src/agents/nodes.py`, `src/agents/guardrails.py` | Fixed Judge node loop-back (`FORCE_JUDGE_REJECT_ROUNDS:N`), HITL `case_status` pre-interrupt persistence, and Guardrail BoW chunk evaluation. Added shell regex and anti-forensic semantic phrases to Guardrails. | Verified |
| 2026-08-11 | `tests/test_skeleton_graph.py`, `tests/test_skeleton_integration.py` | Applied corrected unit tests with short-circuit/round-cap assertions (28/28 passing). Added separate integration suite for Kafka/Neo4j/cross-process HITL (skipped locally via `-m "not integration"`). | Verified |
| 2026-08-11 | `implementation_plan.md`, `task.md` | Created implementation plan for distinct real-time visualization layer using Vite/React and FastAPI WebSockets. | Approved for Execution |

| 2026-08-11 | `docker-compose.yml` | Fixed Kafka KRaft `CLUSTER_ID` base64 UUID, updated Quickwit image tag to `quickwit/quickwit:latest`. | Verified |
| 2026-08-11 | `src/agents/checkpointer.py` | Added stopgap Redis `RedisSaver` checkpointer for cross-process HITL state persistence testing. Added pending_writes and list() notes. | 4/4 Integration Passed |
| 2026-08-14 | `.agents/rules/rules.md` | Added session start (clock in) and session end (clock out) rules to operational directives. | Updated |
| 2026-08-14 | `DECISIONS.md`, `PROGRESS.md` | Created central ADR repository (`DECISIONS.md`) with baseline ADRs 001-007; established bidirectional links with `PROGRESS.md`. | Verified |

---

## Known Blockers, Bugs & Carry-Forward Tracking Items
1. **Stage 3 Checkpointer Refactor:** `src/agents/checkpointer.py` is a Stage 1 test-support stopgap using `pickle`. Replace with `langgraph-checkpoint-redis` / `langgraph-checkpoint-postgres` or add safe serialization (JSON/msgpack) before production use. Note: current `pending_writes` implementation assumes sequential interrupt nodes (safe for Stage 1 topology, must handle mid-fanout writes in Stage 3).
2. **Kafka Integration CI Retention:** Set short retention policy or per-run topic suffixes on `findings.*` Kafka topics before running integration test suite in automated CI.
3. **Stage 7 Guardrail Fine-Tuning:** The `rm -rf` Tier 1 regex will false-positive on findings quoting attacker commands. Fine-tune Tier 2 embedding model with real MiniLM training data beyond phrase matching in Stage 7.


