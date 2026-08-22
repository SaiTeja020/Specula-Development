# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Obey strict WIP=2 constraint (`|active| <= 2`). Update this file **immediately** whenever task status transitions, code is created/modified, or verification commands run.

---

## Current Build Status
- **Active Phase:** Phase 5: Visualization Layer & Agent Integration
- **Active Tasks (WIP=2):**
  1. `TASK-5.1` (Create `src/agents/visualizer_api.py` standalone FastAPI on port 8300)
  2. `TASK-5.2` (Implement WebSocket streaming of LangGraph data flow)
- **Active WIP Count:** 2 (`|active| = 2 / 2`)
- **Last Updated:** 2026-08-20

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

## Atomic Task Registry (WIP=2)

### Phase 1: Local Sandbox & Data Schemas (`ADR-002`, `ADR-004`)

- **Task ID:** `TASK-1.1`
  - **Description:** Create `docker-compose.yml` (Neo4j, Kafka/Redpanda, Redis, Quickwit, ChromaDB).
  - **Status:** `passing`
  - **Verification Command:** `docker compose config`
  - **Acceptance Criteria:** Compose specification valid with ports for Neo4j (7474/7687), Kafka (9092), Redis (6379), Quickwit (7280), Chroma (8000).

- **Task ID:** `TASK-1.2`
  - **Description:** Define base Pydantic schemas for OCSF/OSSEM log ingestion.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_component1_schemas.py`
  - **Acceptance Criteria:** Base OCSF Event class validates standard schema attributes deterministically.

- **Task ID:** `TASK-1.3`
  - **Description:** Create mock log pump (`mock_telemetry_pump.py`) for synthetic event generation.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_component1_addendum_dhcp_boundary.py`
  - **Acceptance Criteria:** Generates synthetic raw Windows Security and Sysmon events with valid structure.

---

### Phase 2: Forensic Preservation & VCT Layer (`ADR-004`, `ADR-006`)

- **Task ID:** `TASK-2.1`
  - **Description:** Implement atomic SHA-256 hashing for incoming raw logs (Preservation Layer).
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_component2_preservation.py`
  - **Acceptance Criteria:** Every raw event receives immutable SHA-256 hash before processing.

- **Task ID:** `TASK-2.2`
  - **Description:** Implement Merkle tree generation for VCT session roots.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_component2_preservation.py -k merkle`
  - **Acceptance Criteria:** Deterministic Merkle root calculation for forensic session verification.

- **Task ID:** `TASK-2.3`
  - **Description:** Build immutable append-only WORM datastore handler (Quickwit client).
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_component2_preservation.py -k worm`
  - **Acceptance Criteria:** Append-only write verification with integrity checking.

---

### Phase 3: Graph Streaming, Ingestion & Vector Retrieval (`ADR-006`)

- **Task ID:** `TASK-3.1`
  - **Description:** Create Kafka stream consumer for normalized OCSF events & ActiveCasesCache.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_component5_broker_case_tagging.py`
  - **Acceptance Criteria:** Active cases routed to Kafka topics with proper case partition keys.

- **Task ID:** `TASK-3.2`
  - **Description:** Write deterministic Cypher `MERGE` query builder for Neo4j.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_component7_graph_ingestion.py`
  - **Acceptance Criteria:** Parameterized Cypher queries build entity/relationship graph nodes without injection risk.

- **Task ID:** `TASK-3.3`
  - **Description:** Implement Phase 2 & 3 OCSF Event Schemas and Normalizers.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_component1_schemas.py`
  - **Acceptance Criteria:** Normalizers map EDR, malware, network, auth, vuln scan, and cloud events to standard OCSF classes.

- **Task ID:** `TASK-3.4`
  - **Description:** Implement Vector Retrieval Layer (`mcp-vector-retrieval`) with ChromaDB/InMemory adapters.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_vector_retrieval.py`
  - **Acceptance Criteria:** Semantic search over ingested evidence embeddings with RBAC filtering.

- **Task ID:** `TASK-3.5`
  - **Description:** Implement FAISS IndexIVFPQ threat-intel corpus (ATT&CK STIX + NVD CVE fetchers & MCP server).
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_threat_intel.py`
  - **Acceptance Criteria:** 29/29 tests passing; STIX/NVD retrieval with atomic hot-reload and rate-limit handling.

---

### Phase 4: LangGraph Orchestration & Multi-Agent Core (`ADR-001`, `ADR-003`, `ADR-005`)

- **Task ID:** `TASK-4.1`
  - **Description:** Define SpeculaState schema with append-reducers for parallel fan-out.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py -k TestStateIntegrity`
  - **Acceptance Criteria:** State models support append-only reducers for findings, debate history, and agent traces.

- **Task ID:** `TASK-4.2`
  - **Description:** Implement 16 ReAct-stub LLM agent nodes with config-driven model mapping.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py -k "TestNormalPath or TestDeadEndPath"`
  - **Acceptance Criteria:** All 16 agents instantiate and route according to graph configuration.

- **Task ID:** `TASK-4.3`
  - **Description:** Implement Guardrail Tier 1 (regex), Tier 2 (semantic BoW), and Tier 3 (LLM).
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py -k "TestGuardrailFailures or TestGuardrailGenuineDetection"`
  - **Acceptance Criteria:** Short-circuits malicious prompt injections, shell escapes, and cypher deletions.

- **Task ID:** `TASK-4.4`
  - **Description:** Implement HITL interrupt/resume with dual-entry routing and FastAPI endpoint on uvicorn.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py -k "TestHITLApproveGuardrail or TestHITLApproveDebate or TestHITLReject or TestHITLClarify"`
  - **Acceptance Criteria:** Interrupts execution on guardrail failure or debate exhaustion; resumes cleanly upon human signal.

- **Task ID:** `TASK-4.5`
  - **Description:** Wire 23-node StateGraph with Send fan-out, Command routing, and ACH debate loop.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py`
  - **Acceptance Criteria:** 28/28 tests passing across all graph execution branches.

- **Task ID:** `TASK-4.6`
  - **Description:** Implement Evidence Collection Agent with multi-criterion relevance filtering and verdict publishing.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/agents/`
  - **Acceptance Criteria:** 12/12 agent tests passing; strict multi-host isolation and 4-part discard conjunction logic verified.

- **Task ID:** `TASK-4.7`
  - **Description:** Implement Supervisor Agent (Orchestrator) graph and Kafka Consumer.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/orchestration/test_supervisor.py`
  - **Acceptance Criteria:** Supervisor graph built and routes according to specifications.

---

### Phase 5: Real-Time Visualization Layer (`ADR-003`, `ADR-007`)

- **Task ID:** `TASK-5.1`
  - **Description:** Create `src/agents/visualizer_api.py` standalone FastAPI service on port 8300 with CORS and health endpoints.
  - **Status:** `active`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_visualizer_api.py`
  - **Acceptance Criteria:** FastAPI app instantiates with health check returning 200 and CORS enabled for frontend origin.

- **Task ID:** `TASK-5.2`
  - **Description:** Implement WebSocket streaming endpoint in `visualizer_api.py` broadcasting LangGraph node execution events and state deltas.
  - **Status:** `active`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_visualizer_ws.py`
  - **Acceptance Criteria:** WebSocket connection receives real-time JSON event packets during graph invocation.

- **Task ID:** `TASK-5.3`
  - **Description:** Build Vite + React frontend dashboard with React Flow graph visualizer for 23 orchestration nodes.
  - **Status:** `not_started`
  - **Verification Command:** `npm test --prefix visualization`
  - **Acceptance Criteria:** React component renders 23 graph nodes with active status highlighting.

- **Task ID:** `TASK-5.4`
  - **Description:** End-to-end integration of frontend visualizer with backend WebSocket streaming.
  - **Status:** `not_started`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_visualization_e2e.py`
  - **Acceptance Criteria:** Live graph run updates node colors and emits findings timeline in frontend.

---

## Pending Dependency & Terminal Requests (Awaiting Human Action)
- **Required for dateutil normalizer tests:**
  ```powershell
  .\venv\Scripts\pip.exe install python-dateutil
  ```

---

## Recent Execution Log
| Date | Component / Task | Changes Made | Verification Result |
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
| 2026-08-18 | `git` | Rebased and merged `skeleton` branch into `main`. | Main branch updated |
| 2026-08-14 | `.agents/rules/rules.md` | Added session start (clock in) and session end (clock out) rules to operational directives. | Updated |
| 2026-08-14 | `DECISIONS.md`, `PROGRESS.md` | Created central ADR repository (`DECISIONS.md`) with baseline ADRs 001-007; established bidirectional links with `PROGRESS.md`. | Verified |
| 2026-08-18 | `faiss_threat_intel_implementation_plan.md`, `src/schemas/threat_intel_metadata.py`, `src/ingestion/indexing/threat_intel_sources.py`, `src/ingestion/indexing/threat_intel_index.py`, `src/mcp/threat_intel_mcp.py`, `scripts/build_threat_intel_index.py`, `tests/ingestion/test_threat_intel.py`, `requirements.txt` | Implemented FAISS IndexIVFPQ threat-intel corpus: ATT&CK STIX + NVD CVE fetchers, in-process ThreatIntelIndex with atomic hot-reload, ThreatIntelMCPServer exposing query_attack_techniques/groups/cves/health_check, offline build script with rate-limited NVD API (NVD_API_KEY env var for key injection), and full 5-category test suite (golden-fixture, training-skip guard, reload, filter-after-search, staleness). | 29/29 Passed |
| 2026-08-18 | `src/ingestion/security_gate/injection_detector.py`, `src/ingestion/broker/case_open_consumer.py`, `tests/ingestion/test_stage2_ingestion_pipeline.py` | Created in-process injection detector, Kafka case-open dispatcher, and Stage 2 fixture test suite. Initial component work; Security Gate not yet wired to block, Kafka serialization simulated. | 15/15 Passed (unit-level only) |
| 2026-08-18 | `src/ingestion/security_gate/pipeline.py`, `src/ingestion/broker/kafka_producer.py`, `src/ingestion/broker/kafka_consumer.py`, `src/ingestion/validation/schema_registry_client.py`, `src/ingestion/run_pipeline.py`, `docker-compose.yml`, `requirements.txt`, `tests/ingestion/test_stage2_e2e_flow.py` | **Gap fixes:** (1) Wired `scan_for_injection()` into `run_security_gate()` — malicious payloads now blocked with `injection_blocked=True`. (2) Replaced hardcoded schema ID with `jsonschema` validation against OCSF JSON Schema; `EventProducer` uses real `SerializingProducer` when broker available. (3) Added 7-step e2e flow test (SHA-256 → Gate → OCSF → wire → deser → Cypher → vector). (4) Replaced Qdrant with ChromaDB in docker-compose. | 15/15 Fixtures + 2/2 E2E + 28/28 Skeleton |
| 2026-08-20 | `TASK-4.6` | Verified pulled Evidence Collection Agent & Relevance Filter tests | 12/12 Passed (`tests/agents/`) |
| 2026-08-20 | Harness Upgrade | Updated `AGENTS.md`, `.agents/rules/rules.md`, and restructured `PROGRESS.md` to WIP=2 state machine | Verified |
| 2026-08-21 | `TASK-4.7` | Created `supervisor_agent.py`, `supervisor_graph.py`, and `kafka_consumer.py` per build spec | 2/2 Passed (`tests/orchestration/test_supervisor.py`) |
| 2026-08-21 | `TASK-4.7` | Rewrote tests to directly evaluate LangGraph state transitions and replaced inert mocks; fixed HITL routing logic | 32/32 Passed (`tests/supervisor_test_suite/`) |
| 2026-08-21 | Ingestion Fix | Fixed MFT USN casting crash & heuristic timestamp bug; refactored container extraction to pull from live Docker endpoints | 212/212 Nodes Written |

---

## Known Blockers, Bugs & Carry-Forward Tracking Items
1. **Stage 3 Checkpointer Refactor:** `src/agents/checkpointer.py` is a Stage 1 test-support stopgap using `pickle`. Replace with `langgraph-checkpoint-redis` / `langgraph-checkpoint-postgres` or add safe serialization (JSON/msgpack) before production use. Note: current `pending_writes` implementation assumes sequential interrupt nodes (safe for Stage 1 topology, must handle mid-fanout writes in Stage 3).
2. **Kafka Integration CI Retention:** Set short retention policy or per-run topic suffixes on `findings.*` Kafka topics before running integration test suite in automated CI.
3. **Stage 7 Guardrail Fine-Tuning:** The `rm -rf` Tier 1 regex will false-positive on findings quoting attacker commands. Fine-tune Tier 2 embedding model with real MiniLM training data beyond phrase matching in Stage 7.
