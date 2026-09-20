# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Obey strict WIP=2 constraint (`|active| <= 2`). Update this file **immediately** whenever task status transitions, code is created/modified, or verification commands run.

---

## Current Build Status
- **Active Phase:** Phase E2E: End-to-End Investigation Integration (Complete)
- **Active Tasks (WIP=2):**
  - None (Pending Selection)
- **Active WIP Count:** 0 (`|active| = 0 / 2`)
- **Last Updated:** 2026-09-20

### Phase E2E — End-to-End Investigation Integration — PASSING ✅ (2026-09-20)
- **Verification:** `pytest tests/integration/test_end_to_end_investigation.py -v` → **10/10 passed**
- **CLI smoke test:** `python scripts/run_investigation.py --case-id case-smoke-001 --query "Investigate suspicious network activity..." --no-hitl` → COMPLETED, all agents ran (Supervisor → Evidence Collection → Log Analysis → Network Forensics → Timeline → Threat Attribution → Debate → Guardrails → Report)
- **Files created:**
  - `src/agents/synthesis.py` — plain-English synthesis step (`synthesize_plain_english()`, `InvestigationResult`)
  - `src/agents/investigation_runner.py` — programmatic runner (`run_investigation()`, `run_investigation_with_hitl_stdin()`, `HITLPausedResult`)
  - `scripts/run_investigation.py` — CLI entrypoint (`--case-id`, `--query`, `--no-hitl`, `--json`)
  - `tests/integration/test_end_to_end_investigation.py` — 10 mocked integration tests
  - `docs/end_to_end_integration_audit.md` — architecture audit
  - `docs/end_to_end_integration.md` — integration guide
- **Files modified:**
  - `src/agents/hitl_api.py` — added `POST /investigate` and `GET /investigation/{thread_id}/result` endpoints
- **Neural limitation:** Tests used `SPECULA_DISABLE_NEURAL=1` (process-local). Not in `.env`.
- **Real E2E run:** `stub` LLM backend. StubLLM responses validate full graph traversal. Real LLM requires `SPECULA_LLM_BACKEND=gemini` + `GEMINI_API_KEY`.

### Phase H.7.2 — Memory Forensics Context Migration — PASSING ✅ (2026-09-20)
- **Verification:** `pytest tests/agents/test_memory_forensics_agent.py -v` → **2/2 passed**
- **Files created:** `src/agents/memory_forensics_agent.py`, `tests/agents/test_memory_forensics_agent.py`, `docs/phase_h7_2_memory_forensics.md`
- **Files modified:** `src/agents/nodes.py` (stub removed), `src/agents/graph.py` (factory wired)

### Phase H.7.1 — Threat Attribution Context Migration — PASSING ✅ (2026-09-20)
- **Verification:** `pytest tests/agents/test_threat_attribution_context_migration.py -v` → **3/3 passed**

### RAG Phase 1 & 1.5 — PASSING ✅ (2026-09-20)
- **Verification:** `pytest tests/test_rag_pipeline.py -v` → **16/16 passed** (including Phase 1.5 UID validation tests)
- **End-to-end:** `python scripts/run_rag_agent.py` → RAG retrieval, context building, and semantic embeddings (all-MiniLM-L6-v2) implemented. E2E script tested (blocked locally only by Gemini Pro API quota limits).
- **Neo4j seeded:** 9 nodes, 22 relationships via `scripts/seed_rag_test_data.py`
- **Files created/modified:** `src/agents/rag/response_validator.py`, `src/ingestion/indexing/vector_store.py`, `src/agents/rag/gemini_client.py`, `scripts/run_rag_agent.py`, `tests/test_rag_pipeline.py`
- **Model note:** Default changed from `gemini-3.6-flash` to `gemini-3.1-pro-preview` per Phase 1.5 requirements. Override via `GEMINI_MODEL` env var.

---

## Architectural Decisions (ADRs)
Central Architecture Decision Records are maintained in [DECISIONS.md](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md).

| ADR ID | Title | Status | Governed Phase |
| :--- | :--- | :--- | :--- |
| [ADR-001](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-001-blackboard-coordination--supervisor-governance-model) | Blackboard Coordination + Supervisor Governance Model | Accepted | Phase 4 |
| [ADR-002](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-002-ingestion-pipeline-bifurcation-preservation-vs-abstraction) | Ingestion Pipeline Bifurcation (Preservation vs. Abstraction) | Accepted | Phase 1 |
| [ADR-003](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-003-model-distribution--deployment-topology) | Model Distribution & Deployment Topology | Accepted | Phase 4 & Phase 5 |
| [ADR-004](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-004-three-tier-cryptographic-provenance-architecture-vct) | Three-Tier Cryptographic Provenance Architecture (VCT) | Accepted | Phase 1 & Phase 2 |
| [ADR-005](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/DECISIONS.md#adr-005-adversarial-quality-control-via-ach-debate-loop) | Accepted | Phase 4 |
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
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_component1_schemas.py`
  - **Acceptance Criteria:** Base OCSF Event class validates standard schema attributes deterministically.

- **Task ID:** `TASK-1.3`
  - **Description:** Create mock log pump (`mock_telemetry_pump.py`) for synthetic event generation.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_component1_addendum_dhcp_boundary.py`
  - **Acceptance Criteria:** Generates synthetic raw Windows Security and Sysmon events with valid structure.

---

### Phase 2: Forensic Preservation & VCT Layer (`ADR-004`, `ADR-006`)

- **Task ID:** `TASK-2.1`
  - **Description:** Implement atomic SHA-256 hashing for incoming raw logs (Preservation Layer).
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_component2_preservation.py`
  - **Acceptance Criteria:** Every raw event receives immutable SHA-256 hash before processing.

- **Task ID:** `TASK-2.2`
  - **Description:** Implement Merkle tree generation for VCT session roots.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_component2_preservation.py -k merkle`
  - **Acceptance Criteria:** Deterministic Merkle root calculation for forensic session verification.

- **Task ID:** `TASK-2.3`
  - **Description:** Build immutable append-only WORM datastore handler (Quickwit client).
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_component2_preservation.py -k worm`
  - **Acceptance Criteria:** Append-only write verification with integrity checking.

---

### Phase 3: Graph Streaming, Ingestion & Vector Retrieval (`ADR-006`)

- **Task ID:** `TASK-3.1`
  - **Description:** Create Kafka stream consumer for normalized OCSF events & ActiveCasesCache.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_component5_broker_case_tagging.py`
  - **Acceptance Criteria:** Active cases routed to Kafka topics with proper case partition keys.

- **Task ID:** `TASK-3.2`
  - **Description:** Write deterministic Cypher `MERGE` query builder for Neo4j.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_component7_graph_ingestion.py`
  - **Acceptance Criteria:** Parameterized Cypher queries build entity/relationship graph nodes without injection risk.

- **Task ID:** `TASK-3.3`
  - **Description:** Implement Phase 2 & 3 OCSF Event Schemas and Normalizers.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_component1_schemas.py`
  - **Acceptance Criteria:** Normalizers map EDR, malware, network, auth, vuln scan, and cloud events to standard OCSF classes.

- **Task ID:** `TASK-3.4`
  - **Description:** Implement Vector Retrieval Layer (`mcp-vector-retrieval`) with ChromaDB/InMemory adapters.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_vector_retrieval.py`
  - **Acceptance Criteria:** Semantic search over ingested evidence embeddings with RBAC filtering.

- **Task ID:** `TASK-3.5`
  - **Description:** Implement FAISS IndexIVFPQ threat-intel corpus (ATT&CK STIX + NVD CVE fetchers & MCP server).
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/ingestion/test_threat_intel.py`
  - **Acceptance Criteria:** 29/29 tests passing; STIX/NVD retrieval with atomic hot-reload and rate-limit handling.

---

### Phase 4: LangGraph Orchestration & Multi-Agent Core (`ADR-001`, `ADR-003`, `ADR-005`)

- **Task ID:** `TASK-4.1`
  - **Description:** Define SpeculaState schema with append-reducers for parallel fan-out.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/test_skeleton_graph.py -k TestStateIntegrity`
  - **Acceptance Criteria:** State models support append-only reducers for findings, debate history, and agent traces.

- **Task ID:** `TASK-4.2`
  - **Description:** Implement 16 ReAct-stub LLM agent nodes with config-driven model mapping.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/test_skeleton_graph.py -k "TestNormalPath or TestDeadEndPath"`
  - **Acceptance Criteria:** All 16 agents instantiate and route according to graph configuration.

- **Task ID:** `TASK-4.3`
  - **Description:** Implement Guardrail Tier 1 (regex), Tier 2 (semantic BoW), and Tier 3 (LLM).
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/test_skeleton_graph.py -k "TestGuardrailFailures or TestGuardrailGenuineDetection"`
  - **Acceptance Criteria:** Short-circuits malicious prompt injections, shell escapes, and cypher deletions.

- **Task ID:** `TASK-4.4`
  - **Description:** Implement HITL interrupt/resume with dual-entry routing and FastAPI endpoint on uvicorn.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/test_skeleton_graph.py -k "TestHITLApproveGuardrail or TestHITLApproveDebate or TestHITLReject or TestHITLClarify"`
  - **Acceptance Criteria:** Interrupts execution on guardrail failure or debate exhaustion; resumes cleanly upon human signal.

- **Task ID:** `TASK-4.5`
  - **Description:** Wire 23-node StateGraph with Send fan-out, Command routing, and ACH debate loop.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/test_skeleton_graph.py`
  - **Acceptance Criteria:** 28/28 tests passing across all graph execution branches.

- **Task ID:** `TASK-4.6`
  - **Description:** Implement Evidence Collection Agent with multi-criterion relevance filtering and verdict publishing.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/agents/`
  - **Acceptance Criteria:** 12/12 agent tests passing; strict multi-host isolation and 4-part discard conjunction logic verified.

- **Task ID:** `TASK-4.7`
  - **Description:** Implement Supervisor Agent (Orchestrator) graph and Kafka Consumer.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/orchestration/test_supervisor.py`
  - **Acceptance Criteria:** Supervisor graph built and routes according to specifications.

- **Task ID:** `TASK-4.8`
  - **Description:** Build Log Analysis Agent Multi-Tier Ground-Truth Benchmark Suite with SHA-256 integrity lock and 3-tier scoring.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\python.exe scripts/evaluate_log_analysis_ground_truth.py`
  - **Acceptance Criteria:** All 4 pre-committed SLA thresholds pass against frozen 50-event dataset and 100k-event baseline seed.

---

### Phase 5: Real-Time Visualization Layer (`ADR-003`, `ADR-007`)

- **Task ID:** `TASK-5.1`
  - **Description:** Create `src/agents/visualizer_api.py` standalone FastAPI service on port 8300 with CORS and health endpoints.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/test_visualizer_api.py`
  - **Acceptance Criteria:** FastAPI app instantiates with health check returning 200 and CORS enabled for frontend origin.

- **Task ID:** `TASK-5.2`
  - **Description:** Implement WebSocket streaming endpoint in `visualizer_api.py` broadcasting LangGraph node execution events and state deltas.
  - **Status:** `passing`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/test_visualizer_ws.py`
  - **Acceptance Criteria:** WebSocket connection receives real-time JSON event packets during graph invocation.

- **Task ID:** `TASK-5.3`
  - **Description:** Build Vite + React frontend dashboard with React Flow graph visualizer for 23 orchestration nodes.
  - **Status:** `not_started`
  - **Verification Command:** `npm test --prefix visualization`
  - **Acceptance Criteria:** React component renders 23 graph nodes with active status highlighting.

- **Task ID:** `TASK-5.4`
  - **Description:** End-to-end integration of frontend visualizer with backend WebSocket streaming.
  - **Status:** `not_started`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/test_visualization_e2e.py`
  - **Acceptance Criteria:** Live graph run updates node colors and emits findings timeline in frontend.

---

## Pending Dependency & Terminal Requests (Awaiting Human Action)
- **Required for dateutil normalizer tests:**
  ```powershell
  . env\Scripts\pip.exe install python-dateutil
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
| 2026-08-22 | `docs/imp_plan.md` fixes (A1–D4) | **A1/B1:** `make_evidence_collection_node` factory fixes node signature; wired in `build_graph()`. **A2:** `_llm_call` extracts `.content` with `hasattr` guard. **A3:** `test_control: Optional[dict]` added to `SpeculaState`. **B2:** EC node uses `KafkaPublishFindingTool`-only publish (no `_run_agent`, no double-publish). **C1:** `TrackingDFKGQueryTool` populates `dfkg_refs` from DFKG query results. **D1:** Dead-end detection moved to `primary_tier_join_node` via `make_primary_tier_join_node` factory; `supervisor_node` strips DEAD_END: regex; tests updated to `test_control` injection. **D2:** Portable `load_dotenv()` auto-discovery replaces hardcoded Windows path in `config.py`. **D3:** `_RESOLVED_GEMINI_MODEL` module-level cache prevents re-querying Google API per call. **D4:** `StubLLM` receives `case_id` at construction; `get_llm()` and `_run_agent()` pass it explicitly. Promoted `dead_end_detector.py`, `react_tools.py`, `evidence_collection_agent.py` to `src/agents/`. | 28/28 + 44/44 Passed |
| 2026-08-22 | `TASK-6.1` Log Analysis Agent | Built `src/agents/log_analysis/` package: config, signatures YAML, finding_builder, detection_rules, anomaly_detector, dedup, llm_reasoner, agent. Added RBAC grant in vector_retrieval.py. | 71/71 Passed (`tests/agents/log_analysis/`) |
| 2026-08-25 | `TASK-4.7` Extended | Integrated Natural Language Query Routing, Capability Fallback Governance, and Async Loop Budgets into Supervisor | 39/39 Passed (`tests/supervisor_test_suite/`) |
| 2026-08-26 | `src/ingestion/normalization/network_normalizer.py`, `src/ingestion/run_pipeline.py` | Implemented binary PCAP dissection using dpkt, passing packet payloads through Security Gate prompt injection check and routing to OCSF NetworkActivity schema. (ADR-008) | Verified (83/83 OCSF events parsed) |
| 2026-08-26 | `src/ingestion/run_pipeline.py`, `src/graph/cypher_builder.py` | Fixed time boundary filtering (using FilterHashtable) and parsed CLI arguments for start/end time. Addressed Neo4j graph pollution by only executing Process MERGE for true Process Creation events (Sysmon EID 1, Security EID 4688). | Verified (2/4219 Process nodes generated) |
| 2026-08-26 | `TASK-5.1`, `TASK-5.2` | Implemented FastAPI visualizer and WebSocket streaming. | Verified |
| 2026-08-26 | `src/agents/checkpointer.py` | Refactored Checkpointer to use official `langgraph-checkpoint-redis` with native serialization, replacing unsafe `pickle`. | Verified (28/28 tests passed) |
| 2026-08-26 | `src/ingestion/run_pipeline.py`, `src/ingestion/ingestion_consumer.py` | Decoupled synchronous ingestion pipeline into distinct Kafka Producer and Consumer. Extracted inline normalization to dedicated modules, fixed hardcoded host logic, and implemented structured semantic text embeddings for ChromaDB vector isolation. | Verified |
| 2026-08-26 | `src/ingestion/run_pipeline.py`, `src/ingestion/ingestion_consumer.py`, `src/ingestion/broker/kafka_consumer.py` | Fixed execution ordering invariant: implemented EventConsumer.consume_loop(), moved specula.cases.opened triggering into ingestion_consumer.py after Distillation -> Cypher -> ChromaDB completes, ensuring Supervisor wakes up to a fully populated graph. | Verified |
| 2026-08-28 | `TASK-4.8` Log Analysis Benchmark | Created frozen 50-event GT fixture (`log_analysis_ground_truth_v1.json`), 100k-event baseline seed (`log_analysis_baseline_seed_v1.json`), and multi-tier benchmark runner (`evaluate_log_analysis_ground_truth.py`) with SHA-256 integrity locks and pre-committed SLA checks. | 4/4 SLA Passed (Near-Miss FP=0%, Clear Malicious Recall=100%, Overall Recall=88%, Overall Prec=100%) |
| 2026-08-31 | Bugfix | Fixed JSON decoding error in `src/orchestration/kafka_consumer.py` by using `deserialize_event` to handle Confluent wire format headers. | Verified (39/39 supervisor tests passed) |
| 2026-08-31 | Bugfix | Removed strict `dfkg_uri` requirement in `SupervisorKafkaConsumer` to support synthetic OCSF trigger events lacking this field. | Verified (39/39 supervisor tests passed) |
| 2026-08-31 | Bugfix | Fixed async invocation error in `SupervisorKafkaConsumer` by replacing `invoke()` with `asyncio.run(ainvoke())` for the LangGraph execution. | Verified (39/39 supervisor tests passed) |
| 2026-08-31 | Enhancement | Reinstated `--start-time` and `--end-time` CLI argument parsing in `src/ingestion/run_pipeline.py` and threaded them through `scripts/start_full_pipeline.py`. | Verified |
| 2026-09-19 | `TASK-4.8` Log Analysis Test Suite | Fixed fixture hash verification for Windows LF/CRLF portability in `evaluate_log_analysis_ground_truth.py` and added `test_ground_truth_benchmark.py` pytest wrapper. | 73/73 Passed (`pytest tests/agents/log_analysis/`) |
| 2026-09-20 | `tests/agents/rag/test_dfkg_retriever.py` | DFKGRetriever tests pass | Verified |
| 2026-09-20 | H.4.1 (Debate Integration Hardening) | Hardened Debate agent prompts to enforce FINAL_ANSWER for ReAct convergence and explicitly instruct Judge to verify DFKG UIDs. | Verified (`python scripts/test_debate_agents_integration.py`) |
| 2026-09-20 | `tests/agents/test_threat_attribution_rag.py` | Phase G: Threat Attribution RAG | Verified |
| 2026-09-20 | `tests/agents/test_network_forensics.py` | Phase H: Network Forensics Functional Agent (ReAct) | Verified |
| 2026-09-20 | `tests/agents/log_analysis/` | Phase H.2: Log Analysis Functional Agent (ReAct) | Verified |
| 2026-09-20 | `tests/agents/timeline/` | Phase H.3: Timeline Reconstruction Functional Agent (ReAct) | Verified |
| 2026-09-20 | `tests/agents/test_debate_agents.py` | Phase H.4: Debate Layer Functional Agents (ReAct) | Verified |
| 2026-09-20 | `src/agents/threat_attribution_agent.py` | Phase H.7.1: Threat Attribution Context Migration | Verified |

---

| State | Phase/Task | Acceptance Criteria |
| :--- | :--- | :--- |
| `passing` | **Phase E: Integrate RAG into ONE agent** | - One existing agent uses RAG to retrieve evidence<br>- Agent distinguishes observation vs inference<br>- Agent survives prompt injection test<br>- Graph UIDs cited correctly<br>- `test_rag_agent_integration.py` runs cleanly |
| `passing` | **Phase G: Threat Attribution RAG** | - Adapter connects FAISS Threat Intel MCP to ReAct loop<br>- Agent merges DFKG facts with ATT&CK context<br>- UIDs and CVE/Group IDs preserved<br>- ReAct architecture implemented for Threat Attribution |
| `passing` | **Phase H.2: Log Analysis Functional Agent (ReAct)** | - Log Analysis ReAct agent implemented and tested<br>- Integrates with RAG and DFKG retrieval |
| `passing` | **Phase H.3: Timeline Reconstruction Functional Agent (ReAct)** | - Timeline Reconstruction ReAct agent implemented and tested<br>- Integrates with RAG and DFKG retrieval |
| `passing` | **Phase H.4: Debate Layer Functionalization** | - Proponent, Critic, Judge implemented as functional agents<br>- Agents independently query DFKG<br>- UID provenance correctly preserved<br>- Prompt injection protected<br>- Command routing from Judge preserved |
| `passing` | **Phase H.4.1: Debate Integration Hardening** | - Fix convergence, enforce DFKG verification by Judge |
| `passing` | **Phase H.5: Blackboard / Multi-Agent Orchestration** | - Shadow-migration to AgentFinding DFKG nodes via Kafka |
| `passing` | **Phase H.6: Multi-Agent Orchestration** | - Transition LangGraph Supervisor to DFKG-only context |
| `passing` | **Phase H.7.1: Threat Attribution Context Migration** | - Replaced `state["timeline"]` with targeted DFKG Cypher query<br>- Preserved UID tracking |
| `not_started` | **Phase I: Integration & UI prep** | - Expose multi-agent trace streams to frontend |
| `not_started` | **Phase F: Multi-Agent RAG Orchestration** | - Publish RAG-enriched findings to Kafka<br>- Downstream agents consume findings without duplicate retrieval |

---

## Known Blockers, Bugs & Carry-Forward Tracking Items
1. **Kafka Integration CI Retention:** Set short retention policy or per-run topic suffixes on `findings.*` Kafka topics before running integration test suite in automated CI.
2. **Stage 7 Guardrail Fine-Tuning:** The `rm -rf` Tier 1 regex will false-positive on findings quoting attacker commands. Fine-tune Tier 2 embedding model with real MiniLM training data beyond phrase matching in Stage 7.
