# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Obey strict WIP=2 constraint (`|active| <= 2`). Update this file **immediately** whenever task status transitions, code is created/modified, or verification commands run.

---

## Current Build Status
- **Active Phase:** Phase 6 — Per-Agent LLM Runtime & Session Isolation
- **Active Tasks (WIP=2):**
  - None
- **Active WIP Count:** 0 (`|active| = 0 / 2`)
- **Last Updated:** 2026-10-13

### Phase LLM-Runtime — Per-Agent LLM Runtime & Concurrency Control — PASSING ✅ (2026-10-13)
- **Verification:** `pytest tests/test_per_agent_llm_runtime.py -v` → **14/14 passed**
- **Architecture:** Isolated logical `AgentSession` per `(case_id, agent_role)` with private conversation memory (`SPECULA_LLM_MAX_HISTORY`). Semaphore-based concurrency limiter (`SPECULA_LLM_MAX_CONCURRENT=3`) preventing thread starvation and leaks. Weight-sharing via reusable client caching. Deterministic model override resolution (`SPECULA_LLM_MODEL_<AGENT>`) without silent fallback. Plain-text structured observability logs. Real model discovery and inference verification API for LM Studio.
- **Files created:** `src/agents/llm_runtime.py`, `tests/test_per_agent_llm_runtime.py`
- **Files modified:** `src/agents/config.py` (wired `get_llm`), `tests/test_llm_backends.py`, `tests/test_hitl_resume.py`

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

### Phase H.7.4 — Investigation Explainability Trace — PASSING ✅ (2026-09-20)
- **Verification:** `pytest tests/integration/test_investigation_trace.py -v` → **Passed**
- **Files created:** `src/agents/investigation_trace.py`, `tests/integration/test_investigation_trace.py`
- **Description:** Trace dir structure enriched with RAG/DFKG explicit blocks, UID provenance, and no internal COT leak.

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

- **Task ID:** `TASK-4.9b`
  - **Description:** Implement a deterministic, case- and host-scoped Memory Forensics Agent with source-image-scoped deduplication and Kafka finding publication.
  - **Status:** `passing`
  - **Verification Command:** `python -m pytest tests/agents/test_memory_forensics.py tests/test_skeleton_graph.py`
  - **Acceptance Criteria:** Deterministic hidden-process, injection, LSASS-handle, and memory-resident YARA findings are evidence-cited, deduplicated per source image, published to the specialist Kafka topic, and graph-routable only via the existing memory dead-end path.

- **Task ID:** `TASK-4.9a`
  - **Description:** Preserve memory-image acquisition time separately while retaining the canonical OCSF `time` and `raw_source_timestamp` fields for artifact ordering.
  - **Status:** `passing`
  - **Verification Command:** `python -m pytest tests/ingestion/test_phase2_phase3_normalizers.py -k memory_dump`
  - **Acceptance Criteria:** Native artifact timestamps drive canonical OCSF ordering fields; capture provenance remains available on every normalized memory artifact; fallback-to-capture is explicit.

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

- **Task ID:** `TASK-4.8`
  - **Description:** Wire Log Analysis, Network Forensics, and Supervisor agents into LangGraph orchestration.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py tests/agents/test_network_forensics.py`
  - **Acceptance Criteria:** Legacy stubs removed, DFKG-sourced adapter factories injected via build_graph, and all 28 graph compilation tests passing.

- **Task ID:** `TASK-4.7`
  - **Description:** Implement Supervisor Agent (Orchestrator) graph and Kafka Consumer.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/orchestration/test_supervisor.py`
  - **Acceptance Criteria:** Supervisor graph built and routes according to specifications.

- **Task ID:** `TASK-4.8`
  - **Description:** Implement deterministic Network Forensics Agent component.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/agents/test_network_forensics.py`
  - **Acceptance Criteria:** Agent evaluates OCSF 4001 events and flags C2, DNS Tunneling, and Exfiltration deterministically.

- **Task ID:** `TASK-4.9`
  - **Description:** Align skeleton to architecture v4: split `identity_cloud` → `identity` (F13a) + `cloud_container` (F13b); add `dag` Dynamic Attack Graph Agent to Sequential Synthesis (F23). Update `_SPECIALIST_MAP`, graph wiring, Kafka topics, stubs, supervisor_agent dispatch list, and test assertions.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py -v`
  - **Acceptance Criteria:** 28/28 passing; zero `identity_cloud` references in source; `dag` present in `agent_traces` membership and ordering assertions.
- **Task ID:** `TASK-4.10`
  - **Description:** Implement memory dump retrieval and ingestion pipeline. Created `src/ingestion/extractors/memory_extractor.py` (WinPmem → Volatility3 `pslist`/`netscan`/`malfind` → JSON) with mock mode (`SPECULA_MEMORY_MOCK=true`). Wired into `run_pipeline.py` via `SPECULA_MEMORY_ENABLED` feature flag. Added `Memory_Dump_Live` to `_SOURCE_TYPE_MAP`. Feeds into existing `memory_dump_normalizer`.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/ingestion/test_memory_ingestion.py -v`
  - **Acceptance Criteria:** 28/28 tests passing; mock extractor output shape verified; all three normalizer branches (pslist/netscan/malfind) produce correct OCSF class_uids; clock_skew_unverified=True for all memory events; full pipeline integration confirmed; UID determinism verified.

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
  - **Status:** `passing`
  - **Verification Command:** `npm run lint --prefix visualization`
  - **Acceptance Criteria:** React component renders 23 graph nodes with active status highlighting.

- **Task ID:** `TASK-5.4`
  - **Description:** End-to-end integration of frontend visualizer with backend WebSocket streaming.
  - **Status:** `not_started`
  - **Verification Command:** `. env\Scripts\pytest.exe tests/test_visualization_e2e.py`
  - **Acceptance Criteria:** Live graph run updates node colors and emits findings timeline in frontend.

- **Task ID:** `TASK-5.5`
  - **Description:** Expand `visualizer_api.py` to proxy real backend datastores (Neo4j, Quickwit, ChromaDB, DuckDB).
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/test_visualizer_api_db.py`
  - **Acceptance Criteria:** New API routes return 200 OK and properly format data from underlying datastores.

- **Task ID:** `TASK-5.6`
  - **Description:** Rework frontend architecture to multi-page dashboard with DB visualizer interfaces.
  - **Status:** `passing`
  - **Verification Command:** `npm run lint --prefix visualization`
  - **Acceptance Criteria:** Frontend renders Landing, Startup, Investigation, and Database visualization pages with Specula design system.

---

## Pending Dependency & Terminal Requests (Awaiting Human Action)

- **Required for dateutil normalizer tests:**
  ```powershell
  . env\Scripts\pip.exe install python-dateutil
  ```

- **Required for live memory forensics (`SPECULA_MEMORY_ENABLED=true`, non-mock):**

  **1. Install Volatility3 (already in requirements.txt — run if not yet done):**
  ```powershell
  .\venv\Scripts\pip.exe install volatility3
  ```

  **2. Download WinPmem (memory acquisition tool):**
  - URL: `https://github.com/Velocidex/WinPmem/releases/latest`
  - Download `winpmem_mini_x64.exe` and place at `tools\winpmem_mini_x64.exe`
  - Requires Administrator privileges at runtime.

  **3. Download Volatility3 Windows symbol pack (~300 MB):**
  - URL: `https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip`
  - Extract the `windows\` folder inside the ZIP into:
    ```
    venv\lib\site-packages\volatility3\framework\symbols\windows\
    ```
  - If your exact build is missing from the pack, Volatility3 will auto-download
    symbols from Microsoft's public symbol server on first run (internet required).

  **4. Add to `.env`:**
  ```
  SPECULA_MEMORY_ENABLED=true
  SPECULA_WINPMEM_PATH=tools/winpmem_mini_x64.exe
  SPECULA_VOL3_PATH=venv/Scripts/vol.py
  ```

  **Dev/CI (no tools required):** Set `SPECULA_MEMORY_MOCK=true` instead.

---

## Recent Execution Log
| Date | Component / Task | Changes Made | Verification Result |
| :--- | :--- | :--- | :--- |
| 2026-09-23 | `TASK-4.9b` | Re-ran deterministic Memory Forensics and LangGraph integration verification. | 34/34 passed (`python -m pytest tests/agents/test_memory_forensics.py tests/test_skeleton_graph.py`); pytest cache write warning only. |
| 2026-09-22 | `TASK-4.9b` | Built deterministic Memory Forensics rules, case/host isolation, source-image-scoped deduplication, Kafka publisher, and LangGraph factory wiring. | 34/34 passed (`python -m pytest tests/agents/test_memory_forensics.py tests/test_skeleton_graph.py`) |
| 2026-09-22 | `TASK-4.9a` | Added canonical memory-artifact versus image-capture timestamp provenance and finalized process-identity and fixture-floor requirements. | 3/3 passed (`python -m pytest tests/ingestion/test_phase2_phase3_normalizers.py -k memory_dump`) |
| 2026-08-09 | `TASK-4.1`–`TASK-4.5` | Built 23-node LangGraph skeleton with guardrails, debate loop, and HITL API | 28/28 Passed |
| 2026-08-18 | `TASK-3.5` | Built FAISS IndexIVFPQ threat-intel corpus, fetchers, and MCP server | 29/29 Passed |
| 2026-08-18 | Stage 2 Ingestion Gaps | Wired injection detector into security gate; added 7-step e2e test | 15/15 + 2/2 Passed |
| 2026-08-20 | `TASK-4.6` | Verified pulled Evidence Collection Agent & Relevance Filter tests | 12/12 Passed (`tests/agents/`) |
| 2026-08-25 | Phase 2 & 3 Schemas | Applied strict validation, registered schemas, wired normalizers | Passed (`pytest tests/ingestion/`) |
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
| 2026-09-01 | Agent tooling | Installed `ui-ux-pro-max` at `.agents/skills/ui-ux-pro-max` and exposed only it to Git | Skill: `validate_data.py` passed; 130/132 bundled tests passed (2 require omitted upstream repo-root helpers). Repo fallback: 241 passed, 2 failed, 17 errors (pre-existing Neo4j/threat-intel fixtures and supervisor sync/async mismatch) |
| 2026-09-01 | `TASK-5.3`, `TASK-5.4` | Built 2-page React + Vite frontend with dark mode enterprise UI, ReactFlow, and hooked to FastAPI mock trigger | Passed (frontend lint zero warnings, backend tests passed) |
| 2026-09-15 | Phase 5 UI/UX | Formally established the Specula Brand Identity System (16 sections). Removed generic ReactFlow diagram from InvestigationConsole and implemented 6-step sequential telemetry view using new strict CSS tokens (`specula-tokens.css`) | Passed (Frontend UI rules adhered) |
| 2026-09-17 | Phase 5 UI/UX | Refined button tokens to darker royal indigo (`#1E40AF`) with 8px radius & white text. Positioned terminal directly below the Service Health Checks box with compact 2-column grid ensuring all 6 services are completely visible without window scroll push | Passed (`npm run lint` 0 warnings, `pytest` 8/8 passed) |
| 2026-09-19 | `TASK-4.8` | Created decoupled Network Forensics agent module with C2, DNS Tunneling, and Data Exfiltration anomaly detection heuristics | 6/6 Passed (`tests/agents/test_network_forensics.py`) |
| 2026-09-19 | `TASK-4.8` | Split `identity_cloud` → `identity` (F13a) + `cloud_container` (F13b); added `dag` Dynamic Attack Graph Agent to Sequential Synthesis (F23). Updated 7 files: `config.py`, `nodes.py`, `graph.py`, `kafka_utils.py`, `state.py`, `supervisor_agent.py`, `test_skeleton_graph.py`. Node count: 23 → 25. | 28/28 Passed (`tests/test_skeleton_graph.py`) |
| 2026-09-19 | `TASK-4.8` Log Analysis Test Suite | Fixed fixture hash verification for Windows LF/CRLF portability in `evaluate_log_analysis_ground_truth.py` and added `test_ground_truth_benchmark.py` pytest wrapper. | 73/73 Passed (`pytest tests/agents/log_analysis/`) |
| 2026-09-20 | `tests/agents/rag/test_dfkg_retriever.py` | DFKGRetriever tests pass | Verified |
| 2026-09-20 | H.4.1 (Debate Integration Hardening) | Hardened Debate agent prompts to enforce FINAL_ANSWER for ReAct convergence and explicitly instruct Judge to verify DFKG UIDs. | Verified (`python scripts/test_debate_agents_integration.py`) |
| 2026-09-20 | `tests/integration/test_investigation_trace.py` | Trace formatting verified | Verified |
| 2026-09-20 | `tests/integration/test_blackboard_integration.py` | Kafka -> Neo4j entity path verified | Verified |
| 2026-09-20 | `tests/integration/test_rag_trace.py` | Offline RAG tracing verified | Verified |
| 2026-09-20 | `tests/agents/test_threat_attribution_rag.py` | Phase G: Threat Attribution RAG | Verified |
| 2026-09-20 | `tests/agents/test_network_forensics.py` | Phase H: Network Forensics Functional Agent (ReAct) | Verified |
| 2026-09-20 | `tests/agents/log_analysis/` | Phase H.2: Log Analysis Functional Agent (ReAct) | Verified |
| 2026-09-20 | `tests/agents/timeline/` | Phase H.3: Timeline Reconstruction Functional Agent (ReAct) | Verified |
| 2026-09-20 | `tests/agents/test_debate_agents.py` | Phase H.4: Debate Layer Functional Agents (ReAct) | Verified |
| 2026-09-20 | `src/agents/threat_attribution_agent.py` | Phase H.7.1: Threat Attribution Context Migration | Verified |
| 2026-09-21 | `src/agents/investigation_trace.py` | Phase H.7.4 Extension: Fixed trace file appending duplication bug. Rewrote TraceRecorder's `_compile_full_report` to generate strict RAG data flow markdown blocks with provenance validation (exposing unsupported stub UIDs). | Verified (`python scripts/run_investigation.py --trace`) |
| 2026-09-21 | `docker-compose.yml`, `src/graph/apoc_triggers.cypher` | Fixed Neo4j startup crash during APOC trigger initialization by upgrading to Neo4j 5 (latest) and explicitly routing trigger installation to the `system` database. | Verified (`python scripts/neo4j_setup.py`) |
| 2026-09-21 | `src/agents/visualizer_api.py`, `src/agents/investigation_runner.py` | Fixed architecture mismatch by wiring `/api/trigger_pipeline` to asynchronously invoke `run_investigation` post-ingestion. Bridged LangGraph `stream()` execution events (`node_active`, `node_complete`) to WebSocket telemetry required by React flow. | Verified (`frontend_integration_e2e_report.md`) |
| 2026-09-21 | `src/ingestion/run_pipeline.py` | Mapped real Windows System events (e.g. DCOM 10016 to AUTH, Power/Hyper-V to PROCESS) to ensure they reach Neo4j without modifying graph architecture. | Verified (Kafka, Neo4j, ChromaDB all received events) |
| 2026-09-21 | `scripts/run_investigation.py` | Attempted real investigation with case `REAL-PC-002` to verify end-to-end evidence retrieval and finding generation. | Failed (LM Studio backend unreachable; see `real_pc_investigation_test.md`) |
| 2026-09-21 | `TASK-5.4` | Refactored pipeline trigger: separated Docker boot to `/api/system/boot` and lifted React state to `PipelineContext` to keep WebSocket alive across pages | Verified via UI linting and component updates |
| 2026-09-21 | `TASK-5.4` | Fixed `StartupPage` UI sync issue to await actual `docker compose down -v` and `up --force-recreate` completion before displaying services as verified | Verified via local UI logic |
| 2026-09-21 | `TASK-5.4` | Lazy-loaded neo4j/langgraph/graph imports in `visualizer_api.py` to prevent numpy 1.26 fatal crash on Py3.13+Windows. Added boot lock, retry button, and `restart: on-failure` for Redpanda | `GET /health` → ok, `POST /api/system/boot` → success, 7/7 containers Up |
| 2026-09-21 | `TASK-5.5` | Upgraded Neo4j Docker image to `5.26.0` to resolve Bolt Protocol v5.5 mismatch with python driver 6.2.0, and updated `numpy` dependency to `2.5.3` to fix silent crash | Verified (558 nodes ingested) |
| 2026-09-24 | Boot Connectivity Fix | **Root Cause 1:** `from .graph import build_graph` was an eager top-level import in `visualizer_api.py`, causing uvicorn to hang during startup while LangGraph/SentenceTransformer initialized. Removed it (lazy import inside `_get_specula_graph()` was already present). **Root Cause 2:** `start_full_pipeline.py` never started the visualizer API on port 8300. Added uvicorn start for `visualizer_api:app` on port 8300 as step 0 with a 3s sleep before consumers. **Root Cause 3:** Duplicate `@app.post('/api/trigger_pipeline')` and `@app.get('/api/data/neo4j')` route definitions in `visualizer_api.py` (second copies referenced undefined `NEO4J_USER`/`NEO4J_URI` variables). Removed duplicate blocks. **Verification:** `python -m uvicorn src.agents.visualizer_api:app --port 8300` binds immediately (no hang); `GET http://localhost:8300/health` → `{"status":"ok"}`; `npm run lint --prefix visualization` → 0 errors; `pytest tests/test_visualizer_api.py` running. | `/health` 200 OK; lint 0 errors |
| 2026-09-24 | Boot Connectivity Fix (3 root causes) | **P1 Frontend blank:** `vite.config.js` was missing `envDir: '../'` — Vite read from `visualization/` directory and couldn't find root `.env` Supabase vars; `createClient('', undefined)` crashed React app. Fixed by adding `envDir: '../'`. **P2 Port 8300 conflict:** `start_full_pipeline.py` blindly started uvicorn on 8300 even if already listening → `WinError 10048`. Fixed by calling `is_port_listening()` before starting and skipping if already up. **P3 Kafka topics:** `create_topics()` existed in `kafka_utils.py` but was never called in the pipeline script; also `specula-winlogbeat-raw` was missing from `TOPICS`. Fixed by adding the topic to manifest and calling `create_topics()` after `wait_for_kafka()` poll. | `pytest test_health_check/test_cors_preflight`: 2/2 PASSED; `npm run lint`: 0 errors; `GET :8300/health`: 200; `is_port_listening()` verified; all 3 required topics in manifest |
| 2026-09-29 | `TASK-4.9` / `TASK-4.10` | Created `src/ingestion/extractors/memory_extractor.py` (WinPmem → Volatility3 pslist/netscan/malfind → JSON, mock mode via `SPECULA_MEMORY_MOCK=true`). Wired into `run_pipeline.py` with `SPECULA_MEMORY_ENABLED` flag. Added 28-test verification oracle. | 28/28 Passed (`tests/ingestion/test_memory_ingestion.py`) |
| 2026-10-03 | Threat Intel Integration | Implemented Threat Intel FAISS index build from master known_attacks Excel file. Successfully mapped extended metadata and populated local vector store. Verified Threat Attribution Agent access via MCP retrieval loop. | Verified (Exact/Semantic lookup tests passed) |
| 2026-10-03 | Frontend Trace Artifacts | Fixed frontend-triggered investigations to correctly initialize the `investigation_runs` trace artifacts exactly like the CLI. Hooked `investigation_trace` into `visualizer_api.py` and implemented error finalization handling. | Verified (Artifacts successfully created in test run) |
| 2026-10-13 | `Phase LLM-Runtime` | Implemented isolated logical sessions per agent/case, private conversational memory, concurrency limiter (`SPECULA_LLM_MAX_CONCURRENT=3`), reusable client cache, deterministic model overrides without silent fallback, plain-text observability logging, and LM Studio discovery API. | 14/14 Passed (`tests/test_per_agent_llm_runtime.py`), 4/4 Passed (`tests/test_llm_backends.py`), 1/1 Passed (`tests/test_hitl_resume.py`), 28/28 Passed (`tests/test_skeleton_graph.py`), 16/16 Passed (`tests/agents/test_debate_agents.py`) |
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
| `passing` | **Phase I: Integration & UI prep** | - Expose multi-agent trace streams to frontend via WS<br>- `/api/trigger_pipeline` successfully runs investigation |
| `not_started` | **Phase F: Multi-Agent RAG Orchestration** | - Publish RAG-enriched findings to Kafka<br>- Downstream agents consume findings without duplicate retrieval |
