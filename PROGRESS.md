# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Obey strict WIP=2 constraint (`|active| <= 2`). Update this file **immediately** whenever task status transitions, code is created/modified, or verification commands run.

---

## Current Build Status
- **Active Phase:** Phase 4: LangGraph Orchestration & Multi-Agent Core
- **Active Tasks (WIP=2):**
  None currently active.
- **Active WIP Count:** 0 (`|active| = 0 / 2`)
- **Last Updated:** 2026-10-03

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
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/agents/test_evidence_collection.py`
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

- **Task ID:** `TASK-4.8`
  - **Description:** Align skeleton to architecture v4: split `identity_cloud` → `identity` (F13a) + `cloud_container` (F13b); add `dag` Dynamic Attack Graph Agent to Sequential Synthesis (F23). Update `_SPECIALIST_MAP`, graph wiring, Kafka topics, stubs, supervisor_agent dispatch list, and test assertions.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py -v`
  - **Acceptance Criteria:** 28/28 passing; zero `identity_cloud` references in source; `dag` present in `agent_traces` membership and ordering assertions.

- **Task ID:** `TASK-4.9`
  - **Description:** Implement memory dump retrieval and ingestion pipeline. Created `src/ingestion/extractors/memory_extractor.py` (WinPmem → Volatility3 `pslist`/`netscan`/`malfind` → JSON) with mock mode (`SPECULA_MEMORY_MOCK=true`). Wired into `run_pipeline.py` via `SPECULA_MEMORY_ENABLED` feature flag. Added `Memory_Dump_Live` to `_SOURCE_TYPE_MAP`. Feeds into existing `memory_dump_normalizer`.
  - **Status:** `passing`
  - **Verification Command:** `.\\venv\\Scripts\\pytest.exe tests/ingestion/test_memory_ingestion.py -v`
  - **Acceptance Criteria:** 28/28 tests passing; mock extractor output shape verified; all three normalizer branches (pslist/netscan/malfind) produce correct OCSF class_uids; clock_skew_unverified=True for all memory events; full pipeline integration confirmed; UID determinism verified.

- **Task ID:** `TASK-4.10a`
  - **Description:** Implement Cloud & Container Forensics Agent Core & Parameterized Detection Rules (F13b) with versioned RuleContext, deterministic finding rollups, and evidence evaluation statuses (`ok`/`no_events`/`error`).
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/test_cloud_container_agent.py -v`
  - **Acceptance Criteria:** 19/19 passing; 13 detection rules (7 cloud, 6 container) tested with golden fixtures; RuleContext evaluation verified; evidence check returns explicit status (`ok`/`no_events`/`error`) without false HITL escalation; deterministic finding UIDs, prompt injection summary escaping, and Kafka partition keys verified.

- **Task ID:** `TASK-4.10b`
  - **Description:** Wire Cloud & Container Forensics Agent into LangGraph Orchestration via `cloud_container_factory.py`, removing stub implementation and verifying graph dead-end routing.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/test_cloud_container_agent.py tests/test_cloud_container_factory.py tests/test_skeleton_graph.py -v`
  - **Acceptance Criteria:** 50/50 tests passing; `cloud_container_factory.py` instantiated; stub `cloud_container_node` wrapped; graph routing verified; 28/28 skeleton graph tests passing.

---

### Phase 5: Real-Time Visualization Layer (`ADR-003`, `ADR-007`)

- **Task ID:** `TASK-5.1`
  - **Description:** Create `src/agents/visualizer_api.py` standalone FastAPI service on port 8300 with CORS and health endpoints.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_visualizer_api.py`
  - **Acceptance Criteria:** FastAPI app instantiates with health check returning 200 and CORS enabled for frontend origin.

- **Task ID:** `TASK-5.2`
  - **Description:** Implement WebSocket streaming endpoint in `visualizer_api.py` broadcasting LangGraph node execution events and state deltas.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_visualizer_ws.py`
  - **Acceptance Criteria:** WebSocket connection receives real-time JSON event packets during graph invocation.

- **Task ID:** `TASK-5.3`
  - **Description:** Build Vite + React frontend dashboard with React Flow graph visualizer for 23 orchestration nodes.
  - **Status:** `passing`
  - **Verification Command:** `npm run lint --prefix visualization`
  - **Acceptance Criteria:** React component renders 23 graph nodes with active status highlighting.

- **Task ID:** `TASK-5.4`
  - **Description:** End-to-end integration of frontend visualizer with backend WebSocket streaming.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/test_visualizer_api.py`
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
  .\venv\Scripts\pip.exe install python-dateutil
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
| 2026-09-01 | Agent tooling | Installed `ui-ux-pro-max` at `.agents/skills/ui-ux-pro-max` and exposed only it to Git | Skill: `validate_data.py` passed; 130/132 bundled tests passed (2 require omitted upstream repo-root helpers). Repo fallback: 241 passed, 2 failed, 17 errors (pre-existing Neo4j/threat-intel fixtures and supervisor sync/async mismatch) |
| 2026-09-01 | `TASK-5.3`, `TASK-5.4` | Built 2-page React + Vite frontend with dark mode enterprise UI, ReactFlow, and hooked to FastAPI mock trigger | Passed (frontend lint zero warnings, backend tests passed) |
| 2026-09-15 | Phase 5 UI/UX | Formally established the Specula Brand Identity System (16 sections). Removed generic ReactFlow diagram from InvestigationConsole and implemented 6-step sequential telemetry view using new strict CSS tokens (`specula-tokens.css`) | Passed (Frontend UI rules adhered) |
| 2026-09-19 | `TASK-4.8` | Created decoupled Network Forensics agent module with C2, DNS Tunneling, and Data Exfiltration anomaly detection heuristics | 6/6 Passed (`tests/agents/test_network_forensics.py`) |
| 2026-09-21 | `TASK-5.4` | Refactored pipeline trigger: separated Docker boot to `/api/system/boot` and lifted React state to `PipelineContext` to keep WebSocket alive across pages | Verified via UI linting and component updates |
| 2026-09-21 | `TASK-5.4` | Fixed `StartupPage` UI sync issue to await actual `docker compose down -v` and `up --force-recreate` completion before displaying services as verified | Verified via local UI logic |
| 2026-09-21 | `TASK-5.4` | Lazy-loaded neo4j/langgraph/graph imports in `visualizer_api.py` to prevent numpy 1.26 fatal crash on Py3.13+Windows. Added boot lock, retry button, and `restart: on-failure` for Redpanda | `GET /health` → ok, `POST /api/system/boot` → success, 7/7 containers Up |
| 2026-09-21 | `TASK-5.5` | Upgraded Neo4j Docker image to `5.26.0` to resolve Bolt Protocol v5.5 mismatch with python driver 6.2.0, and updated `numpy` dependency to `2.5.3` to fix silent crash | Verified (558 nodes ingested) |
| 2026-09-17 | Phase 5 UI/UX | Refined button tokens to darker royal indigo (`#1E40AF`) with 8px radius & white text. Positioned terminal directly below the Service Health Checks box with compact 2-column grid ensuring all 6 services are completely visible without window scroll push | Passed (`npm run lint` 0 warnings, `pytest` 8/8 passed) |
| 2026-09-19 | `TASK-4.8` | Split `identity_cloud` → `identity` (F13a) + `cloud_container` (F13b); added `dag` Dynamic Attack Graph Agent to Sequential Synthesis (F23). Updated 7 files: `config.py`, `nodes.py`, `graph.py`, `kafka_utils.py`, `state.py`, `supervisor_agent.py`, `test_skeleton_graph.py`. Node count: 23 → 25. | 28/28 Passed (`tests/test_skeleton_graph.py`) |
| 2026-09-29 | `TASK-4.9` | Created `src/ingestion/extractors/memory_extractor.py` (WinPmem → Volatility3 pslist/netscan/malfind → JSON, mock mode via `SPECULA_MEMORY_MOCK=true`). Wired into `run_pipeline.py` with `SPECULA_MEMORY_ENABLED` flag. Added 28-test verification oracle. | 28/28 Passed (`tests/ingestion/test_memory_ingestion.py`) |


