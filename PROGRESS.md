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

# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Obey strict WIP=2 constraint (`|active| <= 2`). Update this file **immediately** whenever task status transitions, code is created/modified, or verification commands run.

---

## Current Build Status
- **Active Phase:** Phase 5: Visualization Layer & Agent Integration
- **Active Tasks (WIP=2):**
  1. `TASK-5.3` (Build Vite + React frontend dashboard with React Flow)
  2. `TASK-5.4` (End-to-end integration of frontend visualizer)
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
  - **Status:** `active`
  - **Verification Command:** `npm test --prefix visualization`
  - **Acceptance Criteria:** React component renders 23 graph nodes with active status highlighting.

- **Task ID:** `TASK-5.4`
  - **Description:** End-to-end integration of frontend visualizer with backend WebSocket streaming.
  - **Status:** `active`
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
| 2026-08-09 | `TASK-4.1`–`TASK-4.5` | Built 23-node LangGraph skeleton with guardrails, debate loop, and HITL API | 28/28 Passed |
| 2026-08-18 | `TASK-3.5` | Built FAISS IndexIVFPQ threat-intel corpus, fetchers, and MCP server | 29/29 Passed |
| 2026-08-18 | Stage 2 Ingestion Gaps | Wired injection detector into security gate; added 7-step e2e test | 15/15 + 2/2 Passed |
| 2026-08-20 | `TASK-4.6` | Verified pulled Evidence Collection Agent & Relevance Filter tests | 12/12 Passed (`tests/agents/`) |
| 2026-08-25 | Phase 2 & 3 Schemas | Applied strict validation, registered schemas, wired normalizers | Passed (`pytest tests/ingestion/`) |
| 2026-08-20 | Harness Upgrade | Updated `AGENTS.md`, `.agents/rules/rules.md`, and restructured `PROGRESS.md` to WIP=2 state machine | Verified |
| 2026-08-21 | `TASK-4.7` | Created `supervisor_agent.py`, `supervisor_graph.py`, and `kafka_consumer.py` per build spec | 2/2 Passed (`tests/orchestration/test_supervisor.py`) |
| 2026-08-21 | `TASK-4.7` | Rewrote tests to directly evaluate LangGraph state transitions and replaced inert mocks; fixed HITL routing logic | 32/32 Passed (`tests/supervisor_test_suite/`) |
  1. `TASK-5.3` (Build Vite + React frontend dashboard with React Flow)
  2. `TASK-5.4` (End-to-end integration of frontend visualizer)
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
  - **Status:** `active`
  - **Verification Command:** `npm test --prefix visualization`
  - **Acceptance Criteria:** React component renders 23 graph nodes with active status highlighting.

- **Task ID:** `TASK-5.4`
  - **Description:** End-to-end integration of frontend visualizer with backend WebSocket streaming.
  - **Status:** `active`
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
| 2026-08-09 | `TASK-4.1`–`TASK-4.5` | Built 23-node LangGraph skeleton with guardrails, debate loop, and HITL API | 28/28 Passed |
| 2026-08-18 | `TASK-3.5` | Built FAISS IndexIVFPQ threat-intel corpus, fetchers, and MCP server | 29/29 Passed |
| 2026-08-18 | Stage 2 Ingestion Gaps | Wired injection detector into security gate; added 7-step e2e test | 15/15 + 2/2 Passed |
| 2026-08-20 | `TASK-4.6` | Verified pulled Evidence Collection Agent & Relevance Filter tests | 12/12 Passed (`tests/agents/`) |
| 2026-08-25 | Phase 2 & 3 Schemas | Applied strict validation, registered schemas, wired normalizers | Passed (`pytest tests/ingestion/`) |
| 2026-08-20 | Harness Upgrade | Updated `AGENTS.md`, `.agents/rules/rules.md`, and restructured `PROGRESS.md` to WIP=2 state machine | Verified |
| 2026-08-21 | `TASK-4.7` | Created `supervisor_agent.py`, `supervisor_graph.py`, and `kafka_consumer.py` per build spec | 2/2 Passed (`tests/orchestration/test_supervisor.py`) |
| 2026-08-21 | `TASK-4.7` | Rewrote tests to directly evaluate LangGraph state transitions and replaced inert mocks; fixed HITL routing logic | 32/32 Passed (`tests/supervisor_test_suite/`) |
| 2026-08-21 | Ingestion Fix | Fixed MFT USN casting crash & heuristic timestamp bug; refactored container extraction to pull from live Docker endpoints | 212/212 Nodes Written |
| 2026-08-25 | `TASK-4.7` Extended | Integrated Natural Language Query Routing, Capability Fallback Governance, and Async Loop Budgets into Supervisor | 39/39 Passed (`tests/supervisor_test_suite/`) |
| 2026-08-31 | Bugfix | Fixed JSON decoding error in `src/orchestration/kafka_consumer.py` by using `deserialize_event` to handle Confluent wire format headers. | Verified (39/39 supervisor tests passed) |
| 2026-08-31 | Bugfix | Removed strict `dfkg_uri` requirement in `SupervisorKafkaConsumer` to support synthetic OCSF trigger events lacking this field. | Verified (39/39 supervisor tests passed) |
| 2026-08-31 | Bugfix | Fixed async invocation error in `SupervisorKafkaConsumer` by replacing `invoke()` with `asyncio.run(ainvoke())` for the LangGraph execution. | Verified (39/39 supervisor tests passed) |
| 2026-08-31 | Enhancement | Reinstated `--start-time` and `--end-time` CLI argument parsing in `src/ingestion/run_pipeline.py` and threaded them through `scripts/start_full_pipeline.py`. | Verified |
| 2026-08-31 | Bugfix | Refactored `ChromaVectorStore` to connect to the active ChromaDB Docker container via `HttpClient` (localhost:8000) instead of falling back to ephemeral in-memory instances. | Verified | 39/39 Passed (`tests/supervisor_test_suite/`) |
| 2026-08-31 | Enhancement | Replaced `run_pipeline.py` polling ingestion with real-time `winlogbeat_consumer.py` (ECS-to-Legacy schema adapter) and decoupled `ingestion_consumer.py` (Distillation + Neo4j + ChromaDB 1:1 parity). | Pending Verification | 39/39 Passed (`tests/supervisor_test_suite/`) |
| 2026-08-25 | Ingestion Bug Fixes | Fixed schema misclassification in `run_pipeline.py`, robust hex PID parsing and UNKNOWN_PARENT elimination in `evtx_normalizer.py`, enforced deterministic host mapping in `entity_resolver.py`, and refactored `cypher_builder.py` with static parameterized routing | 182/182 Passed & E2E Success |
| 2026-08-25 | `TASK-3.6` | Added OCSF schemas for Auth & NetworkActivity; added specialized EVTX normalizers for Kerberos, Sysmon Network/File, and cleared logs; added explicit parameterized Cypher builders | 182/182 Passed & E2E Success |
| 2026-08-25 | Ingestion Expansions | Added PowerShell (4104), Defender, and AppLocker parsing; created `DetectionFindingEvent` and `AuditActivity`; fixed `CloudAudit` validation crash | 241/241 Nodes Written |
| 2026-08-25 | `TASK-5.1` & `TASK-5.2` | Created `tests/test_visualizer_api.py` and `tests/test_visualizer_ws.py`. Added `/health` endpoint to `visualizer_api.py` | 5/5 Passed (`pytest tests/test_visualizer*`) |
