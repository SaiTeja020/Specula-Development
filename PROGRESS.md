# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Obey strict WIP=2 constraint (`|active| <= 2`). Update this file **immediately** whenever task status transitions, code is created/modified, or verification commands run.

---

## Current Build Status
- **Active Phase:** Phase 5: Visualization Layer & Agent Integration
- **Active Tasks (WIP=2):**
  1. `TASK-5.1` (Create `src/agents/visualizer_api.py` standalone FastAPI on port 8300)
  2. `TASK-5.2` (Implement WebSocket streaming of LangGraph data flow)
- **Active WIP Count:** 2 (`|active| = 2 / 2`)
- **Last Updated:** 2026-08-22

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
# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Obey strict WIP=2 constraint (`|active| <= 2`). Update this file **immediately** whenever task status transitions, code is created/modified, or verification commands run.

---

## Current Build Status
- **Active Phase:** Phase 5: Visualization Layer & Agent Integration
- **Active Tasks (WIP=2):**
  1. `TASK-5.3` (Build Vite + React frontend dashboard with React Flow graph visualizer)
  2. `TASK-5.4` (End-to-end integration of frontend visualizer with backend WebSocket streaming)
- **Active WIP Count:** 2 (`|active| = 2 / 2`)
- **Last Updated:** 2026-08-26

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
| 2026-07-25 | `AGENTS.md`, `PROGRESS.md` | Initialized development harness and tracking rules | Verified |
| 2026-07-28 | `.agents/skills/mcp-builder`, `.agents/skills.json` | Downloaded and added `mcp-builder` skill from GitHub | Verified |
| 2026-07-28 | `specula_ingestion_final_plan.md` | Adopted authoritative v6 implementation plan | Approved for Execution |
| 2026-07-28 | `src/schemas/*`, `src/ingestion/preservation/*` | Implemented Component 1 (Schemas) & Component 2 (Forensic Preservation) | Verified |
| 2026-08-26 | `src/ingestion/normalization/network_normalizer.py`, `src/ingestion/run_pipeline.py` | Implemented binary PCAP dissection using dpkt, passing packet payloads through Security Gate prompt injection check and routing to OCSF NetworkActivity schema. (ADR-008) | Verified (83/83 OCSF events parsed) |
| 2026-08-26 | `src/ingestion/run_pipeline.py`, `src/graph/cypher_builder.py` | Fixed time boundary filtering (using FilterHashtable) and parsed CLI arguments for start/end time. Addressed Neo4j graph pollution by only executing Process MERGE for true Process Creation events (Sysmon EID 1, Security EID 4688). | Verified (2/4219 Process nodes generated) |
| 2026-08-26 | `TASK-5.1`, `TASK-5.2` | Implemented FastAPI visualizer and WebSocket streaming. | Verified |

---

## Known Blockers, Bugs & Carry-Forward Tracking Items
1. **Stage 3 Checkpointer Refactor:** `src/agents/checkpointer.py` is a Stage 1 test-support stopgap using `pickle`. Replace with `langgraph-checkpoint-redis` / `langgraph-checkpoint-postgres` or add safe serialization (JSON/msgpack) before production use. Note: current `pending_writes` implementation assumes sequential interrupt nodes (safe for Stage 1 topology, must handle mid-fanout writes in Stage 3).
2. **Kafka Integration CI Retention:** Set short retention policy or per-run topic suffixes on `findings.*` Kafka topics before running integration test suite in automated CI.
3. **Stage 7 Guardrail Fine-Tuning:** The `rm -rf` Tier 1 regex will false-positive on findings quoting attacker commands. Fine-tune Tier 2 embedding model with real MiniLM training data beyond phrase matching in Stage 7.
|   2 0 2 6 - 0 8 - 2 6   |   \ s r c / i n g e s t i o n / r u n _ p i p e l i n e . p y \ ,   \ s r c / i n g e s t i o n / i n g e s t i o n _ c o n s u m e r . p y \   |   D e c o u p l e d   s y n c h r o n o u s   i n g e s t i o n   p i p e l i n e   i n t o   d i s t i n c t   K a f k a   P r o d u c e r   a n d   C o n s u m e r .   E x t r a c t e d   i n l i n e   n o r m a l i z a t i o n   t o   d e d i c a t e d   m o d u l e s ,   f i x e d   h a r d c o d e d   h o s t   l o g i c ,   a n d   i m p l e m e n t e d   s t r u c t u r e d   s e m a n t i c   t e x t   e m b e d d i n g s   f o r   C h r o m a D B   v e c t o r   i s o l a t i o n .   |   V e r i f i e d   |  
 |   2 0 2 6 - 0 8 - 2 6   |   \ s r c / i n g e s t i o n / r u n _ p i p e l i n e . p y \ ,   \ s r c / i n g e s t i o n / i n g e s t i o n _ c o n s u m e r . p y \ ,   \ s r c / i n g e s t i o n / b r o k e r / k a f k a _ c o n s u m e r . p y \   |   F i x e d   e x e c u t i o n   o r d e r i n g   i n v a r i a n t :   i m p l e m e n t e d   E v e n t C o n s u m e r . c o n s u m e _ l o o p ( ) ,   m o v e d   s p e c u l a . c a s e s . o p e n e d   t r i g g e r i n g   i n t o   i n g e s t i o n _ c o n s u m e r . p y   a f t e r   D i s t i l l a t i o n   - >   C y p h e r   - >   C h r o m a D B   c o m p l e t e s ,   e n s u r i n g   S u p e r v i s o r   w a k e s   u p   t o   a   f u l l y   p o p u l a t e d   g r a p h .   |   V e r i f i e d   |  
 