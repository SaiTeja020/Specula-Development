# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Obey strict WIP=2 constraint (`|active| <= 2`). Update this file **immediately** whenever task status transitions, code is created/modified, or verification commands run.

---

## Current Build Status
- **Active Phase:** Phase 6: Operational Readiness
- **Active Tasks (WIP=2):**
  - `TASK-6.7` **blocked**: evidence analysis benchmark passed with qwen3:8b; broader integration and signed-in browser gates remain open
  - `TASK-6.8` **blocked**: formal dual reports implemented; expert validation, production ownership and recovery gates remain open
- **Active WIP Count:** 2 (occupied WIP = 2 / 2; 2 blocked)
- **Last Updated:** 2026-10-13

---

## Architectural Decisions (ADRs)
Central Architecture Decision Records are maintained in [DECISIONS.md](DECISIONS.md).

| ADR ID | Title | Status | Governed Phase |
| :--- | :--- | :--- | :--- |
| [ADR-001](DECISIONS.md#adr-001-blackboard-coordination--supervisor-governance-model) | Blackboard Coordination + Supervisor Governance Model | Accepted | Phase 4 |
| [ADR-002](DECISIONS.md#adr-002-ingestion-pipeline-bifurcation-preservation-vs-abstraction) | Ingestion Pipeline Bifurcation (Preservation vs. Abstraction) | Accepted | Phase 1 |
| [ADR-003](DECISIONS.md#adr-003-model-distribution--deployment-topology) | Model Distribution & Deployment Topology | Accepted | Phase 4 & Phase 5 |
| [ADR-004](DECISIONS.md#adr-004-three-tier-cryptographic-provenance-architecture-vct) | Three-Tier Cryptographic Provenance Architecture (VCT) | Accepted | Phase 1 & Phase 2 |
| [ADR-005](DECISIONS.md#adr-005-adversarial-quality-control-via-ach-debate-loop) | Adversarial Quality Control via ACH Debate Loop | Accepted | Phase 4 |
| [ADR-006](DECISIONS.md#adr-006-dynamic-attack-graph-weighting-via-negative-log-transformation) | Dynamic Attack Graph Weighting via Negative Log Transformation | Accepted | Phase 2 & Phase 3 |
| [ADR-007](DECISIONS.md#adr-007-mcp-integration-scope) | MCP Integration Scope | Accepted | Phase 5 |
| [ADR-008](DECISIONS.md#adr-008-pcap-ingestion-and-binary-parsing) | PCAP Ingestion and Binary Parsing | Accepted | Phase 3 |
| [ADR-009](DECISIONS.md#adr-009-evidence-vector-store-runtime) | Evidence Vector Store Runtime | Accepted | Phase 3 |
| [ADR-010](DECISIONS.md#adr-010-development-model-backend-and-fallbacks) | Development Model Backend and Fallbacks | Accepted | Phase 4 |
| [ADR-011](DECISIONS.md#adr-011-hyperledger-fabric-anchoring-status) | Hyperledger Fabric Anchoring Status | Deferred | Phase 2 |
| [ADR-012](DECISIONS.md#adr-012-evidence-bound-attribution-explanations-and-delivery-receipts) | Evidence-bound Attribution Explanations and Delivery Receipts | Accepted | Phase 6 |
| [ADR-013](DECISIONS.md#adr-013-local-ollama-and-no-billable-gcp-validation) | Local Ollama and No Billable GCP Validation | Accepted | Phase 6 |
| [ADR-014](DECISIONS.md#adr-014-evidence-collection-grounded-reports-and-local-runtime-protection) | Evidence Collection, Grounded Reports and Local Runtime Protection | Accepted | Phase 6 |
| [ADR-015](DECISIONS.md#adr-015-offline-attack-workbook-corpus-for-local-validation) | Offline ATT&CK Workbook Corpus for Local Validation | Accepted | Phase 6 |

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

- **Task ID:** `TASK-3.6`
  - **Description:** Add network file inputs to the ingestion runner and preserve original sensor records before normalization.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_network_pipeline.py tests/agents/test_network_forensics.py tests/ingestion/test_component5_broker_case_tagging.py tests/ingestion/test_component7_graph_ingestion.py -q -p no:cacheprovider --basetemp=.pytest-tmp-network-task`
  - **Acceptance Criteria:** Runner accepts Zeek JSONL, Suricata EVE JSON, and PCAP paths; resolves host identity with DHCP leases; preserves raw evidence before processing; writes normalized OCSF through Kafka/DFKG without clearing existing graph data.

- **Task ID:** `TASK-3.7`
  - **Description:** Add continuous tailing for Zeek and Suricata JSONL inputs with persisted offsets and rotation/truncation handling.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_network_pipeline.py tests/agents/test_network_forensics.py tests/ingestion/test_component5_broker_case_tagging.py tests/ingestion/test_component7_graph_ingestion.py -q -p no:cacheprovider --basetemp=.pytest-tmp-network-task`
  - **Acceptance Criteria:** Follow mode processes appended complete JSONL records once from saved byte offsets, reprocesses incomplete/uncommitted records after failure, handles file truncation/replacement, and leaves PCAP as explicit finite captures.

- **Task ID:** `TASK-3.8`
  - **Description:** Receive logs forwarded directly by network endpoints over syslog TCP/UDP and route preserved OCSF events into Kafka.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/ingestion/test_network_syslog.py tests/ingestion/test_network_pipeline.py tests/agents/test_network_forensics.py tests/ingestion/test_component5_broker_case_tagging.py tests/ingestion/test_component7_graph_ingestion.py -q -p no:cacheprovider --basetemp=.pytest-tmp-syslog`
  - **Acceptance Criteria:** Live TCP and UDP records are accepted from configured endpoint senders, original bytes are preserved before parsing, sender identity and message are represented in OCSF, and events are published to Kafka.

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
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/agents/test_evidence_collection.py`
  - **Acceptance Criteria:** 12/12 agent tests passing; strict multi-host isolation and 4-part discard conjunction logic verified.

- **Task ID:** `TASK-4.7`
  - **Description:** Implement Supervisor Agent (Orchestrator) graph and Kafka Consumer.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/orchestration/test_supervisor.py`
  - **Acceptance Criteria:** Supervisor graph built and routes according to specifications.


- **Task ID:** `TASK-4.8`
  - **Description:** Wire Log Analysis, Network Forensics, and Supervisor agents into LangGraph orchestration.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py tests/agents/test_network_forensics.py`
  - **Acceptance Criteria:** Legacy stubs removed, DFKG-sourced adapter factories injected via build_graph, and all 28 graph compilation tests passing.

- **Task ID:** `TASK-4.9`
  - **Description:** Implement deterministic Network Forensics Agent component.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/agents/test_network_forensics.py`
  - **Acceptance Criteria:** Agent evaluates OCSF 4001 events and flags C2, DNS Tunneling, and Exfiltration deterministically.

- **Task ID:** `TASK-4.10`
  - **Description:** Align skeleton to architecture v4: split `identity_cloud` → `identity` (F13a) + `cloud_container` (F13b); add `dag` Dynamic Attack Graph Agent to Sequential Synthesis (F23). Update `_SPECIALIST_MAP`, graph wiring, Kafka topics, stubs, supervisor_agent dispatch list, and test assertions.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py -v`
  - **Acceptance Criteria:** 28/28 passing; zero `identity_cloud` references in source; `dag` present in `agent_traces` membership and ordering assertions.

---

- **Task ID:** `TASK-4.11`
  - **Description:** Complete Network Forensics Agent ingestion contract, deterministic flow analysis, host-scoped findings, and LangGraph adapter.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/agents/test_network_forensics.py tests/test_skeleton_graph.py tests/ingestion/test_component7_graph_ingestion.py tests/ingestion/test_component5_broker_case_tagging.py -q -p no:cacheprovider`
  - **Acceptance Criteria:** Zeek/PCAP OCSF 4001 data yields grounded C2, DNS, lateral-movement and exfiltration findings with source UIDs and byte counts; case/host isolation, bounded execution, Kafka publication and LangGraph state output work without invented findings.

- **Task ID:** `TASK-4.12`
  - **Description:** Add versioned ATT&CK group profiles, evidence-backed ordered TTP extraction, deterministic Jaccard/Smith-Waterman ranking, and confidence bounds.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/agents/test_threat_attribution_agent.py tests/agents/threat_attribution tests/ingestion/test_threat_intel.py -q -p no:cacheprovider --basetemp=.pytest-tmp-threat`
  - **Acceptance Criteria:** ATT&CK relationships populate profiles; only evidence-backed trusted IDs enter scoring; top three follow exact 0.4/0.6 scoring with deterministic ties; missing data yields explicit degraded confidence.

- **Task ID:** `TASK-4.13`
  - **Description:** Wire Threat Attribution to case-scoped DFKG, LangGraph, configured explanation model, and Kafka finding publication.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/agents/test_threat_attribution_agent.py tests/agents/threat_attribution tests/ingestion/test_threat_intel.py tests/test_skeleton_graph.py tests/agents/test_network_forensics.py -q -p no:cacheprovider --basetemp=.pytest-tmp-threat`
  - **Acceptance Criteria:** Graph injects Neo4j and threat intel dependencies; immutable deterministic scores and references reach downstream state and sanctioned Kafka topic; model trace reflects actual backend.

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

## Task ID migration recorded 2026-10-06

Task titles and verification results are retained. Registry and execution-log IDs now use the following unique mapping; exported documents and archives may still contain the original IDs.

| Previous ID and scope | Canonical ID |
| :--- | :--- |
| TASK-4.8 agent wiring | TASK-4.8 |
| TASK-4.8 deterministic network component | TASK-4.9 |
| TASK-4.8 architecture v4 alignment | TASK-4.10 |
| TASK-4.9 complete network contract | TASK-4.11 |
| TASK-4.10 ATT&CK profiles and scoring | TASK-4.12 |
| TASK-4.11 Threat Attribution wiring | TASK-4.13 |

### Phase 6: Operational Readiness (`ADR-009`, `ADR-010`, `ADR-011`)

- **Task ID:** `TASK-6.1`
  - **Description:** Reconcile the project tracker, task identifiers and order; preserve verification history; define the Phase 6 backlog.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\python.exe scripts/validate_progress.py`
  - **Acceptance Criteria:** One canonical registry contains all previously passing task scopes with unique IDs; the repeated stale registry is removed; the former TASK-4.8 collisions have unique IDs; task history remains traceable; Phase 6 includes executable backlog items; active count does not exceed two.

- **Task ID:** `TASK-6.2`
  - **Description:** Align the documented evidence vector-store choice and runtime behavior.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/ingestion/test_vector_retrieval.py -q -p no:cacheprovider`
  - **Acceptance Criteria:** ChromaDB is documented as the persistent evidence store; InMemory is documented as a non-durable test/degraded fallback; Qdrant is identified as a legacy isolated helper and not a deployment dependency; Compose, requirements, README and tracker agree.

- **Task ID:** `TASK-6.3`
  - **Description:** Document actual development model backend behavior and distinguish it from unconfirmed production role assignments.
  - **Status:** `passing`
  - **Verification Command:** `pytest tests/test_skeleton_graph.py -q -p no:cacheprovider`
  - **Acceptance Criteria:** Documentation matches `get_llm` dispatch and agent traces; stub, Gemini, Threat Attribution OpenAI-compatible configuration and fallbacks are distinguished; no production model assignment is invented.

- **Task ID:** `TASK-6.4`
  - **Description:** Reconcile VCT documentation with Hyperledger Fabric implementation status.
  - **Status:** `passing`
  - **Verification Command:** `rg -n -i "Fabric anchoring status|deferred" DECISIONS.md README.md PROGRESS.md`
  - **Acceptance Criteria:** Fabric anchoring is explicitly marked deferred for this milestone unless an implementation and executable oracle are identified; local hash/Merkle support is not described as Fabric anchoring.

- **Task ID:** `TASK-6.5`
  - **Description:** Verify installed Python dependencies against requirements and resolve pending dependency notes.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\python.exe scripts/check_environment.py`
  - **Acceptance Criteria:** All requirements and requested extras satisfy installed versions, pip check is green, and imports/version presence for python-dateutil and google-cloud-logging are recorded; missing dependencies follow the human install rule.

- **Task ID:** `TASK-6.6`
  - **Description:** Execute and record a reproducible case investigation across ingestion, preservation, Kafka, Neo4j, LangGraph, HITL and dashboard.
  - **Status:** `passing`
  - **Verification Command:** `pytest -m integration tests/integration/test_case_investigation_e2e.py -q`
  - **Acceptance Criteria:** A deterministic fixture case has preserved raw evidence and hash, a Kafka event, a case-scoped DFKG record, graph findings and traces, HITL approval/resume, and visible frontend/API result; command passes against declared service versions.

- **Task ID:** `TASK-6.7`
  - **Description:** Run live integration checks for Kafka, Neo4j, Quickwit, Redis, model endpoints, GCP ingestion, API/WebSocket and frontend/backend.
  - **Status:** `blocked`
  - **Verification Command:** `pytest -m live_infra tests/integration/test_ollama_live.py tests/integration/test_live_services.py -k "not external_ingestion_or_model_endpoint" -q`
  - **Acceptance Criteria:** Each integration has a real-service assertion, explicit credential/config requirements, and a recorded zero-exit result; unavailable external services are reported separately.

- **Task ID:** `TASK-6.8`
  - **Description:** Establish production-readiness checks for reliability, performance, security, backup/restore and operations ownership.
  - **Status:** `blocked`
  - **Verification Command:** `pytest -m production_readiness tests/production_readiness -q`
  - **Acceptance Criteria:** Machine-executable checks and an owner/runbook exist for each category; thresholds and restore objectives are approved and results recorded.

- **Task ID:** `TASK-6.9`
  - **Description:** Independently review and verify the existing uncommitted implementation changes before commit and deployment.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\pytest.exe tests/agents tests/ingestion tests/test_skeleton_graph.py tests/test_visualizer_api.py tests/test_visualizer_api_db.py tests/test_visualizer_ws.py -m "not live_infra and not integration" -q -p no:cacheprovider --basetemp=.pytest-tmp-review-oracle`
  - **Acceptance Criteria:** Scope-specific code review findings are resolved or accepted; relevant tests pass; commit contains only reviewed project changes; deployment is attempted only to an authorized target with a recorded health check.

- **Task ID:** `TASK-6.10`
  - **Description:** Order corrected Phase 4 task records numerically and verify task-history cross-references.
  - **Status:** `passing`
  - **Verification Command:** `.\venv\Scripts\python.exe scripts/validate_progress.py`
  - **Acceptance Criteria:** The Phase 4 registry is ordered from TASK-4.1 through TASK-4.13 without gaps being fabricated; each corrected task ID is unique; associated verification commands and execution-log history remain attached to the intended task.

### Phase 7: Production Gate Remediation (proposed backlog)

Local evidence/report and auth/recovery subsets were implemented and verified under TASK-6.7/6.8 on 2026-10-07. The Phase 7 tasks retain their broader production acceptance criteria and are not promoted by those local results. Current evidence and commands: [local remediation](docs/local_remediation.md).

- **Task ID:** `TASK-7.1`
  - **Description:** Implement server-side identity/case authorization and an approved exposure policy for production APIs.
  - **Status:** `not_started`
  - **Verification Command:** `pytest -m production_readiness tests/production_readiness/test_readiness_gates.py::test_sensitive_graph_data_requires_authorization -q`
  - **Acceptance Criteria:** Unauthenticated case/graph access rejected; role/case authorization negative cases and approved access pass; audit ownership and deployment exposure are documented.

- **Task ID:** `TASK-7.2`
  - **Description:** Deploy a supported persistent graph checkpointer and prove analyst approvals survive process restart.
  - **Status:** `not_started`
  - **Verification Command:** `pytest -m production_readiness tests/production_readiness/test_readiness_gates.py::test_checkpoint_durability_is_configured -q`
  - **Acceptance Criteria:** Actual paused investigation survives fresh process initialization and resumes to a closed report; checkpoint backend and dependency/deployment decisions are recorded before implementation.

- **Task ID:** `TASK-7.3`
  - **Description:** Configure durable service storage and implement coordinated whole-system backup/restore to approved RPO/RTO.
  - **Status:** `not_started`
  - **Verification Command:** `pytest -m production_readiness tests/production_readiness/test_full_restore.py -q`
  - **Acceptance Criteria:** A separate restore environment recovers Quickwit, Neo4j, Kafka/offsets/schema registry, Redis/checkpoints, Chroma, FAISS and reports; complete case oracle passes and measured recovery objectives are met.

- **Task ID:** `TASK-7.4`
  - **Description:** Verify authenticated browser investigation and review workflows against authorized production model/feed configurations.
  - **Status:** `not_started`
  - **Verification Command:** `pytest -m production_readiness tests/production_readiness/test_authenticated_browser.py -q`
  - **Acceptance Criteria:** Approved test account performs case selection, live execution, refresh at HITL, approval/rejection and result review; backend authorization is enforced; real model/GCP evidence and browser results are recorded.

---

## Dependency and Infrastructure Status

- Python requirements verified 2026-10-07: 25 direct requirements and 282 dependency constraints, including requested extras; `pip check` passed.
- Previous install requests fulfilled in this venv: python-dateutil 2.9.0.post0 and google-cloud-logging 3.16.3; both imports passed. No install commands were run by the agent.
- Local Docker is running; real backing-service probes, complete development case oracle and deployed visualizer health/readiness passed.
- Current local runtime explicitly selects installed Ollama qwen3:8b; host/container inference and evidence-bound explanation passed. Gemini/hosted settings are not used for current testing.
- gcloud CLI authentication/project configuration confirmed locally; ADC and GCP ingestion are not verified. User prohibits bill-requiring services. Legacy external probes are excluded from the current command and must not run; replacement approval was declined. TASK-6.7 remains blocked for deferred service-ingestion/remaining full integration scope.

---

## Recent Execution Log
| Date | Component / Task | Changes Made | Verification Result |
| :--- | :--- | :--- | :--- |
| 2026-08-09 | `TASK-4.1`–`TASK-4.5` | Built 23-node LangGraph skeleton with guardrails, debate loop, and HITL API | 28/28 Passed |
| 2026-08-18 | `TASK-3.5` | Built FAISS IndexIVFPQ threat-intel corpus, fetchers, and MCP server | 29/29 Passed |
| 2026-08-18 | Stage 2 Ingestion Gaps | Wired injection detector into security gate; added 7-step e2e test | 15/15 + 2/2 Passed |
| 2026-08-20 | `TASK-4.6` | Verified pulled Evidence Collection Agent & Relevance Filter tests | 12/12 Passed (`tests/agents/`) |
| 2026-08-20 | Harness Upgrade | Updated `AGENTS.md`, `.agents/rules/rules.md`, and restructured `PROGRESS.md` to WIP=2 state machine | Verified |
| 2026-08-21 | `TASK-4.7` | Created `supervisor_agent.py`, `supervisor_graph.py`, and `kafka_consumer.py` per build spec | 2/2 Passed (`tests/orchestration/test_supervisor.py`) |
| 2026-08-21 | `TASK-4.7` | Rewrote tests to directly evaluate LangGraph state transitions and replaced inert mocks; fixed HITL routing logic | 32/32 Passed (`tests/supervisor_test_suite/`) |
| 2026-08-25 | Phase 2 & 3 Schemas | Applied strict validation, registered schemas, wired normalizers | Passed (`pytest tests/ingestion/`) |
| 2026-09-01 | Agent tooling | Installed `ui-ux-pro-max` at `.agents/skills/ui-ux-pro-max` and exposed only it to Git | Skill: `validate_data.py` passed; 130/132 bundled tests passed (2 require omitted upstream repo-root helpers). Repo fallback: 241 passed, 2 failed, 17 errors (pre-existing Neo4j/threat-intel fixtures and supervisor sync/async mismatch) |
| 2026-09-01 | `TASK-5.3`, `TASK-5.4` | Built 2-page React + Vite frontend with dark mode enterprise UI, ReactFlow, and hooked to FastAPI mock trigger | Passed (frontend lint zero warnings, backend tests passed) |
| 2026-09-15 | Phase 5 UI/UX | Formally established the Specula Brand Identity System (16 sections). Removed generic ReactFlow diagram from InvestigationConsole and implemented 6-step sequential telemetry view using new strict CSS tokens (`specula-tokens.css`) | Passed (Frontend UI rules adhered) |
| 2026-09-17 | Phase 5 UI/UX | Refined button tokens to darker royal indigo (`#1E40AF`) with 8px radius & white text. Positioned terminal directly below the Service Health Checks box with compact 2-column grid ensuring all 6 services are completely visible without window scroll push | Passed (`npm run lint` 0 warnings, `pytest` 8/8 passed) |
| 2026-09-19 | `TASK-4.8` | Created decoupled Network Forensics agent module with C2, DNS Tunneling, and Data Exfiltration anomaly detection heuristics | 6/6 Passed (`tests/agents/test_network_forensics.py`) |
| 2026-09-19 | `TASK-4.8` | Split `identity_cloud` → `identity` (F13a) + `cloud_container` (F13b); add `dag` Dynamic Attack Graph Agent to Sequential Synthesis (F23). Updated 7 files: `config.py`, `nodes.py`, `graph.py`, `kafka_utils.py`, `state.py`, `supervisor_agent.py`, `test_skeleton_graph.py`. Node count: 23 → 25. | 28/28 Passed (`tests/test_skeleton_graph.py`) |
| 2026-09-21 | `TASK-5.4` | Refactored pipeline trigger: separated Docker boot to `/api/system/boot` and lifted React state to `PipelineContext` to keep WebSocket alive across pages | Verified via UI linting and component updates |
| 2026-09-21 | `TASK-5.4` | Fixed `StartupPage` UI sync issue to await actual `docker compose down -v` and `up --force-recreate` completion before displaying services as verified | Verified via local UI logic |
| 2026-09-21 | `TASK-5.4` | Lazy-loaded neo4j/langgraph/graph imports in `visualizer_api.py` to prevent numpy 1.26 fatal crash on Py3.13+Windows. Added boot lock, retry button, and `restart: on-failure` for Redpanda | `GET /health` → ok, `POST /api/system/boot` → success, 7/7 containers Up |
| 2026-09-21 | `TASK-5.5` | Upgraded Neo4j Docker image to `5.26.0` to resolve Bolt Protocol v5.5 mismatch with python driver 6.2.0, and updated `numpy` dependency to `2.5.3` to fix silent crash | Verified (558 nodes ingested) |
| 2026-09-22 | Phase 1/3 Ingestion | Replaced AWS CloudTrail normalizers and schema mappings with GCP Audit Logs. Updated documentation, run pipeline mock payload, and generated deterministic UIDs. | 12/12 Passed (`pytest tests/ingestion/`) |
| 2026-09-22 | Phase 1/3 Ingestion | Implemented decoupled live GCP Audit Log fetcher via `google-cloud-logging` with strict schema validation, Quickwit VCT preservation layer, and Kafka stream production in `run_pipeline.py`. | 2/2 Passed (`pytest tests/ingestion/test_gcp_audit_fetcher.py`) |
| 2026-10-03 | `TASK-4.11` | Audited existing network agent against the supplied requirements and OCSF/DFKG contracts; set task active | Baseline `tests/agents/test_network_forensics.py`: 6 passed (pytest cache warning) |
| 2026-10-03 | `TASK-4.11` | Reworked network detector to read OCSF endpoints, UTC timestamps, DNS queries and byte counters; added grounded lateral movement heuristic | Pending task oracle |
| 2026-10-03 | `TASK-4.11` | Corrected single-case/host checks and OCSF 2004 publication with evidence UIDs, deterministic finding UID, host partition key, and non-fatal Kafka errors | Pending task oracle |
| 2026-10-03 | `TASK-4.11` | Replaced network LangGraph adapter with case-scoped DFKG read, host batches, individual evidence-backed findings, and honest unavailable-data traces | Pending task oracle |
| 2026-10-03 | `TASK-4.11` | Added network OCSF byte/DNS fields and repaired Zeek, Suricata, and PCAP normalization with deterministic UIDs, endpoint objects, DHCP-bounded resolution, and extracted-field scanning | Pending task oracle |
| 2026-10-03 | `TASK-4.11` | Made network graph writes persist case-linked OCSF Event nodes, per-event connection edges and byte evidence; added Event/Case UID constraints | Pending task oracle |
| 2026-10-03 | `TASK-4.11` | First task oracle: 43 passed, 3 legacy detector assertions failed; updated network tests to use actual OCSF fields and added normalization, graph, PCAP, publication and adapter checks | Re-running task oracle |
| 2026-10-03 | `TASK-4.11` | Corrected event producer host key and preserved explicitly assigned case IDs for network-event routing | Focused oracle: 50 passed before this producer change |
| 2026-10-03 | `TASK-4.11` | Added Zeek/Suricata and PCAP ingestion entry points with original-byte Quickwit/VCT preservation, field scanning, OCSF normalization, Kafka serialization and graph indexing | Pending network contract tests |
| 2026-10-03 | `TASK-4.11` | Focused oracle reached 67 passed; network adapter now scopes by Case HAS_EVENT relationship so immutable evidence may be linked to more than one case | PCAP entry-point verification pending |
| 2026-10-03 | `TASK-4.11` | Added regression evidence for DHCP reassignment and original-byte PCAP preservation before packet publication | Re-running task oracle |
| 2026-10-03 | `TASK-4.11` | Focused oracle reached 68 passed; corrected host partition key to bytes for the real Kafka producer interface | Final verification pending |
| 2026-10-03 | `TASK-4.11` | DFKG findings consumer now keeps the producer's deterministic UID and stores network evidence refs, byte volume, case and host metadata | Final verification pending |
| 2026-10-03 | `TASK-4.11` | Added DFKG consumer regression proving a network finding retains UID, evidence refs and byte volume through Kafka consumption | Final verification pending |
| 2026-10-03 | `TASK-4.11` | Focused oracle reached 69 passed; added budget-exhaustion regression to verify partial result without publication | Final verification pending |
| 2026-10-03 | `TASK-4.11` | Completed network agent, OCSF input paths, case-linked graph storage, Kafka finding output and DFKG evidence metadata | Task oracle: 70 passed, zero exit; live sensor/infra and remote model benchmarking remain separate integration work |
| 2026-10-03 | `TASK-4.11` | Clock-out verification after status transition | Task oracle: 70 passed, zero exit; scoped `git diff --check`: zero exit |
| 2026-10-03 | `TASK-3.6` | Began wiring network file inputs into the CLI runner; existing function-level network ingestion is not yet called by `run_pipeline.py` | Active |
| 2026-10-03 | `TASK-3.6` | Added conversion for native Zeek Unix-second timestamps before OCSF time normalization | Pending file-ingestion tests |
| 2026-10-03 | `TASK-3.6` | Added JSONL/EVE file reader with per-line trace IDs, Quickwit/VCT-first preservation, skip reporting, abort-on-preservation-failure, and DHCP lease JSON loading | Pending task oracle |
| 2026-10-03 | `TASK-3.6` | Initial oracle: code checks passed except pytest could not create Windows temp fixture under AppData; rerunning with workspace-local basetemp | Active |
| 2026-10-03 | `TASK-3.6` | Workspace-local rerun passed 45 tests; CLI now exposes network-only Zeek/Suricata/PCAP inputs and returns useful error exit codes; README includes setup and DHCP lease format | Pending final runner check |
| 2026-10-03 | `TASK-3.6` | Network file ingestion complete; CLI help verified | Task oracle: 45 passed, CLI help zero exit. Scoped diff check found only trailing whitespace in pre-existing local GCP edits within run_pipeline.py; no cleanup made to preserve that work |
| 2026-10-03 | `TASK-3.6` | Final verification after passing transition | Task oracle: 45 passed; scoped diff check: zero exit |
| 2026-10-03 | `TASK-3.7` | Began persisted-offset follow mode for live Zeek and Suricata files | Active |
| 2026-10-03 | `TASK-3.7` | Added complete-line JSONL tailing with atomic checkpoints, restart/resume behavior, replacement/truncation detection, retry on preservation failure, finite PCAP startup, and append-only normalized JSONL output | Verification pending |
| 2026-10-03 | `TASK-3.7` | Added explicit truncation regression; follow-mode oracle passed; CLI exposes follow options; scoped diff check passed | 47 passed, zero exit; CLI help zero exit; scoped `git diff --check` zero exit |
| 2026-10-03 | `TASK-3.8` | Began live endpoint syslog ingestion over TCP/UDP using standard-library listeners; records will be preserved and published as OCSF generic events | Active |
| 2026-10-03 | `TASK-3.8` | Added live UDP/TCP syslog listeners, preservation-before-publication, sender attribution in OCSF generic event, CLI configuration, and endpoint forwarding instructions | Focused syslog + network ingestion oracle: 7 passed, zero exit |
| 2026-10-03 | `TASK-3.8` | Syslog receiver verification complete; loopback endpoint tests exercised both transports, preserved raw bytes, and confirmed OCSF Kafka publication | 49 focused tests passed; CLI help exited zero; scoped diff check passed (pre-existing GCP whitespace remains in shared runner file) |
| 2026-10-03 | `TASK-4.12` | Baseline threat agent oracle passed 12 tests; began deterministic scoring and versioned ATT&CK group profile implementation | Active |
| 2026-10-03 | `TASK-4.12` | Added STIX uses-relationship group profiles, corpus provenance fields, stable-ID lookups, evidence-backed TTP extraction, deterministic scoring and confidence model | Task oracle pending |
| 2026-10-03 | `TASK-4.12` | Deterministic core complete with STIX group relationships, exact 0.4/0.6 scoring, evidence filtering, confidence bounds and degradation | Oracle: 40 passed, zero exit |
| 2026-10-03 | `TASK-4.13` | Began LangGraph injection, timeline event contract, Kafka publication and configured narrative backend | Active |
| 2026-10-03 | `TASK-4.13` | Replaced stub attribution node with injected factory; timeline now freezes cited chronological events; model config supports an explicit OpenAI-compatible Kimi endpoint | Verification pending |
| 2026-10-03 | `TASK-4.13` | Full graph integration preserves candidate scores and citations through Kafka/report; timeline now uses source event time; candidate search expands through CVE-heavy corpus; canonical ATT&CK tactic sequence is labeled inferred and confidence adjusted | Final oracle pending |
| 2026-10-03 | `TASK-4.13` | Expanded UI suite exposed an existing WebSocket test calling absent `/api/graph/run_mock` endpoint; attribution, corpus, graph and visualizer API cases passed | Expanded suite: 94 passed, 1 unrelated 404 failure; task oracle rerun pending |
| 2026-10-03 | `TASK-4.13` | Injection, chronological timeline, deterministic attribution publication and downstream citation retention complete | Task oracle: 91 passed, zero exit; scoped diff check zero exit; live corpus and DFKG service not exercised |
| 2026-10-03 | `TASK-4.12`, `TASK-4.13` | Clock-out verification after passing transitions | Task oracle: 91 passed, zero exit; active WIP 0 |
| 2026-10-06 | `TASK-6.1` | Removed duplicate stale task registry; preserved missing TASK-5.6 verification oracle; assigned unique Phase 4 IDs and retained execution history; added Phase 6 backlog | `scripts/validate_progress.py`: valid, 42 unique tasks, active WIP 1/2 |
| 2026-10-06 | `TASK-6.1` | Re-ran tracker validation after the passing transition | `scripts/validate_progress.py`: valid, 42 unique tasks, active WIP 0/2 |
| 2026-10-06 | `TASK-6.2` | Recorded ADR-009 and aligned README, dependency notes, and legacy vector-indexer description with ChromaDB persistent storage and non-durable in-memory fallback | Focused vector retrieval oracle: 10 passed, zero exit |
| 2026-10-06 | `TASK-6.10` | Added numeric-order assertion to tracker validator and moved TASK-4.7 ahead of TASK-4.8 after corrected unique IDs | Validator rerun pending |
| 2026-10-06 | `TASK-6.10` | Repaired active header, malformed verification command and escaped Python path; added original-to-canonical ID mapping and stable chronological log ordering | Validator rerun pending after interrupted command |
| 2026-10-06 | `TASK-6.10` | Tracker validator now checks occupied WIP, active header, control characters, numeric order and chronological logs; repaired portable documentation links | Validation pending after link cleanup |
| 2026-10-06 | `TASK-6.10` | Corrected tracker order and consistency; verification succeeded before passing transition | Validator: 43 unique task IDs, occupied WIP 2/2; zero exit |
| 2026-10-06 | `TASK-6.4` | Began README reconciliation of ADR-004 target and ADR-011 deferred implementation status | Active; documentation oracle pending |
| 2026-10-06 | `TASK-6.3` | Added complete runtime role matrix, selector and failure behavior, trace limitations and unconfirmed production status; clarified ADR-003 target topology | Graph and stub-dispatch verification pending |
| 2026-10-06 | `TASK-6.4` | README and ADR-004 now distinguish local VCT capabilities from deferred Fabric/case-signing deployment | Documentation oracle pending |
| 2026-10-06 | `TASK-6.3` | Graph oracle executed with explicit stub selectors | 28 passed, zero exit; role-matrix CLI check pending |
| 2026-10-07 | `TASK-6.3`, `TASK-6.4` | Recorded pre-interruption verification evidence and closed model/Fabric documentation tasks | Graph: 28 passed; default-dispatch CLI: 18 roles documented; Fabric documentation oracle zero exit |
| 2026-10-07 | `TASK-6.5`, `TASK-6.9` | Clock-in tracker validation passed; began dependency verification and independent review of existing edits; user confirmed local Docker target | Tracker: 43 unique tasks, occupied WIP 2/2; environment and implementation oracles pending |
| 2026-10-07 | `TASK-6.5` | Added repeatable requirements/extras traversal, pip check and dateutil/GCP import oracle | Verification pending; no packages installed |
| 2026-10-07 | `TASK-6.5` | Requirements/extras and imports verified; removed fulfilled install requests | 25 requirements / 282 constraints satisfy installed versions; pip check zero exit; dateutil 2.9.0.post0 and GCP Logging 3.16.3 import OK |
| 2026-10-07 | `TASK-6.6` | Began local Docker investigation validation after user identified deployment target | Active; Docker access check pending |
| 2026-10-07 | `TASK-6.6`, `TASK-6.9` | Resumed session; validated tracker and inspected repository; Docker Desktop started and existing Kafka, schema registry, Redis, Quickwit, Neo4j and Chroma containers started without rebuilding images or installing packages | Tracker: 43 unique tasks, WIP 2/2; Compose start zero exit; service readiness pending |
| 2026-10-07 | `TASK-6.9` | Independent reviewer identified ignored backend overrides, unsupported narrative claims, corpus refresh provenance race and missing Kafka delivery receipts; adjusted validator registry boundary to current heading | Four fixes and regression verification pending |
| 2026-10-07 | `TASK-6.9` | Recorded ADR-012; fixed attribution backend dispatch, rendered evidence-bound explanation codes, added corpus reload generation check and non-blocking Kafka receipts with immutable returned status; updated runtime matrix | Regression tests and independent re-review pending |
| 2026-10-07 | `TASK-6.9` | Added regressions for supported backend overrides, unknown selectors, narrative overclaims, unsupported explanation codes, corpus A/B/A refresh detection and Kafka immediate/late delivery outcomes | Focused oracle pending |
| 2026-10-07 | `TASK-6.9` | First focused invocation referenced absent threat-intel test paths; no tests ran | Exit 1; locating canonical test paths before rerun |
| 2026-10-07 | `TASK-6.9` | Independent re-review cleared all four fixes; focused suite hit a sandbox permission error in pytest's shared system temporary directory | 55 passed, 9 setup errors; rerun with workspace-local temporary directory; multi-file corpus build atomicity remains an additional review concern |
| 2026-10-07 | `TASK-6.9` | Workspace temporary rerun failed because its parent directory did not exist; switching to ignored root-level pytest temporary directory | 55 passed, 9 setup errors; no implementation failures observed |
| 2026-10-07 | `TASK-6.9` | Focused attribution, Kafka receipt and threat-intelligence suites rerun with writable temporary directory | 64 passed, zero exit; independent re-review cleared four fixes |
| 2026-10-07 | `TASK-6.9` | Broader implementation oracle completed with explicit stub selectors | 349 passed, 1 failed, 16 deselected; existing WebSocket test calls absent run_mock endpoint |
| 2026-10-07 | `TASK-6.6` | Live-flow review found run_pipeline_on_event hashes a payload before adding a hash field, then commits different bytes; preservation errors also permit continuation | Correct preservation byte identity and fail-closed behavior before live acceptance |
| 2026-10-07 | `TASK-6.6`, `TASK-6.9` | Fixed runner to preserve/hash the same unmodified input bytes, advance VCT only after successful commit and stop on preservation errors; replaced stale mock-route WebSocket test with actual broadcaster regression | Expanded verification pending |
| 2026-10-07 | `TASK-6.9` | Expanded implementation oracle including runner preservation and actual WebSocket broadcaster passed | 352 passed, 16 live/integration tests deselected, zero exit; one third-party deprecation warning |
| 2026-10-07 | `TASK-6.6` | Probed running local backing services through real clients | Kafka metadata, Neo4j connectivity, Redis PING, Quickwit HTTP 200, Chroma heartbeat and schema registry HTTP 200 all succeeded |
| 2026-10-07 | `TASK-6.6` | Added actual case investigation, snapshot and analyst review routes with one shared checkpointer; stream broadcasts reflect executed graph updates and reject missing evidence/duplicate concurrent runs | API wiring, frontend connection and live oracle pending; user identified GCP_PROJECT_ID in .env |
| 2026-10-07 | `TASK-6.6` | Wired real investigation routes into visualizer; removed simulated trigger sequence and destructive dashboard teardown/rebuild; boot compatibility endpoint now checks existing services, with backend configuration distinguished from verified inference | Runtime/API and frontend verification pending |
| 2026-10-07 | `TASK-6.6` | Added real Quickwit, Chroma and FAISS dashboard adapters and Redis/corpus injection into shared investigation runtime | Store adapter wiring and UI changes pending; UI/UX skill applied for asynchronous status feedback |
| 2026-10-07 | `TASK-6.9` | Hardened new corpus builds with manifest-bound artifact hashes and loading from the verified byte snapshot; incomplete generations retain the prior index | Regression and re-review pending; older manifests without artifact hashes remain compatibility-only |
| 2026-10-07 | `TASK-6.9` | Extended ADR-012 and health metadata to label verified artifact generations; case attribution now rejects legacy unverified corpus artifacts | Corpus integrity regression pending |
| 2026-10-07 | `TASK-6.6` | Dashboard now waits for WebSocket connection before running an actual case, filters events by case, submits real analyst decisions and shows evidence-derived review data; query parameter selects the fixture case | Frontend build and live acceptance pending |
| 2026-10-07 | `TASK-6.6` | Startup page now reads real service probe results without rebuilding/deleting containers; removed fabricated healthy/integrity/production-ready claims and renamed review fields to reflect cited evidence | Frontend build and live acceptance pending |
| 2026-10-07 | `TASK-6.6` | Frontend production build succeeded; added executable live oracle using synthetic network evidence, real Quickwit/Kafka/Neo4j/Redis/Chroma, a real fixture FAISS corpus, actual LangGraph, HTTP review and dashboard WebSocket updates | Build zero exit (large chunk warning); live case oracle pending; hosted models and real feed ingestion are separate |
| 2026-10-07 | `TASK-6.6` | First live oracle failed at an incorrect corpus writer import before service operations; corrected to the existing atomic artifact writer | Exit 1; rerun pending |
| 2026-10-07 | `TASK-6.9` | Prepared local Docker source deployment override using existing HITL image and read-only source mounts, with visualizer bound to loopback and explicit stub backends; no image build/package installation | Compose validation, independent re-review, commit and deployment pending |
| 2026-10-07 | `TASK-6.6` | Full development fixture investigation verified across real local Docker services, actual graph, HTTP analyst approval and dashboard WebSocket result; machine-verifiable evidence saved to data/verification/local_case_latest.json | Live oracle: 1 passed in 9.25s, zero exit; frontend build passed; task passing (stub models, fixture corpus, in-process checkpoint; production/restart claims excluded) |
| 2026-10-07 | `TASK-6.7` | Began remaining live integration checks using user-provided GCP_PROJECT_ID location | Active alongside TASK-6.9; hosted endpoint settings not supplied |
| 2026-10-07 | `TASK-6.9` | Expanded verification after real API/store and corpus changes passed | 352 passed, 16 deselected, zero exit; independent review of new flow ongoing |
| 2026-10-07 | `TASK-6.9` | Reviewer found refresh at HITL lost frontend review controls; added checkpoint snapshot restore on WebSocket connection, HTTP response fallback and actual findings/trace/report display | Frontend rebuild and review pending |
| 2026-10-07 | `TASK-6.9` | Reviewer identified environment load ordering and mutable WebSocket set iteration/stalled telemetry; load .env before driver/readiness and bound best-effort stream delivery over a connection snapshot | Regression/live rerun pending |
| 2026-10-07 | `TASK-6.9` | Added corpus partial-generation and legacy-attribution rejection regressions; replaced ignored dashboard extraction filters with ingested-case selection; reviewer confirmed snapshot recovery and corpus fixes | Final verification and deployment pending |
| 2026-10-07 | `TASK-6.9` | Reviewer closed backend findings and identified stale snapshot race on case selection; reset case state, ignore cancelled fetches and enforce matching snapshot case ID | Frontend rebuild and final review pending |
| 2026-10-07 | `TASK-6.7` | Inspected configuration presence without exposing secrets | GCP_PROJECT_ID and GEMINI_API_KEY set; GOOGLE_APPLICATION_CREDENTIALS and attribution endpoint/key absent; default GCP credentials not yet verified |
| 2026-10-07 | `TASK-6.9` | Final selected implementation suite passed and source deployed to local Docker without image builds; Compose override valid | 354 passed, 16 deselected, zero exit; deployment health check pending |
| 2026-10-07 | `TASK-6.7` | One-line ADC probe failed due Windows command quoting; replaced it with repeatable external-service probe script using bounded requests and sanitized evidence | No credentials were checked by failed invocation; external probes pending |
| 2026-10-07 | `TASK-6.7` | External probes recorded sanitized results | GCP: DefaultCredentialsError; Gemini: ConnectError under restricted network, retry with host network pending; hosted attribution settings absent |
| 2026-10-07 | `TASK-6.9` | Deployed visualizer responded to real HTTP health/readiness and frontend rebuilt after recovery fixes | HTTP health 200; five backing service probes ready; development backend stub; npm build zero exit (large chunk warning) |
| 2026-10-07 | `TASK-6.6` | Re-ran complete live oracle after final API/corpus/telemetry corrections | 1 passed in 8.57s, zero exit; latest evidence artifact refreshed |
| 2026-10-07 | `TASK-6.7` | Gemini host-network retry reached provider but returned ClientError; requested GCP credential configuration after ADC failure; enhanced sanitized probe with HTTP status and safe reason categories | External integration remains unverified; credential contents never printed |
| 2026-10-07 | `TASK-6.9` | Final read-only review cleared substantive findings; repaired three whitespace lines; added reproducible validation/deployment and implementation-review documentation | Diff check zero exit; commit pending |
| 2026-10-07 | `TASK-6.7` | Sanitized host-network model probe established provider quota failure; marked task blocked with WIP slot retained | Gemini HTTP 429/quota unavailable; GCP ADC missing; attribution endpoint/key absent; no external pass claimed |
| 2026-10-07 | `TASK-6.9` | Reviewer confirmed closure after stale-case guard; final implementation oracle green; corrected PowerShell npm argument forwarding by starting the installed Vite executable directly | 354 passed, 16 deselected, zero exit; frontend source server started on 127.0.0.1:5173; initial npm invocation served wrong root and was stopped |
| 2026-10-07 | `TASK-6.9` | Verified frontend HTML and investigation context module over HTTP; final diff whitespace check passed | Frontend HTTP 200; actual case/review integration asset HTTP 200; no authenticated browser session exercised |
| 2026-10-07 | `TASK-6.9` | Reviewed staged file list and added ADR-012 index entry; tracker and staged diff checks passed | 43 unique tasks; occupied WIP 2/2 (one active, one blocked); 46 reviewed files staged; Word artifacts and secrets excluded |
| 2026-10-07 | `TASK-6.9` | Independently reviewed fixes, local verification, source deployment and commit completed | Passing; implementation commit 145cf97; 354 selected tests passed; live case passed; Docker health/readiness and frontend asset/build checks green; no remote push |
| 2026-10-07 | `TASK-6.8` | Began executable production-readiness gates and operational runbook after review slot closed | Active alongside blocked TASK-6.7; thresholds/owners not assigned |
| 2026-10-07 | `TASK-6.7` | Added executable deployed service/API/WebSocket/frontend asset and external endpoint gates; explicit attribution probe confirmed missing endpoint/key | Live suite pending; availability failures remain failures, not skips |
| 2026-10-07 | `TASK-6.8` | Registered production marker; added integration-evidence, measured Redis throughput, authorization, real isolated raw-evidence restore, checkpoint durability and owner/recovery-policy gates; wrote operational runbook with unapproved proposed values and full-store recovery gaps | Production gate execution pending; no production-ready claim |
| 2026-10-07 | `TASK-6.7` | Executed all live integration gates against deployed services with host-network access | 2 passed, 3 failed, 1 deselected; service/API/WebSocket/frontend assets green; GCP ADC absent, Gemini 429 quota unavailable, attribution endpoint absent |
| 2026-10-07 | `TASK-6.8` | Executed readiness gates and actual raw evidence restore | 2 passed, 4 failed; 4 restored records verified in 6.17s; Redis 94,292 ops/sec microbenchmark (unapproved threshold); authorization, checkpoint durability and owner/policy gates fail |
| 2026-10-07 | `TASK-6.8` | Independent gate review found source-string durability check, zero-record restore loophole and incorrect restart instructions; replaced with two-process pause/restart/resume oracle, required four recorded digests and corrected recovery case lookup | Production oracle rerun pending |
| 2026-10-07 | `TASK-6.8` | Revised executable production oracle completed; blocked state retains WIP slot while production policy/ownership and remediation are outstanding | 2 passed, 4 failed; real process restart lost paused checkpoint; API graph data HTTP 200 without authorization; owner/threshold unset; raw restore 4 records verified in 6.22s; Redis 89,658 ops/sec baseline |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Defined Phase 7 remediation backlog; corrected validator display to count blocked WIP; excluded opt-in live/production gates from default pytest while preserving explicit gate commands | Both current tasks blocked, occupied WIP 2/2; final review and clock-out verification pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Added readiness results document with exact passed/failed scopes, external blockers, real restart failure and limited restore/throughput scope | Final documentation/review and clock-out verification pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Independent reviewer cleared corrected gate/runbook findings; clock-out environment/tracker/diff verification succeeded | 25 requirements / 282 constraints verified; pip check/imports green; 47 unique tasks, occupied WIP 2/2, both blocked; final selected test result and documentation commit pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Clock-out selected implementation oracle and running application health verified; readiness gates remain explicitly failed/blocked | 354 passed, 16 deselected, zero exit; backend/frontend HTTP 200; no new packages installed; no remote push; credential and owner/target questions pending |
| 2026-10-07 | `TASK-6.7` | Clock-in tracker/repo verification passed; user replaces hosted tests with local Ollama and prohibits bill-requiring GCP services; recorded ADR-013 before runtime edits | 47 tasks, occupied WIP 2/2; installed qwen3:8b discovered; gcloud CLI login active/project selected; no GCP service invoked; task resumed active |
| 2026-10-07 | `TASK-6.7` | Saved local-only Ollama adapter and Compose selectors; generic trace records actual model; added isolated local model/attribution verification and endpoint guards | Direct application dispatcher: qwen3:8b SPECULA_OK verified, zero exit; no packages/model pulls |
| 2026-10-07 | `TASK-6.7` | Terminal approval declined for replacing legacy probe script; it remains unchanged and must not run under the new policy. Scoped verification command excludes those hosted/GCP service tests | Local Ollama/CLI checks only; GCP ingestion deferred; no GCP service calls this session |
| 2026-10-07 | `TASK-6.7` | Added current model testing/cost-boundary document, explicitly superseding earlier hosted probe commands and separating CLI login from ADC/ingestion | Local inference/Compose test results pending |
| 2026-10-07 | `TASK-6.7` | Local model dispatcher/security guard and graph regressions passed; Docker override deployed with explicit Ollama selectors | 56 passed, zero exit; Compose no-build update zero exit; live explanation and container inference pending |
| 2026-10-07 | `TASK-6.7` | Docker-to-host Ollama inference passed; initial live attribution rejected unconstrained explanation output while preserving deterministic evidence | Container qwen3:8b SPECULA_OK verified, zero exit; live contract 1 failed; added native JSON schema for supported explanation codes before rerun |
| 2026-10-07 | `TASK-6.7` | Schema-constrained real Ollama attribution test passed; task remains blocked for deferred GCP ingestion and remaining full integration scope, not for hosted quota/configuration | 1 live test passed in 1.54s, zero exit; both WIP slots blocked; gcloud authentication confirmed without GCP service calls |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Selected implementation regressions completed after Ollama schema correction; README/runtime matrix now identify current local Docker selection and supersede older hosted-probe instructions | 360 passed, 16 deselected, zero exit in 16.18s; isolated regressions used stubs; actual Ollama inference/attribution verified separately; independent review of new adapter not completed because reviewer could not read workspace |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Clock-out tracker and diff verification passed; current local deployment uses Ollama; broader integration/readiness tasks retain blocked status | Tracker zero exit: 47 unique tasks, occupied WIP 2/2 (0 active); git diff --check zero exit; changes remain uncommitted; no GCP service calls, packages installed, model downloads or remote push |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | User requests full application diagnostic run; resumed both tasks and added explicit local Ollama mode, longer bounded HTTP waits and actual model traces to full investigation oracle | Clock-in tracker valid: 47 tasks, occupied WIP 2/2; all 9 Docker services running; full Ollama run and readiness rerun pending; no external services authorized |
| 2026-10-07 | `TASK-6.7` | Frontend build passed; first current live suite found frontend server stopped while Ollama and backing-service readiness passed; browser automation inventory has no available browsers | npm build zero exit, 653 KB bundle warning; live suite 2 passed / 1 failed / 3 excluded external probes; restarting installed Vite before rerun; full investigation still running |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Restarted Vite and reran local service/API/WebSocket/frontend checks; readiness gates rerun against local components | Live services 2 passed / 3 external probes excluded, zero exit; production gates 2 passed / 4 failed: anonymous graph HTTP 200, lost checkpoint after real process restart, absent approved Redis threshold (52,490 ops/sec measured), absent operational owner; raw restore passed; gates used prior completed case while new Ollama case runs |
| 2026-10-07 | `TASK-6.7` | First full Ollama case reached HTTP HITL/attribution assertions but WebSocket client timed out after 282.76s; test client was not draining its bounded queue during long synchronous HTTP wait | 1 failed; removed bounded client queue, retained keepalive checks; added paused/final evidence and explicit incomplete-worker assertion before rerun; deployed corpus missing is a separate runtime gap |
| 2026-10-07 | `TASK-6.7` | Complete non-live test collection exposed two additional supervisor failures; added local deployed-application diagnostic using retained synthetic case, bounded HTTP requests and continuously drained WebSocket | 399 passed / 2 failed / 33 deselected in 18.03s; both alternate supervisor tests call synchronous invoke on async dispatch_primary_tier; no production fix claimed; deployed diagnostic pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Environment, tracker, diff and new diagnostic script syntax verification passed during long Ollama rerun | 25 direct requirements / 282 constraints satisfy installed environment, pip check/imports green; tracker 47 tasks / 2 active; diff check zero exit; script py_compile zero exit; corpus/worker/authorization/restart findings retained |
| 2026-10-07 | `TASK-6.7` | Corrected-queue Ollama run reached actual debate exhaustion/HITL, then first approval reached a second guardrail review; previous single-approval oracle incorrectly assumed stub verdict behavior | 1 failed in 326.52s, not a closed-case pass; paused snapshot saved, evidence worker terminal=true; updated harness and deployed diagnostic for up to three distinct synthetic approvals and reviewed snapshot persistence; deployed run ongoing |
| 2026-10-07 | `TASK-6.7` | Captured actual Docker checkpoint, separately from fixture harness; diagnostic report records confirmed deployment gaps | Deployed case at synthesis/dag; evidence_collection terminal=false/max_iterations; attribution model none with unavailable/unverified corpus and insufficient-evidence flags; FAISS HTTP 200/not_ready/0 vectors, DuckDB HTTP 200/unavailable, missing-evidence case correctly HTTP 404; no green full-run claim |
| 2026-10-07 | `TASK-6.7` | Inspected actual deployed OpenAPI contract and queried independent HITL gateway with the running visualizer case | OpenAPI HTTP 200; gateway returns empty case/status/paused nodes and does not share visualizer checkpoint; deployed case progressing through debate on qwen3:8b with observed calls 18–58s; full diagnostic still ongoing |
| 2026-10-07 | `TASK-6.7` | Read-only live Entity.uid constraint check passed; initial deployed diagnostic reached HITL and first approval advanced to second review as observed in fixture | Schema oracle 1 passed, zero exit; deployed diagnostic exit 1 after 473.60s, initial investigation HTTP 200 in 465.86s, first review HTTP 200; incomplete evidence worker and unavailable FAISS/DuckDB recorded; continuing existing case with updated multiple-gate diagnostic |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Completed actual Docker Ollama investigation through second approval, final report and WebSocket run_complete; diagnostic fails acceptance and both tasks returned blocked with WIP slots retained | Continuation 70.61s, HTTP review 200, case closed, diagnostic exit 1; approximately 9m04s execution across both invocations; evidence worker incomplete, attribution unavailable; report has empty citations, invented 2025 date, unsupported C2 claim and incomplete ending; documented remediation in docs/full_application_run.md; no GCP/Gemini service calls |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Final syntax/diff checks passed; tracker rejected renamed WIP headers, so restored validator-compatible labels with explicit occupied/blocked counts | Initial tracker failure: required legacy Active WIP Count heading missing; corrected header; final validator zero exit: 47 tasks, occupied WIP 2/2 (0 active); diagnostic application failures remain blocked |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Clock-out diagnostic report and historical documentation reconciled; current full-run result is authoritative and earlier hosted commands marked excluded | Report docs/full_application_run.md and data/verification/deployed_application_latest.json retain closed-but-failed acceptance evidence; Vite left running on 127.0.0.1:5173; Docker services retained; changes uncommitted; no packages, model pulls, GCP calls or remote push; final tracker and diff checks zero exit |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | User authorizes four defect repairs; resumed existing occupied slots and recorded ADR-014 before implementation; evidence/report scoped to 6.7, auth/restart scoped to 6.8 | Skill-guided builders scoped to separate evidence/report files; mandatory contract, security and real process-restart verification pending; no installs or external services authorized |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Scoped builders implemented parameterized deterministic evidence triage, complete cited report/timeline renderers, and SQLite WAL checkpoint adapter; parent wired graph state/output and backend HTTP/WebSocket protection | Evidence 11 passed, report 11 passed, saver 6 passed (all zero exit); user permits all authenticated users on owned/assigned cases; case ownership/membership checked in Neo4j, client profile roles ignored; runtime/combined security and fresh-process verification pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Added fenced durable execution leases, authenticated case-scoped APIs/browser transport and shared checkpoint mounts; revalidate start/review state under lease | Focused oracle 79 passed; automatic review rejected wildcard validation credential; narrowed setup to analyst permission on one synthetic fixture case, deployment checks pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Expanded authenticated API regressions passed and frontend built; local source deployment initially failed SQLite WAL on Windows bind mount | 89 passed / build zero exit; switched shared checkpoint storage to a persistent Docker named volume, retaining single-host scope; live rerun pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Actual Docker Ollama investigation reached durable HITL in 277.49s with all four original events fetched and triaged; added live security/shared-gateway/restart oracle | Pause oracle zero exit; tool approval quota interrupted subsequent work; on resume Docker engine was stopped, restarting local runtime before checkpoint comparison |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Repeated focused regression green; restored Docker runtime and proved both APIs read the retained Ollama HITL checkpoint after engine shutdown | 89 passed in 21.57s; live recovery capture zero exit: anonymous 401, other case 403, assigned case 200, both gateways same pause; added bounded startup retry to oracle; deliberate API restart next |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Both APIs retained byte-identical paused checkpoint after deliberate Docker restart; resumed request failed because local Ollama was stopped, leaving a saved failed-node checkpoint | Restart/security oracle zero exit; broad suite 449 passed / 3 failed / 33 deselected: two known sync/async supervisor defects plus stale report fixture lacking verified evidence; fixed fixture and added authorized failed-node retry with retained-checkpoint 503 response; regression/resume pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Ollama host and Docker reachability restored (HTTP 200); saved failed-node execution now retrying; added real checkpoint retry/write-permission regressions and local remediation policy/runbook | Report/auth/graph focused follow-up 51 passed, zero exit; retry tests and actual final report oracle pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Actual recovered Ollama run finished in 18.05s with complete four-event collection, full report/timeline endings and every original event cited; both API gateways confirm closed state and retained access boundaries | Deployed diagnostic and closed-recovery oracle zero exit; overall acceptance correctly incomplete for missing/unverified corpus and unconfirmed attribution delivery; added dashboard failed-checkpoint retry behavior and updated current remediation documentation/ADR index |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Retry API regressions passed, recovered closed-case oracle passed, dashboard recovery build passed; broad regression rerun retained only the two prior alternate supervisor sync/async defects | Retry tests 2 passed; default suite 452 passed / 2 failed / 33 deselected in 18.43s; full-suite green is not claimed; final focused/service/environment/tracker oracles pending |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Environment/import/dependency verification passed; root tracker reconciled and accidental duplicate tracker removed; updated dashboard served on 127.0.0.1:5173 | 25 direct requirements / 282 constraints and pip check green; no packages installed; final local inference/service and 93-test remediation oracles ongoing; broad suite retains exactly two pre-existing supervisor failures |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Final four-fix oracle green; local live checks passed Ollama and authenticated API/WebSocket/frontend but backing-service gate found schema registry stopped after Docker shutdown | 93 passed, zero exit; local live suite 2 passed / 1 failed / 3 excluded cloud/hosted checks; starting existing schema-registry container and rerunning service assertion |
| 2026-10-07 | `TASK-6.7`, `TASK-6.8` | Four requested local defects verified and deployed; retained broader tasks blocked with occupied WIP slots; current remediation guide and historical diagnostic reconciled | 93 focused tests passed; actual Ollama inference passed; restored backing-service and authenticated API/WS/frontend asset checks 2 passed; build/scoped lint green with warnings; default suite 452 passed / 2 known supervisor failures / 33 excluded; both gateways verified identical restart checkpoint and full cited final outputs; GCP/browser/corpus/ownership/restore gaps remain |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Began repository cleanup and documentation reconciliation within occupied WIP slots; inspected tracked/untracked files, generated artifacts, current decisions and tracker | Tracker validator zero exit: 47 tasks, occupied WIP 2/2; requested four split ZIPs and Word summaries retained; cleanup/docs and final verification pending |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Removed confirmed generated test/build directories, redundant monolithic ZIP and ignored root logs; removed five unreferenced root scratch/test-rewriter scripts | Preserved requested backend/frontend/tests/config ZIPs, Word summaries, runtime evidence, quarantine, private settings and historical implementation docs; status/doc reconciliation pending |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Added concise PROJECT_STATUS and documentation index distinguishing verified local results, historical plans and unfinished production work | Uses October 7 machine evidence without implying a fresh October 10 application run; root README, runbook and stale readiness text being reconciled |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Reconciled root/dashboard README, operations runbook, readiness history and model matrix with verified local access/restart/report behavior; removed misleading obsolete dashboard instructions | Historical gate results preserved and clearly labeled; production limitations and no-billable-GCP boundary remain explicit; final link/diff and repo-state checks pending |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Removed unused React/Vite starter SVGs after searching dashboard references | Kept used favicon and Specula logo assets; current UI source and required images remain intact |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Finished requested repository cleanup and status navigation; current guides now distinguish October 7 verified fixes from historical gate failures and pending production work | Tracker 47 tasks / 2 occupied blocked slots valid; git diff --check zero exit; 7 documentation pages have zero broken relative links; retained all four split ZIPs, two Word docs and runtime/private evidence; no application tests run for documentation-only cleanup |
| 2026-10-10 | `TASK-6.7` | User authorized next priority; inspected corpus builder/runtime and local ATT&CK v19.2 workbook; recorded ADR-015 before implementation; resumed task in occupied WIP slot | Tracker 47 tasks / 2 occupied slots valid at clock-in; workbook has 697 techniques, 176 groups and 20,628 relationship rows; Docker engine currently stopped; offline build/runtime oracle pending |
| 2026-10-10 | `TASK-6.7` | Implemented standard-library local ATT&CK workbook ingestion, exact FAISS build for small corpora, source/artifact provenance metadata and explicit corpus readiness | Local build, loader/hash checks and Docker read-only mount validation pending; no package installation or network feed use |
| 2026-10-10 | `TASK-6.7` | Built offline ATT&CK v19.2 corpus from existing workbook with exact FAISS index | 873 records (697 techniques, 176 groups; 172 groups with technique relations); source SHA-256 and three artifact hashes verified; local loader ready and G0016 profile present; deployed API and retrieval oracle pending |
| 2026-10-10 | `TASK-6.7` | Corrected local corpus manifest to distinguish source workbook hash, version and actual deterministic embedding algorithm; readiness rejects stale corpus; added workbook contract oracle | Offline rebuild, artifact verification and deployed API checks pending after metadata correction |
| 2026-10-10 | `TASK-6.7` | Rebuilt offline ATT&CK v19.2 corpus and deployed it to both Docker APIs through the read-only data mount | 873 records; exact IndexFlatIP; source SHA-256 and three artifact hashes recorded; focused workbook/corpus/ingestion oracle 31 passed; deployed readiness HTTP 200 reports corpus ready, 873 records, artifacts verified; container technique, group and group-search queries returned ok; case attribution still unverified |
| 2026-10-10 | `TASK-6.7` | Ran read-only post-build attribution on the retained synthetic case, using its frozen timeline, deployed Neo4j and verified corpus | Case-linked four Event UIDs and six cited TTP observations resolved; corpus version/hash and a candidate profile recorded; local Ollama was stopped, so explanation_model_unavailable and model_used=unavailable; no new case was run or finding published |
| 2026-10-10 | `TASK-6.7` | Restarted installed local Ollama and reran retained-case attribution; saved ignored machine evidence in data/verification/local_corpus_latest.json | Zero exit: four confirmed Event UIDs, six ATT&CK TTP observations, ATT&CK-xlsx-v19.2 corpus hash, candidate G1040, actual qwen3:8b explanation; only actor_sequence_inferred flag. Read-only probe did not republish finding or establish retrieval quality/new end-to-end acceptance |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Reconciled README/status/remediation/model documentation with new corpus evidence; corrected corpus loader description and attribution code formatting; returned broad integration task to blocked after local subset | TASK-6.7 and TASK-6.8 occupy WIP 2/2, 0 active; retrieval quality, new end-to-end finding delivery, real browser and production gates remain; final tracker/diff verification pending |
| 2026-10-10 | `TASK-6.7` | Clock-out focused corpus regression suite rerun after final code/doc pass | 31 passed, zero exit in 1.83s; source/artifact hash and retained-case Ollama probe previously passed; broad integration task remains blocked |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Final authenticated Docker readiness assertion passed after documentation reconciliation | Visualizer HTTP 200; overall success; threat_intel ready with 873 records and verified artifacts; no GCP service calls, packages, model downloads or remote push |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Read-only implementation review of current corpus, attribution, readiness and delivery paths | Found hash-vector candidate recall risk, tactic-order sequence overweighting, duplicate-TTP sufficiency error, 26-hour static-corpus readiness expiry and unconfirmed Kafka delivery; no code or tests run for this review; prioritized fixes remain in blocked integration scope |
| 2026-10-10 | `TASK-6.7` | User authorized verification and repair of five reviewed issues; recorded ADR-016 before changes and resumed the occupied integration slot | Focused red/green attribution, freshness and delivery checks plus local Docker Ollama/Kafka evidence pending; TASK-6.8 remains blocked |
| 2026-10-10 | `TASK-6.7` | Added regression cases for inferred tactic order, duplicate TTPs, exhaustive profile retrieval and pinned-workbook freshness | Baseline red run pending; tests intentionally encode corrected behavior before source edits |
| 2026-10-10 | `TASK-6.7` | Reproduced four implementation defects with executable focused oracles | 4 failed as expected: tactic-order changed rank, duplicate single TTP escaped insufficiency, hash-vector shortlist blocked profile lookup, and static workbook exceeded 26-hour timer; fixes pending |
| 2026-10-10 | `TASK-6.7` | Implemented exhaustive verified group listing for attribution, ignored inferred tactic order in alignment, counted distinct TTPs, disabled pseudo-semantic TTP inference and separated static workbook freshness from daily feeds | Focused regressions and existing attribution contracts pending; broker receipt and consumer wiring still pending |
| 2026-10-10 | `TASK-6.7` | First focused green run found scoring-scale regression: no-sequence profile received full Jaccard while recorded-sequence profiles retained weighted score | 71 passed / 1 failed; restored common 0.4 Jaccard scale with zero alignment for inferred/absent chronology; rerun pending |
| 2026-10-10 | `TASK-6.7` | Added bounded broker acknowledgement to attribution receipts and local DFKG consumer service; changed consumer to commit Kafka offsets only after Neo4j result consumption and store topic partition/offset | Focused tests and live Docker broker-to-Neo4j receipt oracle pending; no new packages or services outside local Docker |
| 2026-10-10 | `TASK-6.7` | Focused attribution, corpus freshness and consumer regression suite passed after fixes | 73 passed, zero exit; local Docker deployment and actual Ollama/Kafka consumption oracle pending |
| 2026-10-10 | `TASK-6.7` | Deployed new local DFKG consumer from existing image and restarted both APIs with source-mounted fixes | Compose config valid; consumer and both APIs running; actual broker acknowledgement, Neo4j consumption and Ollama/readiness oracle pending |
| 2026-10-10 | `TASK-6.7` | Published a synthetic retained-case attribution through actual local Ollama, Kafka and the new DFKG consumer; saved ignored machine evidence in data/verification/local_attribution_delivery_latest.json | Zero exit: qwen3:8b, four confirmed Event UIDs, two distinct TTPs, pinned corpus hash, algorithm v2; broker acknowledged findings.attribution partition 0 offset 788 and Neo4j Entity with same finding UID, topic, partition, offset and refs confirmed consumption; historical closed case checkpoint remains unchanged |
| 2026-10-10 | `TASK-6.7` | Reconciled README, current status, remediation, model matrix, validation commands and runbook with exhaustive attribution, pinned freshness and local broker/consumer evidence | Historical October 7 case result preserved; new full unattended case, ranking benchmark, browser and production gates remain open; broader regression and final clock-out pending |
| 2026-10-10 | `TASK-6.7` | Broader local regression suite completed after five fixes | 399 passed / 2 failed / 16 deselected; the two failures are the previously recorded alternate supervisor sync/async invoke defect, outside the five repaired attribution/delivery paths; all 73 focused tests and local Ollama→Kafka→Neo4j probe passed |
| 2026-10-10 | `TASK-6.7` | Final code review removed the legacy FAISS shortlist fallback from attribution; search-only adapters now fail closed; added regression | Prevents silently reintroducing pseudo-semantic candidate selection through an older adapter; focused rerun pending |
| 2026-10-10 | `TASK-6.7` | Final focused retrieval/scoring/freshness/delivery/consumer oracle passed after removing the fallback | 74 passed, zero exit in 7.79s; deployed API restart and final runtime assertion pending |
| 2026-10-10 | `TASK-6.7` | Restarted both APIs with final source; first immediate readiness request raced server startup and connection closed | Consumer remains running; rerun authenticated readiness with bounded startup retry pending; no application defect inferred from the startup race |
| 2026-10-10 | `TASK-6.7` | Authenticated deployed readiness passed after startup retry; current docs now distinguish 74-test local fix result from older four-fix and full-suite history | API HTTP 200 overall success, threat_intel ready/873/artifacts verified; consumer running; broader run 399 passed / 2 known supervisor failures / 16 excluded; final tracker/diff verification pending |
| 2026-10-10 | `TASK-6.7`, `TASK-6.8` | Closed local five-issue repair subset and returned broad integration task to blocked with WIP retained | All five defects reproduced or operationally confirmed, fixed and locally verified; full unattended new-case run, ranking ground truth, browser/GCP scope and production ownership/restore remain; no package install, model download, billable GCP call or git push |
| 2026-10-11 | `TASK-6.7` | Reconnected initialization to a loopback host boot controller that tears down and recreates the project Compose stack while retaining volumes; frontend polls completion and deployed readiness | Focused controller tests 3 passed; frontend build, Compose config and diff check zero exit. Tracker validation initially found the new log row out of order; corrected and passed. Live Docker execution pending because engine access is denied in this session |
| 2026-10-11 | `TASK-6.7` | User browser reached local boot controller but server identity verification returned 503 before Docker execution; added existing local validation token as an offline credential for boot and readiness requests | Four focused controller tests passed; frontend build and diff check zero exit. Live browser retry and Docker recreate remain unverified in this session |
| 2026-10-11 | `TASK-6.7` | Rotated the local validation credential after it was pasted into chat and rewrote the ignored backend policy | Configuration script and tracker validation zero exit; credential file exists and policy expiry is valid; new value not printed; browser retry still pending |
| 2026-10-11 | `TASK-6.7` | Removed browser token entry from local boot; loopback controller now accepts only local dashboard requests and reads the existing private token server-side for visualizer readiness | Four focused controller tests, frontend build and tracker validation passed; live browser/Docker retry pending after host controller restart |
| 2026-10-11 | `TASK-6.7`, `TASK-6.8` | Real browser showed missing ingestion selectors and WebSocket-gated launch; live local Neo4j query confirmed zero Case and Event nodes after container recreation. Restored date/log-limit/port controls and added host-side Windows log ingestion linked to a new local case, plus local investigation/review polling; mounted persistent service volumes in the local Compose override | Source changed; focused tests, Compose validation and live end-to-end verification pending |
| 2026-10-11 | `TASK-6.7`, `TASK-6.8` | Added bounded Windows log ingestion job with preserved raw evidence, parameterized case/Event links and local-token API invocation; frontend no longer requires WebSocket for HTTP launch. Added named data volumes for Neo4j, Quickwit, Kafka and Redis. | 25 focused API/ingestion tests passed; frontend build/lint and Compose config zero exit (pre-existing lint warnings). Real date-bounded Windows extraction and end-to-end browser run pending |
| 2026-10-11 | `TASK-6.7`, `TASK-6.8` | Finished local case launch guards and verification; returned broad tasks to blocked state because live Docker/browser execution and production recovery gates are outstanding. | Focused suite 25 passed using workspace pytest temp; frontend build/lint, Compose config and diff check zero exit. Initial default pytest temp location was denied by Windows sandbox; rerun passed. Host controller restart and real browser run pending. |
| 2026-10-11 | `TASK-6.7` | Diagnosed the user's new 404: port 8400 was still serving the earlier three-route controller. Stopped that process and launched the current controller; clarified the frontend error for future stale-controller 404s. | Current OpenAPI lists local ingestion/status/review routes; invalid interval POST returns expected HTTP 422. Actual date-bounded ingestion and browser case completion remain pending. |
| 2026-10-11 | `TASK-6.7` | Rechecked the replacement controller and frontend after restart. | Authenticated local readiness HTTP 200 success: Redis, Kafka, Quickwit, Neo4j, Chroma and threat-intel ready; LLM configured. Frontend build/lint and tracker validation zero exit. Browser must retry Launch for actual ingestion execution. |
| 2026-10-11 | `TASK-6.7` | Found Data Stores render crash on empty or denied store payloads and lost React-only job state after refresh. Replaced fragile store field access with status cards and added current-job discovery plus tab session job ID recovery. | Code changed; frontend build/lint, controller route and live browser verification pending. Existing in-progress controller must not be restarted until its job finishes. |
| 2026-10-11 | `TASK-6.7` | Added safe Data Stores status rendering, current-job endpoint ordered before dynamic job lookup, refresh polling and New Investigation after paused/completed cases. Kept the existing controller running to avoid interrupting any active ingestion. | Focused controller/pipeline tests 7 passed; frontend build/lint and diff check zero exit. Live browser recovery awaits safe controller restart after the current run. |
| 2026-10-12 | `TASK-6.7` | Diagnosed fresh local case failure at the supervisor node: host Ollama was stopped, so the visualizer could not reach `host.docker.internal:11434`. Started the installed Ollama server and retried the saved checkpoint without reingesting evidence. | Case ingestion had extracted 5,596 records and linked 349 accepted events. Host and container both received HTTP 200 from Ollama `/api/tags` with `qwen3:8b`; checkpoint advanced through 8 traces and 6 findings to debate. Retry still running. |
| 2026-10-12 | `TASK-6.7` | Retry completed to HITL review with 14 traces and no failed nodes. Updated frontend restore path to prefer the saved case snapshot when the original controller job remains in an error state after a successful API retry. | Retry API HTTP 200; case status `hitl_review`, paused at `hitl`, 14 traces, no failed nodes. Frontend build/lint and final tracker validation pending. |
| 2026-10-12 | `TASK-6.7` | A second local ingestion began while diagnosing the first. Preserved it and made an explicit `?case=LOCAL-...` URL take precedence over automatic current-job recovery so the first case remains reviewable. | Original case snapshot remains `hitl_review` with 14 traces and zero failed nodes; new case `LOCAL-28636e994caf46babfdd1fd9d390181a` was ingesting when checked. Frontend verification pending. |
| 2026-10-12 | `TASK-6.7` | Rechecked live state after the URL recovery fix. | Frontend build/lint and diff check zero exit; original case remains at HITL. Second case advanced to `investigating` after extracting 10,000 records and linking 1,989 accepted events. |
| 2026-10-12 | `TASK-6.7` | Diagnosed repeated HITL 409s for case `LOCAL-28636e994caf46babfdd1fd9d390181a`: concurrent clicks arrived while one review held the case lock. Added review-in-progress button lock and periodic saved-snapshot refresh so the UI stops showing a stale HITL gate. | Saved checkpoint confirms approve -> tier-3 guardrail failure -> HITL -> later approve override -> closed with `acceptance_status=incomplete`, 19 traces and final output ref. Frontend verification pending. |
| 2026-10-12 | `TASK-6.7` | Verified the HITL UI repair and current case snapshot. | Frontend build/lint, diff check and tracker validator zero exit. Existing lint warnings only; no new backend review request sent. Case remains closed with limitations; broad live-integration task remains blocked. |
| 2026-10-12 | `TASK-6.7` | Diagnosed missing graph/store display. Direct Neo4j has 2,207 Event and 4 Case nodes; local validation API sees 101 graph nodes, Quickwit returns 10 records and FAISS has 873 vectors. Browser views use a different signed-in identity and admin-only store routes. | Graph and store data intact; local dashboard visibility repair active. Chroma reports zero collections; DuckDB remains unavailable. |
| 2026-10-12 | `TASK-6.7` | Added ADR-017 for local-only store views; extended loopback controller with case-scoped graph proxy and local Quickwit/Chroma/FAISS views; dashboard graph and store pages now use those routes and display errors explicitly. | Code changed; focused tests, frontend build/lint and live controller deployment pending. Production API authorization rules unchanged. |
| 2026-10-12 | `TASK-6.7` | Restarted the completed-job loopback controller and checked all new local dashboard store routes. Returned broad integration task to blocked after the local repair passed. | 9 focused tests passed; frontend build/lint and Python compile zero exit. Live local routes: Neo4j HTTP 200/101 nodes, Quickwit HTTP 200/10 records, FAISS HTTP 200/873 vectors, Chroma HTTP 200/0 collections, DuckDB explicitly unavailable. Browser sign-in path remains separately unverified. |
| 2026-10-12 | `TASK-6.7` | Began case graph and agent execution visibility repair under ADR-018; confirmed live store has 2,207 Events, 703 Processes, 1,504 DetectionFindings, 22 Entities, while prior view returned only 100 Case/Event edges. Added case-scoped bounded multi-type graph response, complete counts, case selector metadata and explicit derived case-tag links. | Code changed; focused verification and live deployment pending. |
| 2026-10-12 | `TASK-6.7` | Updated graph UI with dynamic node legend, case selection, shown/total counts and distinct derived link styling. Saved complete Qwen agent output and citations in new checkpoints; local job polling now displays intermediate snapshots, agent analysis and generated report. | Code changed; verification pending. Existing checkpoints still retain 200-character historical trace observations but full finding summaries remain saved. |
| 2026-10-12 | `TASK-6.7` | Added idempotent AgentRun and Report projection from saved checkpoint steps into case-linked Neo4j nodes, with actual model labels and evidence counts. Backfilled two existing local investigations from their checkpoints. | Backfill zero exit: 19 AgentRun plus Report for closed case and 14 AgentRun for HITL case. Direct live graph query now returns 49 nodes across Case, Event, Process, DetectionFinding, Entity, AgentRun and Report with full per-type counts. |
| 2026-10-12 | `TASK-6.7` | Ran first focused API/controller suite after source changes. | 8 passed, 8 setup errors because sandbox denied default Windows Temp pytest directory; rerun with workspace `--basetemp` pending. Frontend build/lint, Python compile, tracker validator and direct live graph query passed. |
| 2026-10-12 | `TASK-6.7` | Restarted visualizer/HITL APIs and loopback controller after confirming no local job was active; restarted Vite frontend. Repeated the checkpoint projection and checked live routes after API restart. | Focused API/controller suite 16 passed with workspace basetemp; Qwen live role-dispatch/attribution oracle 1 passed; frontend build/lint and Python compile passed. Graph HTTP 200 with 19 AgentRun and 1 Report; checkpoint HTTP 200 with 19 traces and report. Repeated projection retained 19/14 runs without duplicates. |
| 2026-10-12 | `TASK-6.7` | Completed local case graph and agent/report visibility subset under ADR-018; returned broader integration task to blocked in its occupied WIP slot. | Final focused suite 29 passed; live Qwen oracle 1 passed; frontend build/lint, Python compile, tracker validator and diff check zero exit. Running local graph route reports 1 Case, 1,902 Events, 5 Processes, 2 DetectionFindings, 1 Entity, 19 AgentRuns and 1 Report for the closed case. Browser visual review and new end-to-end run remain unverified. |
| 2026-10-12 | `TASK-6.7` | Clock-out reran the verification oracle after final tracker state change. | 29 focused tests passed, tracker validator zero exit with occupied WIP 2/2 and 0 active, live HTTP case graph/report assertion passed. No package installation or git push. |
| 2026-10-12 | `TASK-6.7` | User requested a larger graph sample. Recorded ADR-019 and resumed the occupied task slot to raise the per-type cap to 300. | Clock-in tracker and diff checks zero exit; source change pending. |
| 2026-10-12 | `TASK-6.7` | Raised every case graph node type to 300, allowed up to 2,100 stored relationships among displayed nodes, and reduced layout iterations for larger graph responses. Updated the dashboard copy to state the 300-node cap. | Code changed; tests and live endpoint verification pending. |
| 2026-10-12 | `TASK-6.7` | Checked the revised graph query against the largest local case and ran focused source verification. | Direct graph assertion returned 300 Events, 300 Processes and 300 DetectionFindings (902 nodes, 1,501 edges) while totals remained 1,995/517/1,478; 16 focused tests passed; frontend build/lint, Python compile and tracker validator zero exit. Live API restart pending. |
| 2026-10-12 | `TASK-6.7` | Restarted the visualizer API with the 300-node cap, verified the running local controller route, and returned the broader integration task to blocked in its occupied WIP slot. | Live HTTP 200 returned limit 300, 902 nodes and 1,501 edges; each of Event, Process and DetectionFinding showed 300. Final clock-out verification pending. |
| 2026-10-12 | `TASK-6.7` | Clock-out verification of the 300-per-type local graph view. | 16 focused tests passed; tracker validator and diff check zero exit. Live API returned 300 each for the three populated large types; frontend build/lint zero exit. No packages installed or git push. |
| 2026-10-12 | `TASK-6.7` | Began persisted investigation history and result tabs under ADR-020. Inspected saved checkpoints: timeline artifact exists for closed case even though structured `timeline.events` is empty; DAG node currently stores analysis prose without a verified structured path. | Clock-in tracker validator zero exit; UI guidance search returned keyboard-navigation and empty-state requirements. Implementation pending. |
| 2026-10-12 | `TASK-6.7` | Added an authorized lightweight history endpoint that summarizes accessible saved checkpoints and a loopback dashboard proxy; case snapshots now include the persisted start timestamp. | Backend source changed; focused verification and live restart pending. |
| 2026-10-12 | `TASK-6.7` | Added keyboard-navigable Pipeline, History, Agents, Timeline, Attack Graph and Report tabs. History opens persisted cases; agent cards show actual action, model, output and citations; timeline uses structured reconstruction or preserved event chronology; attack graph tab distinguishes saved prose from a verified path; report tab shows saved status and limitations. | Frontend source changed; build/lint and live UI checks pending. |
| 2026-10-12 | `TASK-6.7` | Ran focused source verification for the history and tab changes. | Frontend build/lint, Python compile and tracker validator zero exit; 16 API/controller tests passed. Live service restart and case history assertion pending. |
| 2026-10-12 | `TASK-6.7` | Restarted visualizer and loopback services and read live history. Four saved checkpoints appeared, including the closed 19-agent report case and the 14-agent HITL case. Corrected history evidence counts to use actual Case-to-Event links so pre-triage cases are not shown with zero events. | Initial history proxy HTTP 200 and saved-status assertion passed; event-count correction needs redeployment and recheck. |
| 2026-10-12 | `TASK-6.7` | Browser inspection reached the sign-in page, so the authenticated visual tabs cannot be inspected with the current browser session. Clarified purpose labels and added attack-analysis availability in history. | Source build previously passed; live tab visual review depends on an existing signed-in browser session. No credentials requested or changed. |
| 2026-10-12 | `TASK-6.7` | Restarted the visualizer API with corrected history counts and checked live history and snapshot through the loopback controller. | HTTP 200 history returned four checkpointed cases: closed case 1,902 linked events, 19 agent steps and report; HITL case 319 linked events, 14 steps and no report; older paused cases 633 and 1,995 linked events. Snapshot HTTP 200 includes start time, 1,902 evidence records, timeline artifact and report. |
| 2026-10-12 | `TASK-6.7` | Completed local investigation history and result tabs under ADR-020; returned broader live integration task to blocked. | Final frontend build/lint, Python compile, diff check and 16 API/controller tests passed. Live history/snapshot assertions passed. Browser visual inspection stopped at sign-in in the available Chrome session; no sign-in credentials were used. |
| 2026-10-12 | `TASK-6.7` | Clock-out reran verification after the final task state update. | 16 focused tests passed, tracker validator zero exit with occupied WIP 2/2 and 0 active, and live history/report HTTP assertion passed. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | User requested ZIP evidence intake and separate formal court/technical reports; recorded ADR-021 before changes and resumed both occupied slots. Case LOCAL-0673fdbd14074f31a7bf1c27d37d422b has 19 traces, 80 evidence records, DAG prose, report, and zero structured reconstruction events. | Clock-in tracker validation passed. Added bounded ZIP preflight/preservation and source-folder ingestion through existing OCSF pipeline; verification pending. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Added ZIP source selection and archive-layout help, preserved upload provenance in case/checkpoint, formal court and technical HTML report builders/download routes, dual artifact state for new runs, report preview/download/print controls and explicit saved-case load errors. Added upload/export and report documentation. | Source changed; security/ingestion/report checks and live deployment pending. Court output is unsigned with review gaps, never a fabricated Daubert pass. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Initial compile/build and regressions passed. Investigation of quiet results found log-analysis base-schema conversion discarded process-specific fields; corrected adapter to retain validated record attributes, report actual model invocation count and emit a trace for no applicable evidence. | 22 existing focused tests passed; frontend build/lint and compile zero exit. Added correction rationale to ADR-021; archive/report security checks pending. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Added executable archive traversal/symlink/duplicate/compression/JSON checks, raw-upload receipt test, dual-report escaping/admissibility checks and log-rule field-retention regression. Report exhibits include normalized JSON hashes; historical adapter/clock/screening limitations are explicit. Downloaded HTML is retained by content hash in ignored report storage. | New verification suite pending. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Ran archive/report and ingestion/detection regressions. Corrected test ZIP construction to retain raw backslashes on Windows and configured the test client as loopback so the real origin guard remains exercised. | 58 passed, 2 test-harness failures; corrected rerun pending. Frontend build/lint, tracker and diff checks passed. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Expanded regression run identified that Python ZipInfo normalizes backslashes on Windows even when reading an archive. Validator now checks the original central-directory filename and rejects control characters. Added actual ingestion-coverage counts and finalized receipt diagnostics. | 95 passed, 1 archive-boundary regression failed before fix; rerun pending. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Corrected archive original-name handling; added execution-start source/runtime manifests for future reports and explicit historical version gaps. Court detection section records structured screening fields and citations rather than model narrative as facts. | 96 focused/security/graph tests passed after ZIP fix; latest report reliability changes compile successfully. Live deployment/report assertions pending. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Restarted completed-job local controller and APIs, fetched both reports for the requested case, verified their exact SHA-256 headers and retained review copies. Added source/date/port/provenance ingestion regression. Browser inventory is empty, preventing visual report inspection. | Court report HTTP 200 (30,492 bytes), technical HTTP 200 (372,454 bytes), invalid archive HTTP 422; verification script zero exit. Final source/regression checks pending. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Final suite passed; an additional source-format review found Sysmon process identity aliases and full executable paths were not handled by Windows process/rule adapters. Corrected aliases/PIDs and basename signature matching, with regressions. Added pending-checkpoint handling so a new upload does not show a false saved-case 404. | 97 tests passed before the final Windows-format correction; frontend build/lint, compile and diff checks passed. Final normalization rerun/redeployment pending. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Verified archive preflight, source/date/port intake, report integrity/escaping, graph flow and final Windows export corrections. | 109 focused regressions passed; final API reload and live report check pending. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Reloaded verified API code, rechecked both live reports and retained printable review copies for the requested case. Returned broader tasks to blocked after completing the local subsets. | 109 focused tests passed; frontend build/lint, Python compile and diff check passed. Live dual report HTTP/SHA-256 assertions and invalid ZIP rejection passed. Visual review unavailable because no browser surfaces are enabled; no new full uploaded Qwen run claimed. Reports are unsigned drafts with validation gaps, not certified admissible evidence. |
| 2026-10-12 | `TASK-6.7`, `TASK-6.8` | Clock-out tracker and repository consistency verification after final state transitions. | Tracker validator and diff check zero exit; 47 unique tasks, occupied WIP 2/2, 0 active. No dependencies installed or remote push. |

| 2026-10-13 | `TASK-6.7` | Clock-in tracker validation passed; resumed sidebar history scope under ADR-022. Added independent saved-case routes, reused artifact views, fixed case selection for Neo4j, authorized case store proxy and evidence-specific Quickwit queries. | Frontend build/lint and case isolation oracle pending; no dependency changes. |
| 2026-10-13 | `TASK-6.7` | Frontend build and lint executed after history relocation. | Both zero exit; existing bundle-size and three lint warnings remain. Case/store tests running. |
| 2026-10-13 | `TASK-6.7` | First backend subset passed; added route access checks and retained global Quickwit display default while case views allow 300 records. | 14 passed; local frontend/controller unreachable, so live browser/server checks unavailable. Final verification pending. |
| 2026-10-13 | `TASK-6.7` | Final build/lint passed. Case-access test exposed a test setup using a captured driver factory, which attempted an unavailable live database; replaced setup with an explicit empty authorization driver. | Corrected isolated test rerun pending; live unavailable state is not treated as passing. |
| 2026-10-13 | `TASK-6.7` | Expanded regression suite completed: 33 passed, 2 failed from captured driver-factory mocks attempting unavailable Neo4j. Corrected the new store-access fixture and the same existing recovery-test fixture without changing runtime authorization. | Full corrected 35-test rerun pending. |
| 2026-10-13 | `TASK-6.7` | Sidebar History and independent case review completed locally. Final oracle: `venv\Scripts\python.exe -m pytest tests/test_case_store_views.py tests/test_local_boot_api.py tests/test_visualizer_api_db.py tests/test_investigation_recovery.py tests/test_api_authorization.py -q --basetemp=.pytest-history-all-verified-20261013`. | 35 passed, zero exit; frontend build/lint, Python compile and diff checks passed. Quickwit case evidence capped at 300, shared FAISS labelled, unsupported case stores explicit. Frontend/controller unavailable for live visual verification. Returned broader task to blocked; next: start services and verify signed-in history navigation with multiple saved cases. |
| 2026-10-13 | `TASK-6.7` | Excluded repository-local pytest scratch directories from Git; clock-out tracker/repository verification. | No source artifacts removed; no dependencies installed or remote push. |
| 2026-10-13 | `TASK-6.7` | Clock-in tracker passed. Diagnosed readiness 401: matching local credential expired 16.69 hours ago. ADR-023 and controller credential renewal added without altering grants. | Scoped renewal verification pending; no secret values printed. |
| 2026-10-13 | `TASK-6.7` | Renewal preserves credential hash and grants; expired renewal and revoked-token rejection tests executed. Live controller has no active investigation and reproduces readiness HTTP 401. | 27 tests passed; safe controller reload/live credential verification pending. |
| 2026-10-13 | `TASK-6.7` | Renewed existing local credential and reloaded idle loopback controller. Scoped oracle: `venv\Scripts\python.exe -m pytest tests/test_local_boot_api.py tests/test_api_authorization.py -q --basetemp=.pytest-boot-renewal-20261013`. | 27 passed; Python compile/diff checks passed. Before renewal live readiness returned visualizer HTTP 401; after renewal and controller reload live readiness asserted success with all store/broker checks ready. Ollama configured only, no inference or Docker teardown repeated. Broader task returned to blocked; next: signed-in browser initialization check. |
| 2026-10-13 | `TASK-6.7` | Inspected evidence.zip as untrusted data. Preflight passed: 9 files/24 records. Offline shared normalization reproduced GCP resource-string AttributeError at cloud_normalizer.py:38; 10 Windows records dropped as EventID 0, MFT rejected for empty path, 2 EDR records dropped. | No database writes, model calls or archive changes. Remaining field mapping diagnosis pending. |
| 2026-10-13 | `TASK-6.7` | ZIP diagnosis complete: layout/JSON valid, 24 records. Offline normalization: 12 dropped (10 Windows, 2 EDR), 3 errors (2 GCP resource strings, 1 MFT missing native path fields), 9 normalized with potential defaults. All 3 UEBA rows become HTTP activity because artifact_type/event_type is absent. | Archive-specific assertions and 15 upload/report regressions passed. Original archive/application source unchanged. 404 is consistent with ingestion abort before investigation checkpoint. Next remediation: field mapping/semantic validation, actionable per-file errors and timestamp provenance; no full ingestion/model run claimed. |
| 2026-10-13 | `TASK-6.7` | Clock-in tracker passed. ADR-024 records explicit upload aliases, preserving originals and rejecting unknown event times. Added exported-record adapter for common Windows/GCP/EDR/MFT/UEBA/memory/vulnerability fields. | Integration, guide modal and scoped verification pending. |
| 2026-10-13 | `TASK-6.7` | Integrated aliases after preservation/security scanning for uploaded records, added file-labelled ingestion exclusions, source-reported memory findings and native modal ZIP guide. | Offline archive normalization and frontend checks pending. |
| 2026-10-13 | `TASK-6.7` | Added visible upload exclusion diagnostics and aliases for target_filename; corrected Windows network normalization to retain missing endpoint addresses as null. Shared source memory findings are labelled declarations. | Initial offline check exposed missing endpoint and file aliases; corrected checks and regression suite pending. |
| 2026-10-13 | `TASK-6.7` | Alias/preservation/upload regressions and frontend build/lint executed. Real user ZIP tested through shared intake using isolated store mocks: 24 raw records preserved, 22 normalized events from 21 records, 3 missing-timestamp exclusions. | 23 tests passed; archive hash unchanged, no actual database/model calls in asserted intake; frontend checks zero exit with existing lint warnings. Controller reload and clock-out checks pending. |
| 2026-10-13 | `TASK-6.7` | Added receipt normalization contract/time policy and verified controller is idle after the original failed upload. Final existing-normalizer regressions started. | User ZIP yields 22 events from 21 records; 3 untimed records preserved/excluded. No real case run started; idle controller reload pending. |
| 2026-10-13 | `TASK-6.7` | Final verification: `venv\Scripts\python.exe -m pytest tests/test_export_aliases.py tests/test_uploaded_evidence.py tests/test_local_case_pipeline.py tests/test_local_boot_api.py tests/ingestion/test_phase2_phase3_normalizers.py tests/ingestion/test_cloud_normalizer.py tests/ingestion/test_stage2_ingestion_pipeline.py -q --basetemp=.pytest-upload-clockout-20261013`. Preserved EDR byte counts, reloaded idle controller, asserted live readiness success. | 59 passed; frontend build/lint and Python compile passed. Native dialog implemented; CUA reports no enabled browser surfaces, so visual/keyboard UI verification remains open. Original ZIP unchanged; no full uploaded Qwen run claimed. Broader task returned to blocked; next: user retry ZIP upload and signed-in popup check. |
| 2026-10-13 | `TASK-6.7` | Clock-in passed. Live upload controller log identifies Neo4j semantic error: MERGE Host uid=null in DetectionFinding write. ADR-025 records nullable host handling and live rollback verification. | Source records preserved before abort; earlier mocked-write oracle missed live constraint. Fix and real query checks pending. |
| 2026-10-13 | `TASK-6.7` | Initial edit helper had an indentation error before executing any writes; corrected helper updated static Cypher host guards for all affected typed-node writers and actual finding title/CVE aliases. | Real rollback oracle and regressions pending. |
| 2026-10-13 | `TASK-6.7` | Live rollback check wrote all 22 uploaded events but host-placeholder assertions caught a separate authentication fallback creating UNKNOWN_HOST. Removed that fallback and used source canonical identity/flat user name. All test transactions rolled back. | Corrected live rollback and regression checks pending; no retained test case. |
| 2026-10-13 | `TASK-6.7` | Executed `venv\Scripts\python.exe -m scripts.verify_uploaded_graph_writes evidence.zip`: actual Neo4j writes for 22 case events and 8 known/missing host templates passed. Transactions rolled back and case absence asserted. Executed focused optional-host/alias/upload/local/graph/stage2 suite. | 59 passed; 3 untimed records excluded as before. Live oracle isolates raw preservation/security; no full agent run claimed. Idle controller reload/clock-out pending. |
| 2026-10-13 | `TASK-6.7` | Reloaded idle controller; live readiness success asserted. Python compile passed; diff check detected relocated whitespace, corrected it before clock-out. Returned broader task to blocked after local nullable-host fix. | Real Neo4j rollback oracle passed (22 events, 8 known/missing host templates); 59 regression checks passed. Original archive/user cases untouched by verification; no full agent run started. Next: retry upload from the dashboard. |
| 2026-10-13 | `TASK-6.7` | Read-only benchmark review of user evidence.zip: all 9 manifest file SHA-256 values matched. Log assertions confirm failed external logons followed by success, encoded PowerShell staging, suspicious executable/LSASS/memory observations, outbound transfer, attempted Security-log clearing and SI/FN/volume timestamp inconsistency. Manifest expectations treated as declarations; encoded payload decoded only as data. | No code/data/model changes or investigation launched. Expected findings documented for comparison; excluded port 443 and absent malware/vulnerability timestamps limit coverage under current intake. Broader task remains blocked. |
| 2026-10-13 | `TASK-6.7`, `TASK-6.8` | Inspected pasted agent/timeline outputs and live saved case LOCAL-b61545991c054e0680d1061d6eb05687. 22 records preserved, timeline.events empty, acceptance incomplete. Root causes: DummyDFKGClient always returns empty citations (log findings dropped), network triage requires source IP/global destination (fixture fails prerequisites), synthesis sees truncated finding summaries, DAG node is an LLM stub with no graph calculation and a prompt asserting nonexistent preconditions. Specialist routing only follows dead-end categories. | Executable diagnostic assertions passed; no source/checkpoint modifications or new inference run. Guardrail Tier 3 failed and final report is incomplete. Next remediation: real case-scoped citation reads, evidence-bound analyses/timeline, fail-closed computed DAG and benchmark assertions. |
| 2026-10-13 | `TASK-6.7` | User requests complete remediation of failed analysis benchmark. ADR-026 recorded before changes: case-scoped citation reads, evidence-driven specialists, validated model selections, cited structured timeline and observed activity DAG, no invented exploit probabilities. | Atomic local acceptance oracle will assert expected fixture findings, controls, graph citations and dual reports; broader production gates retained. |
| 2026-10-13 | `TASK-6.7` | Added validated observation/model-review module, real case-scoped log citations, evidence-driven specialist routing, structured timeline/activity DAG and preserved source identifiers/outcomes in case records. | Debate/report/UI integration and adversarial/fixture checks pending. |
| 2026-10-13 | `TASK-6.7` | Integrated source-grounded supervisor/debate reviews, visible structured activity graph and technical-report graph payload. Network analysis now reports measured nonpublic/test-address transfers separately from potential public exfiltration, using actual canonical host identity when source IP is absent. | Fixture/negative-control/schema tests and fresh model run pending. |
| 2026-10-13 | `TASK-6.7` | Regression checks executed: orchestration/report/network/log/upload suite 84 passed; new incident/control, foreign-citation and hallucinated-output tests 3 passed. Frontend build/lint passed with existing warnings. Added source details to timeline artifacts and explicit file-metadata time labels. | Live model benchmark/API reload pending; historical case unchanged. |
| 2026-10-13 | `TASK-6.7` | First live qwen3:8b benchmark completed as LOCAL-be5e28f66343414cb1f9a1aa8d6728a8: all 5 specialists, 22 structured timeline events, 13 observed-graph nodes/5 temporal edges and both HTML reports. Assertions found network destination fields missing because its typed writer created Event before full intake properties were set; added fill-only enrichment of missing normalized fields and endpoint JSON decoding. | 104 regressions passed; final corrected live benchmark pending. No fabricated VULN probabilities promoted. |
| 2026-10-13 | `TASK-6.7` | Corrected remaining live adapter defects: missing network properties enriched without overwriting existing fields, actual callable log publisher, delivery failures retained as explicit local findings, case-scoped dedup, structured ATT&CK annotations in timeline. Reloaded idle services and started final ZIP run. | Final case result/assertions and regression rerun pending. |
| 2026-10-13 | `TASK-6.7` | Final live qwen3:8b case LOCAL-37e59a09621d4a57ab22edd213cf13ce passed expected findings, benign control, citation membership and report HTTP/SHA256 assertions: 15 validated findings (including 1 measured network transfer), 22 structured timeline events, 15 observation nodes/6 temporal edges, 5 specialists and dual reports. Strict model schema outputs independently checked. Final API restart preserved saved result. | 104 regression tests passed; frontend build/lint, compile and real Neo4j rollback oracle passed. Original failed checkpoint preserved. Three untimed records remain excluded; actor attribution/calibrated exploit probabilities unavailable; reports remain unsigned review drafts. No enabled browser surface for visual verification. Local subset complete; broader tasks remain blocked. |

| 2026-10-13 | `TASK-6.7`, `TASK-6.8` | Read-only review of supplied agent/timeline output for LOCAL-c653ec6838174caabe0845b9a723dda8 and its saved upload receipt. Confirmed 20 normalized events; port exclusions 80/443/53 filter both network records; three untimed malware/vulnerability records excluded. Main observations cited, duplicate unsigned-executable graph entries and model-review/judge limitations remain. report.pdf is 9,437,184 bytes and lacks EOF/trailer; pdfplumber extraction failed with Unexpected EOF. | Progress validation passed (47 tasks, occupied WIP 2/2). No case, model or implementation changes. Next: complete independent agent assessment/correlation and duplicate merging; rerun fixture with ports included; obtain a complete PDF for report review. Broader tasks remain blocked. |

| 2026-10-13 | `TASK-6.7`, `TASK-6.8` | PDF visual render attempted with existing pdftoppm; MiKTeX setup incomplete/access denied before rendering. No installation or escalation attempted. | Report content/layout could not be verified; source PDF also fails extraction. Clock-out progress validation follows; read-only diagnosis complete. |

| 2026-10-13 | `TASK-6.7`, `TASK-6.8` | Reviewed current git diff/stat and untracked implementation files to prepare requested commit message: upload alias normalization/diagnostics, nullable graph writes, case-bound analyses/timeline/activity graph, historical case views/store scoping, ZIP guide modal and controller credential renewal. | No commit created or implementation changed. Progress validation passed; broader task states unchanged. |
