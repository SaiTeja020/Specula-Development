# PROGRESS.md — Specula Development Tracker

> **Notice to AI Agent:** Obey strict WIP=2 constraint (`|active| <= 2`). Update this file **immediately** whenever task status transitions, code is created/modified, or verification commands run.

---

## Current Build Status
- **Active Phase:** Phase 6: Operational Readiness
- **Active Tasks (WIP=2):**
  - `TASK-6.7` **blocked**: local fixes verified; corpus/feed and authenticated browser acceptance outstanding
  - `TASK-6.8` **blocked**: local auth/restart verified; approved thresholds, ownership and full restore outstanding
- **Active WIP Count:** 2 (occupied WIP = 2 / 2; 0 active)
- **Last Updated:** 2026-10-07

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
