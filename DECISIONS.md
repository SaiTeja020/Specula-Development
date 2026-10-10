# DECISIONS.md — Architectural Decision Records (ADRs)

Central Architectural Decision Record (ADR) repository for the Specula Multi-Agent DFIR framework.

---

## 1. Document Purpose & Operational Rules

- **Central ADR Repository:** Records all core architectural, cryptographic, model distribution, and algorithmic decisions made for Specula.
- **Bidirectional Links:** Every ADR links directly to corresponding implementation phases and tasks in [PROGRESS.md](PROGRESS.md).
- **Mandatory Agent Rule:** Any future architectural deviation, library swap, or parameter modification by the AI agent MUST first be logged as a new ADR entry in `DECISIONS.md` before updating codebase files or `PROGRESS.md`.

---

## 2. ADR Index

| ADR-ID | Date | Title | Status | Related `PROGRESS.md` Phase |
| :--- | :--- | :--- | :--- | :--- |
| [ADR-001](#adr-001-blackboard-coordination--supervisor-governance-model) | 2026-08-14 | Blackboard Coordination + Supervisor Governance Model | Accepted | Phase 4 |
| [ADR-002](#adr-002-ingestion-pipeline-bifurcation-preservation-vs-abstraction) | 2026-08-14 | Ingestion Pipeline Bifurcation (Preservation vs. Abstraction) | Accepted | Phase 1 |
| [ADR-003](#adr-003-model-distribution--deployment-topology) | 2026-08-14 | Model Distribution & Deployment Topology | Accepted | Phase 4 & Phase 5 |
| [ADR-004](#adr-004-three-tier-cryptographic-provenance-architecture-vct) | 2026-08-14 | Three-Tier Cryptographic Provenance Architecture (VCT) | Accepted | Phase 1 & Phase 2 |
| [ADR-005](#adr-005-adversarial-quality-control-via-ach-debate-loop) | 2026-08-14 | Adversarial Quality Control via ACH Debate Loop | Accepted | Phase 4 |
| [ADR-006](#adr-006-dynamic-attack-graph-weighting-via-negative-log-transformation) | 2026-08-14 | Dynamic Attack Graph Weighting via Negative Log Transformation | Accepted | Phase 2 & Phase 3 |
| [ADR-007](#adr-007-mcp-integration-scope) | 2026-08-14 | MCP Integration Scope | Accepted | Phase 5 |
| [ADR-008](#adr-008-pcap-ingestion-and-binary-parsing) | Not recorded | PCAP Ingestion and Binary Parsing | Accepted | Phase 3 |
| [ADR-009](#adr-009-evidence-vector-store-runtime) | 2026-10-06 | Evidence Vector Store Runtime | Accepted | Phase 3 |
| [ADR-010](#adr-010-development-model-backend-and-fallbacks) | 2026-10-06 | Development Model Backend and Fallbacks | Accepted | Phase 4 |
| [ADR-011](#adr-011-hyperledger-fabric-anchoring-status) | 2026-10-06 | Hyperledger Fabric Anchoring Status | Deferred | Phase 2 |
| [ADR-012](#adr-012-evidence-bound-attribution-explanations-and-delivery-receipts) | 2026-10-07 | Evidence-bound Attribution Explanations and Delivery Receipts | Accepted | Phase 6 |
| [ADR-013](#adr-013-local-ollama-and-no-billable-gcp-validation) | 2026-10-07 | Local Ollama and No Billable GCP Validation | Accepted | Phase 6 |
| [ADR-014](#adr-014-evidence-collection-grounded-reports-and-local-runtime-protection) | 2026-10-07 | Evidence Collection, Grounded Reports and Local Runtime Protection | Accepted | Phase 6 |

---

## 3. Baseline ADR Entries

### ADR-014: Evidence Collection, Grounded Reports and Local Runtime Protection
- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision:** User authorizes repair of evidence collection, report defects, backend authorization and restart recovery. Evidence membership and triage are executed against case-scoped parameterized DFKG reads with deterministic relevance rules. Model narration may summarize only verified results; it cannot select arbitrary Cypher, fabricate evidence or silently complete an unprocessed batch. Reports and timeline artifacts render structured case evidence with explicit UTC timestamps and citations, preserving incomplete/degraded status rather than treating model prose as verified facts.
- **Runtime protection:** All sensitive HTTP and WebSocket endpoints require server-verified identity with case/role authorization. Browser identity must be conveyed to the backend. Local validation credentials are isolated and never committed or printed. Anonymous health may expose only liveness. Authentication configuration errors fail closed.
- **Persistence:** Use an installed supported durable checkpoint adapter if compatible with the existing infrastructure; otherwise use the installed LangGraph checkpoint contract with a local SQLite transaction/WAL backend using Python's standard library, explicitly scoped to single-host local Docker. Both API processes must share the durable checkpoint location. No dependency installation, hosted model or GCP service is authorized. Persistent checkpoint behavior must pass a real fresh-process pause/resume oracle.
- **Tracking:** Resume TASK-6.7 for evidence/report fixes and TASK-6.8 for authorization/recovery fixes; both broader acceptance criteria remain in force. Phase 7 items remain backlog until their complete oracles are run.

### ADR-013: Local Ollama and No Billable GCP Validation
- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision:** User directs current model testing to local Ollama, using the installed qwen3:8b model. Local runtime selects Ollama explicitly; Gemini/hosted endpoint probes are removed from the active verification workflow. The Ollama adapter rejects remote/cloud models and non-local endpoints and never pulls models or falls back to a hosted provider.
- **GCP boundary:** Validate only local gcloud CLI authentication/project configuration and ADC-file presence. Do not query Cloud Logging, enable services, create resources, change billing, or invoke GCP services that may require billing. CLI authentication does not establish Python ADC or audit ingestion. GCP ingestion remains unverified/deferred under this constraint.
- **Consequences:** Existing stub fixture evidence remains labeled as such. Live model verification must invoke Ollama through the actual role dispatcher and attribution explanation contract. No packages are installed.

### ADR-001: Blackboard Coordination + Supervisor Governance Model
- **Status:** Accepted
- **Context & Problem Statement:** High-volume DFIR analysis requires multiple specialized agents operating concurrently without getting trapped in rigid linear execution chains or unconstrained chaotic message passing. Massive JSON payload passing degrades LLM context windows and increases execution latency.
- **Decision & Tech Choice:** Implement a hybrid Blackboard Coordination + Supervisor Governance model. Specialist agent nodes read and write state directly via Neo4j graph nodes and Kafka streams. LangGraph `StateGraph` supervisor manages high-level routing, HITL interrupt gates, Analysis of Competing Hypotheses (ACH) triggers, and final reporting.
- **Alternatives Considered & Rejected:**
  - *Rigid linear LangGraph chaining:* Inflexible execution path; unable to dynamically adapt to unexpected forensic evidence types.
  - *Unconstrained Agent Blackboard:* High risk of race conditions, infinite loops, and uncoordinated state corruption without supervisor control.
- **Forensic & Research Consequences:** Reduces prompt token overhead by storing state in Neo4j/Kafka; maintains strict auditability of agent actions; enforces loop counters (`loop_count`) for deterministic execution.
- **Link to Progress.md:** [PROGRESS.md -> Phase 4 (LangGraph Blackboard Orchestration)](PROGRESS.md#phase-4-langgraph-orchestration-skeleton)

---

### ADR-002: Ingestion Pipeline Bifurcation (Preservation vs. Abstraction)
- **Status:** Accepted
- **Context & Problem Statement:** DFIR requires dual capabilities: legal admissibility (exact evidence preservation) and rapid LLM token-efficient processing. Direct ingestion of high-volume raw telemetry into LLMs causes context overflow, extreme financial cost, and slow inference.
- **Decision & Tech Choice:** Bifurcate the ingestion pipeline into two distinct streams:
  1. *Forensic Preservation Layer:* Raw logs are cryptographically sealed unmodified in Quickwit with Go/Rust SIMD hashing for legal chain-of-custody.
  2. *Analytical Abstraction Layer:* Raw telemetry undergoes Drain3 log parsing, SimHash deduplication, and MiniBatchKMeans clustering to achieve 90%+ token reduction prior to LLM analysis.
- **Alternatives Considered & Rejected:**
  - *Direct LLM ingestion of raw logs (GenDFIR baseline):* Exceeds context limits, cost-prohibitive, high latency.
  - *Prompt compression on raw evidence:* Distorts log structure, lacks deterministic reproducibility required in court.
- **Forensic & Research Consequences:** Guarantees 100% evidentiary integrity in Quickwit while reducing downstream LLM prompt sizes by >90%.
- **Link to Progress.md:** [PROGRESS.md -> Phase 1 (Evidentiary Data Flow)](PROGRESS.md#phase-1-local-sandbox--data-schemas)

---

### ADR-003: Model Distribution & Deployment Topology
- **Status:** Accepted
- **Implementation status (2026-10-06):** Target role-specific topology; not a verified production matrix. Current dispatcher behavior and deployment unknowns are documented in ADR-010 and [the runtime role matrix](docs/model_runtime_matrix.md).
- **Context & Problem Statement:** DFIR tasks vary significantly in reasoning complexity. Using a single monolithic model for all tasks is inefficient and costly. Conversely, using low-parameter local quantizations for orchestrating complex forensic graphs causes reasoning breakdowns.
- **Decision & Tech Choice:** Deploy a heterogeneous model topology across cloud and vLLM endpoints:
  - *Supervisor & Judge:* Nemotron-3 Ultra (High reasoning, debate evaluation, HITL gating).
  - *Log Analysis Agent:* Qwen2.5-72B (High context window & structured JSON log parsing).
  - *Network Analysis Agent:* Llama-3.3-70B (Graph path & network protocol reasoning).
  - *Malware & Stylometry Agents:* DeepSeek-R1 Distill (Specialized code analysis and reasoning).
  - *Report Generation Agent:* Llama-3.3-8B (Fast, concise summarization).
- **Alternatives Considered & Rejected:**
  - *Monolithic single-LLM architecture:* High cost, unnecessary compute wasted on simple tasks, single point of failure.
  - *Local quantizations for orchestration:* Higher error rate in structured JSON outputs and graph schema compliance.
- **Forensic & Research Consequences:** Optimizes latency, cost, and accuracy by matching task complexity with specialized LLM capacities.
- **Link to Progress.md:** [PROGRESS.md -> Phase 4 & Phase 5](PROGRESS.md#phase-4-langgraph-orchestration-skeleton)

---

### ADR-004: Three-Tier Cryptographic Provenance Architecture (VCT)
- **Status:** Accepted
- **Implementation status (2026-10-06):** Local hashing/Merkle handling is implemented. Case-root RSA/x509 signing and Hyperledger Fabric anchoring are target capabilities; Fabric is explicitly deferred for this milestone under ADR-011.
- **Context & Problem Statement:** Digital forensic evidence must satisfy the Daubert standard for legal admissibility in court, proving no tampering occurred post-collection across millions of incoming events.
- **Decision & Tech Choice:** Implement a three-tier Verifiable Credential & Telemetry (VCT) provenance architecture:
  1. *Atomic SHA-256 Hash Chains:* Generated per event upon ingestion.
  2. *Session Pymerkle Trees:* Batch hashes aggregated into Merkle tree roots per session window.
  3. *Case Anchor & Signature:* Final case Merkle root signed with RSA/x509 certificates and anchored to Hyperledger Fabric.
- **Alternatives Considered & Rejected:**
  - *Unsigned plain text log storage:* Fails legal admissibility standards; vulnerable to silent corruption or alteration.
  - *Simple RDBMS audit log tables:* Database administrators can alter database logs directly without cryptographic trace.
- **Forensic & Research Consequences:** Complete cryptographic integrity proof satisfies legal Daubert standards; tamper-evident verification.
- **Link to Progress.md:** [PROGRESS.md -> Phase 1 & Phase 2](PROGRESS.md#phase-2-forensic-preservation--vct-layer)

---

### ADR-005: Adversarial Quality Control via ACH Debate Loop
- **Status:** Accepted
- **Context & Problem Statement:** Single-pass LLM investigative findings suffer from hallucination and confirmation bias, which are fatal in forensic investigations.
- **Decision & Tech Choice:** Construct an Analysis of Competing Hypotheses (ACH) debate loop:
  - *Proponent Agent:* Nemotron-3 Super generates hypothesis based on evidence.
  - *Critic Agent:* Llama-3.3-70B challenges hypothesis and highlights gaps/hallucinations.
  - *Judge Agent:* Nemotron-3 Ultra evaluates claims.
  - *Execution Controls:* `MAX_ROUNDS = 3`, early termination when $\Delta \text{score} < 0.05$, strict `PARAMETRIC_KNOWLEDGE_REJECTED` filter requiring explicit evidence UIDs, and debate round offloading to Redis.
- **Alternatives Considered & Rejected:**
  - *Open-ended multi-turn LLM debates:* High risk of infinite loops and context exhaustion.
  - *Unconstrained single-pass generation:* High hallucination rate and unverified assumptions.
- **Forensic & Research Consequences:** Enforces empirical evidence anchoring; prevents unbacked LLM assertions from reaching final reports.
- **Link to Progress.md:** [PROGRESS.md -> Phase 4 (StateGraph & ACH Nodes)](PROGRESS.md#phase-4-langgraph-orchestration-skeleton)

---

### ADR-006: Dynamic Attack Graph Weighting via Negative Log Transformation
- **Status:** Accepted
- **Context & Problem Statement:** Standard shortest-path algorithms (e.g., Dijkstra) minimize path weights (distance/latency), whereas cyber attack paths follow the path of *maximum probability of compromise* and *highest impact*.
- **Decision & Tech Choice:** Transform vulnerability metrics (CVSS, EPSS) into path weights using a negative log formula in Neo4j/NetworkX:
  $$W = -\ln(\text{CVSS} \times \text{EPSS} \times \gamma + \epsilon)$$
  This maps high risk (probability near 1) to low edge weight, enabling standard shortest-path algorithms (Dijkstra) to natively compute the most likely attack path.
- **Alternatives Considered & Rejected:**
  - *Standard additive metric routing:* Fails to represent multiplicative probabilities of multi-step exploits.
  - *Static CVSS threshold filtering:* Ignores real-world threat intelligence (EPSS) and temporal exploit likelihood.
- **Forensic & Research Consequences:** Mathematically sound attack path calculation directly inside graph databases.
- **Link to Progress.md:** [PROGRESS.md -> Phase 2 & Phase 3](PROGRESS.md#phase-3-graph-streaming-ingestion--vector-retrieval)

---

### ADR-007: MCP Integration Scope
- **Status:** Accepted
- **Context & Problem Statement:** Over-coupling core algorithmic, graph query, and cryptographic logic to external protocol frameworks like MCP can slow initial prototyping and introduce unnecessary runtime dependencies.
- **Decision & Tech Choice:** Treat Model Context Protocol (MCP) servers (FastMCP) and Agent Skills strictly as deployment-side optimization wrappers and local data gateways. Core graph processing, OCSF parsing, and cryptographic logic remain written in native Python modules inside `src/`.
- **Alternatives Considered & Rejected:**
  - *Mandating MCP as strict prerequisite for core algorithms:* Creates architectural bloat, increases debugging complexity, hinders isolated unit testing.
- **Forensic & Research Consequences:** Clear separation of concerns; fast execution; modular testing without external server overhead.
- **Link to Progress.md:** [PROGRESS.md -> Phase 5 (MCP & Skill Development)](PROGRESS.md#phase-5-visualization-layer)

---

### ADR-008: PCAP Ingestion and Binary Parsing
- **Status:** Accepted
- **Context & Problem Statement:** Raw network packet captures (PCAPs) are critical forensic evidence but are binary files. They cannot be fed directly into text-based normalizers or LLMs, yet they must be preserved immutably and analyzed for lateral movement or C2 beacons.
- **Decision & Tech Choice:** PCAP ingestion follows a strict 4-step pipeline:
  1. *Capture:* Sourced from network sensors (tcpdump/Zeek) or manual uploads via the React dashboard.
  2. *Preservation:* Binary bytes are immediately SHA-256 hashed via Go/Rust SIMD and stored immutably in Quickwit (appended to the VCT ledger).
  3. *Binary Dissection:* Raw PCAPs are dissected using libraries (e.g., dpkt or scapy) to extract structural metadata (IPs, ports, payload).
  4. *Sanitization & Normalization:* Extracted fields pass through the Security Gate for NFKC/prompt-injection checks, then route to etwork_normalizer.py\ for mapping to OCSF NetworkActivity (Class 4001).
- **Alternatives Considered & Rejected:**
  - *Direct text parsing of PCAPs:* Impossible due to binary format, leads to data corruption.
  - *Storing parsed JSON instead of raw PCAP:* Destroys chain of custody; raw evidence must be preserved before parsing.
- **Forensic & Research Consequences:** Ensures legal admissibility of network captures while providing safe, standardized OCSF telemetry for the Network Forensics Agent.
- **Link to Progress.md:** [PROGRESS.md -> Phase 3](PROGRESS.md#phase-3-graph-streaming-ingestion--vector-retrieval)

### ADR-009: Evidence Vector Store Runtime
- **Status:** Accepted
- **Date:** 2026-10-06
- **Context:** Repository documentation described Qdrant, while the active ingestion runner, vector retrieval adapter, visualizer, requirements, and Compose stack use ChromaDB. An in-memory adapter is also available for tests and degraded local operation.
- **Decision:** ChromaDB is the persistent vector store for case evidence in the current development deployment. The `ChromaVectorStore` adapter may fall back to `InMemoryVectorStore` when ChromaDB is missing or unreachable; this fallback is process-local and is not durable. Qdrant is not part of the current deployment contract. The older `vector_indexer.py` helper remains a separate in-memory compatibility helper and does not establish a Qdrant service dependency.
- **Consequences:** Documentation, task records, and deployment examples must identify ChromaDB as persistent storage and InMemory as a non-durable fallback/test adapter. Qdrant references must be explicitly labeled legacy or removed when that helper is retired.
- **Link to Progress.md:** [PROGRESS.md -> Phase 6 (Operational Readiness)](PROGRESS.md)

### ADR-012: Evidence-bound Attribution Explanations and Delivery Receipts
- **Status:** Accepted
- **Date:** 2026-10-07
- **Context:** Independent review found that free-form model explanations can contradict deterministic scores, corpus refreshes can mix provenance, and Kafka queue acceptance does not establish delivery.
- **Decision:** Render attribution facts from validated deterministic results. Models may select only predefined explanation codes supported by those results; no model prose enters findings. Reject attribution computed across a detected corpus generation change. Record Kafka publication as pending, acknowledged, failed or unavailable, with non-blocking delivery callbacks; pending is explicitly unconfirmed and late outcomes are logged rather than mutating returned graph state.
- **Consequences:** Development remains non-blocking on Kafka. Confirmed delivery and downstream ingestion require separate live verification. Threat Attribution backend overrides apply to every supported selector, and unknown selectors fail explicitly.
- **Corpus build contract:** New manifests bind hashes of the FAISS, ID-map and metadata artifacts. Loaders deserialize the verified bytes and retain the prior snapshot if a generation is incomplete. Legacy manifests can be queried for compatibility, but cannot support case attribution until rebuilt with artifact hashes.
- **Link to Progress.md:** [PROGRESS.md](PROGRESS.md)

### ADR-010: Development Model Backend and Fallbacks
- **Status:** Accepted
- **Date:** 2026-10-06
- **Context:** ADR-003 describes a role-specific hosted model topology, while the checked-in runtime configuration defaults to deterministic stubs. No deployment environment or production credentials were available for inspection.
- **Decision:** The checked-in development default is `SPECULA_LLM_BACKEND=stub`, which returns `StubLLM` for roles unless overridden. The optional global `gemini` backend currently resolves a Gemini Flash model and applies it to roles routed through `get_llm`; it does not implement ADR-003's role-specific production matrix. Threat Attribution can independently use an OpenAI-compatible endpoint when `SPECULA_THREAT_ATTRIBUTION_BACKEND=openai_compatible` and its endpoint/key are configured; its model defaults to `kimi-k2.6`. Production role assignments are unconfirmed and must be supplied by deployment owners before a production claim.
- **Consequences:** README and config documentation must distinguish the development default and optional integrations from ADR-003's proposed production topology. Tests and traces should record the backend actually invoked. No secrets or credential values are recorded in this ADR.
- **Link to Progress.md:** [PROGRESS.md -> Phase 6 (Operational Readiness)](PROGRESS.md)

### ADR-011: Hyperledger Fabric Anchoring Status
- **Status:** Deferred
- **Date:** 2026-10-06
- **Context:** ADR-004 describes signing a case Merkle root and anchoring it to Hyperledger Fabric, but this repository contains no Fabric service, client, chaincode, or anchoring integration in the current Compose stack.
- **Decision:** Fabric anchoring is deferred beyond the current development milestone. Current VCT scope is local event hashing and Merkle-chain handling; it must not be represented as Fabric-anchored or production legal anchoring. Reconsider Fabric only with an approved trust model, deployment owner, integration criteria, and verification environment.
- **Consequences:** ADR-004 remains the target architecture for a future phase; implementation status is explicitly deferred. No Fabric deployment will be attempted as part of local documentation reconciliation.
- **Link to Progress.md:** [PROGRESS.md -> Phase 6 (Operational Readiness)](PROGRESS.md)
