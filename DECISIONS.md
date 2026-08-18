# DECISIONS.md — Architectural Decision Records (ADRs)

Central Architectural Decision Record (ADR) repository for the Specula Multi-Agent DFIR framework.

---

## 1. Document Purpose & Operational Rules

- **Central ADR Repository:** Records all core architectural, cryptographic, model distribution, and algorithmic decisions made for Specula.
- **Bidirectional Links:** Every ADR links directly to corresponding implementation phases and tasks in [PROGRESS.md](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/PROGRESS.md).
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

---

## 3. Baseline ADR Entries

### ADR-001: Blackboard Coordination + Supervisor Governance Model
- **Status:** Accepted
- **Context & Problem Statement:** High-volume DFIR analysis requires multiple specialized agents operating concurrently without getting trapped in rigid linear execution chains or unconstrained chaotic message passing. Massive JSON payload passing degrades LLM context windows and increases execution latency.
- **Decision & Tech Choice:** Implement a hybrid Blackboard Coordination + Supervisor Governance model. Specialist agent nodes read and write state directly via Neo4j graph nodes and Kafka streams. LangGraph `StateGraph` supervisor manages high-level routing, HITL interrupt gates, Analysis of Competing Hypotheses (ACH) triggers, and final reporting.
- **Alternatives Considered & Rejected:**
  - *Rigid linear LangGraph chaining:* Inflexible execution path; unable to dynamically adapt to unexpected forensic evidence types.
  - *Unconstrained Agent Blackboard:* High risk of race conditions, infinite loops, and uncoordinated state corruption without supervisor control.
- **Forensic & Research Consequences:** Reduces prompt token overhead by storing state in Neo4j/Kafka; maintains strict auditability of agent actions; enforces loop counters (`loop_count`) for deterministic execution.
- **Link to Progress.md:** [PROGRESS.md -> Phase 4 (LangGraph Blackboard Orchestration)](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/PROGRESS.md#phase-4-langgraph-orchestration-skeleton)

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
- **Link to Progress.md:** [PROGRESS.md -> Phase 1 (Evidentiary Data Flow)](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/PROGRESS.md#phase-1-local-sandbox--data-schemas)

---

### ADR-003: Model Distribution & Deployment Topology
- **Status:** Accepted
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
- **Link to Progress.md:** [PROGRESS.md -> Phase 4 & Phase 5](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/PROGRESS.md#phase-4-langgraph-orchestration-skeleton)

---

### ADR-004: Three-Tier Cryptographic Provenance Architecture (VCT)
- **Status:** Accepted
- **Context & Problem Statement:** Digital forensic evidence must satisfy the Daubert standard for legal admissibility in court, proving no tampering occurred post-collection across millions of incoming events.
- **Decision & Tech Choice:** Implement a three-tier Verifiable Credential & Telemetry (VCT) provenance architecture:
  1. *Atomic SHA-256 Hash Chains:* Generated per event upon ingestion.
  2. *Session Pymerkle Trees:* Batch hashes aggregated into Merkle tree roots per session window.
  3. *Case Anchor & Signature:* Final case Merkle root signed with RSA/x509 certificates and anchored to Hyperledger Fabric.
- **Alternatives Considered & Rejected:**
  - *Unsigned plain text log storage:* Fails legal admissibility standards; vulnerable to silent corruption or alteration.
  - *Simple RDBMS audit log tables:* Database administrators can alter database logs directly without cryptographic trace.
- **Forensic & Research Consequences:** Complete cryptographic integrity proof satisfies legal Daubert standards; tamper-evident verification.
- **Link to Progress.md:** [PROGRESS.md -> Phase 1 & Phase 2](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/PROGRESS.md#phase-2-forensic-preservation--vct-layer)

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
- **Link to Progress.md:** [PROGRESS.md -> Phase 4 (StateGraph & ACH Nodes)](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/PROGRESS.md#phase-4-langgraph-orchestration-skeleton)

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
- **Link to Progress.md:** [PROGRESS.md -> Phase 2 & Phase 3](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/PROGRESS.md#phase-3-graph-streaming-ingestion--vector-retrieval)

---

### ADR-007: MCP Integration Scope
- **Status:** Accepted
- **Context & Problem Statement:** Over-coupling core algorithmic, graph query, and cryptographic logic to external protocol frameworks like MCP can slow initial prototyping and introduce unnecessary runtime dependencies.
- **Decision & Tech Choice:** Treat Model Context Protocol (MCP) servers (FastMCP) and Agent Skills strictly as deployment-side optimization wrappers and local data gateways. Core graph processing, OCSF parsing, and cryptographic logic remain written in native Python modules inside `src/`.
- **Alternatives Considered & Rejected:**
  - *Mandating MCP as strict prerequisite for core algorithms:* Creates architectural bloat, increases debugging complexity, hinders isolated unit testing.
- **Forensic & Research Consequences:** Clear separation of concerns; fast execution; modular testing without external server overhead.
- **Link to Progress.md:** [PROGRESS.md -> Phase 5 (MCP & Skill Development)](file:///c:/Users/S%20Srirama%20Mithilesh/Specula/Specula-Development/PROGRESS.md#phase-5-visualization-layer)
