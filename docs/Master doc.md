# Specula master specification and implementation status

Autonomous multi-agent digital forensics and incident response framework

**Updated:** 29 October 2026

**Context:** SDC-II research project, Computer Science and Engineering, 2025–2026

**Scope:** Project purpose, architecture, supported examinations, verification limits and remaining work.

Specula preserves heterogeneous evidence, normalizes supported records, coordinates bounded forensic examinations and produces cited timelines, graph views and examination reports. The current delivery is a local development system with source-specific analysis and durable case workflows. Production readiness, independently measured forensic accuracy and expert acceptance remain open.

This document reconciles [Master doc.docx](Master%20doc.docx), [Master_doc_planned_changes.md](Master_doc_planned_changes.md), current source, [architectural decisions](../DECISIONS.md) and [the task tracker](../PROGRESS.md). The Word source already includes a Section 14 gap review. Its recommendations are assessed here rather than treated as automatically implemented or newly approved architecture. Both input documents remain unchanged.

## 1. Project explanation

### 1.1 Purpose and problem

Investigators must relate endpoint, network, identity, cloud and file-system evidence while preserving original context. Large log volumes exceed practical manual review and model context budgets. Unconstrained summaries can omit counter-evidence, confuse attempts with successful actions and invent unsupported explanations.

Specula separates preserved sources, deterministic observations, model assessments and analyst decisions. Neo4j supplies case-related entities and relationships; Kafka transports supported event/finding streams; LangGraph coordinates investigation stages. A model response is an assessment of supplied evidence, not a new evidence source.

The intended users are forensic examiners, SOC analysts, incident responders, legal/compliance reviewers and researchers. The system assists their work; qualified review, acquisition authority and custody verification remain human responsibilities.

### 1.2 Objectives and current scope

| Objective | Current interpretation |
| --- | --- |
| Reconstruct incidents across sources | Supported exports and bounded native artifacts work; coverage differs by source. |
| Preserve provenance and repeatability | Raw/member hashes, receipts, deterministic identifiers, execution manifests and durable checkpoints exist. Signed/anchored case provenance remains incomplete. |
| Reduce review volume and latency | Distillation and parallel workers exist. Enterprise compression and five-minute investigation claims remain research targets. |
| Improve correlation and chronology | Source-bound relationships, explicit outcomes and UTC chronology exist. Independent accuracy targets remain unverified. |
| Make analysis reviewable | Expose cited observations, structured hypotheses/challenges, validation and limitations. Private model reasoning is not a required deliverable. |
| Produce examination reports | Distinct court-oriented and technical PDFs exist; they remain unsigned drafts requiring examiner review. |

### 1.3 Status vocabulary

**Implemented** means source provides a bounded capability. **Verified locally** means a recorded executable oracle passed in its stated environment. **Partial** identifies working scope with gaps. **Deferred** identifies deliberately postponed work or live acceptance. **Planned** identifies requirements without sufficient delivery evidence.

These terms do not replace tracker states. Passing component tests do not establish whole-system forensic accuracy or production readiness. Recorded test totals, case results and service counts describe their recorded runs, not the present live environment.

## 2. Research basis and feature scope

### 2.1 Literature context

The supplied proposal identifies *GenDFIR: Advancing Cyber Incident Timeline Analysis Through Retrieval-Augmented Generation and Large Language Models* by Loumachi, Ghanem and Ferrag (2024) as the primary research basis. It describes log-to-document retrieval and LLM timeline synthesis. Specula's research direction adds source-specific examinations, graph relationships, constrained review and preservation metadata.

The proposal also names MADIK, CFA-Bench, CyberSleuth, DFIR-Metric, ForensicsData, ACH and OCSF. These motivate design and evaluation; their presence does not prove reproduction of their results. Bibliographic details, licensing and comparative claims require validation before publication. No new literature review was performed for this reconciliation.

### 2.2 Feature reconciliation

| Proposal feature | Implemented scope | Remaining work or changed assumption |
| --- | --- | --- |
| Semantic compression | Drain3, SimHash and entropy/clustering components; preservation separated from abstraction. | Measure payload-byte reduction and retained entities on representative workloads; no achieved 90% compression claim. |
| DFKG and GraphRAG | Deterministic entities, parameterized writes, case membership, bounded retrieval and case semantic indexing. | Validate retrieval quality, graph completeness and high-degree behavior at scale. |
| Temporal normalization and anti-forensics | Raw/normalized times, DHCP-bounded identity, MFT checks and bounded native FILE-record examination. | Independent clock-correction/timestomping validation; trained XGBoost/SMOTE detection is not an established delivered capability. |
| Evidentiary adversarial review | Separate proponent/critic/judge schemas, citation checks, coverage accounting and bounded correction. | Evaluate disagreement and false acceptance using independent cases. |
| VCT provenance | SHA-256, local hash-chain/Merkle components and source/execution receipts. | Uniform prompt/tool ledger, case signatures, investigator certificates, gossip fork detection and Fabric anchoring remain incomplete. |
| Malware and stylometry | Native PE/Capstone features, hashes/imports and bounded comparisons; imported findings labelled. | Independently labelled family/actor/AI-authorship data and trained classifiers remain unavailable. |
| Guardrails | Unicode sanitization, injection checks, parameterized queries, pattern/similarity checks and model review stages. | No validated fine-tuned Tier 2 safety classifier; adversarial coverage and universal parser isolation remain open. |
| Insider threat | Source-bound behavior context and strictly preceding transfer-counter baselines. | LSTM, FinBERT, communications NER and independently labelled intent detection remain planned. |
| Human review | Protected FastAPI review endpoints, LangGraph interrupt/resume and persisted decisions/state. | Production analyst workflow, escalation ownership and deployed cycle-bound acceptance remain open. |
| Dynamic attack graphs | Observed relationships separated from reviewed exploit topology; deterministic path solver. | Probability needs reviewed prerequisites and calibration. Original CVSS × EPSS probability claims are superseded. |
| Dynamic malware analysis | CAPE v2 connector, sample checks, durable claims and report retention. | Actual guest isolation/execution/snapshot acceptance deferred. YARA → Speakeasy → DRAKVUF is not an integrated delivered pipeline. |
| Impact and attribution | Cited impact context and deterministic ATT&CK profile ranking. | Actor identity, calibrated confidence and independently validated impact estimates remain unproven. |

### 2.3 Agent and model counts

The proposal's thirteen-agent narrative is historical. Its role matrix includes additional safety/report roles and combines identity with cloud. The current graph has **27 registered nodes**, including joins, deterministic stages and terminal controls. Node count is not a measure of independent forensic competence.

Read execution from `src/agents/graph.py`, its factories and saved traces. Deterministic parsers/rules/renderers are not LLM calls. Identity and cloud/container are separate roles; primary and specialist network examination are distinct.

## 3. Datasets and evaluation

### 3.1 Existing evaluation assets

| Asset | Purpose and limit |
| --- | --- |
| Unit/component fixtures | Positive/negative controls for normalization, correlation, native artifacts, citations, authorization and recovery. They verify specified contracts. |
| Synthetic investigation archives and answer keys | Multi-source cases with missed-observation/false-alarm checks. Expected stories and synthetic metadata are not evidence for conclusions. |
| Log-analysis ground truth and baseline seed | Versioned labels under `tests/fixtures/`; narrower than enterprise source coverage. |
| ATT&CK v19.2 workbook | Offline build recorded as 873 technique/group records, including 176 group profiles. A pinned reference, not a current live-feed guarantee. |
| Recorded local Ollama cases/probes | Scoped inference, review, delivery and recovery evidence; not independent actor/family ground truth. |
| Native binary/protocol fixtures | Packet fragments/retransmissions, resident NTFS records, minidumps and PE features with malformed/ambiguous controls. |

### 3.2 Proposed external benchmarks

The original plan names CERT Insider Threat, CICIDS2017/2018, Digital Corpora, DARPA Transparent Computing, ForensicsData, CFA-Bench, CyberSleuth, DFIR-Metric and AutoBnB-RAG. They remain candidate evaluation sources unless an imported version, licence, preprocessing procedure and executed result are recorded. MITRE ATT&CK and NVD are knowledge sources, not automatically forensic truth. EPSS is a separate FIRST source; it must not be conflated with NVD.

### 3.3 Stylometry benchmark

The proposed 2,000–5,000 sample, four-class GPT/Claude/Gemini/human dataset is not established as validated. Pre-2023 repository dates or submission timestamps alone do not prove human authorship. Completion needs controlled generation provenance, verified human labels, deduplication, family/prompt-separated train/test sets, independent annotation and uncertainty reporting.

### 3.4 Required measurements

Measure observation precision/recall, negative-control false alarms, ordering errors, citation correctness, omitted evidence, review coverage and source-specific failures. Actor/family accuracy needs labels independent of retrieval profiles. Report model-response validity separately from forensic correctness. Freeze dataset versions, rules, actual model identities and settings before comparing runs.

## 4. Deployment and persistence

### 4.1 Current deployment

The development system uses single-host Docker Compose, a Windows loopback controller and React/Vite. The local override selects installed Ollama `qwen3:8b` for analysis and `qwen3-embedding:0.6b` in the normalized-consumer embedding path. Local inference is the authorized testing mode; billable GCP and hosted-model probes are excluded.

Ubuntu/air-gapped enterprise deployments, Kubernetes orchestration and the proposal's hardware/RAM budgets are targets rather than verified capacity claims. Ollama failures must remain visible; the local contract does not automatically download models or fall back to hosted inference.

### 4.2 Components

| Component | Current responsibility | Development interface |
| --- | --- | --- |
| Loopback controller | Boot/readiness, local acquisition, ZIP intake and authorized proxy | `127.0.0.1:8400` |
| HITL API | Protected case execution/review | Port 8200 |
| Visualizer API | Protected case/history/results/store APIs and WebSocket | Loopback port 8300 |
| React/Vite | Investigation, history, review, reports and stores | Development port 5173 |
| Kafka | Normalized events, supported findings streams and offsets | Host 9092; internal 29092 |
| Schema Registry | Wire schema validation | Port 8081 |
| Neo4j/APOC | Case membership, typed evidence and analysis/audit projections | Bolt 7687; HTTP 7474 |
| Quickwit | Preserved raw-record index and retrieval | Port 7280 |
| Redis | Active-case cache and supporting coordination components | Port 6379 |
| Chroma | Case-evidence vectors and scoped retrieval | Port 8000 |
| FAISS | Shared versioned threat-intelligence reference corpus | In process |
| DuckDB | Durable case analytics snapshots | Case-specific files |
| SQLite WAL | Local LangGraph checkpoints and execution leases | Shared API checkpoint volume |
| Ollama | Installed local analysis/embedding inference | Host port 11434 |

Actual exposure follows base/local Compose together. These ports are not an approved production exposure policy. Fabric is absent from the deployed stack; Qdrant is not the evidence-vector runtime.

### 4.3 Durability and container dependencies

The APIs share `specula-checkpoints` with SQLite WAL state, transactional writes and execution leases that fence concurrent/stale case workers. This accepted local design is single-host, not a distributed checkpoint database.

The local override adds persistent volumes for Kafka, Redis, Quickwit and Neo4j. Chroma uses `specula-chroma-data` at **`/data`** with a pinned image digest. The old `/chroma/chroma` mount did not cover the active database. Preservation/migration receipts recorded matching counts for 9,344 vectors; that is a historical baseline, not a current count. Historical indexing receipts can disagree with present vectors; the monitor exposes mismatches.

ReportLab is pinned in requirements and baked into the shared `specula-skeleton-hitl-api` image. The build exercises the real PDF renderer and fonts. Rebuild and recreate APIs for dependency changes; installation into one live container is not durable. The loopback controller proxies authorized PDF bytes rather than using the superseded host-rendering workaround.

Uploads, analytics, reference manifests and private settings retain separate storage responsibilities. Volumes alone do not establish off-host backup, retention locks or WORM enforcement. Preserve evidence during routine recovery; do not delete volumes to fix startup.

## 5. User workflow and access

An analyst selects local collection or a supported ZIP, sets applicable filters and starts a case. Preserved evidence feeds investigation. The UI shows execution status, observations, review coverage, timeline, graph, reports and datastore views. History reopens saved snapshots and their PDF preview/download path without rerunning agents.

Supabase supplies authenticated identities. Backend case ownership/membership controls access; client role labels cannot grant privileges. Unowned legacy cases require trusted assignment. Global raw-store views require administrator authorization. Restricted local credentials support declared local/synthetic operations and remain private.

Guest login supplies a tab-scoped frontend identity, bypassing Supabase login to enter the interface. Sign-out is local. It does **not** grant a bearer identity or bypass backend case authorization. Guest entry does not constitute a verified signed-in analyst workflow.

The live-ingestion header groups source/case settings with readable spacing. Buttons/action links share rounded styles; the Specula brand links home. JSON/code panels are escaped, formatted, scrollable and copyable. ZIP guidance uses a file tree and tables; the popup is centered slightly left on desktop and bounded/centered on mobile. Browser visual and authenticated workflow acceptance remain separate from component rendering tests.

## 6. Evidence inputs and coverage

### 6.1 Fourteen conceptual categories

The fourteen categories are research scope, not fourteen complete connectors. Stage markers retain original priority: five foundational categories first, broader sources later. Present support is listed separately.

| Category | Original stage | Current supported scope | Consumers and remaining coverage |
| --- | --- | --- | --- |
| System logs | Stage 1 | Structured Windows collection/exports, Sysmon/EDR context; separate syslog/network routes. | Evidence/log analysis. Full auditd/vendor/endpoint-agent coverage unverified. |
| NTFS artifacts | Stage 1 | Exported records and bounded resident NTFS 3.0/3.1 FILE fragments. | NTFS/time examination. Full disk, nonresident reconstruction and complete USN work remain separate. |
| Network logs/captures | Stage 1 | Zeek/Suricata, TCP/UDP syslog, Ethernet PCAP/PCAPNG and bounded reconstruction. | Primary/specialist network. Captures do not establish full network visibility. |
| AD/cloud audit | Stage 1 | Auth exports/session context, CloudTrail and Azure Activity envelopes, imported GCP audit. | Identity/cloud. Broad AD/IAM effective access and live cloud acquisition remain open. |
| EDR/UEBA | Later stages | Source-export normalization, context and counter analysis. | Log/memory/insider. Vendor production connectors are not established by exports. |
| Malware samples | Later stages | Preserved PE samples, static features, imported findings and optional CAPE. | Malware/stylometry. Live guest and validated family/authorship inference remain open. |
| Email/messaging | Later stages | Related supplied context can inform supported records. | Dedicated EML/MBOX and Slack/Teams/SharePoint connectors remain unverified. |
| Memory dumps | Later stages | Targeted regions, small MDMP process dumps and supplied findings. | Memory specialist. Full-RAM/kernel/complete Volatility work is not delivered by this workflow. |
| Browser artifacts | Later stages | No verified general browser SQLite examination workflow. | Dedicated extraction/correlation remain planned. |
| Threat intelligence | Later stages | Offline ATT&CK corpus, STIX/NVD builder/retrieval and hashed manifests. | Attribution. Provider fallback/feed operations and calibrated labels remain open. |
| Container/Kubernetes | Later stages | Exported logs, audit outcomes/configuration and bounded captured RBAC matching. | Cloud/container. Workload execution and complete effective permissions unverified. |
| Vulnerability scans | Later stages | Exported findings, cited context and reviewed topology input. | DAG/impact. Live scanner integration/calibrated risk remain open. |
| Cloud topology | Later stages | Static identity mapping and source-bound lifecycle/context relationships. | Cloud/graph. Dynamic inventory and ephemeral NAT/pod resolution remain partial. |
| Investigator query | Later stages | Case input and bounded routing/follow-up contracts. | Supervisor. Queries cannot create evidence, tool permissions or arbitrary executable actions. |

### 6.2 Intake contract

The ZIP adapter maps source folders at the archive root: `windows`, `edr`, `memory`, `malware`, `ueba`, `vuln_scan`, `gcp_audit`, `mft`, `container`, `ad_auth`, `network`, `aws_cloudtrail`, `azure_activity`, `access` and `kubernetes`. Folder count is independent of conceptual category count.

JSON holds objects/arrays; JSONL holds one object per line. Native artifacts need designated paths and manifest metadata and are examined as data, never run on the investigator host. Binary EVTX must first be exported for this adapter. Examination code creates native receipts; user JSON cannot forge them.

Limits: 50 MiB compressed, 200 MiB expanded, 25 MiB per file, 500 entries and 100,000 exported records. Preflight rejects unsafe/unsupported members and malformed input. Date/port/file-event filters constrain intake; excluded coverage remains visible. Archive, original-file and normalized-record hashes identify different representations and are not interchangeable.

Use [ZIP upload reference](ZIP_LOG_UPLOADS.md), the current in-app guide and `src/ingestion/upload_archive.py` for exact routes. [Permission export format](access_snapshot_format.md) defines access snapshots. Manifest identity, qualifications, authority and custody are uploader declarations, not authenticated facts.

### 6.3 Native examination limits

Packet analysis supports captured Ethernet IPv4/IPv6 TCP/UDP, complete non-overlapping fragments, bounded TCP reconstruction and DNS/plaintext HTTP/TLS-prefix observations. Gaps, overlap, lower-bound counters and unsupported encryption remain explicit. Captured bytes do not independently prove application receipt or exfiltration.

Memory exposes captured region/module/thread/permission features with omitted-range limits. PE examination exposes independently extracted structure/opcode/import features. NTFS paths require matching host/volume/artifact/record-sequence context; unresolved or reused parents and hard-link alternatives remain visible. Native timestamps do not prove current filesystem state or drive-letter mapping.

## 7. Preservation and evidence contracts

Preserve source bytes/records before analytical transformation. Sanitize the analytical representation while retaining original material. Pydantic validates supported OCSF classes; OSSEM-style source metadata and context/unmapped fields preserve meaning normalization cannot infer. Invalid input cannot silently become successful ingestion.

Generate deterministic UIDs before writes. Resolve hosts using source identity/event time; DHCP validity constrains IP reuse. Static hostname/cloud-ID mapping exists. Complete pod/NAT/cloud identity resolution remains future work. Unknown hosts must not collapse into one invented local identity.

Use parameterized Cypher and idempotent `MERGE` keys. Case membership follows preserved evidence relationships, not a shared entity's first case tag. Process parentage uses host/GUID/start/lifetime context; ambiguous PID-only parents stay unresolved.

Source declarations, deterministic observations, model hypotheses and analyst-reviewed exploit transitions have different evidential status. Failed actions, benign controls, contradictions, inaccessible channels and incomplete acquisition must remain visible in review/reporting.

### 7.1 Cryptographic and source identity boundaries

SHA-256 binds the exact representation hashed. Merkle roots aggregate recorded leaves; they do not establish that an acquisition was authorized, a source was truthful or every relevant event was collected. Quickwit append-only client behavior is not equivalent to independently enforced WORM retention. Full per-prompt/per-tool transcripts, authenticated case signing, investigator certificates, Fabric anchoring and the proposed peer-gossip fork detector remain future integration work under the relevant accepted decisions.

Source-event identity and case membership must survive retry and shared-entity reuse. A successful acknowledgement from one storage stage cannot stand in for missing graph/vector/analytics receipts. Report/render hashes must stay distinct from original evidence hashes.

## 8. Investigation graph and agents

### 8.1 Executed flow

```text
Authorized case evidence
  -> Supervisor
  -> Evidence collection + Log analysis + Primary network
  -> Primary join
  -> Required/source-triggered specialists when applicable
  -> Specialist join
  -> Bounded investigative follow-up
  -> Timeline reconstruction -> Threat attribution -> DAG/impact
  -> Proponent -> Critic -> Judge
       -> bounded correction, or incomplete review -> HITL
  -> Guardrails 1 -> 2 -> 3
       -> failure -> HITL
  -> Report generation + Timeline artifact generation
  -> Final output join

HITL: approve follows its entry-specific route;
      reject closes rejected; clarify returns to Supervisor.
```

Joins precede synthesis. Supported evidence needs as well as dead ends can trigger specialists; the original dead-end-only description is outdated. Authorized local follow-up may append bounded acquisition and reanalyze evidence. Late external findings do not automatically establish a consistent new report revision.

### 8.2 Role capability map

| Role/stage | Current responsibility | Limit |
| --- | --- | --- |
| Supervisor | Source-cohort review, source-derived plan and controlled dispatch. | Primary fan-out is graph-defined; model selection cannot invent tools. |
| Evidence collection | Case-linked retrieval, preserved context, triage and acquisition receipts. | Retrieval is not proof of complete acquisition. |
| Log analysis | Signatures/context, persistence lifecycle, script reconstruction and correlations. | Reconstructed code is not run; source outcomes constrain interpretation. |
| Primary network | Flow/session rules and suspicious/benign context. | Volume/periodicity alone is not confirmed C2 or exfiltration. |
| Network specialist | Packet/protocol examination and scoped correlations. | Missing/encrypted bytes limit conclusions. |
| Memory | Targeted native artifacts and labelled imported findings. | No blanket kernel/rootkit/credential-dump confirmation. |
| Identity | Host/session/SID/logon lifetimes, recorded privileges, supported permission snapshots. | Complete effective AD/IAM access unverified. |
| Cloud/container | Lifecycle/audit context and captured Kubernetes RBAC rules. | API configuration/rule match is not execution/effective access. |
| Malware/stylometry | Static features, comparisons and optional laboratory observations. | Similarity is not author/family/original-host execution. |
| Insider threat | Source counters and preceding within-case baselines. | No inferred intent; lower-bound counters are not comparable measurements. |
| Follow-up | Select server-built case-cited tasks, preserve receipts/dead ends. | Two rounds, up to six selected actions per round; no model-supplied command execution. |
| Timeline | Full chronology plus labelled relationships and uncertainty. | Association/order is not causation. |
| Attribution | Trusted/cited ATT&CK mapping, profile comparison and constrained explanation. | Ranking is not actor identity or calibrated probability. |
| DAG/impact | Observed topology, cited impact, separately reviewed exploit paths. | Weighted probability requires preserved calibration evidence. |
| Proponent/critic/judge | Distinct hypotheses/challenges/resolution contracts. | Valid structured output is not factual correctness. |
| Guardrails | Escalate detected unsafe/invalid output and review failures. | Current tiers are not a complete production safety boundary. |
| Report/artifact renderers | Deterministically render saved evidence and limitations. | Presentation cannot cure incomplete acceptance. |

### 8.3 Review and loop limits

Model assessments allow one corrective retry. Submitted/validated coverage is separate from preserved-event count. Foreign citations and invalid schemas are rejected. Independent argument/challenge/resolution contracts prevent automatic acceptance of the critic's position.

Evidence-backed review permits one corrective debate cycle before unresolved/incomplete review reaches HITL. The legacy skeleton branch retains a three-round cap/confidence-delta convergence check; it is not the real-evidence acceptance rule. Partial review remains incomplete even if a human authorizes draft output.

ReAct helpers have iteration/tool/timeout budgets and state includes `loop_count`. The standalone supervisor has a three-attempt HITL helper, but the deployed factory initializes that helper count on entry. A durable end-to-end clarification/re-dispatch cap still requires verification. Graph recursion limits alone do not establish that business policy.

### 8.4 Local audit follow-up

`local_endpoint_audit` is limited to a case originally collected from the current Windows host. Uploaded archives cannot trigger acquisition from the machine they describe. The collector validates bearer identity, case authorization, source host, stage and preserved anchors. It derives a five-minute context window clipped to the original selected dates, refuses windows over one hour and reads fixed Security, Sysmon Operational and PowerShell Operational channels, at most 100 records per channel.

One durable acquisition claim is allowed per case/cycle; interrupted claims do not silently repeat collection. New evidence follows preservation, normalization, graph/vector/analytics and normalized-stream contracts without replacing ownership or initial provenance. At most one automatic evidence reanalysis follows acquisition; unresolved/partial results require review. End-to-end live acquisition acceptance remains open. See [follow-up acquisition](followup_acquisition.md).

### 8.5 CAPE laboratory experiments

Only preserved, hash-verified native PE bytes can be submitted to the configured authenticated CAPE v2 API. Imported JSON, URLs, arbitrary paths and model options cannot select executable content. Durable claims precede submission; returned task IDs precede polling. Uncertain submissions are not automatically repeated. Raw accepted reports are bound to sample, task, custom case identity and guest and are retained with protected downloads.

Fixed Windows/drop-route settings request isolation; actual guest/firewall isolation still needs acceptance. Laboratory timestamps and behavior are not original-host chronology. Local HTTP-emulator/concurrency/reload/report tests verify the connector contract, not a functioning malware sandbox. Real benign-control execution, capture attribution and clean-snapshot restoration remain deferred at the user's request. See [CAPE integration](cape_integration.md) and [sandbox setup](malware_sandbox_setup.md).

## 9. Runtime harness and models

### 9.1 Blackboard and transport

Kafka/Neo4j provide transport/shared evidence rather than workers forwarding uncontrolled prompt histories. Normalized consumers and supported publishers expose delivery states and references. Queueing, broker acknowledgement and completed graph writes are different results; consumer write/offset receipts establish the latter path.

The proposal's universal all-agent Kafka/VCT write claim does not describe every current path. APIs also project checkpointed AgentRuns, reports, timelines and analysis relationships directly into Neo4j using deterministic keys. These are analysis/audit projections, not new source evidence. Uniform publication and cryptographic tool/write coverage remain partial.

The supervisor/coordination layer owns dead-end reasoning. APOC milestone patterns do not determine investigative inactivity. The proposed GraphRAG limits of three hops, 100 nodes and 300 relationships are bounds to verify per tool; frontend caps do not prove retrieval completeness or universal enforcement.

### 9.2 Tools, rules and replay

Normalization, graph, retrieval, threat-intelligence and examination modules exist under `src/mcp/`, `src/ingestion/` and `src/agents/`. Their presence does not establish the entire conceptual five-server MCP roster, runtime dataset-query service or centralized provider fallback/sandbox bridge.

Tool arguments derive from supported server contracts, case membership and validated references. Native parsers have input/budget controls; universal process/container isolation remains a security/deployment task.

Role-specific signatures/configuration and execution source fingerprints exist. Hot-reloadable rules, immutable case-pinned rule lookup and deterministic replay across model/feed changes remain incomplete. Package/source manifests are provenance, not a replay engine.

### 9.3 Actual model selection

Local Compose selects Ollama; isolated regressions may use `SPECULA_LLM_BACKEND=stub`. Optional Gemini/OpenAI-compatible settings and model labels are separate from actual invocation. Traces identify deterministic steps, backend/model, validity and limitations.

The original Nemotron/Qwen/Llama/DeepSeek/Kimi/MiniMax role matrix is a research deployment option, not the installed production topology; its malware model labels are internally inconsistent. Provider availability, cost, model diversity and safety calibration need independent decisions. See [model runtime matrix](model_runtime_matrix.md) and [local model testing](local_model_testing.md).

The local adapter verifies installed models and rejects prohibited cloud/remote paths. Using one model family across roles does not supply independent model diversity. Deterministic citation/outcome checks do not eliminate correlated reasoning errors.

### 9.4 Observability and guardrails

Case/trace identifiers, model metadata, latency, retries, receipts and saved reviews support inspection. Complete trace continuity through every tool, transport and analyst decision remains to be accepted. Analyst disagreement must not silently retrain rules/models or rewrite evidence.

Tier 1 uses deterministic patterns. Tier 2 uses unsafe-phrase similarity with bag-of-words or an available sentence-transformer path; it is not a delivered fine-tuned SAFE/UNSAFE classifier. Tier 3 invokes model review. Failure escalates. The proposal's latency/robustness claims remain targets, not established benchmarks.

### 9.5 Deterministic scoring and interpretation

ATT&CK candidate scoring in `src/agents/threat_attribution/scoring.py` combines `0.4 * Jaccard + 0.6 * Smith–Waterman`. Jaccard compares observed/profile technique sets. Local alignment uses match 2, mismatch/gap -1, normalized by twice the shorter sequence length. Missing profile sequence, including a sequence inferred only from ATT&CK tactic order, contributes zero alignment rather than fabricated order. Stable sorting returns at most three candidates. Confidence bounds are heuristic evidence measures, not statistical actor-authorship probabilities.

Within-case insider baselines use strictly preceding observations from a seven-day window, at most 100 prior samples, with at least 20 needed. Median/MAD and magnitude controls identify source-counter deviation; partial-capture lower bounds are excluded as incomparable. This replaces any claim that an LSTM or sentiment model has already detected insider intent.

The original blast-radius expression based on sensitive-asset counts and logged exfiltration bytes remains a proposal unless its inputs and computation are verified for a case. Current impact observations must not turn source counters into confirmed stolen bytes. Likewise, the original CVSS/EPSS/gamma attack-path expression is not a calibrated exploitation model; reviewed topology follows ADR-031.

## 10. Ingestion and datastore behavior

### 10.1 Common contracts

```text
Capture / upload
  -> original representation and SHA-256 preservation receipt
  -> sanitized analytical text and source identity
  -> supported OCSF normalization and validation/quarantine
  -> deterministic UID and case tagging
  -> supported Kafka publication / abstraction / indexing
  -> typed graph persistence and case-scoped investigation
```

Entry points differ: archive intake and the continuous normalized consumer do not execute one identical function. Verify preservation and indexing receipts for each path. Preservation failure must stop affected intake rather than fabricate success.

Network inputs include finite files, Zeek/Suricata JSONL follow mode with offsets/rotation handling, and configured TCP/UDP syslog. Kafka orders within partitions; cross-host chronology uses recorded UTC instants and uncertainty, never arrival order.

The original Go/Rust SIMD/Filebeat fleet and universal raw-Kafka sketch are not current descriptions of every path. Python components implement hashing/preservation. Threat-intelligence loading has a separate hashed manifest/reference path and must not masquerade as case evidence.

### 10.2 Analytical stores and monitoring

Chroma case/event keys and model-digest-aware indexing support local embeddings and scoped retrieval. Missing/stale collections or receipt mismatches remain visible. In-memory fallback is non-durable and cannot establish successful persistent indexing.

FAISS holds a shared versioned reference corpus with hashes and verified atomic reload. Hash/deterministic embeddings in test/compatibility paths do not establish semantic quality. DuckDB holds atomically replaced per-case analytics with parameterized authorized reads. Neither needs invented activity to look dynamic.

Store/graph monitors poll every ten seconds while visible, refresh on focus/manually, prevent overlap and show timestamps/failures. Quickwit totals and Chroma counts come from live APIs. Graph refresh preserves unchanged layouts. DuckDB snapshots and the FAISS corpus change when their writers/builders update them, not every time the UI polls.

## 11. Examination reports

### 11.1 Different audiences and content

| Report | Emphasis | Required review |
| --- | --- | --- |
| Court submission draft | Scope/authority declarations, acquisition/receipt, inventory, custody, supported observations, exhibits, limitations and unsigned examiner/reviewer fields. | Qualified examiner, actual authority/custody and jurisdiction-specific submission review. |
| Technical report | Telemetry coverage, filters, cited detections, event details, methods, execution provenance, gaps and analyst follow-up. | Technical validation and missing-evidence assessment. |

Both use the same evidence with distinct structure/content. ReportLab renders paginated PDFs; compact HTML companions and original historical output remain where saved. Download hashes identify the delivered representation; manifest digests/source citations are not authenticated custody or case signatures.

The original seventeen-section proposal is a content checklist, not a requirement to duplicate report bodies. Raw model/state dumps, platform boilerplate and unsupported legal conclusions do not belong in the narrative. Detailed execution records remain available in saved case/technical views.

### 11.2 Incomplete and historical cases

Closed workflow status and complete forensic acceptance differ. Missing actor sequence, incomplete model coverage, absent labels, unsupported mapping and evidence requests remain explicit. Historical downloads can render a current template from saved evidence; generation time differs from investigation time, and missing historical version metadata must be disclosed.

PDF/history delivery retains authorization and final-report gates. Human permission to proceed does not certify findings or remove limitations. Hashes and formatting cannot confer admissibility; no court approval, laboratory accreditation or complete-system error rate is asserted.

## 12. Timeline, graphs and explanation

The timeline groups recorded UTC instants into readable days/events, preserving original-field context, host/account identity, unknown times, filters and expandable evidence. Capture/acquisition metadata and adjusted timestamps are distinct from event time. Model selection cannot suppress preserved chronology.

Relational graphs show source-supported entities/relationships with their basis. They are distinct from reviewed exploit topology. Chronological association, shared identity or ATT&CK labels do not establish causation/exploitation.

The exploit solver verifies reviewer identity, case citations, acyclic topology and transition inputs. Calibrated transitions can use `-ln(p)` costs; otherwise probability is unavailable. CVSS severity and EPSS are not multiplied into case-specific success probability. Vulnerability/impact observations remain useful without invented certainty.

Timesketch integration, ATT&CK heatmaps, timeline image export, signed appendices and universal causal-chain display remain separate deliverables unless working implementations and executed oracles are recorded.

## 13. Outcomes and acceptance targets

### 13.1 Deliverables

| Deliverable | Current state | Remaining acceptance |
| --- | --- | --- |
| Unified chronology | Implemented citations/context/uncertainty. | Independent accuracy and optional Timesketch/export integration. |
| Explanatory findings | Evidence-bound rules and structured model assessments. | Independent correctness, omissions and false alarms. |
| ATT&CK/actor comparison | Versioned ranking and limitations. | Trusted labels and confidence calibration. |
| Case graph/execution audit | Typed case-linked evidence and analysis views. | Completeness, scale and trace continuity. |
| Exploit/risk analysis | Reviewed-topology solver and source context. | Real prerequisites, calibration and priority validation. |
| Court/technical PDFs | Distinct tested renderer, saved-case delivery and durable image dependency. | Expert and signed-in browser acceptance. |
| Cryptographic provenance | Local hashes/Merkle components, receipts/manifests. | Uniform ledger, signatures/certificates, Fabric and fork detection. |

### 13.2 Quantitative research targets

| Metric | Original target | Evidence needed |
| --- | --- | --- |
| Correlation accuracy | 95% | Independent labels and defined precision/recall denominators. |
| Timeline accuracy | 96% | Ground-truth order, unknown times/skew and completeness scoring. |
| Attribution accuracy | 94% | Verified actor labels and held-out cases. |
| Investigation time | Five minutes | Declared hardware, volume/source mix/model; analyst wait separate from compute. |
| Time reduction | 89% against 45 minutes | Matched baseline/task scope; original numbers are proposal assumptions. |
| Hallucination rate | Below 5% | Claim-level unsupported/error metric and blinded review. |
| Compression | At least 90% reduction and at least 95% entity retention | Matched normalized payload bytes excluding wire envelopes, summary overhead and retained-entity/citation evaluation. |

These are targets, not achieved results. Original baseline percentages and ransomware/insider/supply-chain stories are illustrative, not measured deployments. Formal measurement protocols require approval before being claimed as acceptance criteria.

## 14. Planned-change reconciliation

All items map to the supplied planned-changes source. Design resolution is distinct from runtime verification; accepted ADRs govern where they supersede the proposal.

### 14.1 Two cross-document conflicts

| Conflict | Reconciled position |
| --- | --- |
| Specialist direct writes versus all-agent Kafka | Kafka-mediated evidence/findings remain the design direction. Checkpoint-to-Neo4j analysis/audit projections also exist. Universal publication/VCT coverage is partial. |
| APOC versus supervisor dead ends | Supervisor/coordination owns progress reasoning; APOC milestone patterns do not determine dead ends. End-to-end degraded dispatch acceptance remains necessary. |

### 14.2 Eight prior design resolutions

| ID | Question | Current assessment |
| --- | --- | --- |
| R1 | Source-to-worker mappings | Explicit in Sections 6/8; supported scope is narrower than complete-source claims. |
| R2 | Retry duplicates/concurrency | Deterministic UIDs, MERGE and leases address defined paths; full replay acceptance remains separate. |
| R3 | Evidence prompt injection | Sanitization/checks/constrained review exist; complete robustness remains partial. |
| R4 | Critic automatically wins | Separate judge consumes both arguments with citation/coverage checks; correctness still needs evaluation. |
| R5 | Debounced ambiguous dead ends | Supervisor ownership resolves the design conflict; runtime notifications still need testing. |
| R6 | Parser attack surface | Input/budget/malformed controls exist; universal restricted-container isolation remains open. |
| R7 | Unbounded debate context | Review batches and bounded retrieval mitigate growth; worst-case context accounting remains open. |
| R8 | Primary/specialist audit asymmetry | Shared traces/checkpoints/AgentRun projections exist; uniform cryptographic tool/write coverage is incomplete. |

### 14.3 Twelve recommendations

| ID | Recommendation | Current treatment | Remaining acceptance |
| --- | --- | --- | --- |
| O1 | Debate cap without convergence | Structured correction then HITL; legacy exhaustion also escalates. | Independent review-quality/fresh-case acceptance. |
| O2 | Durable checkpoint authority | Accepted local SQLite WAL; Redis is not authoritative. | Multi-host and production restore acceptance. Proposed Postgres/write-through split was not adopted. |
| O3 | Case rule-version pinning | Execution source/package fingerprints exist. | Immutable bundles and pinned lookup across reload/retry. |
| O4 | Deterministic replay | Corpus hashes/model traces/receipts exist. | Freeze external responses and corpus/rule/router/model state; replay without altering originals. |
| O5 | Broader fallback flags | Local selector rejects prohibited fallback; review errors/coverage visible. | Uniform end-to-end substitution policy across primary/attribution/safety roles. |
| O6 | Golden fixtures for all skills | Extensive time/abstraction/graph/attribution/protocol/solver controls. | Independent labels, representative coverage and measured skill correctness. |
| O7 | Flag intel provider substitution | Provider/version/hash metadata exist. | Live substitution, stale cache and circuit-breaker flags/receipts. |
| O8 | Frozen report read boundary | Snapshots, joins, leases and final-report gates exist. | Distributed zero-lag boundary and late-write reopen/version policy. |
| O9 | Synthesis waits for specialists | Joins/follow-up precede timeline/attribution/DAG. | Every late update/retry/reanalysis path must avoid stale synthesis. |
| O10 | Bound HITL redispatch | Loop budgets and standalone helper exist. | Durable deployed clarification count and terminal manual-override state across restarts. |
| O11 | Trace HITL handoff | Case/trace state and standalone trace payload exist. | Complete analyst-decision/transport/audit correlation. |
| O12 | Learn from analyst disagreement | Decisions/review data can be retained. | Owned thresholds, scoreboard/recalibration and evaluated changes; no automatic training claimed. |

### 14.4 Seven additional issues

| ID | Issue | Current treatment and remaining work |
| --- | --- | --- |
| N1 | Cross-partition ordering | UTC chronology replaces arrival order; clock uncertainty needs independent evaluation. |
| N2 | Redis case-tagging failure | Cache tries Redis lookups then returns `UNASSIGNED_CONTINUOUS`, not a durable metadata fallback. Define/test reconciliation without silent misassignment. |
| N3 | Cloud/container identity churn | Static cloud-ID maps and lifecycle context exist; complete pod/instance/NAT resolution remains partial. |
| N4 | Hidden fourteen-source scope | Section 6 separates original stages and present support; complete new sources with individual acceptance. |
| N5 | Guardrail model adequacy | Actual selector differs from proposed hosted 7B label; validate high-risk decisions/containment policy. |
| N6 | Shared supervisor/judge blind spots | Distinct roles/counter-evidence checks exist, local family is shared; evaluate bias and production diversity. |
| N7 | Compression byte boundary | Section 13 gives proposed matched payload boundary; verify instrumentation, summary overhead and retention before claiming success. |

## 15. Remaining delivery work

### 15.1 Canonical task states

The tracker records 47 tasks: 41 `passing`, one `active`, one `blocked` and four `not_started`. This is not an overall completion percentage. Earlier topology/stub tasks remain passing within their historical scopes.

| Task | State | Remaining scope |
| --- | --- | --- |
| TASK-6.7 | active | Bounded Kubernetes RBAC/source examinations; broader AD/IAM semantics, trusted labels, full live follow-up and fresh accepted cases remain open. |
| TASK-6.8 | blocked | Production reliability/performance/security/recovery ownership and expert acceptance. PDF/UI subsets do not close it. |
| TASK-7.1 | not_started | Production identity/exposure policy and audit ownership; local backend authorization already exists. |
| TASK-7.2 | not_started | Production checkpoint/recovery acceptance; local SQLite pause/resume already exists. |
| TASK-7.3 | not_started | Coordinated off-host restore of stores, offsets, schemas, references/reports against approved RPO/RTO. |
| TASK-7.4 | not_started | Authenticated browser and approved model/feed deployment acceptance; hosted/GCP remains subject to local-only policy. |

This edit does not promote tasks. Some proposed Phase 7 test filenames are placeholders; they require real executable oracles before completion.

### 15.2 Recommended completion order

1. Finish/evaluate bounded Kubernetes/AD/IAM interpretation, protocol/identity edge cases and trusted-label positive/negative controls.
2. Exercise authorized acquisition through appended evidence, single-cycle reanalysis, synthesis and saved reports. Preserve prior cases and decisions.
3. Obtain qualified review of both report formats, methods, custody declarations, citations and limitations in authorized examination scenarios.
4. Verify signed-in browser creation/history, HITL refresh/approve/reject/clarify, retry, downloads/previews, guest boundaries and responsive behavior.
5. Resume deferred CAPE provisioning only when requested; prove isolation, benign-control execution, capture attribution and clean-snapshot restoration.
6. Assign service/security/backup owners, approve exposure/workload objectives, implement restore oracles and demonstrate coordinated recovery/sustained load.
7. Establish independent research datasets and measured baselines; revisit classifiers, production model diversity, connectors and anchoring through explicit decisions.

This order is a recommendation, not authorization to deploy, purchase/install services, detonate samples or change accepted architecture.

### 15.3 Deferred research and platform extensions

Beyond the active acceptance gates, remaining proposal scope includes full browser/email/messaging extraction, broader endpoint/cloud/scanner connectors, trained timestomping and AI-authorship classifiers, independently validated insider models, production model diversity, comprehensive isolated parsing, hot-reloadable case-pinned rules, provider-fallback observability, replay snapshots, distributed report consistency, analyst-disagreement calibration and complete signed/anchored provenance. Timesketch, heatmaps and image export also need dedicated implementation and oracles.

The proposed four/eight-hour low/medium-severity auto-approval and webhook timeout policies are not established delivered behavior. The current workflow requires explicit review where it pauses; this document does not enable automatic approval or active containment. Remote EDR collection, arbitrary file acquisition, whole-RAM dumping and automated host remediation are outside the bounded local follow-up contract.

## 16. Verification and reproducibility

### 16.1 Recorded evidence

The latest recorded whole-source cleanup regression passed **805 tests, with 33 opt-in probes deselected**. Earlier counts describe earlier revisions. Six frontend guest/timeline/polling/content tests, lint and build passed for the latest presentation work, with existing Fast Refresh/bundle warnings. Opt-in production/live/browser gates are not implied to pass.

PDF verification includes distinct-content/layout/authorization tests, fresh-image rendering and saved-case delivery. Store verification includes API probes, polling regression and Chroma preservation counts. Evidence lives in the tracker and ignored `data/verification/`. This documentation update does not rerun infrastructure or certify current live health.

### 16.2 Representative executable checks

Run from the repository root with installed dependencies. These are source-specific checks, not substitutes for full tracker acceptance.

```powershell
# Tracker
.\venv\Scripts\python.exe scripts/validate_progress.py

# Review, PDF/history and authorization contracts
.\venv\Scripts\python.exe -m pytest tests/test_structured_evidence_review.py tests/test_examination_pdf.py tests/test_api_authorization.py tests/agents/test_investigation_api_history.py -q -p no:cacheprovider

# Native sources and source-bound relationships
.\venv\Scripts\python.exe -m pytest tests/test_packet_forensics.py tests/test_memory_examination.py tests/test_ntfs_records.py tests/test_identity_sessions.py tests/test_kubernetes_audit.py tests/test_evidence_correlations.py -q -p no:cacheprovider

# Store and checkpoint contracts
.\venv\Scripts\python.exe -m pytest tests/test_case_store_views.py tests/test_case_semantic_index.py tests/test_case_analytics.py tests/agents/test_durable_checkpointer.py tests/test_investigation_recovery.py -q -p no:cacheprovider

# Frontend
node --test visualization/tests/guest.test.mjs visualization/tests/timeline.test.mjs visualization/tests/polling.test.mjs visualization/tests/review-content.test.mjs
npm run lint --prefix visualization
npm run build --prefix visualization
```

The existing production suite under `tests/production_readiness/` requires fresh approved evidence, named owners and approved thresholds. Failures/absent infrastructure remain failures, not completion. Coordinated restore/browser backlog tests require implementation/approval; do not cite nonexistent files as successful oracles.

## 17. Source map and maintenance

| Source | Responsibility |
| --- | --- |
| [Original Word proposal](Master%20doc.docx) | Original Sections 1–14, research rationale and historical targets. |
| [Planned changes](Master_doc_planned_changes.md) | Two conflicts, eight prior resolutions, twelve recommendations and seven additional issues, assessed in Section 14. |
| [DECISIONS.md](../DECISIONS.md) | Accepted architecture; notably ADR-011 and ADR-027 through ADR-039. ADR-038 supersedes host PDF rendering; ADR-031 corrects probability assumptions. |
| [PROGRESS.md](../PROGRESS.md) | Canonical task states, execution evidence and open gates. |
| [Documentation map](README.md) | Context and operating references. |
| `src/agents/graph.py`, `nodes.py`, factories/examination modules | Actual routing, safety limits and analysis. |
| `src/ingestion/`, `src/schemas/`, `src/graph/`, `src/mcp/` | Intake/preservation, normalization, identity, transport, graph/index/tool contracts. |
| Compose files and `Dockerfile.hitl` | Services, volumes, local model selection and image dependencies. |
| `visualization/src/`, `visualization/tests/` | Interface behavior and component regression. |
| `tests/`, `scripts/` | Executable verification/evaluation; results require actual execution evidence. |

Maintain a coherent specification here. Record chronological changes/transient runs in the tracker rather than appending repeated completion reports. Preserve distinctions between design, source and verification; record a decision before changing architecture.
