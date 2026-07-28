**Specula (Specula-Agent)**

Autonomous Multi-Agent Digital Forensic & Incident Response (DFIR) Framework

| Project Focus: Autonomous Multi-Agent DFIR Scene Reconstruction | Domain: AI & Cybersecurity (Digital Forensics) |
| :---- | :---- |
| **Academic Context:** SDC-II Research Project (2025–2026) | **Department:** Computer Science & Engineering |

 

**1\. Project Explanation**

**1.1 Project Idea**

Specula (Specula-Agent) is an autonomous multi-agent artificial intelligence framework engineered to reconstruct digital crime scenes from fragmented, heterogeneous evidence without requiring continuous manual analyst intervention. The system coordinates a team of thirteen specialized AI agents—each responsible for a distinct domain of forensic investigation—through a centralized Digital Forensic Knowledge Graph (DFKG) that serves as shared investigative memory.

Rather than feeding raw logs directly into a single language model—which fails due to context window limits, token budget exhaustion, and hallucination—Specula distributes evidence analysis across parallel specialist agents, compresses evidence intelligently using entropy-based semantic distillation, grounds all reasoning in verifiable graph citations, and produces court-ready forensic reports satisfying Daubert legal admissibility standards.

**1.2 Problem Statement**

Modern digital forensic investigations face four compounding crises that make manual investigation increasingly untenable:

| Crisis Domain | Scale / Operational Impact | Forensic Consequence |
| :---- | :---- | :---- |
| Log Volume Explosion | A clean Windows Server installation generates over 4,000,000 events in a short timeframe. | Critical evidence is buried in noise; manual triage is impossible at speed. |
| Context Window Limits | Single LLMs cannot process millions of raw log records without exhausting token budgets. | AI-assisted investigation truncates evidence and loses investigative continuity. |
| Manual Correlation | Analysts must manually stitch fragmented alerts across dozens of log types and systems. | Process is slow, expensive, error-prone, and leads to severe investigator burnout. |
| Legal Inadmissibility | Unconstrained LLM outputs hallucinate IP addresses, file paths, and timelines. | AI-generated findings are rejected under Daubert legal standards in court proceedings. |

 

**1.3 Project Objectives**

·       **Reduce Average Investigation Duration:** Lower investigation duration from 45 minutes to 5 minutes (an 89% time reduction) via autonomous multi-agent parallelization.

·       **Achieve High Investigative Accuracy:** Reach 95% evidence correlation accuracy and 96% attack timeline reconstruction accuracy.

·       **Mitigate AI Hallucinations:** Reduce the AI hallucination rate to below 5% through adversarial debate and DFKG-grounded reasoning.

·       **Ensure Legal Admissibility:** Produce forensic reports that satisfy Daubert legal admissibility standards via cryptographic Merkle provenance.

·       **Multi-Source Ingestion:** Handle 14 heterogeneous input categories spanning OS logs, network PCAPs, memory dumps, and cloud audit trails.

·       **Explainable Reasoning:** Provide auditable chain-of-thought reasoning traceable directly to raw evidence for every finding.

**2\. Base Paper & Literature Grounding**

**2.1 Primary Base Paper Selected**

**Selected Primary Base Paper:** "GenDFIR: Advancing Cyber Incident Timeline Analysis Through Retrieval-Augmented Generation and Large Language Models" — Authored by Fatma Yasmine Loumachi, Mohamed Chahine Ghanem, and Mohamed Amine Ferrag (2024).

**2.2 Methodology & Key Contributions of the Base Paper**

The GenDFIR framework introduced an innovative approach to automating cyber incident timeline analysis by combining Llama 3.1 8B in a zero-shot setting with a Retrieval-Augmented Generation (RAG) agent. Its core methodology comprises:

·       **Stage 1 — Data Preprocessing & Structuring:** Transforms raw event logs (CSV format) into structured textual document knowledge bases representing the incident.

·       **Stage 2 — Context Retrieval & Semantic Enrichment:** Uses embedding models (mxbai-embed-large) and cosine similarity to retrieve relevant incident events (top-k evidence) based on user prompts.

·       **Stage 3 — LLM Decoder Timeline Synthesis:** Processes weighted event contexts through Llama 3.1 8B to generate plain-text timeline reports, root cause analyses, and mitigation suggestions.

**2.3 Supporting Literature Matrix**

| Paper / Source | Domain Focus | Key Contribution to Specula |
| :---- | :---- | :---- |
| GenDFIR (Loumachi et al., 2024\) | Timeline Analysis & RAG | Establishes zero-shot RAG log retrieval, DFIR prompt engineering, and context enrichment baselines. |
| MADIK Framework (London Met Uni) | Multi-Agent Coordination | Establishes agent-to-agent coordination patterns across artifact-specific forensic specialists. |
| CFA-Bench & CyberSleuth | Network Forensics | Provides ground-truth evaluation datasets for network forensics with real PCAPs and CVE detection tasks. |
| DFIR-Metric Benchmark | Evaluation Methodology | Introduces Task Understanding Score (TUS) rewarding partial correctness in multi-step reasoning. |
| ForensicsData (ANY.RUN Triplets) | Malware Behavior | 5,000+ Q-C-A triplets used to benchmark the Malware Behavior Agent narrative accuracy. |
| Analysis of Competing Hypotheses (ACH) | Adversarial Reasoning | Structured analytic technique adapted as the Evidentiary Adversarial Debate protocol for hallucination mitigation. |
| OCSF Standard | Log Normalization | Universal ingestion schema standardizing evidence across cloud, endpoint, and network telemetry. |
| Verifiable Conversation Transcripts (VCT) | Chain-of-Custody | Three-tier Merkle structure making AI reasoning chains tamper-evident under Daubert admissibility standards. |

 

**2.4 How Specula Extends and Improves Upon Existing Work**

The primary base paper, **GenDFIR** (*Loumachi et al., 2024*), introduced a zero-shot framework combining a single Large Language Model (**Llama 3.1 8B**) with a standard Retrieval-Augmented Generation (**RAG**) pipeline. In GenDFIR, raw event logs are converted into flat textual document chunks, indexed via vector embeddings (mxbai-embed-large), and queried using cosine similarity to assemble an incident timeline summary.

While GenDFIR demonstrated the feasibility of using LLMs for DFIR timeline generation, it exhibits critical operational bottlenecks:

1. **Single-Agent Bottleneck:** Relies on a single RAG agent without domain-specialized workers.  
2. **Flat Vector Retrieval Failure:** Cosine similarity over isolated log chunks misses multi-hop, non-linear lateral movement and entity relationships.  
3. **Context Window Flooding:** Has no algorithmic log compression or entropy triage layer, leaving it vulnerable to context window exhaustion when processing millions of enterprise events.  
4. **Unconstrained Hallucination Risk:** Generates summaries without cryptographic proof or mandatory citation checks, failing judicial evidence standards (**Daubert standard**).  
5. **Narrow Analytical Scope:** Lacks active capabilities for anti-forensic timestomping detection, AI-code stylometry, zero-trust command execution, automated attack graph traversal, or dynamic malware detonation.

**Complete Specula Feature Set & Improvements Over GenDFIR**

**1\. Semantic Compression and Entropy-Based Log Distillation**

* **Specula Specification:** Operates as a two-layer system. The *Forensic Preservation Layer* first commits all raw logs immutably to **Quickwit** and hashes them into the Verifiable Conversation Transcripts (**VCT**) chain using Go/Rust SIMD hashing at the edge. The *Analytical Abstraction Layer* then applies **Drain3** template extraction followed by **SimHash** similarity checking to prevent template poisoning attacks. It uses **MiniBatchKMeans** clustering with cosine distance to collapse low-entropy events into summaries while retaining high-entropy anomalous events intact. Reduces LLM input volume by 90%+ without legally compromising the original evidence corpus.  
* **Specula Improvement over GenDFIR:** GenDFIR feeds raw text chunks directly into its vector database and prompt context, causing rapid token budget exhaustion when handling enterprise-scale logs (e.g., 4M+ Windows events). Specula introduces **information-entropy log distillation**, filtering out syntactic noise before LLM ingestion while preserving critical forensic indicators.

**2\. Digital Forensic Knowledge Graph (DFKG) and Topological GraphRAG**

* **Specula Specification:** Replaces linear supertimelines with a **Neo4j** relational ontology where nodes represent forensic entities (users, devices, IPs, processes, files, malware, ATT\&CK techniques) and edges represent observed actions between them. Deterministic UIDs generated by hashing source device ID, file path, database name, and row number prevent duplicate nodes across concurrent agents. GraphRAG queries combine **FAISS IndexIVFPQ** cosine similarity search with **APOC-bounded Breadth-First Search (BFS)** subgraph expansion (max 3 hops, max 100 nodes, max 300 relationships) to retrieve structured context for LLM reasoning. Supernode detection pre-checks node degree before BFS to prevent traversal explosions.  
* **Specula Improvement over GenDFIR:** *(Feature not present in GenDFIR)* GenDFIR relies exclusively on flat vector similarity over text chunks, which loses relational context across systems. Specula transitions from flat text RAG to **Topological GraphRAG**, mapping multi-hop lateral movement and complex causal subgraphs across heterogeneous endpoints.

**3\. Algorithmic Temporal Normalization and Timestomping Detection**

* **Specula Specification:** Detects anti-forensic timestamp manipulation by requiring three conditions simultaneously: the $STANDARD\_INFORMATION Created timestamp predates the volume creation date, the USN Journal shows a BasicInfoChange event with no corroborating application log entry within ![][image1] seconds, and the timestamp precision shows suspicious microsecond rounding. Replaces static rules with an **XGBoost classifier** trained on a SMOTE-balanced feature vector of timestamp deltas, precision bitmask fields, and USN reason codes. Time anchor correlation matrices using linear regression on simultaneous multi-device events resolve clock drift and normalize all timestamps to UTC baseline prior to DFKG ingestion.  
* **Specula Improvement over GenDFIR:** *(Feature not present in GenDFIR)* GenDFIR assumes raw log timestamps are truthful and chronologically accurate. Specula actively identifies, isolates, and mathematically corrects **anti-forensic timestomping** and multi-device clock skew before timeline synthesis occurs.

**4\. Evidentiary Adversarial Debate and Analysis of Competing Hypotheses (ACH)**

* **Specula Specification:** A three-agent **LangGraph** debate framework where the *Proponent Agent* constructs a hypothesis with mandatory DFKG node UID citations, the *Critic Agent* independently queries the DFKG for counter-evidence and argues alternative explanations (also with mandatory citations), and the *Judge Agent* evaluates arguments using an ACH evidence matrix. The Judge automatically rejects any argument not backed by explicit DFKG citations. Runs up to a configurable maximum of 3 debate rounds, terminating early when the confidence score delta between agents falls below 0.05. Softmax credibility weighting with Laplace smoothing handles the cold-start problem. LangGraph state stores only UID references, with full argument content held in **Redis** to prevent state bloat.  
* **Specula Improvement over GenDFIR:** GenDFIR relies on single-pass, unvalidated LLM generation, which remains susceptible to parametric hallucinations and bias. Specula enforces a structured **Adversarial ACH Debate**, ensuring that any ungrounded assertion is flagged as PARAMETRIC\_KNOWLEDGE\_REJECTED and discarded.

**5\. Verifiable Conversation Transcripts (VCT) and Cryptographic Provenance**

* **Specula Specification:** Secures the investigative chain of custody through a three-tier cryptographic structure:  
  1. *Atomic Level:* Every prompt-response pair is SHA-256 hashed and linked into a hash chain.  
  2. *Session Level:* Completed sub-task chain tails are aggregated into a Merkle tree using pymerkle with incremental leaf support.  
  3. *Case Level:* All session roots aggregate into a final Merkle root signed by both the server RSA key and the human investigator's digital certificate, anchored to **Hyperledger Fabric** via fabric-sdk-py.

A **gRPC gossip protocol** with a 30-second timeout window and 2-peer confirmation requirement detects view forks from compromised agents without false alerts from legitimate network partitions. Satisfies Daubert admissibility standards.

* **Specula Improvement over GenDFIR:** *(Feature not present in GenDFIR)* GenDFIR provides no tamper-evident guarantees for its internal AI reasoning chain. Specula provides **cryptographic chain-of-custody tracking** for every LLM reasoning step, rendering the generated output legally defensible in court under **Daubert legal standards**.

**6\. LLM-Generated Code Stylometry and Authorship Attribution**

* **Specula Specification:** Analyzes recovered malicious scripts to determine whether they were human-authored or generated by a specific LLM. A language detection step using linguist routes scripts to the appropriate parser—Python's built-in ast module, javalang for Java, pycparser for C, bashlex for shell scripts, and a subprocess-wrapped PowerShell AST parser for PowerShell. Extracts AST node type n-gram frequencies, Program Dependency Graph (PDG) structural features, identifier naming patterns, and control flow complexity metrics. An **XGBoost classifier** trained on a novel synthetic benchmark dataset (scripts generated by GPT-4, Claude, Gemini, and human authors) outputs a class label with an explicit confidence score, acknowledging inter-model boundaries as probabilistic rather than deterministic.  
* **Specula Improvement over GenDFIR:** *(Feature not present in GenDFIR)* GenDFIR cannot analyze or attribute malicious code scripts. Specula introduces **AI Code Stylometry**, allowing investigators to determine if recovered malware scripts were generated by specific LLMs or human actors.

**7\. Zero-Trust Guardrail Execution**

* **Specula Specification:** A mandatory three-tier validation layer that intercepts all agent outputs before execution:  
  * *Tier 1 (\<5ms):* Runs deterministic regex and AST signature matching after Unicode NFKC normalization and zero-width character stripping to catch homoglyph and encoding-based injection bypass attempts.  
  * *Tier 2 (\<50ms):* Runs a local fine-tuned **MiniLM vector classifier** for SAFE/UNSAFE semantic intent classification on write operations only.  
  * *Tier 3 (1–3s):* Reserves full secondary LLM semantic validation exclusively for containment actions and high-risk DFKG writes.

Implements parameterized Cypher queries throughout to prevent graph injection attacks.

* **Specula Improvement over GenDFIR:** *(Feature not present in GenDFIR)* GenDFIR lacks security filters to protect itself against adversarial log inputs. Specula implements a **Zero-Trust Guardrail Architecture** to prevent indirect prompt injection (e.g., OWASP LLM05) embedded inside malicious log telemetry from hijacking agent execution.

**8\. Dedicated Fraud and Insider Threat Agent**

* **Specula Specification:** Ingests raw message body text, DLP alerts, UEBA scores, and file access patterns from mandatory fields in email, messaging, and UEBA input sources. Runs **spaCy NER** on communications to identify mentions of sensitive systems, competitors, and behavioral indicators. Uses an **LSTM Autoencoder** trained on 90-day user activity baselines from the CERT dataset to score behavioral anomalies by reconstruction error. Applies **One-Class SVM** for users with fewer than 100 message samples, switching to **HDBSCAN** only when sufficient history exists. Uses ProsusAI/finbert or a fine-tuned CERT-corpus model for sentiment analysis to prevent domain mismatch.  
* **Specula Improvement over GenDFIR:** *(Feature not present in GenDFIR)* GenDFIR focuses strictly on explicit system log events and cannot detect non-signature behavioral anomalies or corporate insider threats. Specula adds a **specialized Insider Threat Agent** capable of modeling semantic sentiment and behavioral baseline deviations across enterprise messaging and UEBA data streams.

**9\. Formalized Human-in-the-Loop (HITL) Approval Gate**

* **Specula Specification:** A **FastAPI \+ React** dashboard that the Supervisor Agent escalates to when confidence scores fall below 0.7, adversarial debate produces unresolved conflict, blast radius exceeds the predefined threshold, or any active containment action is proposed. Presents the human analyst with the full ACH evidence matrix, blast-radius-ranked asset list, Explainability Agent chain-of-thought trace, and VCT session Merkle root for verification. Analyst actions: APPROVE, REJECT, or REQUEST\_CLARIFICATION. Implements a tiered timeout policy: low-severity findings auto-approve after 4 hours, medium-severity escalate to a secondary analyst after 2 hours (with auto-approval after 8 hours), and high-severity actions never auto-approve (notifying SOC leadership via webhook after 1 hour). Analyst agreement rate is tracked as the primary evaluation metric.  
* **Specula Improvement over GenDFIR:** *(Feature not present in GenDFIR)* GenDFIR operates as an unmonitored "black box" text generator without formal escalation points. Specula embeds a **legally mandated Human-in-the-Loop gate**, ensuring human oversight over critical findings and automated containment commands.

**10\. Dynamic Attack Graph Construction**

* **Specula Specification:** Ingests vulnerability and asset inventory data (14th input source) from OpenVAS, Nessus, or Qualys APIs and cross-references with DFKG host nodes. Queries a locally cached **DuckDB** table of daily EPSS score dumps from FIRST.org rather than making live API calls to prevent rate limiting. Models the network as a directed networkx graph where edge weights use a negative log transformation:

![][image2]

so Dijkstra's algorithm correctly identifies the most dangerous exploitation path rather than the safest one. The precondition confirmation factor ![][image3] when forensic evidence in the DFKG confirms the precondition, and ![][image4] when unconfirmed. Unchained vulnerabilities with EPSS above 0.3 are flagged as residual risk and ranked for remediation output.

* **Specula Improvement over GenDFIR:** *(Feature not present in GenDFIR)* GenDFIR cannot assess vulnerability chains or post-incident residual risk. Specula dynamically constructs **forensically weighted attack graphs**, combining live forensic evidence with EPSS/CVSS scores to map viable attack paths and prioritize post-incident patching.

**11\. Malware Behavior Agent with Tiered Dynamic Analysis**

* **Specula Specification:** Operates as a three-tier pipeline selecting analysis depth based on sample complexity and available infrastructure:  
  * *Tier 1 (\<1s):* Runs YARA rule matching via yara-python against the MalwareBazaar ruleset plus custom rules derived from previous DFKG malware nodes.  
  * *Tier 2 (\~5s):* Runs Speakeasy user-mode Windows emulation requiring no hypervisor—handles shellcode, DLLs, and standard executables.  
  * *Tier 3:* Escalates to either CAPE Sandbox on bare-metal KVM hardware or an external API (ANY.RUN, Hybrid Analysis) when Speakeasy reports evasion or insufficient coverage.

All tiers output structured behavioral telemetry that the agent writes into the DFKG as typed edges (CALLED\_API, DROPPED, CONNECTED\_TO), enabling automated ATT\&CK mapping. **DRAKVUF VMI** on Xen is supported as a gold-standard upper tier when hypervisor infrastructure is available, validated against versioned Pydantic schema models to catch parser-version mismatches.

* **Specula Improvement over GenDFIR:** *(Feature not present in GenDFIR)* GenDFIR has no capability to analyze or detonate malicious binaries. Specula integrates **tiered dynamic malware detonation and VMI telemetry ingestion**, mapping behavioral execution outputs directly into the shared DFKG memory.

**12\. Investigative Synthesis and Blast Radius Quantification**

* **Specula Specification:** The final synthesis feature that runs after all specialist agents complete. Computes blast radius as a composite score of affected node count weighted by asset sensitivity classification, plus log-scaled estimated exfiltration volume derived from file size properties on confirmed exfiltration edges in the DFKG:

![][image5]

Performs threat actor attribution by computing both Jaccard set similarity and **Smith-Waterman sequence alignment scores** between the observed TTP sequence and MITRE ATT\&CK group profiles, combining them as a weighted score (![][image6]) to reward matching TTP order rather than just TTP presence. Returns top-3 candidate threat actors with similarity scores and confidence bounds. Produces a ranked asset impact list fed directly to the HITL Approval Gate dashboard and outputs court-ready PDF reports via **ReportLab**.

* **Specula Improvement over GenDFIR:** GenDFIR outputs unstructured, plain-text narrative summaries without quantitative impact scoring or sequence-aligned attribution. Specula provides **mathematical blast radius quantification**, sequence-aligned TTP threat actor attribution, and automated court-ready PDF report synthesis.

| Capability / Dimension | GenDFIR Baseline (Loumachi et al., 2024\) | Specula Framework |
| :---- | :---- | :---- |
| System Architecture | Single LLM RAG Agent (Llama 3.1 8B) | 13 Specialized Agents across 5 Cognitive Tiers |
| Context Retrieval | Flat Vector Search (Cosine Similarity over text chunks) | Topological GraphRAG (Neo4j DFKG \+ APOC BFS \+ FAISS IndexIVFPQ) |
| Log Scale Handling | Uncompressed Text Prompts (Token Bottleneck) | Entropy-Based Distillation (Drain3 \+ SimHash \+ MiniBatchKMeans, 90%+ Compression) |
| Hallucination Mitigation | Unconstrained Single-Pass Generation | Evidentiary ACH Debate (Proponent/Critic/Judge with mandatory DFKG citations) |
| Legal Admissibility | None (Unverified text output) | Cryptographic Provenance (3-Tier Merkle Trees \+ Hyperledger Fabric, Daubert Standard) |
| Timestomping Analysis | None (Assumes raw timestamps are accurate) | MFT SIvsFN Checks \+ XGBoost Classifier \+ Time Anchor Regression |
| Code Stylometry | None | AST / PDG Parsing across 6 Languages \+ XGBoost AI-Authorship Classifier |
| Security / Guardrails | None (Vulnerable to Indirect Prompt Injection) | 3-Tier Zero-Trust Validation (Regex \+ MiniLM Classifier \+ Parameterized Cypher) |
| Insider Threat Analysis | None | LSTM Autoencoder \+ FinBERT Sentiment Analysis on corporate comms & UEBA |
| Human-in-the-Loop | None | Formalized HITL Gate (React Dashboard with Tiered Timeouts & Agreement Tracking) |
| Vulnerability Analysis | None | Dynamic Attack Graph (Dijkstra Traversal on negative log CVSS × EPSS × γ) |
| Malware Detonation | None | Tiered Sandbox Execution (YARA → Speakeasy → CAPE / DRAKVUF VMI) |
| Threat Attribution | Unstructured text mention | Sequence-Aligned Attribution (0.4×Jaccard+0.6×Smith-Waterman) |
| Impact Scoring | Qualitative summary | Quantitative Blast Radius Formulation (BR=N⋅Wˉ+ln(Bytes+1)) |

**2.5 Agent-Model Rationale Matrix**

| Agent | Model | Inference | Rationale/Justification |
| :---- | :---- | :---- | :---- |
| Supervisor | [Nemotron-3 Ultra](https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B-NVFP4) | Together AI via HF | Top-tier reasoning for orchestration, dead-end detection, and routing decisions |
| Evidence collection | [Qwen2.5-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct) | Novita/Together via HF | Mostly tool-calling/fetching, low reasoning load — cheapest model that's reliable at function calling |
| Log analysis | [Qwen2.5-72B-Instruct](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct) | Novita/Together via HF | Needs strong pattern recognition over high-volume normalized logs |
| Network forensics | [Llama3.3-70B-Instruct](https://huggingface.co/meta-llama/Llama-3.3-70B-Instruct) | Groq via HF | Comparable capability tier to log analysis, keeps the two parallel primary agents balanced in latency |
| Timeline reconstruction | [DeepSeek-V3.2](https://huggingface.co/deepseek-ai/DeepSeek-V3.2) | Novita / together via HF | Strong multi-hop/temporal reasoning across disparate evidence sources |
| Threat attribution (RAG) | [Kimi K2.6](https://huggingface.co/moonshotai/Kimi-K2.6) | Together/Fireworks via HF | Best long-context handling for retrieving and reasoning over ATT\&CK/CVE corpora |
| Memory forensics | [Qwen3 32B](https://huggingface.co/Qwen/Qwen3-32B) | Nscale/Deepinfra via HF | Mid-size, good general performance, moderate volume of memory dump summaries |
| Identity and cloud | [Prism-ML-Ternary-Bonsai-27B](https://huggingface.co/prism-ml/Ternary-Bonsai-27B-gguf) | Together AI via HF | Smaller specialized model sufficient for structured AD/cloud audit log analysis |
| Malware behavior & code stylometry | [DeepSeek-R1-Distil-Qwen-14B](https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Qwen-14B) | Nscale via HF | Strongest reasoning model for code-structure analysis (AST/PDG) and authorship inference |
| Insider threat | [MiniMax-M2.5](https://huggingface.co/MiniMaxAI/MiniMax-M2.5) | Novita/Featherless AI via HF | Good at sentiment/behavioral narrative synthesis from communications data |
| Proponent (debate) | [Nemotron-3 Super](https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16) | Featherless AI via HF | Strong hypothesis construction, one tier below Ultra to keep debate asymmetric-but-capable |
| Critic (debate) | [Llama3.3-70B-Instruct](https://huggingface.co/meta-llama/Llama-3.3-70B-Instruct) | Groq/Novita via HF | Independent model family from proponent, reduces correlated blind spots in the debate |
| Judge (debate) | [Nemotron-3 Ultra](https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B-NVFP4) | Together AI via HF | Same top-tier model as supervisor — final arbitration needs the strongest available reasoning |
| Guardrail Tier 3 semantic check | [Qwen2.5-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-VL-7B-Instruct) | Novita/Together via HF | Fast, cheap, only invoked for containment/high-risk writes — small model is enough given Tier 1/2 already filtered |
| Report generation | [Llama-3.3-8B-Instruct](https://huggingface.co/DavidAU/Llama3.3-8B-Instruct-Thinking-Heretic-Uncensored-Claude-4.5-Opus-High-Reasoning) | Featherless AI via HF | Formatting/synthesis into a fixed template, deterministic task, doesn't need a large model |

 

**3\. Dataset**

**3.1 Benchmark & Ground-Truth Datasets**

Specula utilizes established public datasets for RAG grounding, knowledge lookup, and empirical evaluation. Crucially, no heavy LLM fine-tuning is performed—this avoids catastrophic forgetting and excessive compute overhead.

| Dataset / Source | Purpose in Specula System | Evaluated Agent / Feature |
| :---- | :---- | :---- |
| CERT Insider Threat v6.2 (CMU SEI) | Grounding and evaluation for behavioral anomaly detection in enterprise logs. | Insider Threat Agent |
| CICIDS2017 / CICIDS2018 | Network traffic evaluation containing labelled benign and multi-attack traffic (PCAPs & Zeek logs). | Network Forensics Agent |
| Digital Corpora Forensic Images | Disk images, memory dumps, MFT files, and user artifacts for timeline ground truth. | Memory Forensics Agent & Timestomping Feature |
| DARPA Transparent Computing | System provenance data with known manipulation events for temporal anomaly evaluation. | Timestomping Detection (Feature 3\) |
| ForensicsData (ANY.RUN Triplets) | 5,000+ Q-C-A triplets testing LLM-generated malware behavioral narrative accuracy. | Malware Behavior Agent |
| CFA-Bench \+ CyberSleuth | Network forensic reasoning benchmark measuring CVE detection and attack confirmation. | Network Forensics & Threat Attribution Agents |
| DFIR-Metric Benchmark | Multi-step reasoning evaluation measuring Task Understanding Score (TUS). | All Primary & Specialist Agents |
| AutoBnB-RAG Simulation Dataset | Agent strategy validation environment based on Backdoors & Breaches tabletop framework. | Supervisor & Dynamic Attack Graph Agents |
| NVD / NIST CVE Database | Daily EPSS CSV dump and CVE vulnerability metadata for attack path weighting. | Dynamic Attack Graph Agent |
| MITRE ATT\&CK STIX Dataset | Threat actor TTP profiles in machine-readable STIX format for attribution matching. | Threat Attribution Agent |

 

**3.2 Novel Synthetic Dataset: Code Stylometry Benchmark**

To fill an identified research gap—the total absence of public datasets containing malware scripts labeled by whether they were generated by specific LLMs (GPT-4, Claude, Gemini) versus human authors—this project creates a novel benchmark dataset.

·       **Data Collection:** Human samples are collected from MalwareBazaar and pre-2023 VirusTotal submissions (ensuring clean human ground truth). AI samples are generated by submitting identical attack specifications to GPT-4, Claude Sonnet, and Gemini Pro across Python, PowerShell, Bash, and JavaScript.

·       **Dataset Scale:** 500 samples per class across four class labels: {GPT4, Claude, Gemini, Human} (2,000 samples minimum; 5,000 target for statistical reliability).

·       **Labeling Methodology:** Human samples are verified via git blame timestamps and pre-LLM repository creation dates. AI samples are labelled by generating model. Inter-annotator agreement is validated via Cohen's Kappa score.

·       **Preprocessing & Feature Extraction:** All samples undergo Unicode NFKC normalization to prevent homoglyph contamination, comment stripping to eliminate author metadata, Abstract Syntax Tree (AST) extraction (via ast, javalang, pycparser, powershell-ast, bashlex), and lexical/syntactic feature vectorization.

**4\. Deployment**

**4.1 Deployment Architecture & Platform**

Specula is deployed as a containerized, locally hosted microservices stack designed for air-gapped Security Operations Center (SOC) environments where evidence cannot be transmitted to external cloud providers. An optional cloud-API mode is supported for non-air-gapped deployments.

·       **Platform:** Local bare-metal server or on-premise virtual machine (Ubuntu 24.04 LTS primary, Windows Server 2022 secondary).

·       **Minimum Hardware Spec:** 16GB RAM, 8-core CPU, 512GB SSD. Uses quantised local Qwen 7B Q4 via Ollama (No GPU required).

·       **Recommended Hardware Spec:** 32GB RAM, 16-core CPU, 1TB NVMe, NVIDIA RTX 3060 12GB GPU for accelerated inference.

·       **Orchestration:** Docker \+ Docker Compose for single-node SOC deployment; Kubernetes optional for multi-node enterprise SOCs.

**4.2 Microservices Architecture & Stack**

| Microservice Component | Technology Stack | Port / Interface & RAM Budget |
| :---- | :---- | :---- |
| Log Ingestion Agent | Filebeat \+ Go custom processor | Ships SHA-256 hashed logs to Kafka (\~100MB RAM) |
| Message Broker | Apache Kafka (single broker) | Internal Queue :9092 (\~300MB RAM) |
| Raw Evidence Store | Quickwit (append-only index) | REST API :7280 (200–400MB RAM) |
| Knowledge Graph | Neo4j Community \+ APOC plugin | Bolt :7687 / HTTP :7474 (512MB–1GB RAM) |
| Vector Index | FAISS IndexIVFPQ | Python in-process library (\~200MB RAM) |
| Embedding Store | ChromaDB | HTTP :8000 (200–400MB RAM) |
| State & Debate Cache | Redis | Internal :6379 (100–200MB RAM) |
| Asset / CVE Store | DuckDB local store | In-process library (50–200MB RAM) |
| LLM Inference Engine | Too many to list(Quantised) | HTTP :11434 (4–6GB RAM) |
| Agent Orchestration | LangGraph (Python) | Internal state graphs (\~200MB RAM) |
| MCP Data Gateways | FastAPI microservices | Internal :8100–8105 (\~100MB RAM) |
| Blockchain Ledger | Hyperledger Fabric | Internal :7050 (\~300MB RAM) |
| HITL Analyst Dashboard | FastAPI backend \+ React frontend | HTTPS :443 (\~100MB RAM) |

 

**4.3 Deployment Workflow**

·       **Step 1 — Infrastructure Provisioning:** docker-compose up \-d initializes all microservices. Neo4j, Quickwit, and Kafka start with append-only forensic configurations and write locks.

·       **Step 2 — Evidence Ingestion:** Filebeat agents ship system logs. Network taps forward PCAPs. API connectors pull cloud audit trails.

·       **Step 3 — OCSF Normalization:** FastMCP servers normalize incoming evidence to Open Cybersecurity Schema Framework prior to DFKG ingestion.

·       **Step 4 — Autonomous Investigation:** SIEM alert triggers the Supervisor Agent. Tier 2 primary and Tier 3 specialist agents run in parallel via Blackboard pattern.

·       **Step 5 — Adversarial QC & HITL Gate:** Adversarial ACH debate validates findings. Supervisor escalates blast radius and confidence scores to the React analyst dashboard.

·       **Step 6 — Report Delivery:** Court-ready PDF is generated by ReportLab with appended case-level Merkle root and VCT audit proof.

**5\. Target Users**

| Target User Group | Operational Context | How Specula Benefits Them |
| :---- | :---- | :---- |
| Digital Forensic Investigators | Law enforcement, private forensic firms, and IR consulting practices. | Reduces evidence correlation from hours to 5 minutes; outputs court-ready reports with cryptographic provenance. |
| SOC Analysts (Tiers 1–3) | Enterprise SOC teams triaging alerts in real time. | Provides pre-correlated, ranked attack narratives rather than raw alert queues, dramatically reducing fatigue. |
| Incident Response Teams | Emergency IR teams responding to active network breaches. | Compresses timeline reconstruction from days to minutes and highlights unchained residual risks for hardening. |
| Legal & Compliance Teams | In-house legal counsel needing admissible evidence for court. | Provides cryptographically signed, tamper-evident VCT transcripts satisfying Daubert legal admissibility standards. |
| Academic Researchers | University research groups in AI security and DFIR. | Provides 12 novel features, a novel synthetic code stylometry benchmark, and an open evaluation framework. |

 

**6\. Input to the Application**

**6.1 Accepted Evidence Input Sources (14 Categories)**

| Input Category | Specific Technical Sources | Consuming Agent(s) |
| :---- | :---- | :---- |
| System Logs | Windows EVTX, Linux auditd syslogs, Sysmon logs | Log Analysis & Evidence Correlation Agents |
| NTFS Artifacts | $MFT, $USNjrnl, $FILE\_NAME & $STANDARD\_INFORMATION | Memory Forensics & Timestomping Module |
| Network Logs & PCAPs | Suricata IDS, Zeek connection/DNS/HTTP logs, raw PCAP | Network Forensics Agent |
| AD & Cloud Audit | Active Directory LDAP/Kerberos, AWS CloudTrail, Azure Logs | Identity & Cloud/Container Agents |
| EDR & UEBA Telemetry | CrowdStrike Falcon, SentinelOne, Wazuh, Splunk UBA | Memory Forensics & Insider Threat Agents |
| Malware Samples | YARA-matched binaries, PE headers, CAPE / ANY.RUN JSON | Malware Behavior & Code Stylometry Agents |
| Email & Messaging | Raw EML/MBOX files, Slack API, Teams Graph API, SharePoint | Evidence Correlation & Insider Threat Agents |
| Memory Dumps | Volatility 3 outputs, WinPmem/LiME memory images | Memory Forensics Agent |
| Browser Artifacts | Chrome/Firefox/Edge SQLite databases (History, Cookies) | Evidence Correlation Agent |
| Threat Intel Feeds | MITRE ATT\&CK STIX, MISP IOC feeds, VirusTotal, NVD CVE | Threat Attribution & Malware Behavior Agents |
| Container / K8s Logs | Kubernetes audit logs, Falco runtime security, Docker logs | Cloud & Container Agent |
| Vulnerability Scans | OpenVAS / Nessus / Qualys API outputs, software manifests | Dynamic Attack Graph Agent |
| Cloud Topology | AWS/Azure/GCP Cloud Logging SDK, Cartography asset graphs | Cloud & Container Agent |
| Investigator Query | Natural language query submitted via React dashboard | Supervisor Agent (routes to specialists) |

 

**6.2 Input Capture, Processing, and Validation Workflow**

·       **Capture Channels:** Automated pulling via Filebeat agents and API connectors (boto3, falconpy); manual upload of disk images/malware binaries via dashboard; on-demand natural language query submission.

·       **OCSF Normalization:** All raw evidence is converted to Open Cybersecurity Schema Framework (OCSF) standard JSON via FastMCP gateways before touching agent prompts.

·       **Schema Check:** Pydantic models validate all OCSF events. Violations raise INGESTION\_ERROR and quarantine malformed records.

·       **Integrity Verification:** Go SIMD processor computes SHA-256 hash of raw logs upon arrival, committing them to Quickwit append-only store. Any mismatch raises TAMPER\_DETECTED.

·       **Security Gate:** All evidence text passes through Unicode NFKC normalization and Rebuff prompt injection detection before agent consumption.

| Priority Tier | Rank | Log / Evidence Type | Primary Consuming Agent / Module | Core Forensic Purpose & Dependency |
| :---- | ----- | :---- | :---- | :---- |
| Tier 1: Critical (Core Pillars) | 1 | System Logs (EVTX, Linux syslogs, Sysmon) | Log Analysis & Evidence Correlation | Foundational telemetry; feeds initial timeline, entropy distillation, and primary DFKG nodes. Google Docs+ 2 |
|  | 2 | NTFS Artifacts ($MFT,$USNjrnl, SI/FN) | Memory Forensics & Timestomping Module | Crucial for anti-forensic timestomping detection via XGBoost before timeline synthesis. Google Docs+ 1 |
|  | 3 | Active Directory & Auth Logs (LDAP, Kerberos, MFA) | Identity & Cloud Agents | Tracks identity context, privileges, and initial compromise vectors across hosts. Google Docs+ 3 |
|  | 4 | EDR Telemetry & Memory Dumps (CrowdStrike, Volatility) | Memory Forensics Agent | Deep endpoint process execution tracing, volatile memory analysis, and root cause mapping. DOCX+ 1 |
| Tier 2: High (Network & Cloud Context) | 5 | Network Logs & PCAPs (Suricata, Zeek, Raw PCAP) | Network Forensics Agent | Maps network-level lateral movement, C2 channels, and calculates exfiltration volumes. Google Docs+ 2 |
|  | 6 | Cloud Audit & Container Logs (CloudTrail, K8s, Falco) | Cloud & Container Agent | Expands investigation into cloud control planes, multi-cloud infrastructure, and container runtime events. DOCX+ 1 |
|  | 7 | Malware Samples & Binaries (YARA, PE Headers, CAPE) | Malware Behavior & Code Stylometry | Tiered sandbox execution (YARA → Speakeasy → CAPE/DRAKVUF) and LLM code stylometry analysis. Google Docs+ 3 |
| Tier 3: Medium (Specialized Threat Intelligence) | 8 | UEBA Data & Messaging Logs (DLP, Slack, Teams, EML) | Insider Threat Agent | Mandatory inputs for the LSTM Autoencoder and spaCy NER to score non-signature behavioral anomalies and exfiltration. Google Docs+ 1 |
|  | 9 | Threat Intel Feeds (MITRE ATT\&CK STIX, NVD) | Threat Attribution Agent | Required for Smith-Waterman sequence-aligned threat actor attribution and TTP matching. Google Docs+ 2 |
|  | 10 | Vulnerability Scans (OpenVAS, Nessus, Qualys) | Dynamic Attack Graph Agent | Feeds EPSS/CVSS scores into Dijkstra's negative log network graph for residual risk mapping. Google Docs+ 3 |
| Tier 4: Supporting (Enrichment) | 11 | Browser Artifacts (Chrome/Firefox SQLite) | Evidence Correlation Agent | Provides web activity, download histories, and phishing landing page entry points. DOCX |
|  | 12 | Cloud Topology & Asset Data (Cartography) | Cloud & Container Agent | Enriches DFKG host nodes with network mapping and asset sensitivity classifications. Google Docs+ 1 |

### **Ingestion pipeline**

The pipeline turns 14 heterogeneous evidence sources into OCSF-normalized, tamper-evident, DFKG-ready records before any agent touches them.

![][image7]

```py
# Stage 1-2: capture + integrity commit
async def ingest_source(raw_bytes: bytes, source_type: str) -> str:
    doc_hash = sha256_simd(raw_bytes) # Go/Rust SIMD hasher, called via FFI
    await quickwit_client.commit(index="raw-evidence", doc=raw_bytes, id=doc_hash)
    await vct_chain.append(doc_hash) # hash chain, atomic level
    return doc_hash

# Stage 3: OCSF normalization (per-source FastMCP gateway)
def normalize_to_ocsf(raw_bytes: bytes, source_type: str) -> dict:
    parser = OCSF_PARSERS[source_type] # e.g. evtx_parser, zeek_parser, cloudtrail_parser
    return parser.to_ocsf(raw_bytes)

# Stage 4: schema validation
def validate(event: dict) -> OCSFEvent | None:
    try:
        return OCSFEvent.model_validate(event) # Pydantic
    except ValidationError:
        quarantine_store.put(event) # raises INGESTION_ERROR downstream
        return None

# Stage 5: security gate
def security_gate(event: OCSFEvent) -> OCSFEvent:
    event.text_fields = unicodedata.normalize("NFKC", event.text_fields)
    if rebuff.detect_injection(event.text_fields).is_injection:
        event.flag = "QUARANTINED_INJECTION"
    return event

# Stage 6: entropy distillation (batched, not per-event)
def distill_batch(events: list[OCSFEvent]) -> list[OCSFEvent]:
    templates = drain3.mine(events)
    templates = simhash_dedupe(templates) # anti template-poisoning
    clusters = MiniBatchKMeans(n_clusters=k).fit(templates.vectors)
    return keep_high_entropy(events, clusters) # low-entropy → summarized, anomalies kept whole

# Stage 7: DFKG load
def load_to_dfkg(event: OCSFEvent):
    uid = sha256(f"{event.device_id}:{event.path}:{event.db}:{event.row}".encode())
    neo4j_session.run(
        "MERGE (n:Entity {uid: $uid}) SET n += $props",
        uid=uid.hexdigest(),
        props=event.model_dump()
    )
```

Kafka sits between stages 2 and 3 as the durability buffer (Filebeat → Kafka → FastMCP consumer group), so a normalization crash never loses raw evidence — replay from the Kafka offset, not from source. 

**7\. Expected Outcome**

**7.1 Primary System Output Deliverables**

·       **Deliverable 1 — Unified Chronological Attack Supertimeline:** Cross-correlated sequence of confirmed attack events exported to Timesketch for interactive review.

·       **Deliverable 2 — Executive Summary Narrative:** Plain-English explanation of attack mechanics generated for non-technical stakeholders, with every claim citing DFKG graph nodes.

·       **Deliverable 3 — MITRE ATT\&CK Mapping & Threat Actor Attribution:** Smith-Waterman sequence alignment \+ Jaccard similarity top-3 threat actor candidates with explicit confidence scores.

·       **Deliverable 4 — DFKG Subgraph Visualizations:** Neo4j interactive relationship network rendering full attack chains (User \-\> Email \-\> Binary \-\> C2).

·       **Deliverable 5 — Dynamic Attack Graph & Remediation Priority List:** Exploitation path map isolating unchained vulnerabilities with EPSS \> 0.3 as residual risk priorities.

·       **Deliverable 6 — Court-Ready PDF Investigation Report:** ReportLab PDF featuring Executive Summary, ATT\&CK Heatmaps, Blast Radius Scores, and Cryptographic Appendix.

·       **Deliverable 7 — Cryptographic VCT Audit Transcript:** Three-tier Merkle proof chain anchored to Hyperledger Fabric for legal admissibility under Daubert standards.

**7.2 Quantitative Performance Targets**

| Performance Metric | Specula Target Target | Traditional SIEM / Single-LLM Baseline |
| :---- | :---- | :---- |
| Evidence Correlation Accuracy | 95% | 72% |
| Attack Timeline Reconstruction Accuracy | 96% | 68% |
| Threat Attribution Accuracy | 94% | 70% |
| Total Investigation Duration | 5 minutes | 45 minutes |
| Investigation Time Reduction | 89% reduction | Baseline |
| AI Hallucination Rate | \< 5% | 18% (single-LLM baseline) |
| Information Retention Rate (Compression) | \>= 95% entity retention at \>=90% compression | N/A (No compression) |

 

**7.3 Real-World Use Cases & Practical Impact**

·       **Use Case 1 — Enterprise Ransomware Incident:** A manufacturing firm detects file encryption across 200 hosts. Specula ingests EVTX, Sysmon, and PCAPs, outputting the initial access vector, lateral movement chain, C2 servers, blast radius (47 affected hosts), and remediation steps in 5 minutes (vs. 6-hour manual response).

·       **Use Case 2 — Insider Threat Data Exfiltration:** A financial institution suspects data theft. The Insider Threat Agent analyzes email bodies, DLP alerts, and USB logs. The LSTM autoencoder detects behavioral deviation 3 weeks prior, outputting a court-ready narrative with signed VCT Merkle proofs.

·       **Use Case 3 — CI/CD Supply Chain Attack:** Cloud & Container Agent analyzes K8s pod logs. Code Stylometry Agent determines injected build script exhibits AI-generated characteristics. Dynamic Attack Graph maps exploitation paths, completing cross-layer investigation in 5 minutes.

*— End of Proposal Document —*

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAAUCAMAAABYi/ZGAAADAFBMVEUAAAAiIiIiIk4iInUiTnUiTpoidb1OTk5OTnVOdZpOmt51InV1Tk51mt51vf+aTiKavd6a3v+9dSK9dU69mnW93v+9///emk7e////vXX//73//94AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4T/VSAAAAAXRSTlMAQObYZgAAAFNJREFUeF5jYKAi4BZjYELiSjMCwQ8Yj1kMLMYG4SGrgwGCYv94GBF8iHkgIM3Ih6H3KcMfDDEQQBaTFATpZUcSAfLZGRk5gDQjEEIAy29keVoDAPA8Bixg+vzIAAAAAElFTkSuQmCC>

[image2]: <data:image/png;base64,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>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGcAAAAVCAMAAABsdQABAAADAFBMVEUAAAAiIiIiIk4iInUiTk4iTnUiTpoidb1OIiJOIk5OInVOTk5OTnVOmppOmt51IiJ1Ik51TiJ1vb11vd51vf+aTiKaTnWadU6avd6avf+a3v+9dSK9dU69mk693v+9///emk7emnXe/97e////vXX/3pr/3r3//73//94AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADumHnmAAAAAXRSTlMAQObYZgAAAVNJREFUeF7tlN1OwkAQhc9uDUUtEiwbTSVIQpV9/6ehETRiUkikJkr9oQg4bbe0VjDBlCv5LqYne5qZ7MxkgT3/keuTlWLMzDpFUjNqdSUvOFDVwL/5BSF1v5po/wAwFuCSUamrclK+ELqjVL+UgUOAT+1SG2/Tcer8AaagVOtp8zut8olRM2/8pPPLlZeKoJ93FH2Obgn22X3eWEcn2qE4bgtNCYtBkD9eiwO03MDJH/+O/gG8syWHDJ6pjBR1lOuCh8uCVkkKwCJlMyksaJdCl0+Q0U0oZox8WoWcTWhUggGNWVMOz6O9FpE1hjmBAcxN6EdzH3BJ9Sz6ojLzze5pmiVjpIdZjh03uI3n2bMfnIZLfZt4j8pddc9RpROWm/q6yXgNwxhR4htgQHsNn8WeBS96HzQvDHQxi5Q9jE3Do76FzNUvibEt4UB2yU7enT2F8QUXN2Cew6g9hgAAAABJRU5ErkJggg==>

[image4]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAAUCAMAAABYi/ZGAAADAFBMVEUAAAAiIiIiIk4iInUiTk4iTnUiTpoidb1OIiJOTiJOTk5OTnVOdb1Omt51IiJ1TiJ1mr11vd51vf+aTiKadU6avd6a3v+9dSK9dU69mnW93v+9///emk7e3r3e////vXX/3pr/3r3/3t7//73//94AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACsBTqeAAAAAXRSTlMAQObYZgAAAIlJREFUeF7FjtsKgkAURdceC5O07CEjQqPo/3+qtyB7CLoh1nEm/YKg9XI262zODPycnbQIab+W8srCysEs8s4VFh2O+wiS1rv2BGNbcY1h8j1j1Lm5QHfFKOfL2oYy2KqvlUqHXs8xu5mLn/AYeiRvc9OG7u2D6WgDjcydKyl9+U5xkVz41j/4ABIEFNdfmUxwAAAAAElFTkSuQmCC>

[image5]: <data:image/png;base64,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>

[image6]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAO0AAAAUCAYAAABh0LpeAAAFzUlEQVR4Xu1aYXrjKAxNr5Lch1xmyf8eo+5VQm8SH8WMnkCAZUjwTLqb7jDf9zq1AFkgPUlm5vD+/n4YGBj4OdgIBgYGXhsbwcDAwGtjIxgYGHhtpF/87PzxeGRYN3s9sQY/T97QfC3/v8P72U/m6J33T9/77/hhpjXWGH+0rmv+K+JE+zVT337/dvAPZxEkJh2Y5aCxDw9QgkvLnwHYRD78Ft1/ij2knSfTNQ/Y6wdJmnOn/r3wzrJ/jbX8nj/xNeuJpPT+azmaaWX3XtLaE9lDOujPm8jmT7PgvNyS9dIZLWeaezjkeTV4WnU5nfxtgcr7c/9r8A8ODjoAEYbgue8gOHRyjystglbLeD25jApDdQz4G0m71w+w4R6pS7QI4axp+kH7oOXLvXgGaafziRPcIRKMfLIEGTqUpbR5gW6Z18KPI22ZBQHJsHqygIMJWa6zPdb6HwWjzJGAAUnmaBM7RTmXSUTBF8ZNCoaWHLoMB/y6svEaGkMQI5gxNsWALttWN38PafU53fMDWei5qnTqDvvJunA2OOMWYSUxtcYDOXyqwNLK23iu2kdCyi97XOQcGaTkcDi8ybj4BevvVUc/f64qKG2GySmJT4hniYjls/a9kBlrS7tEr7uc0x6NsUmPd/8sJ3q/s2ePtR9XZvsbZJZ+h228j+uN5RdJKB/hWfYxu4s/n7M9Wv8N46zL8FqMJQfUgqXVdnEwY7CTtGXAIBjY+EYw5DWZtAh8rJmc846qu7Y3tJGkk9o4BI2MteTiAOgq5WxfSg6GvxNBWhAkBINlXeLYHsI8g7Q1P/AYHeIczyOc6f1KBT+I/p7Emdvj7bcyv5POB62zjf41+Ls4o3IvQko/fy3sQ4NOjfxJIhBHSAO/JH2K+CvbYmVFK4xAd5wMyKd2XYER+GYKwZ7sWPn+xnPxbE4SY+z0N7wDuoydvJvCJ8IUSvGbkCqMYy+ZtA/PJZIv2Sf20H4wBnuy/jAuiQNjyQG1YNEHBcDZqZJF0krW1nM1JLi0vAbdmpUo28KQBLYVpyXX0POwdx0sug2VKlTTnUnfRo2EwF4/aDtZf9Fe1yAJ9BHBBezbKScykWtbOagKcuszK9vfnvZY1nMAE3lApIBcgVFdmXT0jGqE38sKzKSj94BnordEIKX1oUiu22NJCtcbdXmzwPH58pxIKkkOaR+woyDlGZXeXvO+SOfpmCu2tgdj12XZ6MfYJ+yhMZ6sHdAKFiGpDkKBnq/ROw/QpGWicPaSrCOkDQepidCSiy5UKK7AnP3uk1Z/a94jrcYzKq2eB9RI++jiStbp9/TAxW5H9qJ18Lu/i7Rftmip80UTiCYk4taYq11RgSleQZiyzca49n2dtOFZx/he0rKOO6St29NBWibB5gLk8aVDf3u8Jit+f5TpS9IGB2Z71pW2/m3XlqOy4vJFAui5lVZjD2n3+KFm5yPSlkTXPukB1shnzb9J2tIGjUDWW/w2XldgtMqBkDnw2ffX5PvHlRYEqtigSZXs2UHaUFlhT5gfnjtJq0lRVpYQ1PVv0F7SapK2AgbvQvsjpBDS6koXLjtyQOgAmuK7anJdgTW5a2TQ9kqL2UPGPaTd4we9D4ArQeX7E2hfRNWTJ/vWFIkK/xZc7Fmf7T7SBrJIxdTj5XpNCg2+pEH3FdvkoB8VONxjrKtsrszpOZF2S1LcPMs3r+iYceAg3FNIC3s+KvZ0kJaFaCVw8HBMJEuc3CStzK9VNME81TM/E7N4T5KLHWXAYG5xCxxIpAIK/7kgjidCNuSlLgTtI9KKrvJ8YENrzyX2kBbY4wduqzi41/uroUXOCZdtFT8A2HN5c4pbcxlj2W+SludHuyEDsfR4L2ldvI0O90B5brjYyrexSW/pe6q4obKVpAl2yXvL22PEpOjTpErv3UFafr6E2+dgzy3a00nagYGBn4GNYGBg4LWxEQwMDLw2NoKBgYHXxkYwMDDw2tgIBgYGXhu/AABvpyiAOfMWAAAAAElFTkSuQmCC>

[image7]: <data:image/png;base64,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>