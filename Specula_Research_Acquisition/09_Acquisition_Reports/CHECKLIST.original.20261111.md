# Specula — Research Resource Acquisition Checklist

**Purpose:** Acquire, verify, and organize the resources needed for the Specula IEEE empirical research paper.

**Priority definitions:** P0 = essential for initial evaluation; P1 = broader comparative study; P2 = optional or feature-specific.

## Instructions for the acquisition agent

- [ ] Treat this file as the authoritative acquisition checklist.
- [ ] Audit the existing Specula project and this acquisition folder before downloading anything.
- [ ] Do not overwrite existing files or download duplicates.
- [ ] Use official source pages and preserve source URLs, release/version, acquisition date, licence, and access restrictions.
- [ ] Download only publicly accessible and legally obtainable material.
- [ ] Ask before very large downloads, paid resources, installing software, changing the Specula environment, or accessing restricted material.
- [ ] Do not bypass authentication, institutional access, payment, encryption, or dataset restrictions.
- [ ] Keep ground-truth answer keys and evaluation labels access-controlled and separate from evidence supplied to the system under evaluation.
- [ ] Never mark an item downloaded until its files are present and integrity/completeness checks have passed.
- [ ] If an item cannot be obtained, record why and provide the official source link and next action.
- [ ] Pin repositories to a release or commit; do not silently track a moving branch.
- [ ] Preserve original archives and record any preprocessing separately.

## 0. Existing Specula project audit — do first

- [ ] Locate the existing Specula project and confirm which directories/files are accessible.
- [ ] Inventory existing datasets, papers, tools, documentation, scripts, fixtures, answer keys, manifests, and logs.
- [ ] Check whether an offline MITRE ATT&CK STIX v19.2 copy already exists; verify its version before acquiring another.
- [ ] Retain existing copies of:
  - [ ] `Master doc.docx`
  - [ ] `IEEE-paper-outline.txt`
  - [ ] `Base Paper.pdf` (GenDFIR)
  - [ ] `A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using LLMs.pdf`
  - [ ] `Metrics for Specula Agents`
  - [ ] `Report format`
  - [ ] `Output report format and standards`
  - [ ] `Specula Features`
  - [ ] `SPECULA DATA FLOW`
  - [ ] `Master_doc_planned_changes.md`
  - [ ] `architecture_agents.html`
  - [ ] Existing synthetic case archives
  - [ ] Existing test answer keys and baseline seeds
  - [ ] Existing experiment manifests and logs
- [ ] Review the current Specula-Development repository, `skeleton` branch, for evaluation scripts, test fixtures, dependency lockfiles, Compose configuration, model settings, ingestion adapters, and experiment source commit.
- [ ] Produce `existing_resource_inventory.csv` and identify duplicates/missing resources.

## 1. Forensic datasets and ground-truth files

Acquire original evidence, documentation, answer keys where legitimately available, acquisition manifests, and checksums together. Record access restrictions.

### P0 — initial evaluation

- [ ] **NIST CFReDS — Hacking Case**
  - Official source: https://cfreds.nist.gov/
  - Seek: evidence image, case documentation, known findings.
  - Record exact case/image name, version, size, licence/terms, and checksum.
- [ ] **NIST CFReDS Archive — Data Leakage Case**
  - Official source: https://cfreds-archive.nist.gov/
  - Seek: disk evidence, scenario description, reference findings.
  - Verify current availability and exact download instructions.

- [ ] **DARPA OpTC**
  - Official source: https://github.com/FiveDirections/OpTC-data
  - Seek first: README, documentation, errata, eCAR documentation, red-team ground-truth PDF, and a small documented endpoint/network JSON subset.
  - Do not attempt the approximately terabyte-scale compressed corpus as a single download.
  - Estimate subset size and required storage; obtain approval before large downloads.
  - Preserve the exact subset selection and source commit.

### P1 — broader comparative study

- [ ] **Digital Corpora M57-Patents**
  - Official source: https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
  - Seek: selected disk images, RAM/PCAP where available, detective reports, scenario documentation.
  - Important: answer keys are encrypted/restricted to qualified faculty or other authorized recipients. Do not bypass restrictions or redistribute restricted keys.
- [ ] **CERT Insider Threat**
  - Official source: https://doi.org/10.1184/R1/12841247.v1
  - Seek: one documented release, CSV records, README, and `answers.tar.bz2` only if access terms permit.
  - Record release/version and licence/access conditions.
- [ ] **CIC-IDS2017**
  - Official source: https://www.unb.ca/cic/datasets/ids-2017.html
  - Seek: labeled CSV files, selected PCAPs, attack schedules, and dataset paper.
  - Record chosen subset and storage requirements.

### P2 — optional

- [ ] **CSE-CIC-IDS2018**
  - Official source: https://www.unb.ca/cic/datasets/index.html
  - Seek: selected network flows, traffic captures, and labeling documentation.
  - Acquire only if it adds coverage not already provided by selected datasets.

## 2. Benchmark datasets and evaluation repositories

### P0

- [ ] **DFIR-Metric benchmark**
  - Official source: https://github.com/DFIR-Metric
  - Seek: official evaluation code and released MCQ, CTF, and forensic-search components/datasets.
  - Record repository commit, dataset versions, licences, and setup instructions.
- [ ] **DFIR-Metric paper**
  - Source: https://arxiv.org/abs/2505.19973
  - Download paper and record authors, title, version/date, and bibliographic metadata.
- [ ] **MITRE ATT&CK Enterprise STIX data**
  - Official source: https://github.com/mitre-attack/attack-stix-data
  - Seek: versioned STIX JSON collection.
  - First check the existing Specula offline ATT&CK v19.2 copy; avoid unnecessary duplicate acquisition.
- [ ] **NIST CFTT / CFReDS test cases**
  - Dataset portal: https://cfreds.nist.gov/
  - Identify relevant deterministic forensic-tool validation cases; acquire in P1 if not needed for the initial pilot.

### P2 — verify before acquisition

- [ ] **CFA-Bench**
  - Verify exact original publication, authors, and official release repository before acquiring.
  - Do not substitute a similarly named benchmark.
- [ ] **CyberSleuth benchmark/framework**
  - Verify exact intended paper and official implementation before acquiring.
  - Do not substitute a similarly named project.

## 3. Research papers

Two papers are already supplied in the Specula project. Retain them; do not redownload unless a newer/publisher version is specifically needed.

### P0

- [ ] **GenDFIR — Loumachi et al. (2024)** — already available; verify local file.
  - https://arxiv.org/abs/2409.02572
- [ ] **A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using LLMs — Hmimou et al. (2025)** — already available; verify local file.
  - https://doi.org/10.1109/ACCESS.2025.3602681
- [ ] **DFIR-Metric — Cherif et al. (2025)**
  - https://arxiv.org/abs/2505.19973
- [ ] **Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks — Lewis et al.**
  - https://arxiv.org/abs/2005.11401
- [ ] **ReAct: Synergizing Reasoning and Acting in Language Models — Yao et al.**
  - https://arxiv.org/abs/2210.03629

### P1

- [ ] **GraphRAG: From Local to Global — Edge et al.**
  - https://arxiv.org/abs/2404.16130
- [ ] **Drain: An Online Log Parsing Approach — He et al.**
  - https://arxiv.org/abs/1806.04356
- [ ] **Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization — Sharafaldin et al.**
  - https://www.unb.ca/cic/datasets/ids-2017.html
- [ ] **MADIK original paper**
  - Exact bibliography is not established in the source checklist. Verify intended title, authors, DOI, and task with the Specula project owner before selecting a paper.
- [ ] **CyberSleuth original paper**
  - Verify exact intended title, authors, DOI, and task before acquisition.
- [ ] **CFA-Bench original paper**
  - Verify exact intended title, authors, DOI, and task before acquisition.

### Additional literature — discover and verify before adding

- [ ] Analysis of Competing Hypotheses (ACH)
- [ ] Multi-agent debate
- [ ] Evidence provenance
- [ ] Semantic compression
- [ ] Forensic timelines
- [ ] Timestamp manipulation
- [ ] Graph-based threat correlation

For each additional paper, record why it is relevant to an implemented feature or evaluation question. Do not add papers solely because their titles appear related.

## 4. Software repositories and tools

These are reference/conditional installation resources, not instructions to reinstall the existing Specula stack. First check whether each tool is already installed or represented in the project. Do not install or modify environments without approval.

### A. Forensic acquisition and analysis — P1

- [ ] **Velociraptor** — https://github.com/Velocidex/velociraptor — endpoint artifact acquisition/lab captures.
- [ ] **Plaso / log2timeline** — https://github.com/log2timeline/plaso — independent timeline extraction.
- [ ] **Timesketch** — https://github.com/google/timesketch — reference timeline analysis/review.
- [ ] **Zeek** — https://github.com/zeek/zeek — network event extraction.
- [ ] **Suricata** — https://github.com/OISF/suricata — network security events.
- [ ] **Wireshark / TShark** — https://www.wireshark.org/download.html — PCAP inspection/verification.
- [ ] **Volatility 3** — https://github.com/volatilityfoundation/volatility3 — independent memory examination.
- [ ] **Eric Zimmerman's forensic tools** — https://ericzimmerman.github.io/ — Windows artifact parsing.

### B. Semantic compression, retrieval, and graphs

- [ ] **Drain3** — P0, check installed copy — https://github.com/logpai/Drain3
- [ ] **LangGraph** — P0, check installed copy — https://github.com/langchain-ai/langgraph
- [ ] **Neo4j** — P0, check installed copy — https://github.com/neo4j/neo4j
- [ ] **FAISS** — P0, check installed copy — https://github.com/facebookresearch/faiss
- [ ] **Chroma** — P0, check installed copy — https://github.com/chroma-core/chroma
- [ ] **OCSF Schema** — P0 — https://github.com/ocsf/ocsf-schema
- [ ] **NetworkX** — P1 — https://github.com/networkx/networkx
- [ ] **scikit-learn** — P1 — https://github.com/scikit-learn/scikit-learn

### C. Adversarial testing and controlled lab generation

Only use in a dedicated, authorized, isolated test environment, with a separately recorded execution diary.

- [ ] **Atomic Red Team** — P1 — https://github.com/redcanaryco/atomic-red-team
- [ ] **MITRE CALDERA** — P2 — https://github.com/mitre/caldera
- [ ] **Sigma rules** — P1 — https://github.com/SigmaHQ/sigma
- [ ] **CAPE Sandbox** — P2 — https://github.com/kevoreilly/CAPEv2
- [ ] **YARA-X** — P2 — https://github.com/VirusTotal/yara-x

### D. Experiment and reproducibility utilities

- [ ] **pytest** — P0 — https://docs.pytest.org/
- [ ] **pandas** — P0 — https://pandas.pydata.org/
- [ ] **SciPy** — P1 — https://scipy.org/
- [ ] **statsmodels** — P1 — https://www.statsmodels.org/
- [ ] **psutil** — P1 — https://github.com/giampaolo/psutil
- [ ] **MLflow** — P2 — https://mlflow.org/
- [ ] **DVC** — P2 — https://dvc.org/

For the first pilot, existing Python dependencies, structured CSV/JSON output, and a versioned experiment manifest may be sufficient. MLflow and DVC are optional until experiment volume justifies them.

## 5. Standards, forensic guidelines, and technical documentation

Some ISO standards may require institutional access or purchase. Do not obtain unauthorized copies. Record metadata and access status if full text is unavailable.

### P0

- [ ] **ISO/IEC 27037** — identification, collection, acquisition, and preservation — https://www.iso.org/standard/44381.html
- [ ] **ISO/IEC 27041** — investigative-method suitability and validation — https://www.iso.org/standard/44405.html
- [ ] **ISO/IEC 27042** — digital evidence analysis and interpretation — https://www.iso.org/search.html?q=ISO%2FIEC+27042
- [ ] **ISO/IEC 27043** — incident investigation principles — https://www.iso.org/search.html?q=ISO%2FIEC+27043
- [ ] **NIST SP 800-86** — forensic techniques in incident response — https://csrc.nist.gov/pubs/sp/800/86/final
- [ ] **NIST SP 800-61 Rev. 3** — incident response — https://csrc.nist.gov/pubs/sp/800/61/r3/final
- [ ] **MITRE ATT&CK documentation** — https://attack.mitre.org/
- [ ] **OCSF schema documentation** — https://schema.ocsf.io/

### P1

- [ ] **NIST AI 600-1** — Generative AI risk management — https://doi.org/10.6028/NIST.AI.600-1
- [ ] **Daubert v. Merrell Dow Pharmaceuticals** — https://supreme.justia.com/cases/federal/us/509/579/
- [ ] **NIST Computer Forensics Tool Testing (CFTT)** — https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt

Use NIST SP 800-61 Rev. 3 (released April 2025) for current incident-response guidance. Retain Rev. 2 only if needed for historical comparison.

## 6. Evaluation artifacts — create, do not download

Create templates initially. Populate factual ground truth only from verified sources and authorized reviewers. Do not invent labels or results.

- [ ] `dataset_manifest.csv` — dataset URLs, versions, checksums, licences, acquisition dates.
- [ ] `case_ground_truth.csv` — verified events, outcomes, identities, timestamps, evidence IDs.
- [ ] `critical_evidence.csv` — critical evidence labels and supporting rationale.
- [ ] `ground_truth_relationships.csv` — typed graph relationships and source references.
- [ ] `known_temporal_order.csv` — confirmed event-order pairs and uncertain orderings.
- [ ] `reviewer_instructions.pdf` — blinded assessment protocol and labeling definitions.
- [ ] `reviewer_scores.csv` — independent claim-level and citation-level judgments.
- [ ] `experiment_config.yaml` — dataset subset, model identity, retrieval settings, run parameters.
- [ ] `baseline_results.csv` — single-agent, multi-agent RAG, and Specula measurements.
- [ ] `ablation_results.csv` — compression, GraphRAG, and debate component-removal measurements.
- [ ] `latency_resource_log.csv` — runtime, token usage, resource consumption, failures, timeouts.
- [ ] `statistical_analysis.ipynb` — case-level analysis, uncertainty, reviewer agreement.
- [ ] `reproducibility_manifest.json` — source commits, environment versions, hashes, run identifiers.

Ground-truth files must be separately access-controlled. Reviewers should be blinded to the producing system. Preserve original judgments even after adjudication.

## 7. First 10 acquisitions — execute this pilot first

- [ ] 1. One NIST CFReDS case — https://cfreds.nist.gov/
- [ ] 2. OpTC README, errata, and red-team ground truth — https://github.com/FiveDirections/OpTC-data
- [ ] 3. A small documented OpTC event subset — https://github.com/FiveDirections/OpTC-data
- [ ] 4. DFIR-Metric evaluation code and datasets — https://github.com/DFIR-Metric
- [ ] 5. DFIR-Metric research paper — https://arxiv.org/abs/2505.19973
- [ ] 6. Versioned MITRE ATT&CK STIX collection — https://github.com/mitre-attack/attack-stix-data
- [ ] 7. OCSF schema definitions — https://github.com/ocsf/ocsf-schema
- [ ] 8. NIST SP 800-86 — https://csrc.nist.gov/pubs/sp/800/86/final
- [ ] 9. NIST SP 800-61 Revision 3 — https://csrc.nist.gov/pubs/sp/800/61/r3/final
- [ ] 10. Plaso and Timesketch reference implementations — https://github.com/log2timeline/plaso and https://github.com/google/timesketch

After the pilot, consider CERT Insider Threat, an appropriate M57-Patents subset, and additional benchmarks only where they cover a missing forensic capability.

## 8. Required output files and tracking

Create these in the acquisition workspace:

- [ ] `00_Master_Inventory/master_acquisition_tracker.xlsx`
- [ ] `00_Master_Inventory/existing_resource_inventory.csv`
- [ ] `00_Master_Inventory/missing_resources_report.csv`
- [ ] `00_Master_Inventory/restricted_resources_report.csv`
- [ ] `08_Checksums_And_Manifests/dataset_manifest.csv`
- [ ] `08_Checksums_And_Manifests/repository_manifest.csv`
- [ ] `08_Checksums_And_Manifests/research_paper_bibliography.csv`
- [ ] `08_Checksums_And_Manifests/resource_checksums.csv`
- [ ] `09_Acquisition_Reports/acquisition_summary.pdf`
- [ ] `09_Acquisition_Reports/acquisition_log.md`

The master tracker should contain: resource name, category, priority, official source, download URL, version, expected/actual size, acquisition status, local path, SHA-256, licence/access restrictions, verification status, date checked/acquired, and notes.

Use clear statuses such as:
- `EXISTS — VERIFIED`
- `DOWNLOADED — VERIFIED`
- `PARTIALLY DOWNLOADED`
- `PENDING`
- `RESTRICTED`
- `UNAVAILABLE`
- `DUPLICATE — EXISTING COPY`
- `NOT REQUIRED — JUSTIFICATION RECORDED`

## 9. Recommended workspace layout

Specula_Research_Acquisition/
- `CHECKLIST.md`
- `00_Master_Inventory/`
- `01_Forensic_Datasets/`
- `02_Benchmarks/`
- `03_Research_Papers/`
- `04_Software_Repositories/`
- `05_Standards_Documentation/`
- `06_Existing_Project_Resources/`
- `07_Evaluation_Artifacts/`
- `08_Checksums_And_Manifests/`
- `09_Acquisition_Reports/`

## Definition of done

The task is complete only when every checklist item has a recorded status, every acquired item has a verified local path and provenance record, unresolved/restricted items are explained, and the master tracker and acquisition summary are generated. Do not claim the entire project is complete merely because the first 10 pilot items are complete.
