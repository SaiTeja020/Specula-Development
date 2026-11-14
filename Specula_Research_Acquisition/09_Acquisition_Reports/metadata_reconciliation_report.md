# Metadata reconciliation report

11 November 2026. Backup: `09_Acquisition_Reports\remediation_20261111T064220Z`. Original source values remain in byte-verified backups and `metadata_corrections.csv/json` in that directory.

## Corrected scope

- All 25 identified records now point to actual existing files: CL-070, CL-072, CL-104–CL-116, CL-127–CL-136. No missing file was invented.
- All 15 pre-existing dataset-manifest disagreements were reconciled from preserved original sources; all 23 dataset-manifest rows now match their master rows exactly.
- CL-121, CL-124 and CL-125 are P0 aliases, as their primary checklist entries specify.
- Website snapshots explicitly represent reference pages, not downloaded/installed software. Empty CSVs, unconfigured configuration, unexecuted analysis and draft reviewer instructions have separate states.
- CFA-Bench original-paper record now links to actual DOI metadata, not to a benchmark README as paper full text. Full text remains unavailable.
- Generated report sizes/hashes are detached. The workbook does not contain an impossible self-hash or pretend to know its final byte size before export. Detached manifest entries include full local relative paths.
- NIST remains P0/DEFERRED; OpTC subset remains UNAVAILABLE; MADIK remains NEEDS CONFIRMATION. Raw evidence, repositories, task labels and answer keys are unchanged.

## Original disagreement IDs

CL-033, CL-035, CL-040, CL-041, CL-042, CL-044, CL-045, CL-118, CL-120, CL-121, CL-122, CL-123, CL-124, CL-125, CL-126

## Every changed master record

| ID | Resource | Changed fields | Current status |
| --- | --- | --- | --- |
| CL-001 | Treat this file as the authoritative acquisition checklist. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-002 | Audit the existing Specula project and this acquisition folder before downloading anything. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-003 | Do not overwrite existing files or download duplicates. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-004 | Use official source pages and preserve source URLs, release/version, acquisition date, licence, and access restrictions. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-005 | Download only publicly accessible and legally obtainable material. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-006 | Ask before very large downloads, paid resources, installing software, changing the Specula environment, or accessing restricted material. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-007 | Do not bypass authentication, institutional access, payment, encryption, or dataset restrictions. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-008 | Keep ground-truth answer keys and evaluation labels access-controlled and separate from evidence supplied to the system under evaluation. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-009 | Never mark an item downloaded until its files are present and integrity/completeness checks have passed. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-010 | If an item cannot be obtained, record why and provide the official source link and next action. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-011 | Pin repositories to a release or commit; do not silently track a moving branch. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-012 | Preserve original archives and record any preprocessing separately. | artifact_state, checksum_reference, metadata_authority, resource_kind | RECORDED |
| CL-013 | Locate the existing Specula project and confirm which directories/files are accessible. | artifact_state, checksum_reference, metadata_authority, resource_kind | AUDITED |
| CL-014 | Inventory existing datasets, papers, tools, documentation, scripts, fixtures, answer keys, manifests, and logs. | artifact_state, checksum_reference, metadata_authority, resource_kind | AUDITED |
| CL-015 | Check whether an offline MITRE ATT&CK STIX v19.2 copy already exists; verify its version before acquiring another. | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-016 | Retain existing copies of: | artifact_state, checksum_reference, metadata_authority, resource_kind | AUDITED |
| CL-017 | Master doc.docx | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-018 | IEEE-paper-outline.txt | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-019 | Base Paper.pdf (GenDFIR) | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-020 | A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using LLMs.pdf | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-021 | Metrics for Specula Agents | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-022 | Report format | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-023 | Output report format and standards | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-024 | Specula Features | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-025 | SPECULA DATA FLOW | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-026 | Master_doc_planned_changes.md | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-027 | architecture_agents.html | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-028 | Existing synthetic case archives | artifact_state, checksum_reference, metadata_authority, resource_kind | AUDITED |
| CL-029 | Existing test answer keys and baseline seeds | artifact_state, checksum_reference, metadata_authority, resource_kind | AUDITED |
| CL-030 | Existing experiment manifests and logs | artifact_state, checksum_reference, metadata_authority, resource_kind | AUDITED |
| CL-031 | Review the current Specula-Development repository, skeleton branch, for evaluation scripts, test fixtures, dependency lockfiles, Compose configuration, model settings, ingestion adapters, and experiment source commit. | artifact_state, checksum_reference, metadata_authority, resource_kind | AUDITED |
| CL-032 | Produce existing_resource_inventory.csv and identify duplicates/missing resources. | artifact_state, checksum_reference, metadata_authority, resource_kind | AUDITED |
| CL-033 | NIST CFReDS — Hacking Case | artifact_state, checksum_reference, metadata_authority, resource_kind | DEFERRED |
| CL-034 | NIST CFReDS Archive — Data Leakage Case | artifact_state, checksum_reference, metadata_authority, resource_kind | DEFERRED |
| CL-035 | DARPA OpTC | artifact_state, checksum_reference, metadata_authority, resource_kind | PARTIALLY DOWNLOADED |
| CL-036 | Digital Corpora M57-Patents | artifact_state, checksum_reference, metadata_authority, resource_kind | RESTRICTED / DEFERRED |
| CL-037 | CERT Insider Threat | artifact_state, checksum_reference, metadata_authority, resource_kind | PARTIALLY DOWNLOADED |
| CL-038 | CIC-IDS2017 | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE / DEFERRED |
| CL-039 | CSE-CIC-IDS2018 | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING — CONDITIONAL |
| CL-040 | DFIR-Metric benchmark | artifact_state, checksum_reference, metadata_authority, resource_kind | PARTIALLY DOWNLOADED |
| CL-041 | DFIR-Metric paper | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-042 | MITRE ATT&CK Enterprise STIX data | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-043 | NIST CFTT / CFReDS test cases | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING — CONDITIONAL |
| CL-044 | CFA-Bench | artifact_state, checksum_reference, metadata_authority, resource_kind | PARTIALLY DOWNLOADED |
| CL-045 | CyberSleuth benchmark/framework | artifact_state, checksum_reference, metadata_authority, resource_kind | PARTIALLY DOWNLOADED |
| CL-046 | GenDFIR — Loumachi et al. (2024) — already available; verify local file. | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-047 | A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using LLMs — Hmimou et al. (2025) — already available; verify local file. | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-048 | DFIR-Metric — Cherif et al. (2025) | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-049 | Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks — Lewis et al. | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-050 | ReAct: Synergizing Reasoning and Acting in Language Models — Yao et al. | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-051 | GraphRAG: From Local to Global — Edge et al. | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-052 | Drain: An Online Log Parsing Approach with Fixed Depth Tree | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-053 | A Directed Acyclic Graph Approach to Online Log Parsing — He et al. (2018) | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-054 | Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization — Sharafaldin et al. | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-055 | MADIK original paper | artifact_state, checksum_reference, metadata_authority, resource_kind | NEEDS CONFIRMATION |
| CL-056 | CyberSleuth original paper | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-057 | CFA-Bench original paper | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status, version | METADATA ONLY — FULL TEXT UNAVAILABLE |
| CL-058 | Analysis of Competing Hypotheses (ACH) | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-059 | Multi-agent debate | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-060 | Evidence provenance | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-061 | Semantic compression | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-062 | Forensic timelines | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-063 | Timestamp manipulation | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-064 | Graph-based threat correlation | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-065 | Velociraptor — https://github.com/Velocidex/velociraptor — endpoint artifact acquisition/lab captures. | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-066 | Plaso / log2timeline — https://github.com/log2timeline/plaso — independent timeline extraction. | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-067 | Timesketch — https://github.com/google/timesketch — reference timeline analysis/review. | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-068 | Zeek — https://github.com/zeek/zeek — network event extraction. | artifact_state, checksum_reference, metadata_authority, resource_kind | DEFERRED |
| CL-069 | Suricata — https://github.com/OISF/suricata — network security events. | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-070 | Wireshark / TShark — https://www.wireshark.org/download.html — PCAP inspection/verification. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, notes, resource_kind, sha256, verification_status, version | WEBSITE REFERENCE — VERIFIED |
| CL-071 | Volatility 3 — https://github.com/volatilityfoundation/volatility3 — independent memory examination. | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-072 | Eric Zimmerman's forensic tools — https://ericzimmerman.github.io/ — Windows artifact parsing. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, notes, resource_kind, sha256, verification_status, version | WEBSITE REFERENCE — VERIFIED |
| CL-073 | Drain3 — P0, check installed copy — https://github.com/logpai/Drain3 | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-074 | LangGraph — P0, check installed copy — https://github.com/langchain-ai/langgraph | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-075 | Neo4j — P0, check installed copy — https://github.com/neo4j/neo4j | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-076 | FAISS — P0, check installed copy — https://github.com/facebookresearch/faiss | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-077 | Chroma — P0, check installed copy — https://github.com/chroma-core/chroma | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-078 | OCSF Schema — P0 — https://github.com/ocsf/ocsf-schema | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-079 | NetworkX — P1 — https://github.com/networkx/networkx | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-080 | scikit-learn — P1 — https://github.com/scikit-learn/scikit-learn | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-081 | Atomic Red Team — P1 — https://github.com/redcanaryco/atomic-red-team | artifact_state, checksum_reference, metadata_authority, resource_kind | DEFERRED |
| CL-082 | MITRE CALDERA — P2 — https://github.com/mitre/caldera | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING — CONDITIONAL |
| CL-083 | Sigma rules — P1 — https://github.com/SigmaHQ/sigma | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-084 | CAPE Sandbox — P2 — https://github.com/kevoreilly/CAPEv2 | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING — CONDITIONAL |
| CL-085 | YARA-X — P2 — https://github.com/VirusTotal/yara-x | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING — CONDITIONAL |
| CL-086 | pytest — P0 — https://docs.pytest.org/ | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-087 | pandas — P0 — https://pandas.pydata.org/ | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-088 | SciPy — P1 — https://scipy.org/ | artifact_state, checksum_reference, metadata_authority, resource_kind | EXISTS — VERIFIED |
| CL-089 | statsmodels — P1 — https://www.statsmodels.org/ | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING |
| CL-090 | psutil — P1 — https://github.com/giampaolo/psutil | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-091 | MLflow — P2 — https://mlflow.org/ | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING — CONDITIONAL |
| CL-092 | DVC — P2 — https://dvc.org/ | artifact_state, checksum_reference, metadata_authority, resource_kind | PENDING — CONDITIONAL |
| CL-093 | ISO/IEC 27037 — identification, collection, acquisition, and preservation — https://www.iso.org/standard/44381.html | artifact_state, checksum_reference, metadata_authority, resource_kind | RESTRICTED |
| CL-094 | ISO/IEC 27041 — investigative-method suitability and validation — https://www.iso.org/standard/44405.html | artifact_state, checksum_reference, metadata_authority, resource_kind | RESTRICTED |
| CL-095 | ISO/IEC 27042 — digital evidence analysis and interpretation — https://www.iso.org/search.html?q=ISO%2FIEC+27042 | artifact_state, checksum_reference, metadata_authority, resource_kind | RESTRICTED |
| CL-096 | ISO/IEC 27043 — incident investigation principles — https://www.iso.org/search.html?q=ISO%2FIEC+27043 | artifact_state, checksum_reference, metadata_authority, resource_kind | RESTRICTED |
| CL-097 | NIST SP 800-86 — forensic techniques in incident response — https://csrc.nist.gov/pubs/sp/800/86/final | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-098 | NIST SP 800-61 Rev. 3 — incident response — https://csrc.nist.gov/pubs/sp/800/61/r3/final | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-099 | MITRE ATT&CK documentation — https://attack.mitre.org/ | acquisition_status, artifact_state, checksum_reference, metadata_authority, resource_kind | WEBSITE REFERENCE — VERIFIED |
| CL-100 | OCSF schema documentation — https://schema.ocsf.io/ | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-101 | NIST AI 600-1 — Generative AI risk management — https://doi.org/10.6028/NIST.AI.600-1 | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-102 | Daubert v. Merrell Dow Pharmaceuticals — https://supreme.justia.com/cases/federal/us/509/579/ | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-103 | NIST Computer Forensics Tool Testing (CFTT) — https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt | acquisition_status, artifact_state, checksum_reference, metadata_authority, resource_kind | WEBSITE REFERENCE — VERIFIED |
| CL-104 | dataset_manifest.csv — dataset URLs, versions, checksums, licences, acquisition dates. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | RESOURCE MANIFEST — POPULATED |
| CL-105 | case_ground_truth.csv — verified events, outcomes, identities, timestamps, evidence IDs. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | EVALUATION TEMPLATE — EMPTY |
| CL-106 | critical_evidence.csv — critical evidence labels and supporting rationale. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | EVALUATION TEMPLATE — EMPTY |
| CL-107 | ground_truth_relationships.csv — typed graph relationships and source references. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | EVALUATION TEMPLATE — EMPTY |
| CL-108 | known_temporal_order.csv — confirmed event-order pairs and uncertain orderings. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | EVALUATION TEMPLATE — EMPTY |
| CL-109 | reviewer_instructions.pdf — blinded assessment protocol and labeling definitions. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | REVIEWER PROTOCOL — DRAFT |
| CL-110 | reviewer_scores.csv — independent claim-level and citation-level judgments. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | EVALUATION TEMPLATE — EMPTY |
| CL-111 | experiment_config.yaml — dataset subset, model identity, retrieval settings, run parameters. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | CONFIGURATION TEMPLATE — UNCONFIGURED |
| CL-112 | baseline_results.csv — single-agent, multi-agent RAG, and Specula measurements. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | EVALUATION TEMPLATE — EMPTY |
| CL-113 | ablation_results.csv — compression, GraphRAG, and debate component-removal measurements. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | EVALUATION TEMPLATE — EMPTY |
| CL-114 | latency_resource_log.csv — runtime, token usage, resource consumption, failures, timeouts. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | EVALUATION TEMPLATE — EMPTY |
| CL-115 | statistical_analysis.ipynb — case-level analysis, uncertainty, reviewer agreement. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | ANALYSIS TEMPLATE — UNEXECUTED |
| CL-116 | reproducibility_manifest.json — source commits, environment versions, hashes, run identifiers. | acquisition_status, actual_size_bytes, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, sha256, verification_status | REPRODUCIBILITY TEMPLATE — UNPOPULATED |
| CL-117 | 1. One NIST CFReDS case — https://cfreds.nist.gov/ | artifact_state, checksum_reference, metadata_authority, resource_kind | DEFERRED |
| CL-118 | 2. OpTC README, errata, and red-team ground truth — https://github.com/FiveDirections/OpTC-data | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-119 | 3. A small documented OpTC event subset — https://github.com/FiveDirections/OpTC-data | artifact_state, checksum_reference, metadata_authority, resource_kind | UNAVAILABLE |
| CL-120 | 4. DFIR-Metric evaluation code and datasets — https://github.com/DFIR-Metric | artifact_state, checksum_reference, metadata_authority, resource_kind | PARTIALLY DOWNLOADED |
| CL-121 | 5. DFIR-Metric research paper — https://arxiv.org/abs/2505.19973 | artifact_state, checksum_reference, metadata_authority, priority, resource_kind | DOWNLOADED — VERIFIED |
| CL-122 | 6. Versioned MITRE ATT&CK STIX collection — https://github.com/mitre-attack/attack-stix-data | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-123 | 7. OCSF schema definitions — https://github.com/ocsf/ocsf-schema | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-124 | 8. NIST SP 800-86 — https://csrc.nist.gov/pubs/sp/800/86/final | artifact_state, checksum_reference, metadata_authority, priority, resource_kind | DOWNLOADED — VERIFIED |
| CL-125 | 9. NIST SP 800-61 Revision 3 — https://csrc.nist.gov/pubs/sp/800/61/r3/final | artifact_state, checksum_reference, metadata_authority, priority, resource_kind | DOWNLOADED — VERIFIED |
| CL-126 | 10. Plaso and Timesketch reference implementations — https://github.com/log2timeline/plaso and https://github.com/google/timesketch | artifact_state, checksum_reference, metadata_authority, resource_kind | DOWNLOADED — VERIFIED |
| CL-127 | 00_Master_Inventory/master_acquisition_tracker.xlsx | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |
| CL-128 | 00_Master_Inventory/existing_resource_inventory.csv | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |
| CL-129 | 00_Master_Inventory/missing_resources_report.csv | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |
| CL-130 | 00_Master_Inventory/restricted_resources_report.csv | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |
| CL-131 | 08_Checksums_And_Manifests/dataset_manifest.csv | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |
| CL-132 | 08_Checksums_And_Manifests/repository_manifest.csv | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |
| CL-133 | 08_Checksums_And_Manifests/research_paper_bibliography.csv | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |
| CL-134 | 08_Checksums_And_Manifests/resource_checksums.csv | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |
| CL-135 | 09_Acquisition_Reports/acquisition_summary.pdf | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |
| CL-136 | 09_Acquisition_Reports/acquisition_log.md | acquisition_status, artifact_state, checksum_reference, local_storage_path, metadata_authority, resource_kind, verification_status | ARTIFACT — VERIFIED VIA DETACHED MANIFEST |

## Field-level evidence and preservation

The complete before/after value, authoritative source and inspection time for every field change are recorded in `09_Acquisition_Reports\remediation_20261111T064220Z\metadata_corrections.csv`. This includes new derived classification fields; it does not replace original acquired source values. Saved release dates describe original publication/release metadata, not a fabricated acquisition or runtime date.

## Unresolved discrepancies / limits

- No publisher signature/authenticity claim is added by local hash reconciliation. Where a licence or exact version date was not established, it remains unresolved or points to preserved metadata.
- Release/metadata snapshots are not live runtime validation. No ISO access, missing original document, CFA paper download, OpTC payload or large dataset restriction is silently resolved.
- Thirty-one mutable datastore hashes remain explicitly deferred. No original stores were opened for writes, reset or reindexed.
- Historical acquisition_summary.pdf and earlier receipts remain historical records. The security plan and post_remediation_verification.md supersede any assumption that the top-level evaluator ACL describes all descendants.
- Final workbook/detached checksum verification is reported separately in post_remediation_verification.md. No security or empirical-readiness gate is made passing by metadata repair.

## Final linked-source URL corrections

The field ledger now contains 874 entries. Two reference-only tool gaps remain unresolved even though their website snapshots are verified.

| ID | Field | Original | Corrected | Authority |
| --- | --- | --- | --- | --- |
| CL-057 | download_url | https://github.com/SmartData-Polito/CFA-bench/blob/da8a92fa16d6d6f30e702299c8e368cb6461d5f7/README.md | https://api.crossref.org/works/10.1109/EuroSPW67616.2025.00031 | download_events.jsonl response record at exact linked local path |
| CL-057 | licence_access_restrictions | Public repository; explicit reuse licence not found; no redistribution permission inferred | Public DOI metadata; paper full text not acquired; publisher rights/terms unresolved for use beyond metadata | download_events.jsonl response record at exact linked local path |
| CL-070 | download_url |  | https://www.wireshark.org/download.html | download_events.jsonl response record at exact linked local path |
| CL-072 | download_url |  | https://ericzimmerman.github.io/ | download_events.jsonl response record at exact linked local path |
| CL-072 | expected_size_bytes |  | 32914 | download_events.jsonl response record at exact linked local path |

## Additional contradictions detected by final verification

CL-019 and CL-020 distinguish missing named originals from separately acquired bibliographic equivalents. The latter remain present and verified; no paper was deleted or redownloaded. CL-015 now states that the prior offline copy is XLSX, not STIX. CL-027 now links its existing integrity proof directly. These changes increase unresolved named-original dispositions to 50 without changing the nine acquired-paper count.

| ID | Field | Before | After | Authority |
| --- | --- | --- | --- | --- |
| CL-019 | acquisition_status | DOWNLOADED — VERIFIED | UNAVAILABLE | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | resource_kind | existing_resource_or_audit_step | named_original_lookup | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | artifact_state | NOT_ASSERTED_AS_EXPERIMENT_RESULT | EXACT_NAMED_ORIGINAL_NOT_LOCATED | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | local_storage_path | C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\03_Research_Papers\2409.02572\2409.02572v4.pdf |  | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | sha256 | bf40c1cbddfc137e004c9d258d12244d70a6e180272b9def7560c82b54357b1d |  | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | actual_size_bytes | 1197620 |  | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | version | 2409.02572v4 | UNRESOLVED for the requested named original | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | checksum_reference | Direct SHA-256 in row | No bytes asserted for missing named original; see separate acquired paper record and bibliography | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | verification_status | Executable local hash/format/commit checks passed; scientific validity not established | Exact requested local filename not located; acquired bibliographic equivalent is a separate artifact | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | metadata_authority | CHECKLIST.md; original source values retained in 09_Acquisition_Reports\remediation_20261111T064220Z\backup\00_Master_Inventory\checklist_status.csv | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-019 | notes | Checklist line 30; no unverified acquisition claimed; Actual arXiv PDF parsed and hashed; original metadata preserved.; Size/hash identify the linked local file; multipart/repository totals are in manifests. | Checklist line 30; no unverified acquisition claimed; Actual arXiv PDF parsed and hashed; original metadata preserved.; Size/hash identify the linked local file; multipart/repository totals are in manifests.; Reconciled named-original lookup: no acquired-copy hash/size is attributed to the absent original. The separately acquired equivalent paper remains verified in the bibliography. | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-020 | resource_kind | existing_resource_or_audit_step | named_original_lookup | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-020 | artifact_state | NOT_ASSERTED_AS_EXPERIMENT_RESULT | EXACT_NAMED_ORIGINAL_NOT_LOCATED | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-020 | sha256 | a935ebc932bad60bdf107919bb44a714be60b2296b362d3951a4d2e25e37688b |  | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-020 | actual_size_bytes | 3557681 |  | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-020 | version | IEEE version of record 2025 | UNRESOLVED for the requested named original | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-020 | checksum_reference | Direct SHA-256 in row | No bytes asserted for missing named original; see separate acquired paper record and bibliography | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-020 | verification_status | No exact local name located; external copies not assumed missing | Exact requested local filename not located; acquired bibliographic equivalent is a separate artifact | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-020 | metadata_authority | CHECKLIST.md; original source values retained in 09_Acquisition_Reports\remediation_20261111T064220Z\backup\00_Master_Inventory\checklist_status.csv | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-020 | notes | Checklist line 31; no unverified acquisition claimed; Existing named local paper not found; official open IEEE PDF parsed (17 pages), DOI and CC BY 4.0 metadata verified.; Size/hash identify the linked local file; multipart/repository totals are in manifests.; NAMED ORIGINAL NOT LOCATED IN AUDITED SCOPE | Checklist line 31; no unverified acquisition claimed; Existing named local paper not found; official open IEEE PDF parsed (17 pages), DOI and CC BY 4.0 metadata verified.; Size/hash identify the linked local file; multipart/repository totals are in manifests.; NAMED ORIGINAL NOT LOCATED IN AUDITED SCOPE; Reconciled named-original lookup: no acquired-copy hash/size is attributed to the absent original. The separately acquired equivalent paper remains verified in the bibliography. | 00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained |
| CL-015 | acquisition_status | EXISTS — VERIFIED | AUDITED — XLSX EXISTS; ORIGINAL STIX NOT LOCATED | Original inventory and offline workbooks are XLSX; separately acquired versioned STIX is recorded under CL-042/CL-122 |
| CL-015 | resource_kind | existing_resource_or_audit_step | audit_step | Checklist asks to check the prior offline copy; a workbook is not STIX JSON |
| CL-015 | artifact_state | NOT_ASSERTED_AS_EXPERIMENT_RESULT | EXISTING_XLSX_REFERENCE_NOT_STIX | known_attacks/enterprise-attack-v19.2.xlsx ZIP/XML format |
| CL-027 | sha256 |  | 1c6041a468365578ec29c9b2e24b91bbb5154aace80e8133d47a770c8f087a90 | Fresh hash of exact existing architecture_agents.html, already covered by resource_checksums.csv |
| CL-027 | actual_size_bytes |  | 256322 | Filesystem byte size of exact existing path |
| CL-027 | checksum_reference | No acquired bytes asserted; see status/notes | 08_Checksums_And_Manifests/resource_checksums.csv#C:\Users\DELL\Specula-skeleton\docs\architecture_agents.html | Existing independent per-file integrity ledger |
