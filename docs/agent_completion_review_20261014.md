# Sequential agent completion review — 2026-10-14

This records the additional work authorized after the per-agent completeness audit.
“Verified” below means the stated supported implementation has an executed oracle.
It does not mean unlimited forensic coverage, correct attribution for every incident,
or judicial admissibility. Existing cases and their historical rejected outputs remain unchanged.

## Implemented and verified stages

| Agent / component | Additional supported implementation | Executed verification |
|---|---|---|
| Supervisor | Case-derived executable task catalog; Qwen chooses only available case tasks; bounded rounds, persisted receipts, no repeat after checkpoint resume. Only disputed/insufficient-context assessments generate further work. | `tests/test_investigation_followup.py`; actual Qwen probe selected six actions and obtained six complete source/native receipts. |
| Evidence collection | Structured local WinEvent XML/EventData/host/record/channel acquisition, explicit channel failures, generic retention of unmapped events, acquisition requests, Qwen receipt explanation with immutable deterministic triage. | `tests/test_windows_acquisition.py`, `tests/agents/test_evidence_collection_runtime.py`; real System-channel acquisition retained two structured records. |
| Log analysis | Context-only cases no longer skipped; service/task lifecycle XML, bounded script-fragment reconstruction, command attempts and source correlations. | `tests/test_endpoint_context.py`, existing log-analysis suite. |
| Network primary / specialist | Native Ethernet PCAP/PCAPNG intake and OCSF sessions; IPv4/IPv6 TCP/UDP; bidirectional handshake/reset metadata; sequence-aware captured ranges, retransmission/overlap/gap controls; DNS and HTTP/TLS-prefix observations. Primary findings receive structured Qwen interpretation. | `tests/test_packet_forensics.py`, network/ingestion suites; real binary fixtures flow through ZIP, OCSF and source receipts. |
| Memory | Small process minidumps and captured regions; module names/ranges, thread descriptors, memory-info permissions/type; private writable-executable region observations with benign alternatives; explicit missing/omitted byte coverage. | `tests/test_memory_examination.py`, `tests/test_independent_forensic_tools.py`. |
| Malware stylometry | Independent PE/Capstone opcode and trigram features, import hashes and structure; architecture-aware exact-hash/opcode/sequence/import comparisons with visible comparison limits. | `tests/test_malware_stylometry.py`, native-tool suite. |
| Identity | Host/observed-boot/logon-ID/SID-bound lifetimes, privileges, credential/logoff requests, group/account changes and Kerberos context; typed recorded-session source relationships. | `tests/test_identity_sessions.py`; host/SID/reuse/tie/logoff negative controls. |
| Cloud / container | GCP plus native AWS CloudTrail and Azure Activity export support; provider outcomes, exact tenant-scoped key/resource lifecycles, cross-principal credential references, namespace/runtime UID controls. No cloud API/billing calls. | `tests/test_cloud_lifecycle.py`, cloud/alias/correlation suites. |
| Insider | Finite source-counter baselines with SID/host isolation, duplicate/failed measurement exclusion, preceding seven-day window, saved median/MAD/threshold/coverage. | `tests/test_behavior_baselines.py`, existing positive/negative baseline controls. |
| Threat attribution | Semantic search suggestions remain unverified and cannot become ranked observed techniques; profile ambiguity and absent actor calibration explicit. Legacy “confidence” fields are labelled heuristic evidence weights. | Attribution suite: 42 passed. |
| Timeline / timestomping | Native NTFS 3.x resident FILE fragments, update-sequence/torn-record checks, SI/FN/date/reference provenance; unplaced times retained; actual cited model explanations rather than ID selection alone. | `tests/test_ntfs_records.py`, timeline/correlation suite; actual Qwen reconstruction explanation probe. |
| DAG | Source relationship direction preserved; reverse/equal-time links cannot become chronological paths. Candidate chains expose failed operations and unmet exploit prerequisites; actual cited model assessments. | `tests/test_review_safety_completion.py`, graph/correlation suite. |
| Proponent / critic / judge | Existing scoped-citation/coverage contracts and bounded corrective debate retained; unresolved/failed follow-up and source-change gates added. Independent saved-label evaluation reports per-role misses and benign-control false alarms. | Structured review, investigative review, graph/HITL suites; `tests/test_agent_evaluation.py`. |
| Guardrails | Hypothesis-conditioned final decoder, bounded context, localized certainty/negation and uncalibrated-probability checks, source/tool completeness. | `tests/test_review_safety_completion.py`, grounding suites; real Qwen hypothesis-grounding probe. |
| HITL / reports | New fields survive snapshots/AgentRun projection; acquisition requests and current-cycle examination receipts appear in court-oriented and technical drafts with explicit incompleteness. No automatic analyst approval. | Recovery, projection and report tests; existing live checkpoints retained at HITL after API/controller reload. |

## Concrete capability limits that remain

These cannot be promoted to completion using schema tests or synthetic fixtures.

1. **Acquisition breadth:** local WinEvent collection and supported uploads work. Remote EDR/host acquisition needs a configured authorized collector and source access. Missing artifacts become specific case/host/time/citation-bound requests.
2. **Packet coverage:** complete non-overlapping IPv4/IPv6 TCP/UDP fragment sets now reconstruct within explicit VLAN/time/byte limits. Missing/overlapping fragments retain incomplete/rejected receipts. TCP measurements exclude repeated sequence positions and expose lower bounds when retention limits apply. Encrypted-content decryption, post-fragment IPv6 extension decoding, non-Ethernet link-layer support and exhaustive protocol examination remain unavailable. Captured headers/counters do not establish completed exfiltration.
3. **Memory coverage:** bounded process/region examination does not establish kernel-wide visibility, rootkit absence or completed credential extraction. A whole-RAM upload is not a prerequisite for the supported tools.
4. **Family/authorship classifiers:** similarity tools are implemented; independently labelled references and calibrated evaluation are not available. The user confirmed no such reference datasets are available on 2026-10-14. A compiler/shared-library match cannot become a validated malware-family or authorship verdict.
5. **AD/IAM breadth:** recorded lifetimes and changes work; a complete effective-permission model needs directory/policy/ACL snapshots and source-specific authorization semantics. Individual group changes do not prove an effective exploit path.
6. **Actor identity:** cited ATT&CK profile comparison works; independently established actor labels and discriminating evidence are required for calibrated attribution. The user confirmed such labelled reference investigations are unavailable. No model size change supplies that evidence.
7. **Exploit topology:** observed chains expose prerequisites; automatic verification of vulnerable state and successful exploitation is not available from temporal links. The separately implemented analyst-reviewed solver requires case-cited topology and calibration inputs.
8. **General detection accuracy and production acceptance:** held-out labelled investigations, expert review, sustained recovery/load verification and ownership remain separate gates. The machine has reported thermal shutdowns; short software probes do not certify hardware stability.
9. **Reports:** renderers produce cited unsigned documents. Expert qualifications, laboratory validation, prior custody, jurisdiction and admissibility decisions require human review.

## Verification scope

- Complete local regression: **631 passed**, 33 deferred external/integration/production probes excluded.
- Deployed local live-service/model suite: **3 passed**, three deferred external probes excluded.
- Existing complex-case saved-output answer-key oracle: **23 passed**. This is historical saved-output evidence, not a claim that the whole case reran under these new agent contracts.
- Frontend build/lint: passed; existing lint and large-bundle warnings remain.
- Container source compiles the **27-node** graph including adaptive follow-up.
- Real Qwen planner, timeline explanation and final grounding probes passed without checkpoint writes.
- Existing cases remain at HITL; their approvals/rejected model outputs were not rewritten.

Private non-mutating model receipts are `agent_followup_probe.json`, `agent_timeline_probe.json`
and `agent_grounding_probe.json` under `data/private/`. The independently labelled evaluation
entry point is `python -m scripts.evaluate_agent_findings SNAPSHOT ANSWER_KEY --output RESULT`.
Labels must be maintained separately from model prompts and outputs. The evaluator rejects
empty, non-string or duplicate evidence references, duplicate observation labels, malformed
role/type fields and invalid classification lists before calculating metrics. Results remain
limited to supplied independent labels; no trusted held-out family/actor references are
currently available, so general accuracy and calibration remain unmeasured.

## Subsequent supported extensions — 2026-10-15

- Network: complete non-overlapping IPv4/IPv6 TCP/UDP fragment sets, source packet provenance,
  VLAN/time isolation, incomplete/overlap/budget receipts and retransmission-safe analytics.
  Raw counters remain available; capped retained counters are labelled lower bounds.
- Timeline/log analysis: NTFS parent-record number plus sequence identities, bounded
  volume-relative paths with source hash chains, hard-link alternatives and explicit
  missing/reused/cyclic/deleted/reparse/extension dead ends. Recorded parent links are
  host/volume/artifact scoped and remain noncausal. Different files sharing a directory
  are no longer equated. NTFS 3.0 identities need a declared contiguous record range.
- Insider: saved baseline readiness/citations/median/MAD/threshold use the detector's same
  strictly preceding seven-day and 100-sample window. Capped native counters are excluded
  from comparable baselines. These remain within-case source measurements.
- Executed controls: packet/native-specialist 30 passed; expanded NTFS/correlation/endpoint/packet
  handoff 66 passed; final baseline/native oracle 30 passed. Final whole-source verification
  and deployed refresh results are recorded in PROGRESS.md.
- Whole local source suite: **670 passed**, 33 deferred probes deselected; deployed local
  service/model suite **3 passed**, three deferred probes deselected. Actual new native
  binary source contracts passed inside the refreshed container. History retains 21 cases;
  both previously checked cases remain at HITL. This is not a full newly accepted investigation
  or a classifier accuracy calibration.

Format references: [IPv4 fragmentation](https://www.rfc-editor.org/rfc/rfc791.html),
[IPv6 fragmentation](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5),
[NTFS source structures](https://github.com/torvalds/linux/blob/master/fs/ntfs3/ntfs.h).
The parser conservatively rejects overlapping IPv4 fragments as ambiguous source data;
it does not infer a target host's overlap policy.

## Agent extensions verified on 2026-10-15

- Permission sources: `access/` snapshots support ordered Windows token/DACL checks
  and bounded AWS IAM request evaluation. Missing or unsupported authorization semantics
  remain indeterminate. Four native Windows AccessCheck comparisons passed. See
  [export contract](access_snapshot_format.md). This is not complete Windows/AD/IAM authorization.
- Follow-up acquisition: authenticated host-side Windows audit collection binds case,
  host, source anchors, original dates and durable cycle claims. Append ingestion retains
  ownership and original provenance; new evidence permits one bounded reanalysis.
  Native audit reads, bearer boundaries and compiled graph controls passed. A complete
  live acquisition-to-new-case reanalysis has not yet been verified. See
  [collection scope](followup_acquisition.md).
- Network: bounded HTTP framing/body digests and captured TLS ClientHello SNI/ALPN/cipher
  examination retain ambiguity, truncation and encrypted-content limitations. No decryption
  or completed-transfer inference is supplied.
- Memory: actual captured Windows x86/AMD64/WOW64 control contexts are mapped to recorded
  module/page/byte coverage. Private executable instruction pointers remain qualified
  observations, not injection proof or kernel-wide examination.
- Cloud: native `kubernetes/` audit Event/EventList inputs preserve cluster/audit/stage
  identities. API outcomes, admitted versus proposed Pod settings, impersonation and
  scoped recorded RBAC subject associations include successful revocation handling.
  Effective Kubernetes authorization and container escape are not established.
- Grounding: permission/configuration/API/protocol-only citations cannot establish
  unqualified payload execution, credential extraction, exfiltration or privilege escalation.
- Final whole-source regression: **736 passed**, 33 deferred probes deselected; final
  new-source handoff oracle: **74 passed**. These are source tests, not a fresh full
  investigation, independent accuracy calibration or a current deployment acceptance.
- Dynamic malware execution: the user deferred sandbox provisioning. The CAPE v2
  submission/poll/report connector is now implemented with durable case/sample/task
  claims, raw report digests, source-bound malware-agent review, laboratory-only
  graph scope and authenticated UI downloads. See [integration contract](cape_integration.md).
  Local HTTP emulator verification is distinct from live guest/snapshot acceptance,
  which remains deferred. Original-host execution and classifier accuracy are not
  established by a laboratory report.
- CAPE extension verification: **33 CAPE contract controls passed** as part of
  the final **769 passed**, 33 deferred-probe-deselected source regression.
  Frontend build/lint passed with existing warnings. Refreshed container confirms
  disabled-CAPE behavior and health 200; history retains 21 cases and both checked
  saved investigations remain at HITL without failed nodes. No sample ran in a
  real sandbox during this acceptance stage.

## Remaining acceptance gates — 2026-10-16

- Independent evaluation: evaluator input validation is implemented and its focused suite
  passes 20 tests. Available internal synthetic evaluations were rerun on 2026-10-16:
  complex-case oracle passed 23/23 saved-output expectations and 23/23 deterministic source
  replay expectations; the frozen 50-event log-analysis fixture passed its preset thresholds
  with 88% full-pipeline recall and 100% precision (rules-only recall 60%). The log fixture
  explicitly comes from the project harness and is not double-blind external evaluation.
  General real-case detection accuracy, family/actor calibration and expert review remain
  unmeasured because trusted independent real-case labels and qualified reviewers are not supplied.
- Production readiness: current explicit gate run returned **1 passed, 5 failed**. Anonymous
  graph access was rejected. Recorded integration evidence is older than the gate's 24-hour
  freshness window; the Redis throughput threshold and operational owner/RPO/RTO approvals
  are unset; restart and isolated raw restore checks are blocked on fresh authorized case
  evidence. See [operations runbook](operations_runbook.md) for required inputs. No
  production-readiness claim is supported.
- Reports: both renderers remain unsigned, cited drafts. Expert review, custody and jurisdiction
  determinations require an assigned qualified reviewer and an analyst-reviewed case.
- Domain breadth: current Kubernetes analysis records API stages, admitted/proposed Pod settings
  and bounded subject-to-binding context. It can now identify a context-only match between a
  captured Role/ClusterRole rule version, binding and later audited request, including namespace,
  verb, API group, resource and subresource scope. It does not establish a complete policy
  inventory or actual authorization decision. Aggregated ClusterRoles, resource-name rules,
  admission/authorizer chains and omitted policy sources remain unsupported. Matching follows
  Kubernetes RBAC Role/ClusterRole binding scope and resource/subresource rules; see the
  [Kubernetes RBAC reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).
  Windows DACL and AWS IAM analysis are bounded exported-snapshot models; complete AD token,
  delegation, policy inheritance and provider-specific authorization remain unsupported or
  indeterminate without complete source snapshots and source-specific semantics. Broader
  packet/protocol and memory limits listed above also remain explicit.
- Hyperledger Fabric remains deferred under ADR-011 pending an approved trust/deployment model
  and an executable integration environment.
