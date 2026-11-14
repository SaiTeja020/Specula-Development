# Specula research acquisition progress

## Scope
2026-11-11, Asia/Calcutta. Acquisition-only workspace under the existing
TASK-6.7 research-evaluation scope. Parent implementation and parent task states
are read-only. Parent tracker verification passed: 47 tasks, occupied WIP 2/2
(one active, one blocked). No package installation, service changes or git push.

## Tasks (WIP <= 2)
| Task | State | Acceptance criteria | Executable verification oracle |
| --- | --- | --- | --- |
| Local resource audit and acquisition deliverables | passing | Inventory scoped existing resources, hash stable files, preserve originals, produce requested reports | `..\venv\Scripts\python.exe 09_Acquisition_Reports\verify_campaign.py` (PASS: 5,096 unique file hashes rechecked; 31 mutable hashes deferred explicitly) |
| Checklist-driven discovery and acquisition | active | Process CHECKLIST.md first ten and remaining priorities; preserve versions/provenance; unresolved resources retain explicit status | `..\venv\Scripts\python.exe 09_Acquisition_Reports\verify_campaign.py` verifies acquired scope only; full acquisition remains incomplete where deferred/restricted/pending |

## Execution log
- Clock-in: acquisition folder empty; parent project readable, git working tree clean,
  HEAD b9b2012edaed8da5062113ddc9982e3c33b27983 on skeleton.
- Read parent PROGRESS.md and architectural decisions; no architecture changes.
- First tracker invocation used acquisition cwd and failed because tracker was
  absent here; rerun from parent passed. Existing parent states preserved.
- Checklist not found by project filename search or attachment text-title search.
  Asked user for its local path or contents. Unknown checklist items are not
  classified as missing datasets and no substitute acquisition list is invented.
- Disk check via Python: 120,458,502,144 free bytes at initial observation.
- Authoring begins: isolated audit script, CSV manifests, XLSX tracker and PDF
  summary. Existing files will be inventoried in place; evaluator artifacts
  will not be copied into agent-evidence directories.
- Audit script written and running. It records hashes with a 64 MiB per-file,
  512 MiB total read budget, skips mutable datastores, checks bounded archive
  CRCs, and creates duplicate and verification-exception manifests. Outputs use
  exclusive creation so reruns cannot overwrite prior artifacts.
- Audit completed: 2,489 files inventoried; 2,458 SHA-256 hashes recorded;
  31 mutable datastore/index files deferred; 93 exact duplicate groups (654
  member files), all preserved. Forty evaluator artifacts indexed separately.
  CSV manifests, readme boundaries and audit summary written. Tracker builder
  written using the bundled artifact tool; no packages installed.
- First XLSX reconciliation failed before export; normalizing empty strings to
  blank cells for COUNTA and exposing observed totals for diagnosis. PDF created;
  system MiKTeX pdftoppm failed (incomplete setup / access denied). Checking
  already-installed renderer alternatives; no setup or installation attempted.
- CHECKLIST.md supplied by user and read in full. Checklist acquisition is now
  active. Preliminary XLSX exported after blank-cell correction; summary totals
  reconcile and formula-error scan is clear. Bundled Poppler rendered PDF.
- Direct network download probe failed with sandbox WinError 10013. Official
  first-ten pages are readable via web. Preparing bounded official-source fetches
  for sandbox escalation; no authentication or access restrictions bypassed.
- Official metadata/docs and four pilot PDFs downloaded (NIST answer key,
  OpTC ground truth, DFIR-Metric paper, plus SP 800-86 and SP 800-61r3).
  NIST eight raw image parts total 4,871,301,120 bytes; approval requested and
  payload paused. OpTC data link is public Google Drive; direct web access failed,
  so no small event subset is claimed. Cloning pinned small DFIR-Metric/OCSF
  repositories and sparse Plaso/Timesketch source-only references next; large
  fixture directories omitted explicitly. No implementations executed.
- User deferred large evidence downloads; no large payloads will proceed.
  Four pinned clones passed git connectivity checks. Official ATT&CK v19.2
  STIX (53,835,637 bytes) and licence acquired; existing resources were XLSX,
  so this is a required different format, not an identical duplicate.
- Remaining source checks: CERT v1 metadata exposes CC BY 4.0 and publisher
  checksums; M57 public page acquired. UNB direct downloads fail TLS certificate
  validation; ISO pages return HTTP 403. No TLS/access checks bypassed.
- Drain source resolves to a different bibliographic title; user clarification
  requested with the ambiguous MADIK/CyberSleuth/CFA-Bench entries. No substitute.
  Installed project package versions inspected via metadata without imports;
  pandas and several optional utilities are absent and will not be installed.
- User supplied exact bibliographic corrections. Preserved original checklist
  as 09_Acquisition_Reports/CHECKLIST.original.20261111.md, then updated the
  authoritative checklist: Drain 2017 corrected, 2018 related paper separate;
  CyberSleuth and CFA-Bench identified; MADIK candidate NEEDS CONFIRMATION.
  Hacking Case explicitly DEFERRED/P0 retained, dependent experiments pending.
- Open IEEE Hmimou full-text response acquired (3,557,681 bytes), pending PDF
  structure/title verification. Official DOI metadata confirms CC BY 4.0.
- Evaluator-only directory inheritance disabled and ACL restricted to current
  Windows account plus SYSTEM. Receipt saved. Same-account agent processes
  remain able to read it: a distinct evaluation identity/read-root policy is
  still required before running blinded experiments.
- Source/fixture/config supplement hashed 322 existing files without modifying
  them. Corrected Drain 2017 and related 2018 PDFs and CyberSleuth v2 acquired.
- OpTC chosen endpoint host-group archive is 1.86 GB (deferred). A 117 KB public
  network-file attempt returned a 2,040-byte Google quota HTML response, not
  gzip; it must not be counted as evidence. Publisher CFA-Bench endpoint returned
  zero bytes; the public university manuscript is visible via web but direct
  validated-TLS download is blocked. Trying Windows certificate validation
  returned HTTP 403; no bypass performed. Paper remains pending actual bytes.
- CFA-Bench full small benchmark clone and CyberSleuth source-only clone now
  pinned and connectivity-verified. Command-local safe.directory fixed the
  cross-account ownership issue without changing global Git settings.
- Continuing bounded P1 reference-source archives (32 MiB each maximum), using
  exact remote HEAD commits. Oversized archives are not saved; none installed
  or executed. Paper corrections remain preserved in the checklist backup.
- Verified the CFA paper links SmartData-Polito/CFA-bench (52.4 MB current raw
  tree, small individual files). Acquiring its benchmark clone with labels kept
  evaluator-only, and a source-only CyberSleuth clone excluding 199 MB evidence.
- Protected ACL initially granted only sandbox identity; elevated acquisition
  runs as DELL and git init failed. Corrected by granting the human DELL account
  access as well; no content lost. Empty newly-created clone initialization may
  resume; existing committed clones remain untouched. Initial ACL receipt is
  retained and corrected receipt saved separately.

## Latest verification and reporting checkpoint
- Campaign format checks passed: 14 PDFs parsed, STIX 26,086 objects matched to
  the pinned official Git blob, OCSF version.json is 1.9.0, all acquired ZIPs pass
  CRC, six clones are clean and pinned, and 59 CFA raw evidence files across 20
  cases are byte-identical under opaque filenames. No labels copied to evidence.
- Five additional P1 source archives acquired; Zeek and Atomic Red Team exceeded
  the 32 MiB bound and were not saved. No packages installed or tools run.
- 136 checklist checkbox rows recorded. Existing inventory covers 2,810 unique
  files including the source/fixture/config supplement. Nine research papers
  acquired; CFA paper remains unavailable locally, MADIK is metadata only.
- Preliminary audit/report versions archived before canonical report updates.
  Detailed named-original audit distinguishes exact local matches from related
  documents. Metadata refinement records precise arXiv/IEEE/MITRE/OpTC licences;
  the regenerated tracker is reconciling all counts against its source sheets.
- Empty experiment/reviewer/ground-truth templates created; no labels or results
  invented. Final PDF reports and complete original/acquired hash recheck next.
- First final oracle completed hash, repository, evidence-copy, template,
  workbook coverage/cache and structure checks, then failed on PDF line-wrapped
  text. Normalize extracted whitespace for semantic assertion. Visual review
  passed all three summary pages and reviewer page; workbook review caught
  ISO timestamps displayed as Excel serials and literal null. Date/byte formats
  and blank handling corrected; prior workbook preserved before regeneration.
- Kept first-page extracts of ground-truth PDFs only inside protected evaluator
  receipts, removing them from the general format-verification receipt.
- Corrected final oracle PASS: 5,096 unique local file hashes rechecked, 31
  mutable hashes deferred, all six pinned clones and 59 evidence copies checked,
  all 136 rows covered, workbook cached totals reconciled and parent source
  unchanged. Local audit/deliverable task transitioned to passing independently.
- Final deliverable statuses set to CREATED/VERIFIED after the successful oracle.
  Extending the final run with native PCAP record-boundary checks and exact
  authoritative checklist name equality; no reference program execution.
- Extended oracle PASS: all 20 classic-PCAP files contain 23,152 structurally
  complete packet records; all 136 checkbox names exactly match CHECKLIST.md.
  Final workbook dates/blanks and all four worksheet previews visually checked;
  summary PDF three pages and reviewer protocol one page visually checked.
- Parent tracker and git whitespace checks passed from parent cwd; a prior
  parent-validator call from acquisition cwd checked the wrong local journal
  and failed schema discovery, then was rerun correctly. Parent states remain
  unchanged, source tree unchanged; only this acquisition folder is untracked.
- Clock-out: reports, manifests, bibliography, checksums, exact source versions,
  original report backups and blank evaluation templates delivered. Acquisition
  task remains active for explicitly unresolved resources; no global completion,
  independent scientific validation, installations or experiment results claimed.

## Next steps
NIST Hacking stays P0/DEFERRED; dependent experiments stay pending. Resolve OpTC
public-download quota and the remaining restricted/source-access gates; obtain
MADIK relevance confirmation. Enforce a distinct agent identity/read root before
blinded evaluation. Large evidence remains deferred unless the user changes it.

## Post-audit remediation — 11 November 2026
- Scope: authorized metadata/report repair and proposed security/protocol design
  only. Existing passing task remains locked; work continues within the active
  acquisition task's remediation subset (one occupied local slot).
- Read current tracker/decisions and reran parent verification: 47 tasks, WIP 2/2;
  parent HEAD unchanged and only acquisition folder untracked.
- Security inspection first: Docker 29.0.1 available with zero containers;
  Docker Desktop runs as DELL. Existing image has no explicit user and predates
  current source. Ollama service unavailable; cached model manifests inspected
  without inference. Development mounts/stores and broader descendant ACLs are
  unsuitable as assumed isolation. No services or security settings changed.
- Created security_isolation_plan.md with exact proposed worker restrictions,
  deployment/source-image gates, access tests and approval boundary, before
  metadata repair. Model endpoint adapter compatibility remains explicit.
- Baseline/backup oracle passed: 19 metadata files backed up with matching hashes
  under 09_Acquisition_Reports/remediation_20261111T064220Z; all 5,096 immutable
  resource hashes match, 31 mutable datastore hashes remain deferred. All 296
  evaluator files (including repository internals) fingerprinted for preservation.
- Next: record field-level authoritative corrections and recalculate tracker;
  draft protocol with observed settings separated from proposed/unknown values;
  verify immutable resources, backups, metadata consistency and original source.
- Metadata repair executed: all 25 missing path references assigned to actual
  existing artifacts, 15 dataset disagreements reconciled, three priority aliases
  set to P0. Website references and empty/unconfigured/unexecuted templates now
  have explicit types/states. CFA paper row points to DOI metadata, not README.
  Full field-level before/after provenance saved (869 records, including derived
  classifications) with original metadata retained in backups. Resource bytes,
  original evaluator material and repository clones were not modified.
- Generated deliverable hashes/sizes now use detached-manifest references to
  avoid workbook/self-checksum cycles. Website snapshots do not discharge the
  still-unacquired Wireshark/Zimmerman tool scope; keep those gaps in reports.
- Next: approved draft-only protocol, regenerated workbook and independent
  post-remediation oracle. Actual-runtime access tests remain approval-blocked.
- Protocol draft and machine-readable proposed configuration created: cached
  qwen3:8b / qwen3-embedding:0.6b manifests and source defaults observed; live
  model version/digests, global budgets and independent truth remain unresolved.
  No inference, case ingestion, reviewer labeling or experiment runs occurred.
- Workbook source-perturbation/restoration checks passed. First new oracle
  detected a pre-existing stale SHA/size on CL-020 (named original unavailable,
  separate acquired copy existed). Also correcting CL-019 original-vs-equivalent
  ambiguity and CL-015 XLSX-vs-STIX wording; no source resource changes.
- Preservation checks passed for 5,096 resource hashes, all 296 evaluator files,
  all 411 ACL descriptors, 20 PCAPs/39 logs/23,152 packets and parent source.
  The failed first report/receipt is retained as history; rerun follows after
  metadata correction. DELL host read probe still opens both evidence and labels;
  this is not a passed actual-runtime isolation test. Zero containers running.
- Final post-remediation oracle PASS for authorized integrity/metadata scope:
  20 metadata backups verified; all 5,096 resource hashes, 296 evaluator files,
  411 ACL descriptors and original repository/clones unchanged; 136 dispositions,
  all 25 repaired paths, 23 matching dataset rows, three P0 aliases and all
  detached references verified. Twenty PCAPs/39 logs/23,152 packets preserved.
- Additional original/equivalent and XLSX/STIX corrections fully recorded; the
  field ledger has 900 before/after records including derived classifications.
  Fifty unresolved dispositions remain because an absent named original is no
  longer silently equated to a separately acquired paper. Nine acquired papers
  remain verified; no resource bytes were lost or changed.
- Workbook recalculation and restoration checks passed; six final previews
  covering all four sheets inspected. Thirty-two final artifact checksums
  regenerated and verified. Four requested Markdown reports and an explicitly
  unfrozen machine-readable protocol draft are available.
- Clock-out: authorized metadata preparation complete. Resource integrity and
  acquired-subset metadata PASS; same-account host separation FAIL; proposed
  actual-runtime access tests, safe smoke and controlled experiments BLOCKED
  pending the user's required security/protocol approvals. No ACL/account/mount/
  credential/service changes, model inference, ingestion or evaluation runs.
- Next: user review of security_isolation_plan.md and experiment_protocol_draft.md;
  only after explicit approval provision the isolated preflight runtime and prove
  allowed evidence reads plus denied evaluator/tool/API/retrieval reads. Parent
  source and all original evidence remain read-only; no full experiment start.
