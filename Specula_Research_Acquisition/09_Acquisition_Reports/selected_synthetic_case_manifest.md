# Selected synthetic case manifest

11 November 2026. **PREPARATION ONLY — NOT EXECUTED OR FROZEN.**
Workspace: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition`. Supporting receipts: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_smoke_preparation_20261111_run01`.
Source commit: `b9b2012edaed8da5062113ddc9982e3c33b27983` (tracked tree clean).
No runtime was built, created, started or reconfigured during this preparation.
No model invocation, investigation, normalization pipeline or benchmark was executed.
Pure ZIP/JSON input-contract checks and local file/image inspection were performed.


## Selection and integrity

One existing case: parent `output/evaluation-pilot/case-001.zip`. Eight records,
five supported JSON/JSONL files, no native PE, memory image or PCAP to execute.
This is the smallest of the existing 2,904/3,476/3,499-byte pilot archives.
No generator was rerun and no new forensic scenario or expected finding was invented.

| Asset | Exact path | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Original evidence, unchanged | `C:\Users\DELL\Specula-skeleton\output\evaluation-pilot\case-001.zip` | 2904 | `8d8d228df7a841e3a30da9a839e9ec4de5aee00fef35c640e534460e7b21ff5d` |
| Separately retained original expected findings, NEVER mount | `C:\Users\DELL\Specula-skeleton\output\evaluation-pilot\case-001-answer-key.json` | 7574 | `45aaccad30a19e7548c9c6cfe21aae33873f2bc5fd9c635f9ba678d57211c193` |
| Agent-visible derivative | `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_smoke_preparation_20261111_run01\agent_evidence\case-input.zip` | 2750 | `cbf8263fe0e1c94996412996d88d0e01a85990fca92737d97eee58d55782de14` |
| Agent-visible checksum | `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_smoke_preparation_20261111_run01\agent_evidence\package.sha256` | measured in final manifest | Hashes the derivative only |

Only the `agent_evidence` subdirectory is a candidate host read root. The run
directory, these documents, receipts, originals and expected findings are not mounts.
The derivative ZIP is a separate prepared artifact; it is not described as the
byte-identical original. Windows ACLs and original attributes were not changed.
Read-only mount protection will apply only after a separately approved provision.

| ZIP member | Records | Source adapter |
| --- | ---: | --- |
| `edr/alerts.jsonl` | 3 | edr |
| `edr/network.jsonl` | 1 | edr |
| `ueba/events.json` | 1 | ueba |
| `windows/Security.json` | 2 | evtx |
| `windows/Sysmon.jsonl` | 1 | evtx |
| `manifest.json` | 0 | File hashes/sizes only; not an event |

`src/ingestion/upload_archive.py:validate_archive` accepted the source and
derivative, and ZIP CRC checks passed. Actual normalization is a future smoke step,
not asserted by successful archive validation. No acquisition or model run occurred.

## Exact sanitization and preserved context

- Removed exactly one top-level `synthetic` flag from each of eight records.
- Replaced the fixture manifest with a file-hash/size-only manifest; removed
  `fixture_id`, `synthetic` and fixture-description metadata.
- Preserved all other parsed source values, record order and supported member
  paths. JSON serialization/ZIP compression changed deterministically; original
  byte custody remains documented by the original archive hash above.
- Outer filename is neutral `case-input.zip`. No original answer key, expected
  conclusion, class/scenario label, scorer, source-to-answer mapping, report,
  prior run result or annotation is in the evidence root.
- Source-native event outcomes, detector names, ticket IDs, signer strings and
  `baseline_status` remain evidence. They are not evaluator-added expected labels.
  Some source strings say “Synthetic”; removing them would alter source facts
  and the encoded-command evidence. They are not a shortcut license to infer
  benignness/maliciousness. No command or encoded payload is executed.
- Input UUIDs/trace IDs and neutral original record IDs remain source provenance.
  `run_pipeline.py` recomputes `uploaded-event-context-v2` event UIDs; source UUIDs
  must not be assumed equal to graph UIDs. The evaluator later links source
  record IDs to actual normalized UIDs outside the worker. No answer mapping was
  placed in the package.

`case_derivation.json` records each removal and before/after hashes. The static
verification oracle compares every derivative source value to its original
counterpart, not just the manifest. It also rejects forbidden annotation fields,
reparse points and multiple-link files in the proposed read root.

## Expected findings retained outside the agent

The existing key retains three developer-authored expected observations and seven
same-host recorded-time pairs. The source expectations concern deployment context
for an encoded command, scheduled-backup context for a large transfer, and reset/MFA
context for a failure/success login sequence. The same key cautions against treating
encoded execution, transfer volume or a shared source address alone as proof of
maliciousness/attribution. These are retained source expectations, not new model
outputs, judgments or measurements.

Ground-truth status is literally `developer-authored; independent review pending`. The key is independently
retained from the evidence package, but **not independently adjudicated ground truth**.
Its causal/entity labels and independent claim annotations are null. Operator review
and explicit acceptance of these planted-control limitations are required. Do not
use this one synthetic case to claim empirical accuracy or generalization.

## Separate approved-reference candidate

`agent_evidence/reference_only` contains four unchanged copies of the existing
parent `data/threat_intel` corpus: `faiss_index.bin`, `faiss_id_map.json`,
`metadata_store.json`, `build_manifest.json`. Total 3,191,887 bytes.
The three artifact hashes match their original build manifest. Metadata audit found
only 697 `attack_technique` and 176 `attack_group` records, all from `local_attack_xlsx`,
with an exact reference-field allowlist; no case/expected-answer fields or case index.
Public ATT&CK group/technique relations are reference knowledge, not evaluator mappings.

Frozen source version `ATT&CK-xlsx-v19.2`; original build `2026-10-10T09:40:36Z`;
embedding method `sha384-byte-repeat-v1`, dimension 384. This is a static hashed
reference index, not the Qwen semantic case index. No timestamp was refreshed,
index rebuilt, reference queried or FAISS binary loaded in preparation.
The original workbook provenance was not independently revalidated here; hashes
establish copy integrity. Staleness and reference limitations must remain visible
in actual health/output metadata. Approval may exclude this corpus, but then the
plan must explicitly accept missing-reference abstention/incomplete attribution.
