# Isolation verification summary

Date: 11 November 2026. Evidence directory: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01`.
Scope: approved synthetic access-control preflight only. No forensic investigation,
model inference, ingestion, functional smoke test or empirical evaluation was run.
The existing development services, source, evaluator ACLs and original evidence were not changed.


## Decision

**PASS — isolated canary access-control runtime, exact tested configuration only.**
Permitted evidence reads succeeded; restricted ground-truth/mapping/label reads,
parent traversal and Linux symlink escape failed. Windows junction admission was
rejected before mounting. Actual Specula API/tool access probes passed under
UID:GID 10001:10001, with only one evidence bind and network mode `none`.
Worker completed with exit code 0. This is an executed boundary test, not an
inference from Windows folder names or evaluator ACL descriptions.

| Gate | Decision | Evidence |
| --- | --- | --- |
| Actual worker identity, privileges, source and evidence read | PASS | IDs 10001; zero capabilities; no-new-privileges; 164 source hashes; expected permitted hash |
| Direct/traversal/symlink and admission denial | PASS | Runtime errno 2; host canaries verified present; candidate junction rejected and never mounted |
| Host filesystem/service exposure | PASS for this profile | Exact one read-only bind, no ports/socket/parent mounts; network probes errno 101 |
| Actual API/tool negative access | PASS for tested surfaces | Uvicorn child UID 10001; 401/403/404 responses; actual case authorization 403; forensic tool rejects missing image before analysis |
| Logs/temp/image/index contamination | PASS for empty profile | Zero markers in output/tmp or 38,425 exported files; no store/index mounted or populated |
| Resource/evaluator/source preservation | PASS | 5,096 resource hashes, 296 evaluator file hashes and 411 ACL descriptors match; parent tracked status empty |
| Full model/store/harness isolation | BLOCKED | Not provisioned, approved or tested; adding any network/service/mount invalidates extension of this PASS |
| Functional smoke testing | BLOCKED | Separate user approval required; no smoke case was run |
| Controlled empirical evaluation | BLOCKED | Separate approval and unresolved protocol/truth/normalization/budget gates remain |

## Exact assessed boundary

Image: `sha256:bf00809a2e299cac191e08996957da0630b56af6f442296e9a9bc14ce62258e3`. Worker: `14304b75923a756ae9e10c4b32df19c4ad9891a5a1c6f3d25d8fdb58eae44c08`.
Parent commit: `b9b2012edaed8da5062113ddc9982e3c33b27983`. Effective host data root:
`C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01\fixtures\evidence` -> `/evidence/agent_evidence` read-only.
Python `3.10.22 (main, Oct  6 2026, 02:05:33) [GCC 14.2.0]`. Controller `DESKTOP-N08P1L3\DELL` is trusted;
the evaluated worker is Linux 10001, not that Windows host identity.
See `isolated_runtime_configuration.md` for exact flags and raw mount output,
`runtime_access_test_results.md` for every probe, `isolation_change_log.md` and
`isolation_rollback_plan.md` for the complete change/rollback record.

Machine receipt: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01\verification_20261111T073307Z.json`.
Runtime raw receipt: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01\runtime_receipt.json`.
Full image hashes: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01\image_file_manifest.json`.
No functional correctness, model quality or benchmark result is claimed.

## Remaining risks and approvals

1. Host curator/Docker administrators can still read evaluator originals and
   control containers. Existing evaluator ACL weaknesses remain unchanged. This
   boundary assumes a trusted coordinator and Docker Desktop/Linux kernel; no
   adversarial kernel/daemon escape certification is claimed. A compromised host
   management plane is outside this tested worker boundary.
2. Only synthetic evidence was admitted. Real CFA evidence content and filename
   leakage, supported normalization and independent ground-truth review require
   approval/review before release. Original answer material stays outside runtime.
3. No model, persistent graph/vector/search/checkpoint store, MCP service, scoring
   script or host tool API was exposed. Fresh per-run stores, actual model images,
   model-network namespace/endpoint compatibility, helper identities and all
   active tool/retrieval paths need approved configuration and effective tests.
   Empty-profile scans do not certify future post-ingestion embeddings or logs.
4. The public viewer credential expires and grants no cases. A later authenticated
   case principal, model/tool permissions or entrypoint changes require review;
   do not reuse this public credential as a real evaluation credential.
5. Protocol remains an unfrozen draft. No reviewer decisions, ground-truth labels,
   measurements, seeded results or empirical readiness were fabricated. Prior
   deferred/unavailable acquisition dispositions remain unchanged.

No further permission was needed for the completed bounded provisioning.
The next action needing approval is a specifically configured functional smoke
test, followed separately by full evaluation preparation/approval. Neither starts
automatically. Adding evidence/services/network requires renewed isolation checks.

## Final checkpoint

Fresh post-test `evaluator_acl_final_check.json` again matches all 411 original descriptors. Strengthened `verification_20261111T073829Z.json` is PASS. The current report/script/progress hash inventory is `isolation_20261111_run01/final_artifact_checksums.csv`; `final_artifact_receipt.json` records its digest and validation. Earlier inventories/receipts remain historical snapshots and are not overwritten.
