4# Readiness results — 2026-10-07

## Current interpretation of earlier gates

The table below records the **earlier** production gate run before the October 7 repairs. After that run, a local Ollama case collected all four events, generated complete cited report/timeline artifacts, enforced backend case access and survived a restart. [Project status](PROJECT_STATUS.md) and [local remediation](local_remediation.md) are the current interpretation. The deployed corpus, delivery receipts, browser workflow, owners, thresholds and whole-system restore remain open. Hosted/GCP checks are excluded under the current user instruction.

## Completed development work

- Tracker reconciled, current phase/backlog recorded, duplicate task IDs migrated and chronology validated.
- ChromaDB documented as the persistent case vector store; InMemory is non-durable fallback/test storage. Qdrant is not deployed.
- Installed Python environment verified: 25 direct requirements, 282 dependency constraints, clean pip check, dateutil/GCP logging imports.
- All 18 role backends and fallback behavior documented; current local deployment explicitly uses stubs.
- Fabric anchoring explicitly deferred; no deployment claim.
- Independent review defects corrected; implementation committed as `145cf97` and deployed using existing Docker images/read-only source mounts.
- Selected implementation oracle: **354 passed, 16 deselected**; actual development investigation oracle: **1 passed**; frontend build and HTTP assets passed.

## Live integration gates

Command: `pytest -m live_infra tests/integration -q`

Result: **2 passed, 3 failed, 1 deselected**. Deployed store readiness and API/WebSocket/frontend assets passed. External failures:

| Integration | Actual result | Required action |
| --- | --- | --- |
| GCP | `DefaultCredentialsError`; project ID present | Configure approved credentials, then prove audit extraction/preservation/downstream ingestion |
| Gemini | HTTP 429; provider quota unavailable | Supply usable quota/configuration and repeat bounded inference probe |
| Attribution endpoint | Endpoint/key unset | Configure approved endpoint/key/model and run real inference check |

Authenticated browser workflow was not exercised. Frontend authentication alone does not protect backend APIs.

## Historical production gates (before local remediation)

Command: `pytest -m production_readiness tests/production_readiness -q`

Result: **2 passed, 4 failed**.

| Category | Actual result |
| --- | --- |
| Development integration evidence | Passed; real local case, HTTP review and WebSocket result present |
| Raw evidence backup/restore | Four records restored into a separate Quickwit index, hashes verified; latest restore 6.22 seconds |
| Throughput | Measured 89,658 Redis operations/sec for 2,000 pipelined operations; gate fails because no approved workload/threshold exists |
| Security | Graph data returned HTTP 200 without backend authorization; gate fails |
| Persistence | Actual paused graph did not survive fresh process initialization; restart/resume gate fails |
| Operations | Owner and approved RPO/RTO are unset; gate fails |

Raw-record restore and Redis microbenchmark are narrow baselines. Local authorization and checkpoint restart defects were later repaired and verified; the table above remains an execution record, not the current behavior. Coordinated multi-store recovery and end-to-end throughput remain unverified. Phase 7 keeps the broader production exposure, restore and authenticated browser criteria. TASK-6.7 and TASK-6.8 remain blocked and retain both WIP slots.

See [operations_runbook.md](operations_runbook.md), [local_validation.md](local_validation.md), and [implementation_review.md](implementation_review.md). Sanitized machine evidence is stored under `data/verification` and is excluded from version control along with runtime data.
