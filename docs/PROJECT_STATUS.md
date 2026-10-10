# Specula project status

Updated 2026-10-10. Implementation evidence below was recorded on 2026-10-07; this documentation and repository cleanup do not establish a new full application run.

## What is working in the local milestone

| Area | Verified result | Scope |
| --- | --- | --- |
| Ingestion and preservation | A synthetic four-event case passed raw-byte/hash checks, Kafka offsets, Neo4j case relationships and Chroma indexing. | Development fixture and local backing services. |
| Investigation and analyst review | The local Ollama `qwen3:8b` investigation reached HITL, resumed and closed; the dashboard WebSocket emitted `run_complete`. | Synthetic case; model quality and every specialist role are not independently established. |
| Evidence collection | All four original Event UIDs were fetched and triaged through a parameterized case query. | Deterministic collection for the verified case. |
| Reports | Report and timeline ended completely; the report cited all four original events and recorded unavailable attribution as a limitation. | Structured local output. The closed case has `acceptance_status=incomplete`. |
| Access control | HTTP and WebSocket requests require verified identity and case access. Both APIs returned 401 anonymously and 403 for another case. | Local analyst credential and mocked provider tests; a real Supabase browser session is still untested. |
| Recovery | Both APIs read the same SQLite checkpoint in a persistent Docker volume. A paused checkpoint survived engine/API restarts with an identical snapshot; a failed model node was retried and the case closed. | One Docker host; whole-system backup/restore is not verified. |

The focused four-fix suite passed **93 tests**. The default suite recorded **452 passed, 2 failed, 33 deselected**; the two existing failures are synchronous calls into the separate async supervisor graph. Frontend build, scoped lint, installed Python dependency checks and local Ollama/service checks passed. See [local remediation](local_remediation.md) for the exact commands and [the diagnostic history](full_application_run.md) for the original defects.

## What remains

| Priority | Work | Completion evidence needed |
| --- | --- | --- |
| 1 | Build and load a verified ATT&CK/FAISS corpus in the deployed container. | Manifest and artifact hashes verified; real case attribution cites the loaded corpus; readiness reports it as ready. |
| 2 | Prove finding delivery and unattended service flow. The current case flags `kafka_delivery_unconfirmed`; a fixture wires ingestion stages explicitly. | Broker acknowledgement and consumption receipts, restart/replay behavior, and an end-to-end case without manual fixture orchestration. |
| 3 | Fix the alternate supervisor sync/async mismatch. | Both `tests/orchestration/test_supervisor.py` tests pass through the intended execution API. |
| 4 | Validate case ownership and analyst review in a real signed-in browser. Assign owners/members to pre-existing cases through a trusted process. | Approved user can access only assigned cases, refresh a paused run, review it and see the final report; unrelated users are denied. |
| 5 | Define production operations and recoverability. | Named owners, approved throughput/RPO/RTO targets, durable storage for all stores, a complete isolated restore and security/performance gates. |
| Deferred | GCP audit ingestion under the no-billable-services constraint; Hyperledger Fabric anchoring. | A separate authorized scope and executable acceptance checks. |

The deployed FAISS corpus was missing in the last run, so threat attribution remained unavailable/unverified. DuckDB reporting was unavailable. These gaps and the missing delivery receipt keep the workflow's acceptance status incomplete despite case closure. No production-ready claim is made.

## Working rules and boundaries

- `PROGRESS.md` is the task ledger and verification history. `TASK-6.7` and `TASK-6.8` remain blocked and occupy both WIP slots because their broader integration and production criteria are unfinished.
- `DECISIONS.md` records the architecture choices. Current local Docker selects Ollama; do not run the legacy hosted/GCP probe script under the user's no-billable-services instruction.
- Source lives in `src/`, UI in `visualization/`, executable checks in `tests/`, local commands in `scripts/`. Runtime evidence, checkpoints, credentials and quarantine are under ignored `data/` and `quarantine/` paths.
- Changes from the October 7 remediation remain uncommitted. The four requested split ZIP deliverables and two Word summaries are retained in the repository root; they are older snapshots, not current source builds.

For setup and validation, start with [the local remediation guide](local_remediation.md). For operations and remaining gates, use [the runbook](operations_runbook.md) and [readiness history](readiness_results.md).
