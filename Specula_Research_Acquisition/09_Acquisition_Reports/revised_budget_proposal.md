# Revised budget proposal — R1

11 November 2026. READ-ONLY diagnostic; no recovery action or configuration
proposal was applied. No process/service/model/container/distro was stopped or
started. No cache was cleared, file deleted, host/WSL setting changed or forensic
investigation run. Only new diagnostic/report files and acquisition progress
metadata were written. Evidence: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\memory_diagnostic_20261111_run01`.


## Necessity, status and recommendation

The unchanged approved stack remains 517.512 MiB short at sampled VM
minimum, so this separately reviewable fallback is necessary to document.
**UNAPPROVED, UNAPPLIED, UNTESTED.** Prefer user-confirmed harmless recovery first.
R1 is not a claim that services fit or a license to proceed past a failed startup.
No revised containers/configuration were created. Machine-readable proposal:
`C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\memory_diagnostic_20261111_run01\revised_budget_PROPOSED.json` (budget data only, not a deployment file).

## Proposed caps, preserving all mandatory services

| Component | Approved MiB | Proposed R1 MiB | Reduction MiB |
| --- | ---: | ---: | ---: |
| ollama | 7,168 | 7,168 | 0 |
| worker | 1,024 | 768 | 256 |
| neo4j | 768 | 512 | 256 |
| kafka | 768 | 512 | 256 |
| chroma | 384 | 256 | 128 |
| quickwit | 384 | 256 | 128 |
| redis | 64 | 64 | 0 |
| gateway | 64 | 64 | 0 |
| coordinator | 64 | 64 | 0 |
| anchor | 16 | 16 | 0 |
| **Total** | **10,704** | **9,680** | **1,024** |

Ollama remains 7,168 MiB. Both exact model manifests/weights, local-only backend,
generation context 8192, generic/structured output caps 1024/2048, temperature 0,
think=false, embedding CPU placement and retrieval settings remain unchanged.
All service/software pins, non-root UIDs, evidence-only mount, fresh datastores,
network policy, model gateway/capture, case authorization, HITL and integrity
requirements remain mandatory. SQLite/DuckDB remain in worker storage; nothing
is replaced by a stub or shared development store. Approval 1's one-chat/one-embed
limit, no retries and no forensic investigation remain unchanged.

## Justification and per-change risks

| Change | Reason / expected benefit | Risks / affected work | Approval and validation |
| --- | --- | --- | --- |
| Worker 1024 -> 768 MiB | Small eight-record future smoke and current canary scope justify considering a tighter Python cap; 256 MiB less maximum budget | Full current module imports/PDF/graph memory have not been measured; may OOM. Only new runtime, not existing Specula, would be affected | New approval; actual non-root API/PDF/import health and RSS/peak checks before any case; no root/model fallback |
| Neo4j 768 -> 512 MiB | Empty/single-case disposable graph, 256 MiB lower budget | JVM heap/pagecache/native memory need explicit supported sizing; startup could fail. Smaller cache may alter latency | New approval; review pinned image's heap/cache configuration; run bounded empty-store readiness; stop if minimum unsupported |
| Kafka 768 -> 512 MiB | Single broker/topic for tiny normalized stream, 256 MiB lower budget | KRaft/JVM/native overhead may exceed cap; delivery must remain acknowledged, never buffered fallback | New approval; review heap/native settings and actual broker/controller health under non-root identity |
| Chroma 384 -> 256 MiB | Tiny one-case vector collection, embeddings served by unchanged Ollama; 128 MiB lower budget | Server version/native caches may need more memory; no dimension/model change permitted | New approval; real client/server/case-filter checks; no automatic model download or embedding substitution |
| Quickwit 384 -> 256 MiB | Few serialized records, 128 MiB lower budget | Indexer heap/cache defaults may not fit; preservation must remain durable | New approval; verify supported pinned-version internal budget and commit/read receipt; no ignoring failed preservation |

These caps are **trial design limits, not verified minimums or measured savings**.
Internal heap/cache values and exact version-supported options remain unresolved
until reviewed; no guessed flags are represented as a validated configuration.
If a required process cannot start non-root within approved R1 limits, report
BLOCKED and stop. Do not raise limits, remove services, change context/model,
enable swap-dependent execution or patch original source to manufacture a PASS.

## Capacity arithmetic for R1

| Target | VM available required MiB | Difference vs sampled available |
| --- | ---: | --- |
| R1 admission | 9,680 | 506.488 MiB remains at current minimum |
| R1 + 1 GiB | 10,704 | Additional 517.512 MiB needed |
| R1 + 2 GiB | 11,728 | Additional 1,541.512 MiB needed; only 230.664 MiB allowed for VM/core baseline |

R1 would satisfy the numerical cap-only check in this snapshot, **but alone
still misses the 1 GiB operational target**. Optional approved Kubernetes recovery
could help; its 851.9 MiB PSS is not guaranteed additional RAM, and the
435.9 MiB private-dirty footprint alone is less than that remaining
target gap. Remeasure; do not add all PSS or page cache to availability.
Two GiB reserve is still not credible at this ceiling with required Docker/core
overhead. Windows physical-backing and paging concerns remain even when guest
arithmetic fits; host application closure or a larger-memory host may be needed.

## Separate review/approval conditions

- Explicitly approve these five changed caps and future pinned-version internal
  heap/cache configuration. All other approved controls/model settings stay fixed.
- Record post-recovery Windows and guest capacity/pressure and a fresh admission
  decision. Do not treat a lower cap sum as observed resident-memory recovery.
- Provision only new isolation containers/volumes after authorization; collect
  effective UID/mount/capability/rule/service/gateway evidence, then exactly the
  approved benign model requests without retry. Stop new services afterward.
- Any OOM, sustained paging/PSI, incomplete logging, forbidden access, failed
  service or model canary blocks further work. Do not relabel a failed smaller
  configuration as equivalent to the original accepted runtime.
- Changes affect prospective runtime resource ceilings and potentially timing;
  do not mix later performance measurements across budgets without recording
  this confound. This is functional preparation, not an empirical result.
- Approval 2 remains separately required; no case intake or investigation here.

Recommendation: consider R1 only if recovery cannot safely fund the original
profile. For unrelated work that must remain open, a suitably sized dedicated
host is preferable to further speculative reductions below R1.
