# Functional smoke-test plan

11 November 2026. **PREPARATION ONLY — NOT EXECUTED OR FROZEN.**
Workspace: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition`. Supporting receipts: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_smoke_preparation_20261111_run01`.
Source commit: `b9b2012edaed8da5062113ddc9982e3c33b27983` (tracked tree clean).
No runtime was built, created, started or reconfigured during this preparation.
No model invocation, investigation, normalization pipeline or benchmark was executed.
Pure ZIP/JSON input-contract checks and local file/image inspection were performed.


## Goal and boundaries

One run of one existing eight-record case through actual intake, orchestration,
evidence-based specialist dispatch, graph/timeline and report paths. No baseline,
repeat campaign, performance target or accuracy estimate. The user has approved
preparation only; the following procedure is future work and is not executed by
opening these documents. Provisioning and case execution require separate approval.

Do not use `scripts/run_evaluation_pilot.py`: it targets the host boot controller,
loops over three cases and writes existing output paths. Do not start
`scripts/local_boot_api.py`: it controls development services and host collectors.
Do not use `scripts/local_case_pipeline.investigate_case`: its host token path and
hardcoded local URL are for the existing deployment. Reuse only the unchanged
uploaded-case ingestion function inside the new image; use the actual authorized
API directly for the investigation. No host Windows acquisition or active sample.

## Source trace and execution contracts

| Stage | Actual implementation | Contract inspected |
| --- | --- | --- |
| ZIP preflight | `src/ingestion/upload_archive.py:validate_archive`, `archive_batches` | JSON/JSONL source folders, limits, hash receipts, reject unsafe paths/symlinks/encryption |
| Intake | `scripts/local_case_pipeline.py:ingest_uploaded_case`, `_ingest_batches` | Reads only supplied upload; Quickwit raw records; normalized Neo4j events/case ownership; lineage, vectors, analytics and Kafka delivery receipts |
| Normalization | `src/ingestion/export_aliases.py:adapt_export`, `src/ingestion/run_pipeline.py:run_pipeline_on_event` | OCSF validation, deterministic UID before graph writes; source context/outcomes preserved; uploaded-context-v2 UID differs from source UUID |
| Authorized entry | `src/agents/visualizer_api.py:app`; `investigation_api.py:POST /api/investigations` | Requires case write authorization and ingested events; seeds evidence_review_required, trace and execution manifest; refuses duplicate existing run |
| Persistence | `src/agents/checkpointer.py:SQLiteCheckpointSaver`, `durable_case_lock` | SQLite WAL, typed checkpoints, execution lease; actual resume via Command; no in-memory substitute |
| Graph | `src/agents/graph.py:build_graph` | Supervisor fan-out to evidence/log/network -> primary join -> relevant specialists or follow-up -> timeline -> attribution -> DAG -> proponent/critic/judge -> guardrails/HITL -> report/timeline artifact -> final join |
| Specialist nodes | `src/agents/nodes.py`, relevant factories | Evidence-driven dispatch; unsupported/missing artifacts stay unavailable; no fabricated specialist success or forced dispatch |
| Analysis graph | `src/agents/agent_graph.py:persist_case_execution`, `persist_case_analysis` | Case-scoped run/finding/analysis projections; checkpoint authoritative if projection fails, but smoke gate requires expected projection writes |
| Timeline | `src/agents/timeline_reconstruction.py:reconstruct` | Recorded source time retained; evidence UID refs; same-host ordering is not proof of causation; qualified clock models |
| Final artifacts | `nodes.py:report_generation_node`, `timeline_artifact_generation_node`, `final_output_join_node` | Deterministic cited renderers, report/timeline metadata; closed alone does not imply complete |
| PDF | `examination_reports.py:render_examination_pdf`, API `/reports/{kind}` | Authorized court/technical PDF from saved evidence, digest headers; 409 before final report, 503 if PDF dependency missing |
| Auth/HITL | `api_auth.py`, `investigation_api.py:/review`, `nodes.py:hitl_node` | Read/write/case checks; real interruption and human Command(resume=decision); no auto-approval |

`build_graph`'s older docstring mentions Redis-backed checkpoints, but the actual
API factory now calls `build_persistent_checkpointer` with SQLite by default.
The API factory passes Redis, Neo4j, case retriever and reference MCP object but
does not pass a Kafka finding producer; the upload path's normalized Kafka
publication is mandatory and separate. Do not claim an omitted finding-topic
producer or an independent Kafka consumer was exercised by this profile.

## Future procedure — one case only

1. **Approval/admission.** Approve the new runtime design and bounded canary tests,
   not the case. Verify all pinned images/models/source/package/reference hashes,
   available memory/storage, no existing-volume reference, no reparse/hardlink
   escape and no evaluator materials in any image/release. Allocate a new opaque
   case ID, e.g. `SMOKE-<random hex>`, and one new project ID. No label in the name.
   Do not use `LOCAL-<32 hex>` which enables host-collector follow-up identity.
2. **Provision-only stage.** Build the reviewed new image; provision the fresh
   namespace, rule initializer, non-root dependencies, private credentials and
   state. Verify effective worker/helper IDs, ports, rule counters, empty stores,
   known model tags/digests and API/PDF dependencies. No graph/ingestion/model
   completion is inferred from readiness. Any bounded model canary also needs
   explicit approval. Execute the separate functional isolation test plan; abort
   before intake if any forbidden read/connection/leak succeeds.
3. **Separate case-execution approval.** Record permission for this exact case hash,
   one attempt, proposed caps and HITL behavior. Do not treat the accepted old
   network-none preflight as acceptance of the expanded functional topology.
4. **Evidence intake.** Mount only the prepared read root; verify the derivative
   checksum from worker identity. Run unchanged `ingest_uploaded_case` from a
   reviewed runtime-only wrapper using: supplied new case ID,
   `/evidence/agent_evidence/case-input.zip`, actual `validate_archive` receipt,
   no date filter, `max_events=100` per file, `exclude_ports=[]`.
   These settings retain all eight supplied records and do not collect host logs.
   Store a controller copy of provenance/receipts outside the agent read root.
5. **Normalization and stores.** Require coverage of all eight unique source record
   IDs; no unexplained rejection/duplicate/event loss. Record actual event UID,
   trace, source type/time/context and source-record linkage for each. Do not
   predetermine runtime UID values. Verify Quickwit preserved serialized-record
   hashes against the sanitized input, Neo4j case/HAS_EVENT links and lineage,
   Chroma document/chunk/hash/case receipts, DuckDB rows and Kafka acknowledgment
   count for unique normalized events. Raw-record hashes are hashes of the
   function's sorted JSON serialization, not automatically the ZIP member hash.
6. **Investigation start.** Coordinator alone submits exactly one authenticated
   `POST http://127.0.0.1:8300/api/investigations` with the new case ID and neutral
   raw_input `Investigate preserved case evidence`. Use actual source factory,
   durable SQLite and real Ollama backend, not StubLLM or a fake graph. The
   one-case token is never available to model tools. Record submission, image,
   runtime manifest, beginning time, gateway exchanges and resource counters.
7. **Orchestration/specialists.** Capture actual node/AgentRun/finding traces and
   projection receipts. Verify primary-tier work and evidence-driven routes.
   Log which specialists were eligible, dispatched, completed or unavailable;
   do not require every specialist for a case without corresponding artifacts.
   Missing-memory/malware/new-host acquisition requests remain explicit gaps.
   Do not enable CAPE, original host collector, downloads or unsupported tooling.
   Existing follow-up source limits are two rounds and six planned actions per
   round; retain them and record actual actions/outcomes. These are scoped
   follow-up limits, not a claimed universal graph tool budget. Any unexpected
   tool surface or unbounded action path blocks this minimal profile for review.
8. **Timeline/citations.** Validate each timeline `uid`/`dfkg_refs` against actual
   case events/source-record linkage. Check recorded time values and seven
   retained same-host time-pair expectations externally. No cross-host causal
   order, actor identity or clock correction is fabricated. Resolve every
   report/finding citation to retained evidence; source support requires operator
   review beyond syntactically valid UID links.
9. **HITL if reached.** Persist snapshot and stop the active timer at the actual
   interrupt. Record reason, pending nodes, review coverage and missing artifacts.
   No automatic POST review, injected resume or forced guardrail result. Human
   reviewer may later explicitly approve/reject/clarify through the actual
   authorized `/api/investigations/{case_id}/review` endpoint. Approval after a
   guardrail failure can route straight to report; approval after debate entry
   still routes through guardrails. Respect either result. Clarification is an
   additional human-approved execution segment, not an invisible repeat.
10. **Report/termination.** If guardrails complete or an explicitly authorized
    review permits it, let the real report/timeline nodes run. Save report text,
    court/technical HTML metadata, timeline artifact, final checkpoint/status and
    both authorized PDF downloads. Compare X-Report-SHA256 to downloaded bytes,
    verify PDFs parse/render and cite actual case evidence. No report is expected
    merely because a graph invocation returned at HITL. Verify final join fields
    and lack of pending/error tasks, then stop only the newly approved runtime.
11. **Capture/cleanup.** Export case-scoped receipts, logs, gateway transcripts,
    source/hash manifests and resource measurements to curator output; no evaluator
    answer file travels back into the runtime. Rehash original ZIP/key, derivative,
    references/models and parent source. Stop new worker/gateway/model processes
    on deadline/failure; a timed-out HTTP poll alone does not cancel the graph.
    Stop new stores and anchor last. Retain all new volume IDs/audit/checkpoints;
    no pruning, file deletion, old-service restart or `docker compose down -v`.

## Expected outcomes and failure conditions

| Gate | Expected contract, not a measured result | Fail / partial condition |
| --- | --- | --- |
| Intake | Valid ZIP and 8 source IDs covered; no source loss | Unsafe file, hash mismatch, unsupported/excluded source not explained |
| Stores | Actual durable preservation, graph/vector/analytics and Kafka receipts | A swallowed fallback/buffer, missing acknowledgment or empty case is failure |
| Model path | Only two pinned local models; complete captured real exchanges | Stub/cloud/fallback, wrong digest, hidden/bypassed call or malformed unretained response |
| Workflow | Real node transitions and correct conditional dispatch | Fake/stub graph, unbounded retry, unsupported tool execution, projection silently omitted |
| HITL | If required, real durable interrupt and no unauthorized resume | Automatically approving/clearing incompleteness to obtain artifacts |
| Timeline/citations | Recorded times retained, references resolve to this case | Invented event/time/clock confidence or foreign/unresolved citation |
| Reports | Actual generated text/timeline plus parseable/rendered court/technical PDFs, hashes recorded | Placeholder/empty artifact, PDF unavailable, 409 claimed as success |
| Completeness | Distinguish final closed/acceptance_status and artifact metadata | Closed with incomplete metadata is not an unqualified PASS |
| Bounds/security | Caps respected, no leakage, originals unchanged | OOM/deadline/call cap, forbidden read/network/auth, original change => stop and FAIL |

Possible legitimate outcomes: complete closed case with artifacts (functional
PASS only if all gates pass); durable HITL pause (gate mechanism PASS, end-to-end
report coverage BLOCKED pending a real decision); reject-closed case (expected
reject behavior but no report-path PASS); closed/incomplete report (mechanics
partial, completeness not PASS); dependency/model failure (FAIL/BLOCKED with reason).
Never override a retained incomplete review or stale/unverified reference flag
just to mark the smoke green. No expected response wording, latency, accuracy,
token usage or resource measurement is invented. One successful smoke would
establish functional plumbing for this case, not empirical evaluation readiness.
