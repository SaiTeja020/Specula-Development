"""Create approval documents from inspected source and measured preparation receipts."""
import json
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
REPORTS=RUN.parent
def read(name):return json.loads((RUN/name).read_text(encoding='utf-8'))
def write(name,text):
    with (REPORTS/name).open('x',encoding='utf-8',newline='\n') as f:f.write(text)
case=read('case_derivation.json');models=read('local_model_pins.json');images=read('local_image_pins.json')
ref=read('reference_preparation_receipt.json')
prefix=str(RUN)
common=f'''11 November 2026. **PREPARATION ONLY — NOT EXECUTED OR FROZEN.**
Workspace: `{ROOT}`. Supporting receipts: `{prefix}`.
Source commit: `b9b2012edaed8da5062113ddc9982e3c33b27983` (tracked tree clean).
No runtime was built, created, started or reconfigured during this preparation.
No model invocation, investigation, normalization pipeline or benchmark was executed.
Pure ZIP/JSON input-contract checks and local file/image inspection were performed.

'''
write('selected_synthetic_case_manifest.md','# Selected synthetic case manifest\n\n'+common+f'''
## Selection and integrity

One existing case: parent `output/evaluation-pilot/case-001.zip`. Eight records,
five supported JSON/JSONL files, no native PE, memory image or PCAP to execute.
This is the smallest of the existing 2,904/3,476/3,499-byte pilot archives.
No generator was rerun and no new forensic scenario or expected finding was invented.

| Asset | Exact path | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Original evidence, unchanged | `{ROOT.parent}\\output\\evaluation-pilot\\case-001.zip` | 2904 | `8d8d228df7a841e3a30da9a839e9ec4de5aee00fef35c640e534460e7b21ff5d` |
| Separately retained original expected findings, NEVER mount | `{ROOT.parent}\\output\\evaluation-pilot\\case-001-answer-key.json` | 7574 | `45aaccad30a19e7548c9c6cfe21aae33873f2bc5fd9c635f9ba678d57211c193` |
| Agent-visible derivative | `{prefix}\\agent_evidence\\case-input.zip` | {case['derived_bytes']} | `{case['derived_sha256']}` |
| Agent-visible checksum | `{prefix}\\agent_evidence\\package.sha256` | measured in final manifest | Hashes the derivative only |

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

Ground-truth status is literally `{case['truth_status']}`. The key is independently
retained from the evidence package, but **not independently adjudicated ground truth**.
Its causal/entity labels and independent claim annotations are null. Operator review
and explicit acceptance of these planted-control limitations are required. Do not
use this one synthetic case to claim empirical accuracy or generalization.

## Separate approved-reference candidate

`agent_evidence/reference_only` contains four unchanged copies of the existing
parent `data/threat_intel` corpus: `faiss_index.bin`, `faiss_id_map.json`,
`metadata_store.json`, `build_manifest.json`. Total {sum(x['bytes'] for x in ref['files']):,} bytes.
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
''')
pin_rows='\n'.join('| '+', '.join(x['tags'])+' | `'+x['id']+'` | `'+(x['user'] or 'unset/root default')+'` |' for x in images)
model_rows='\n'.join(f"| {x['name']} | `{x['manifest_sha256']}` | {sum(y['bytes'] for y in x['blobs']):,} |" for x in models)
policy=(RUN/'network_policy.PROPOSED.nft').read_text()
write('functional_runtime_design.md','# Functional runtime design\n\n'+common+f'''
## Recommendation and topology

**GO recommendation for a separately approved, provisioning-only isolation stage.**
All necessary model assets and candidate service images are already local; no
download is required by this design. This recommendation is not permission to
provision now or to start a case. Worker launch must fail closed until its new
namespace policy is installed and inspected. Functional execution remains NO-GO
until actual isolation/compatibility/admission checks pass and the user authorizes it.

Use a NEW standalone project `specula-smoke-20261111-01`; never merge development
Compose or reuse any development container, volume, index, policy or token.
An anchor container has `network_mode: none`, no ports and no host aliases.
Worker, services and coordinator attach with `network_mode: service:anchor`.
They share only loopback networking; PID, mount and IPC namespaces remain private.
There is no Ethernet interface/default route, bridge, host gateway or host service.
This accommodates the existing localhost-only Quickwit default and Ollama adapter
without changing application source or exposing Windows localhost services.

## Intended service identities and allowlist

| Component | Intended UID:GID | Listener / dependency | Fresh writable data | Reason |
| --- | --- | --- | --- | --- |
| Specula worker/API and one-shot upload helper | 10001:10001 | API 127.0.0.1:8300; outbound ports below | only new checkpoints/analytics/tmp | Actual `visualizer_api:app` plus actual upload helper |
| Ollama | 10011:10011 | 127.0.0.1:11435; worker DENIED direct access | private HOME/tmp; selected model release read-only | Generation and semantic embeddings |
| Neo4j | 10012:10012 | Bolt 127.0.0.1:7687; HTTP disabled | new /data,/logs/config as needed | Evidence, case ownership, analysis projections |
| Kafka KRaft single-node | 10013:10013 | broker 9092, controller 9093 (worker DENIED) | new kafka data/config/secrets dirs | Normalized OCSF delivery receipts |
| Chroma | 10014:10014 | 127.0.0.1:8000 | new persistence directory | Per-case semantic vectors |
| Quickwit | 10015:10015 | REST 7280; internal 7281 if needed, worker DENIED | new metastore/index dirs | Raw-record preservation receipt |
| Redis | 10016:10016 | 127.0.0.1:6379 | new /data | Scratchpad/dead-end heuristic |
| Model capture gateway | 10017:10017 | 127.0.0.1:11434 -> 11435 | private bounded transcript volume | Actual chat/embed request and response capture |
| Coordinator | 10018:10018 | NO listener; client to API/store/gateway | private one-case credentials/output | No evaluator material or expected findings |
| Namespace anchor | 10019:10019 | no listener | none | Retains private no-network namespace |

All are dedicated numeric non-root identities; these are proposed overrides, not
claims about image defaults or effective service identities already tested.
Existing images mostly default to root (see table below); stock launch defaults
are not approved. Direct binary/entrypoint configuration, writable config paths
and UID ownership must be verified under each override after approval. Do not
fall back to root to make startup pass. Any root-only initialization is limited
to new disposable volumes, with no host/evaluator mounts, and must be explicitly
approved. Prefer precreated tmpfs/new-volume ownership at the intended UID.

## Network policy — proposed, not applied

An independently controlled one-shot namespace initializer installs the following
rules using the already cached image
`registry.k8s.io/kube-proxy@sha256:913cc83ca0b5588a81d86ce8eedeb3ed1e9c1326e81852a1ea4f622b74ff749a`.
Read-only image-archive inspection confirmed `/usr/sbin/nft` and its library exist;
no kube-proxy process/container was created or run. Override entrypoint to nft;
grant only the namespace-init job CAP_NET_ADMIN in this NEW namespace, never host
network/PID mode, privileged mode, a daemon socket or host mount. It exits before
workers start. No evaluated process receives CAP_NET_ADMIN or UID 0.

```nft
{policy}
```

The established/related rule permits API response packets and replies to allowed
connections. New worker connections are IPv4-loopback TCP only to the six listed
ports; API 8300, raw Ollama 11435, Kafka controller 9093, Quickwit internal 7281,
Neo4j HTTP, IPv6 new connections, DNS, host ranges and Internet are denied.
Other service identities have loopback-only namespace connectivity; the namespace
has no external route. The services are trusted fresh dependencies of this one
case, not a multi-tenant security boundary. The worker may write required case
data through these services; originals remain outside them/read-only.
Inspect actual namespace inode, links/routes, rule handles/counters and worker UID
before any workload. Missing nft support, a failed rule load or missing deny probe
blocks worker/model start. This extra policy is essential: a shared loopback
namespace alone would expose direct Ollama/admin ports and bypass capture.

## Model capture gateway contract — must be reviewed and implemented before use

Use a separate minimal non-root relay, not an application patch. Permit only
GET `/api/tags`, GET `/api/version`, POST `/api/chat` and POST `/api/embed`;
reject model pull/create/push/delete, arbitrary paths/URLs, redirects and oversized
bodies. Forward only to fixed `127.0.0.1:11435`; no URL can be supplied by a prompt.
POST chat may select only `qwen3:8b`, embed only `qwen3-embedding:0.6b`; validate
local `/api/tags` digests against the pins below and forbid remote models.
Preserve supported original request/response bytes and schemas; do not fabricate
replies or silently clamp sampling/context. Tag every exchange with monotonic
sequence, wall timestamps, model digest, raw-body hashes/status/length and measured
duration. Store complete JSON requests/responses only in the relay's private output
volume, never in an agent-readable log/index. A host collector can later scan them.

Proposed bounds for approval: 40 chat POSTs, 20 embed POSTs (no automatic reset),
8 MiB request / 32 MiB response, 300s per upstream exchange and 1800s whole active
case including ingestion, excluding a documented human pause. Exceedance fails
closed, preserves receipts and aborts this attempt; it never produces a success
response or restarts the case. Tests must prove counters, model/path allowlists,
logging coverage, timeouts, and inability to bypass port 11434.
No existing relay is asserted: implementation and static review are provisioning
work requiring approval; it must pass isolated canary tests before case execution.

## Filesystems and auth

- Worker root read-only; cap_drop ALL, no-new-privileges, pids limit 256, private
  PID/IPC, no devices/GPUs/Docker socket/SSH/host HOME/parent or acquisition mount.
  Bounded noexec,nosuid,nodev tmpfs for /tmp and /run. No inherited .env.
- ONLY `{prefix}\\agent_evidence` may bind read-only at `/evidence/agent_evidence`.
  Set `SPECULA_THREAT_INTEL_DIR=/evidence/agent_evidence/reference_only` if approved.
  No other part of this report/acquisition/source tree is mounted.
- New worker-only state volumes at `/app/data/checkpoints` and `/app/data/analytics`;
  no original `data/private`. `SPECULA_CHECKPOINT_BACKEND=sqlite`,
  `SPECULA_CHECKPOINT_PATH=/app/data/checkpoints/specula.sqlite3`,
  `SPECULA_ANALYTICS_DIR=/app/data/analytics`. SQLite/WAL must survive worker
  restart for inspection but never be reused for a new smoke attempt.
- Ollama alone receives a NEW release containing only the two verified manifests
  and referenced blobs. Do not mount `C:\\Users\\DELL\\.ollama`, host model HOME,
  arbitrary cache entries, keys or conversation history. Copy selected files to a
  new read-only release after approval; do not modify the cache. No pull endpoint.
- Read-only new backend policy contains only hashes of high-entropy, expiring,
  one-case local credentials. Tokens stay with coordinator/human, never image,
  model prompt, worker environment, evidence, logs or persisted checkpoint.
  Use subject `local-validation` with analyst role for the actual helper's case
  owner, plus a separate human reviewer principal scoped to that case. No wildcard
  grants or embedded public preflight token. Worker cannot initiate API calls to 8300.
  Review remains the actual authorized endpoint, not a scripted auto-approval.
- Case-specific API grants are application controls; raw DB credentials are not
  row-level isolation. Therefore use one-case-only disposable stores, never shared
  production cases. Do not store evaluator labels/expected findings even in a
  separate collection of an allowed datastore.

## Software/model pins already inspected

| Local image reference | Immutable local ID/digest | Observed default user |
| --- | --- | --- |
{pin_rows}

Names `latest` above identify inspected cache entries only; deployment must use
their full digests and `pull_policy: never`. Semver for cached Chroma/Quickwit
binaries remains unobserved; digest pins are exact, and version APIs/binary output
must be collected after approval. No mutable tag alone is an approved pin.
The old preflight image entrypoint/public policy is not a functional entrypoint.
Build a NEW functional image from the reviewed scratch-image inputs: same hashed
local library tar, exact current 164 source files, and ONLY the unchanged
`scripts/local_case_pipeline.py` needed for intake. Add reviewed runtime-only
entry/relay/coordinator scripts separately, no generators/scorers/tests/.git/.env.
Source hashes and library/distribution inventory are in supporting JSON receipts.
New build digest is unresolved until that approved build; do not relabel the
preflight digest as if it already contained the functional helper.

| Local model | Manifest SHA-256 (required live digest comparison) | Referenced blob bytes |
| --- | --- | ---: |
{model_rows}

Every manifest config/layer blob SHA-256 and size was checked in this preparation.
Source defaults: `SPECULA_LLM_BACKEND=ollama`,
`SPECULA_THREAT_ATTRIBUTION_BACKEND=ollama`, `SPECULA_OLLAMA_MODEL=qwen3:8b`,
`SPECULA_OLLAMA_BASE_URL=http://127.0.0.1:11434`,
`SPECULA_EMBEDDING_MODEL=qwen3-embedding:0.6b`, `SPECULA_EMBEDDING_NUM_GPU=0`.
Chat context 8192, generic output 1024 / structured output 2048, temperature 0,
think false, num_thread 2, num_batch 128, keep_alive 15m, cooldown default 15s,
120s chat read deadline. Do not switch to stub, cloud or another model on failure.
No devices/GPUs in the initial design; CPU-only capability/timing is unmeasured.
Case embeddings: 2000-character chunks, batch 32, cosine, required case filter,
retrieval top-k 5 events. Actual model embedding dimension/live API version is
unresolved until approved runtime checks; do not assert historical dimension 1024.
No model seed is sent by current source; record null, one run only. No invented
determinism or whole-graph token budget. Gateway call caps are additional approved
preflight limits; token consumption must be measured from actual exchanges.

## Dependency minimality, resources and lifecycle

Required: Neo4j, Quickwit, Kafka, Chroma+Ollama, Redis and worker-local SQLite/DuckDB.
The existing upload helper calls these, including acknowledged normalized-topic
publication; dropping Kafka silently changes the intake contract. No external
Schema Registry is needed for this path: `case_stream` validates embedded OCSF
schema locally. No Kafka consumer, separate HITL server, browser/frontend, boot
controller, CAPE, live Windows/GCP collector or hosted provider is needed: upload
helper writes the case graph and index directly; `visualizer_api:app` registers
investigation/review/report routes on the same durable graph.

Observed Docker memory cap: 12,539,568,128 bytes, 20 CPUs; host physical total
16,454,352 KiB and free 3,686,820 KiB at inspection. Free memory is time-dependent
and not proof a loaded stack fits. Proposed caps, requiring approval and fresh
host/VM headroom check: Ollama 7 GiB, worker 1 GiB, Neo4j 768 MiB, Kafka 768 MiB,
Chroma 384 MiB, Quickwit 384 MiB, Redis 64 MiB, relay 64 MiB, coordinator 64 MiB,
anchor 16 MiB (10,704 MiB total). Configure matching JVM/indexer/cache internal
limits; exact service configuration and non-root writable paths remain to be
validated. Stop on OOM/readiness failure, never weaken identity or reduce model
context silently. Do not change Docker daemon/host memory or existing services.

New service config, credential generation, writable-path ownership, gateway,
namespace init and component startup tests are unapplied provisioning work.
They must be approved explicitly and recorded by image/ID/volume/UID/rule hash.
Stop only the new project services on abort/finish; retain checkpoint, audit and
volume IDs for operator review. No `down -v`, pruning, Git reset or automatic deletion.
''')
write('functional_smoke_test_plan.md','# Functional smoke-test plan\n\n'+common+f'''
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
| PDF | `examination_reports.py:render_examination_pdf`, API `/reports/{{kind}}` | Authorized court/technical PDF from saved evidence, digest headers; 409 before final report, 503 if PDF dependency missing |
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
   authorized `/api/investigations/{{case_id}}/review` endpoint. Approval after a
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
''')
write('functional_isolation_test_plan.md','# Functional isolation test plan\n\n'+common+f'''
## Execution status and acceptance rule

All tests below are **NOT RUN**. The accepted prior network-none, single-canary
profile is historical evidence only; it does not establish these added services,
model relay, credentials, mounts or data flows are safe. Provision only after
approval, and prohibit intake until required pre-ingestion checks pass. Model
canary inference requires explicit bounded authorization. After ingestion/run,
repeat the applicable access/leakage checks before declaring functional PASS.

Worker probes must use real UID:GID 10001:10001 in the exact new worker image,
its private PID/mount namespaces and the actual shared network namespace.
Helpers need their own effective-identity/mount checks too. Docker/Windows curator
is trusted management, not an evaluated identity. Do not infer denial from ACLs.

## Canary and reference arrangement

Curator creates fresh harmless restricted markers for ground truth, expected
findings, filename mapping and evaluation labels OUTSIDE every runtime image,
mount and reachable service. Keep values on curator host only; never pass them
as environment, argv, prompt, stdin or negative-test expected-value arguments.
Record their actual host presence/hashes. Use an independent permitted evidence
canary whose hash is public. Negative requests name paths, not marker contents.
Host scanner compares returned bytes/logs/index exports against withheld values.

Use a separate benign decoy case marker to test case-filter correctness in new
stores; it is not a ground-truth canary and contains no answer. Seed it only in
the separately approved test phase, record it, and require zero retrieval into
the selected case. Do not import a real prior case or evaluator material.

## Tests to execute and retain raw output

| ID | Boundary/probe | Required result and retained evidence |
| --- | --- | --- |
| F01 | Effective identity, image/source fingerprint, capabilities, no-new-privileges, PID/mount namespace; every helper | Expected distinct nonzero UIDs; zero worker/helper capabilities; exact pinned source/image; no shared host PID or Docker control socket. One-shot net-init exits before worker starts. |
| F02 | Actual Docker inspect/mountinfo and evidence admission | Only candidate agent_evidence host bind, read-only; expected new per-component volumes/tmpfs; no parent, evaluator, model HOME, reports, backups, production data or source mount. Reject reparse/symlink/unexplained multi-links before admission. |
| F03 | Permitted ZIP/reference read and write attempts as worker | Read hashes match prepared package/reference receipts. Write/truncate/rename attempts fail without changing any evidence; use a new harmless write probe, never corrupt a source test file. |
| F04 | Direct, `..`, encoded/alternate-separator, Windows drive/UNC/file-URI and `/proc/*/root` path attempts | Cannot read ground truth, maps, labels, host home/source/backups or unrelated store data. ENOENT for namespace-excluded files is documented alongside curator presence and mount proof, not called Windows ACL denial. |
| F05 | Runtime Linux symlink escape; unmounted synthetic Windows junction candidate | Symlink cannot reach withheld host canary; evidence admission rejects junction before mounting. Never point a new link at real evaluator originals. |
| N01 | Net namespace links/routes/DNS/aliases plus actual nft rules/counters | Only loopback; no default route/host alias/host namespace; UID10001 policy matches proposed ports. Failed/missing policy blocks worker, not just a warning. |
| N02 | Allowed service probes from UID10001 | Successful protocol-aware connection to Redis6379, Bolt7687, Chroma8000, Kafka9092, Quickwit7280, model gateway11434. No placeholder health response substitutes for a real service. |
| N03 | Forbidden connections from actual worker | Direct Ollama11435, Kafka-controller9093, Quickwit7281, Neo4j7474, API8300, host:8400/11434, DNS/IPv6, unrelated Docker ranges, public IP and daemon endpoints fail. Record syscall/protocol result and firewall counters. |
| N04 | Relay bypass and abuse | Worker direct 11435 fails even though gateway10017 can reach it; arbitrary URL/path, pull/create/delete and wrong model rejected by gateway. No redirected credential or request. |
| A01 | Actual API auth from coordinator namespace/identity | No token 401; viewer cannot write 403; analyst only approved case; nonexistent/foreign case access denied; expired/revoked test credential denied; no wildcard/admin identity supplied to agent. Record actual status and no response body leakage. |
| A02 | API access from worker and actual application tools | Worker cannot connect to API8300; negative filesystem/examination probe through real permitted tool rejects external canary before any examination/cache write. Inventory active tools; no arbitrary shell, host browser/search/collector/SSH or new file access tool enabled. |
| A03 | Human gate | Unauthorized review cannot resume; real HITL checkpoint remains pending until explicit human decision. If approval authorizes a bounded HITL probe, execute only approved scenario and record decision source; never force guardrails in the forensic case. |
| R01 | Fresh graph/vector/search/Redis/checkpoint/analytics before intake | Actual case/document/index counts show no prior case/prompt/cache/evaluator contents. Required default schemas/collections may exist and are recorded; they are not claimed empty merely by new volume name. Reference-only FAISS exactly matches approved manifest and 873 allowed records. |
| R02 | After intake, complete membership/content inspection | All Chroma documents/chunks and metadata, Quickwit stored raw records, Neo4j case/events, Kafka normalized messages, DuckDB rows and Redis scratch entries belong to admitted input or declared canaries; no expected labels/answer files. Preserve hash/UID linkage for every event. |
| R03 | Actual `CaseEvidenceRetriever` case-filter and reference separation | Query selected case returns only its event citations/chunks; foreign decoy marker excluded; empty/nonexistent case is handled per implementation, never a cross-case fallback. FAISS records are public references, not case evidence/truth. No precomputed answer embeddings. |
| M01 | Real model inventory | Live Ollama version, tags and both digests match cached pins; no remote model fields; selected weights are only approved files; no `/api/pull`. Actual embedding shape recorded, not invented. |
| M02 | Approved benign chat/embed canary roundtrip through exact configured adapter/gateway | Actual requests/responses captured completely with hashes, model/digest/status/counts; no evaluator markers in request, response, logs, tmp or indexes. No case execution during this bounded probe. If model inference not approved, mark BLOCKED, never PASS. |
| M03 | Whole smoke model trace and bounds | Every chat/embed POST accounted for by gateway; no bypass port works; request model/options/schema match approved source; no extra prompt corpus, keys, expected findings, annotation fields or prior output inserted. Call/body/deadline gates fail closed. |
| M04 | Withheld marker and annotation scan | Curator scans raw and decoded transcripts, worker/gateway logs, checkpoints/WAL, scratch/tmp, reports and exported store content for withheld markers, original evaluator filenames and answer serialization. Semantic overlap with source facts is reviewed, not automatically declared contamination. |
| I01 | Integrity before/after each phase | Original ZIP/key unchanged, derivative and reference hashes unchanged, source commit/tracked tree unchanged, pinned model blob hashes retained; verify fresh copies and any derived serialization against their own recorded hashes. |
| L01 | Termination/abort | Actual new investigation/model processes stop on approved deadline/cap/OOM and no background execution remains; preserve checkpoint and reason. No production service/volume touched, no auto-repeat/resume or deletion. |

## Prompt and output review

The relay's private transcript/output volume is not mounted into worker and is
not ingested or used as a retrieval corpus. Coordinator has no HTTP file server
or evaluator repository. Any retained expected-answer comparison happens on the
curator host after collection; no scorer/key is copied into the new stack.
Inspect actual prompts (including structured schema and correction attempts),
responses, usage metadata, logs, decoded JSON/base64 payloads and all active
retrieval documents. An exact answer marker/path or evaluator serialization
match fails isolation; shared normal security terminology alone is not proof of
leakage. Missing transcripts/unsupported index export means coverage BLOCKED.

Filesystem/tool/API/store/model probes are additive. API case authorization is
not proof raw database access is case-isolated. This is a one-case runtime with
fresh stores, so no sensitive other-case records may be hosted. The accepted
preflight does not test kernel/daemon escapes or a malicious host curator.

## Gate outcome rules

- PASS only for tests actually executed against this exact runtime identity and
  configuration with expected permitted successes and forbidden failures.
- FAIL on any forbidden read/connection, label/answer exposure, integrity change,
  self-approval, bypass, unsafe privilege or unrecorded model request.
- BLOCKED on unavailable image/tool/kernel support/model/service, missing output,
  absent approval or untested required boundary. Never silently downgrade a test
  or enable broader privileges/network/host services to pass it.
- Keep a per-test machine receipt with command, identity, inputs limited to
  non-sensitive paths/hashes, exit/HTTP status, output location, timestamp and
  reviewer sign-off. These documents contain no invented probe results.
''')
write('smoke_test_approval_checklist.md','# Smoke-test approval checklist\n\n'+common+f'''
## Current recommendation

**GO recommendation for provisioning the proposed fresh runtime for isolation
validation, after explicit approval of the concrete scope below.** No current
authorization to apply it is inferred. **NO-GO for investigation execution now.**
The actual one-case workflow remains blocked until new-runtime tests pass and
the user gives separate case-execution authorization. Preparation success is not
a functional result or empirical-readiness claim.

## Prepared and statically verified

- [x] Existing eight-record case selected; original ZIP/key retained and hashed.
- [x] Sanitized 2,750-byte derivative ZIP and file-hash manifest created; pure
  archive contract/CRC checks PASS. Eight `synthetic` flags and fixture manifest
  labels excluded; all other source values preserved.
- [x] Separately retained expected findings located: 3 developer-authored
  observations / 7 same-host time pairs; independent adjudication still pending.
- [x] Candidate reference-only corpus copied unchanged and manifest-verified;
  873 reference records audited by type/source/field allowlist, old date preserved.
- [x] Both cached model manifests and every referenced blob match SHA-256/size.
- [x] Eight existing runtime images plus the firewall-tool candidate pinned;
  no pull/download/install. Read-only archive inspection confirms nft binary.
- [x] Real source entrypoints/dependencies/HITL/timeline/report contracts traced;
  host boot/pilot runner explicitly excluded from proposed execution.
- [x] Proposed worker UID10001 network allowlist recorded in
  `network_policy.PROPOSED.nft`; never applied.
- [x] No new container/network/volume, service/ACL/source/evaluator change or
  investigation/inference. Preparation receipts explicitly say runtime_results=null.

## Approval 1 — provisioning and bounded isolation only (NOT granted here)

- [ ] Approve new standalone project name/IDs and exact image/build inputs; no
  modification/reuse of development services, production volumes or accepted old
  canary container configuration.
- [ ] Approve only `agent_evidence` read-only bind and the frozen reference corpus
  with its original provenance/staleness limitations. No evaluator/parent mount.
- [ ] Approve creation of fresh model release from selected verified blobs only;
  no host .ollama HOME or entire cache exposure, no model download.
- [ ] Approve fresh disposable service/checkpoint/analytics volumes and distinct
  non-root UIDs. Approve narrowly scoped new-volume ownership initialization if
  needed, never evaluator ACL changes or permanent root service fallback.
- [ ] Approve one-shot CAP_NET_ADMIN initializer ONLY in the NEW network-none
  namespace; no privileged/host-network job. Require inspection and successful
  worker deny probes before worker/model workload is enabled.
- [ ] Approve new bounded model capture gateway/coordinator runtime helpers,
  static review, image hashes and tests. Existing Specula source stays unchanged.
- [ ] Approve fresh expiring one-case auth policies/credentials, held by operator;
  no wildcard/admin grant or public old preflight credential. No token in model
  context, evidence, checkpoint or worker configuration.
- [ ] Approve proposed per-component resource caps and a new host/VM headroom
  check; no daemon memory change, GPU exposure, context reduction or model swap.
- [ ] Explicitly approve or defer a bounded benign chat/embed canary used to
  validate model capture. Deferral leaves M02 BLOCKED and prevents a case launch.
- [ ] Require raw result receipts for F01–L01 applicable pre-intake tests; stop
  on missing nft support/non-root permissions/client compatibility/health checks.

## Approval 2 — one functional case (NOT granted here)

- [ ] Review the actual provisioned image digests, effective identities, mounts,
  namespace/firewall rules and every required isolation PASS receipt. Resolve
  missing/failed checks first; prior preflight alone is insufficient.
- [ ] Approve exact derivative hash `{case['derived_sha256']}`; one new opaque
  case ID, no dates/port exclusions, max_events=100/file, one attempt, no repeat.
- [ ] Accept planted-control expected-key status and independent-review limitation;
  record an operator truth review without inventing judgments in advance.
- [ ] Approve 40 chat / 20 embed POST cap, body bounds, per-exchange and 1800s
  active case deadline; specify controlled abort and collection, no auto-retry.
  Current source sends no model seed; seed remains null, no reproducibility claim.
- [ ] Approve actual Ollama models/options, case retrieval settings and frozen
  reference; live version/dimension and effective settings recorded before intake.
- [ ] Decide HITL policy: pause and request a real decision if interrupted;
  no auto-approval, forced guardrails or silent clarification. A paused case may
  validate HITL plumbing but cannot pass unexecuted report-generation gates.
- [ ] Approve post-run evidence citation/timeline/report review outside the worker,
  including court/technical PDF render checks and proper incomplete outcomes.
- [ ] Approve stop-only cleanup of newly created processes, retaining volumes,
  receipts and checksums. No data deletion, pruning or production-service changes.

## Unresolved runtime facts — resolve after approved provisioning, before a case

New functional image digest; effective non-root service startup/config/write
paths; nft kernel/UID-rule behavior in exact namespace; relay implementation and
capture/bounds/bypass tests; new credentials/IDs; live Ollama version and model
digests; actual embedding vector shape; Chroma/Quickwit binary versions/client
compatibility; fresh store contents; service CPU/RAM headroom; actual execution
manifest and PDF runtime imports. These are unmeasured, not assumed green.

Ground-truth review and reference staleness handling also remain operator decisions.
No data-format reimplementation or Specula source fix is authorized. If actual
startup requires application modifications, unavailable tools/models, existing
service changes or broader filesystem/network privileges, stop and report
BLOCKED for a separate approval decision.

## Readiness interpretation

| Decision | Current state |
| --- | --- |
| Preparation artifact integrity | PASS only after preparation verifier receipt; no runtime result |
| Recommendation to provision isolation-validation stage | GO, subject to Approval 1; no action performed |
| Permission/readiness to start functional case | NO-GO; Approval 2 and actual isolation gates outstanding |
| Full end-to-end functional success | NOT TESTED |
| Controlled empirical evaluation | NO-GO; unfrozen protocol, independent truth and additional evaluation gates remain |

No checkbox for a future action has been checked merely because it is proposed.
See `functional_smoke_test_plan.md`, `functional_runtime_design.md`,
`selected_synthetic_case_manifest.md` and `functional_isolation_test_plan.md`.
''')
print(json.dumps({'documents_created':5,'status':'PREPARED_ONLY','provisioning_recommendation':'GO_AFTER_EXPLICIT_APPROVAL','investigation':'NO_GO'}))
