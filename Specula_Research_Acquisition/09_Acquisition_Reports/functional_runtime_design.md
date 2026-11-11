# Functional runtime design

11 November 2026. **PREPARATION ONLY — NOT EXECUTED OR FROZEN.**
Workspace: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition`. Supporting receipts: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_smoke_preparation_20261111_run01`.
Source commit: `b9b2012edaed8da5062113ddc9982e3c33b27983` (tracked tree clean).
No runtime was built, created, started or reconfigured during this preparation.
No model invocation, investigation, normalization pipeline or benchmark was executed.
Pure ZIP/JSON input-contract checks and local file/image inspection were performed.


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
# UNAPPLIED. New network namespace ONLY. Requires separate provisioning approval.
# The worker and every helper retain separate PID/mount namespaces and non-root UIDs.
# No interface except loopback exists in the proposed shared network namespace.
table inet specula_smoke {
    chain output {
        type filter hook output priority 0; policy accept;
        meta skuid 10001 ct state established,related accept
        meta skuid 10001 ip daddr 127.0.0.1 tcp dport { 6379, 7687, 8000, 9092, 7280, 11434 } accept
        meta skuid 10001 reject
    }
}

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
- ONLY `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_smoke_preparation_20261111_run01\agent_evidence` may bind read-only at `/evidence/agent_evidence`.
  Set `SPECULA_THREAT_INTEL_DIR=/evidence/agent_evidence/reference_only` if approved.
  No other part of this report/acquisition/source tree is mounted.
- New worker-only state volumes at `/app/data/checkpoints` and `/app/data/analytics`;
  no original `data/private`. `SPECULA_CHECKPOINT_BACKEND=sqlite`,
  `SPECULA_CHECKPOINT_PATH=/app/data/checkpoints/specula.sqlite3`,
  `SPECULA_ANALYTICS_DIR=/app/data/analytics`. SQLite/WAL must survive worker
  restart for inspection but never be reused for a new smoke attempt.
- Non-evidence configuration/policy files must be baked into reviewed new images
  or populated into fresh, component-scoped named volumes by the coordinator.
  Do not add host configuration binds from the acquisition or parent directory.
- Ollama alone receives a NEW release containing only the two verified manifests
  and referenced blobs. Do not mount `C:\Users\DELL\.ollama`, host model HOME,
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
| alpine:3.22 | `sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8` | `unset/root default` |
| specula-isolation-canary:20261111-01 | `sha256:bf00809a2e299cac191e08996957da0630b56af6f442296e9a9bc14ce62258e3` | `10001:10001` |
| ollama/ollama:0.13.3 | `sha256:6c76395793f40a5e78f120e880ca82c67e39eb908ad90eee8ce755535529d0ec` | `unset/root default` |
| neo4j:5.26.0 | `sha256:5a015e53de1895e7eee1574ae0325cf8c4b89587222778108c594bdd45a474b5` | `unset/root default` |
| confluentinc/cp-kafka:7.5.3 | `sha256:51145a40d23336a11085ca695d02bdeee66fe01b582837c6d223384952226be9` | `appuser` |
| redis:7.2-alpine | `sha256:05a97a479bc73de66f087dc05b569010772880f778cc8671fa6b8aadee32e5c6` | `unset/root default` |
| chromadb/chroma:latest | `sha256:1e0b73a187a28757c572acba508c46f48c9e8b0acaf5c20e6d95cdedce1acdf6` | `unset/root default` |
| quickwit/quickwit:latest | `sha256:072a655ded8498283e1073617d3e8d17ddd2be189a82325e30254ebbdf8cb8a6` | `unset/root default` |

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
| qwen3:8b | `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` | 5,225,388,164 |
| qwen3-embedding:0.6b | `ac6da0dfba84a81fdbfbaf330198c33cd77c4cdfc53e8bc50eb581914a15621d` | 639,150,858 |

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

Explicit service endpoints in the new worker configuration:
`NEO4J_URI=bolt://127.0.0.1:7687`, `REDIS_HOST=127.0.0.1`, `REDIS_PORT=6379`,
`KAFKA_BOOTSTRAP_SERVERS=127.0.0.1:9092`, `CHROMA_HOST=127.0.0.1`,
`CHROMA_PORT=8000`, `QUICKWIT_ENDPOINT=http://127.0.0.1:7280` for views.
The upload client's hardcoded `http://localhost:7280` is also inside this same
closed namespace and must be tested as written; do not patch it or assume an
environment override changes that constructor default. Configure Ollama's bind
as `OLLAMA_HOST=127.0.0.1:11435`, selected release via `OLLAMA_MODELS=/models`
and a new writable HOME; never expose its host HOME. Set `SPECULA_CAPE_ENABLED=false`
and `SPECULA_LOCAL_COLLECTOR_URL=http://127.0.0.1:8400` (no listener, worker denied).
No cloud API keys/proxies, host verification token or collector credential.
Fresh datastore credentials, if configured, must belong only to these disposable
stores and must not be confused with the coordinator-only case API tokens.

## Dependency minimality, resources and lifecycle

Required: Neo4j, Quickwit, Kafka, Chroma+Ollama, Redis and worker-local SQLite/DuckDB.
The existing upload helper calls these, including acknowledged normalized-topic
publication; dropping Kafka silently changes the intake contract. No external
Schema Registry is needed for this path: `case_stream` validates embedded OCSF
schema locally. No Kafka consumer, separate HITL server, browser/frontend, boot
controller, CAPE, live Windows/GCP collector or hosted provider is needed: upload
helper writes the case graph and index directly; `visualizer_api:app` registers
investigation/review/report routes on the same durable graph.
The selected security-gate path uses the in-process sanitizer/injection detector;
the separate legacy `rebuff_gate.py` REST adapter is not that intake call path.
No Rebuff8080 service or network exception is proposed.

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
