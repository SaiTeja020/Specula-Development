# Functional isolation test plan

11 November 2026. **PREPARATION ONLY — NOT EXECUTED OR FROZEN.**
Workspace: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition`. Supporting receipts: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_smoke_preparation_20261111_run01`.
Source commit: `b9b2012edaed8da5062113ddc9982e3c33b27983` (tracked tree clean).
No runtime was built, created, started or reconfigured during this preparation.
No model invocation, investigation, normalization pipeline or benchmark was executed.
Pure ZIP/JSON input-contract checks and local file/image inspection were performed.


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
