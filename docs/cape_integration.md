# CAPE dynamic examination integration

The malware specialist supports CAPE's authenticated **v2** file API. Sandbox
provisioning and live acceptance are deferred at the user's request. The local
HTTP emulator exercises the connector; it is not a malware runtime and never
executes the submitted fixture.

## What runs

Only native PE samples already preserved in the case's evidence ZIP are eligible.
The tool checks the archive receipt, member inventory and sample SHA-256 before
sending bytes. Imported findings, model text, URLs and arbitrary filesystem paths
cannot select remote downloads or local execution. Duplicate sample bytes in a
case share an experiment; separate cases do not.

The configured guest receives a file submission with Windows platform, fixed
`drop` network route, no model options and no full-memory dump request. CAPE and
its firewall must actually enforce isolation; requesting a route does not certify
the deployment. Process behavior may differ with blocked network access.

## Configuration when the sandbox is available

Add these settings to `data/private/backend.env` for the Docker API services:

```dotenv
SPECULA_CAPE_ENABLED=true
SPECULA_CAPE_URL=https://cape.example.internal/apiv2
SPECULA_CAPE_TOKEN_FILE=/app/private/cape_token
SPECULA_CAPE_MACHINE=win-lab
SPECULA_CAPE_TIMEOUT=120
SPECULA_CAPE_WAIT_SECONDS=30
SPECULA_CAPE_MAX_SAMPLES=3
```

Put the API token alone in `data/private/cape_token`. The existing read-only
private mount exposes it at `/app/private/cape_token`. Do not commit this file or
put credentials in the URL. HTTPS certificate verification stays enabled. HTTP
is limited to explicitly configured private IP/loopback endpoints or
`host.docker.internal`; named remote hosts require HTTPS. Proxies and redirects
are disabled. The selected machine identifier must match CAPE's task `machine`
and report `info.machine.name`; aliases with different labels require aligning
the CAPE configuration first.

Restart/recreate the API services to load changed environment settings. An
ordinary container restart does not reload Compose env-file contents; use the
existing no-build/no-pull recreation workflow when activating CAPE later.
No new Python package is needed. For a host Python process, set a host token-file
path instead of `/app/private/cape_token`.

Defaults remain disabled. Supported bounds are 10–600 seconds guest timeout,
0–120 seconds polling budget and 1–10 samples per malware-agent invocation.
The polling budget bounds waiting between requests; each HTTP request also has
connect/read timeouts and a 16 MiB decoded response limit. The graph runs this
synchronous tool in its existing background execution thread, not the HTTP event
loop. Queue/processing time can exceed the polling budget.

## Durable tasks and recovery

`cape.sqlite3` lives beside `SPECULA_CHECKPOINT_PATH`, using the same persistent
checkpoint directory. Its case/sample/endpoint/guest/timeout-based UID is claimed
before submission. Task IDs are committed before polling. Reruns reuse the saved
task; changed experiment configuration gets a new identity. Read-only polls may
repeat. Concurrent invocation cannot submit the same experiment twice.

- `deferred`: disabled; static examination only.
- `pending`: submitted, still queued/running/processing, or response/binding
  validation unavailable. No behavioral conclusion is accepted from an invalid
  report. Operation/error codes retain a safe diagnostic without credentials.
- `submission_unknown`: submission outcome uncertain. The connector never
  resubmits automatically; an operator must reconcile the task using its
  `specula:<receipt UID>` custom value in CAPE. Automatic reconciliation is not
  implemented. Do not delete the durable claim to force a retry without checking
  CAPE for an existing task.
- `failed`: CAPE reports analysis/processing/reporting failure.
- `partial`: report accepted but errors, absent coverage fields or projection
  limits remain. The full accepted JSON is still preserved.
- `complete`: report identity and supported projection coverage passed. This
  describes the laboratory examination, not a benign verdict or exhaustive
  detection coverage.

Pending tasks are polled again when the malware specialist executes again, such
as the existing HITL clarification/reanalysis loop. There is no autonomous
background poll after that node returns, and no automatic analyst approval.
Finish or reanalyse pending tasks before approving a final report if their
behavior is material to the case.

## Evidence and presentation

Task metadata and report IDs, custom case binding, sample hash and guest identity
must agree. Raw accepted JSON is retained byte-for-byte in SQLite with SHA-256;
its hash is rechecked on cached use and download. A corrupted cached report is
unavailable, not silently accepted. Store backups must include `cape.sqlite3`.

Receipts retain bounded process, file/registry/mutex, DNS/TCP/UDP/HTTP, signature
and dropped-file observations. Limits and missing fields are explicit. Model
review gets compact cited projections; full retained receipts are in checkpoints
and AgentRun review JSON. Signatures are CAPE-reported detections, not validated
family/actor attribution. Guest times never enter the original-host timeline.
Sandbox facts retain laboratory effect scope and do not inherit the source
host's identity or form host temporal-precedence edges.

Agents displays task state, coverage and a JSON download with browser digest
verification. Both examination reports include sandbox limitations. Incomplete
tasks mark report coverage incomplete. The backend download route is:

```text
GET /api/investigations/{case_id}/sandbox/{receipt_uid}/report
```

It uses existing case read authorization. Local dashboard cases use the matching
`/api/local/cases/{case_id}/sandbox/{receipt_uid}/report` proxy; this does not expose
the CAPE token. No raw report is rendered as HTML or executed as a script.

## Verification and remaining acceptance

```powershell
venv\Scripts\python.exe -m pytest tests/test_cape_sandbox.py -q
```

Contract checks cover real HTTP multipart requests, pending/failed/reported
states, source/case/guest/route identity, interrupted submissions, replay,
concurrency, limits, authenticated downloads and agent scope. Live acceptance
still needs an isolated CAPE instance, a harmless executable control, actual
behavior capture, clean-snapshot restoration and a complete case reanalysis.
Network PCAP, screenshots and dropped binaries are not downloaded by this
connector; their report metadata is retained when supported.

Official sources:
[CAPE v2 routes](https://github.com/kevoreilly/CAPEv2/blob/master/web/apiv2/urls.py),
[v2 response implementation](https://github.com/kevoreilly/CAPEv2/blob/master/web/apiv2/views.py),
[request parameters](https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/common/web_utils.py),
[authentication documentation](https://capev2.readthedocs.io/en/latest/usage/api.html).
The legacy `/tasks/report/...` examples are not the v2 report route.
