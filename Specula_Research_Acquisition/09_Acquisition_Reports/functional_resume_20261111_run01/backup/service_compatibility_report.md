# Service compatibility report

11 November 2026. Approval 1 authorized provisioning and exactly one benign
chat plus one benign embedding request. **OVERALL BLOCKED: memory admission.**
No new runtime was built, created or started; no model request or investigation
was issued. Approval 2 remains ungranted. Audit directory: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_provisioning_20261111_run01`.


## Compatibility matrix

| Component | Intended identity | Actual startup/compatibility result |
| --- | --- | --- |
| Functional worker / actual Specula API | 10001:10001 | BLOCKED / new image not built, imports/initialization not run |
| PDF / ReportLab runtime | same worker | BLOCKED / no new runtime import or PDF render check |
| Ollama | 10011:10011 | BLOCKED / no startup, version/tags or inference check |
| Neo4j | 10012:10012 | BLOCKED / no fresh data volume, identity or Bolt/schema check |
| Kafka KRaft | 10013:10013 | BLOCKED / no broker/controller, ownership or acknowledgment check |
| Chroma | 10014:10014 | BLOCKED / no server/client/vector shape check |
| Quickwit | 10015:10015 | BLOCKED / no metastore/index/config/REST check |
| Redis | 10016:10016 | BLOCKED / no server/scratchpad check |
| Capture gateway | 10017:10017 | BLOCKED / implementation and validation not started |
| Coordinator | 10018:10018 | BLOCKED / no credentials or API role checks |
| Namespace anchor | 10019:10019 | BLOCKED / no namespace/container created |
| nft one-shot initializer | namespace-only approved exception | BLOCKED / never executed; no CAP_NET_ADMIN process started |
| SQLite checkpoints / DuckDB analytics | 10001:10001 | BLOCKED / no fresh storage or write/read/restart check |

Candidate software digests are recorded in the approved runtime design and static
local_image_pins.json. They are inspected local assets, not new effective runtime
image digests. Binary versions for the new Chroma/Quickwit/API deployment remain
unmeasured. No existing development datastore was queried to simulate a fresh one.

## Verified preservation facts

Parent HEAD remains b9b2012edaed8da5062113ddc9982e3c33b27983; tracked status empty.
Original resource/evaluator/source/model hashes and ACL comparisons passed as
recorded in preservation_receipt.json. No application-source change, installation,
identity fallback, root service, host ACL change or service reconfiguration occurred.
The old synthetic preflight's API startup is historical evidence only and does
not establish initialization of the expanded functional image.

## Required next compatibility checks

After memory admission passes, build from approved inputs, then verify every
proposed non-root entrypoint and fresh writable path before enabling a workload.
Validate actual source imports/PDF dependency, model tag digests, embedded-schema
Kafka path, Chroma/Neo4j/Quickwit client compatibility and empty persistent stores.
Record actual IDs/capabilities/namespaces/mountinfo. Stop BLOCKED on startup errors
requiring root/privileged fallback or unapproved source/package changes.

No initialized store is claimed empty in this report: no fresh store exists yet.
No case was created, ingested, indexed, investigated or resumed.
