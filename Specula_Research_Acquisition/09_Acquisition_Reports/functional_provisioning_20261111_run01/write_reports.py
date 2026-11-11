"""Report the mandatory admission block; never label unexecuted runtime tests PASS."""
import json,shlex
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
REPORTS=RUN.parent
memory=json.loads((RUN/'memory_admission.json').read_text())
preservation=json.loads((RUN/'preservation_receipt.json').read_text())
assert memory['status']=='BLOCKED' and preservation['status']=='PASS'
def write(name,text):
    with (REPORTS/name).open('x',encoding='utf-8',newline='\n') as stream:stream.write(text)
common=f'''11 November 2026. Approval 1 authorized provisioning and exactly one benign
chat plus one benign embedding request. **OVERALL BLOCKED: memory admission.**
No new runtime was built, created or started; no model request or investigation
was issued. Approval 2 remains ungranted. Audit directory: `{RUN}`.

'''
sample_rows='\n'.join(f"| {i+1} | {x['time_utc']} | {x['MemAvailable_bytes']:,} | {x['MemAvailable_bytes']/1024**2:,.3f} |" for i,x in enumerate(memory['samples']))
caps='\n'.join(f'| {k} | {v:,} |' for k,v in memory['component_caps_MiB'].items())
command_rows='\n'.join('- `'+shlex.join(x['argv'])+'` (exit '+str(x['exit_code'])+')' for x in json.loads((RUN/'command_outputs.json').read_text()))
delta=json.dumps(memory['container_delta_vs_preparation'])
write('functional_runtime_provisioning_report.md','# Functional runtime provisioning report\n\n'+common+f'''
## Admission decision and interpretation

**BLOCKED before allocation.** The approved component limits total
{memory['required_MiB']:,} MiB / {memory['required_bytes']:,} bytes
({memory['required_bytes']/1024**3:.3f} GiB). The lower fresh Docker VM available
reading was {memory['available_bytes']:,} bytes ({memory['available_bytes']/1024**3:.3f} GiB).
The shortfall was {memory['shortfall_bytes']:,} bytes
({memory['shortfall_bytes']/1024**2:.3f} MiB).

The admission rule used the complete approved cap budget against Linux
`MemAvailable`, with no additional reserve and no swap credit. This is a
conservative allocation policy: caps are upper bounds, not measured peak demand.
It does **not** establish that a smaller/subset deployment could not start or
that a model actually failed/OOMed. No service/model was started to test demand.
The blocked claim is specifically that full-budget admission was not satisfied.
No limit was lowered, component omitted, VM setting changed or swap relied on
to get around the user's memory stop condition.

| Sample | UTC | VM MemAvailable bytes | MiB |
| --- | --- | ---: | ---: |
{sample_rows}

Docker's configured/visible total is {memory['docker_engine']['memory_bytes']:,}
bytes and {memory['docker_engine']['cpus']} CPUs. Total memory is not free memory.
VM MemAvailable already accounts for reclaimable cache; cache was not added a
second time. Available swap {memory['samples'][-1]['SwapFree_bytes']:,} bytes
was not counted as RAM. Host WMI observation: total physical
{memory['host_observation_KiB']['TotalVisibleMemorySize']:,} KiB, available/free
physical {memory['host_observation_KiB']['FreePhysicalMemory']:,} KiB. Windows and
VM memory were not added together, which would risk double counting. CPU count
is an inventory fact; no CPU-load/canary-performance suitability was proven.

| Approved component | Cap MiB |
| --- | ---: |
{caps}

## Actual actions and exact commands

Read approved runtime design/checklist, local progress and parent decisions.
Parent progress validator passed: `python -B scripts\\validate_progress.py`
from `C:\\Users\\DELL\\Specula-skeleton` (47 tasks, WIP 2/2, one active).
Acquisition script entrypoints, run from `{ROOT}`:

```powershell
python -B 09_Acquisition_Reports\\functional_provisioning_20261111_run01\\check_admission.py
python -B 09_Acquisition_Reports\\functional_provisioning_20261111_run01\\check_preservation.py
```

Underlying successful read-only admission commands (raw stdout/stderr/exit codes
retained in `command_outputs.json`):

{command_rows}

Additional original-file/ACL reads used Python SHA-256 and PowerShell `Get-Acl`
against the previously retained immutable inventories, plus
`git --no-optional-locks -C .. status --porcelain=v1 -uno` and `rev-parse HEAD`.
No runtime create/build/start/exec/copy, network/volume create, policy application,
model API or service compatibility request was issued.

## Runtime/configuration status

- Project `specula-smoke-20261111-01`: planned name only, **not created**.
- New functional image digest: **not built / unresolved**. Historical candidate
  pins remain in the approved design and preparation `local_image_pins.json`;
  none is misrepresented as a newly provisioned functional image.
- Intended worker UID:GID 10001:10001 and helper UIDs 10011–10019: **not executed**.
  Host coordinator Docker reads ran as DELL; that is not a worker-identity test.
- Effective worker read roots, mounts/mountinfo, namespaces/capabilities and
  listeners: **N/A — no worker/helper exists**. The prepared evidence root was
  not mounted into any new container.
- New container/image/network/volume identifiers: none. New volume IDs `[]`.
  No credentials or model release created. No nft rule or CAP_NET_ADMIN job.
- Existing container ID/state comparison against preparation: `{delta}`.
  Running containers: `[]`. No existing service was changed or stopped.

## Preservation and cleanup

Read-only verification PASS: {preservation['immutable_resource_hashes_verified']:,}
immutable resource hashes; {preservation['mutable_hashes_deferred']} mutable datastore
hashes explicitly deferred; 296 evaluator files and 411 ACL descriptors unchanged;
two model manifests/seven referenced blob entries verified; source ZIP/key,
prepared derivative and four reference copies unchanged.
Parent tracked tree clean at `{preservation['parent_head']}`.
Evidence: `preservation_receipt.json` and `evaluator_acl_check.json`.

Only new audit scripts/receipts, five reports, a progress backup and appended
acquisition progress entries were written. No original implementation, forensic
evidence, evaluator material, permission, service, image or volume was changed.
There is nothing newly started to stop and no rollback of runtime configuration
is needed. Preserve all audit files. No deletion/pruning was performed.

## Resume condition

Recheck resource headroom before allocations. Under this admission policy, VM
MemAvailable must cover the full 10,704 MiB approved budget without swap. The user
may free unrelated resources themselves; this agent did not terminate processes
or change services. If a smaller budget/profile or different memory admission
policy is desired, obtain explicit approval rather than silently changing limits.
Approval 1 itself need not be repeated for an unchanged approved design once its
mandatory admission conditions are met. Approval 2 remains separately required.
''')
write('functional_isolation_results.md','# Functional isolation results\n\n'+common+'''
## Result matrix

| Gate | Result | Actual evidence / reason |
| --- | --- | --- |
| Resource admission | BLOCKED | Full approved cap budget exceeds two fresh VM MemAvailable readings; memory_admission.json |
| Original resource/source/evaluator preservation | PASS | Preservation receipt records actual file hashes, current ACL comparisons and clean parent tracked tree |
| Existing runtime preservation | PASS for observed containers | IDs/states unchanged; zero running containers; no mutating runtime command issued |
| Effective worker/helper UID/GID | BLOCKED / NOT RUN | No new worker/helper process exists; proposed identities are not observations |
| Private PID/mount/net namespaces, zero capabilities | BLOCKED / NOT RUN | No new runtime to inspect |
| Effective Docker mount configuration/mountinfo | BLOCKED / NOT RUN | No new bind/volume mounted; planned evidence-only bind is not an effective-access result |
| nft policy load and counters | BLOCKED / NOT RUN | No namespace or one-shot initializer created, no rule applied |
| Required service connectivity as worker | BLOCKED / NOT RUN | No service or worker start |
| Forbidden host/filesystem/service access | BLOCKED / NOT RUN | No actual worker available for negative probes |
| Direct Ollama port 11435 denial | BLOCKED / NOT RUN | Planned restriction not installed or tested |
| Actual tool/API authentication and case grants | BLOCKED / NOT RUN | No new policy, credential or API process |
| Fresh-store contents / retrieval/index leakage | BLOCKED / NOT RUN | No fresh datastore/volume exists; absence of a store is not a successful content audit |
| Image filesystem/layer scan | BLOCKED / NOT RUN | New image not built; no new hidden-path/key/mapping assertion |
| Prompt/response/log/temp leakage | BLOCKED / NOT RUN | No gateway/model execution or transcripts to scan |
| Original evidence integrity | PASS | Original ZIP/key, derivative and reference copy hashes rechecked |
| Eight-record investigation | NOT AUTHORIZED / NOT RUN | No intake, normalization, graph request, scoring or HITL decision |

The prior accepted synthetic isolation PASS belongs only to its historical exact
configuration. It has not been promoted to a PASS for a new service topology.
No prohibited access was observed because the required worker tests were not
executed; that fact cannot be called denied effective access.

## Failures and unresolved boundaries

Severity **BLOCKER**: memory admission fails the conservative full-approved-budget
check. No actual service crash or security-boundary failure was induced. All
expanded isolation boundaries remain unverified and therefore BLOCKED, rather
than assumed safe from source review or folder names.

Effective identities, mountinfo, namespace handles, capability fields, nft rule
handles/counters, allowed/denied probe outputs and store/label scans have no new
runtime values to report. The proposed values remain documented in
functional_runtime_design.md and functional_isolation_test_plan.md.

After admission succeeds under approved policy, execute those tests from actual
UID10001 and inspect each helper independently. Do not enable broader privileges,
reuse development stores or skip model-port denial to make a gate green.
''')
write('model_gateway_validation.md','# Model gateway validation\n\n'+common+f'''
## Gateway and canary status

**BLOCKED / NOT IMPLEMENTED OR EXECUTED in this provisioning attempt.** The
mandatory admission stop preceded image/helper work. No gateway process, listener,
counter store, capture volume, model release, new credential or model exchange exists.
Only the earlier proposed gateway contract is available; it is not a tested relay.

| Required validation | Result |
| --- | --- |
| GET tags/version; POST chat/embed exact route allowlist | BLOCKED / NOT RUN |
| Arbitrary URL, redirect and unauthorized model-operation rejection | BLOCKED / NOT RUN |
| Exact local model and digest enforcement | BLOCKED / NOT RUN at live API |
| Complete request/response bytes, hashes and execution metadata | BLOCKED / no exchange |
| Chat/embed counters, non-reset behavior and fail-closed limits | BLOCKED / NOT RUN |
| 8 MiB request, 32 MiB response limits and 300s deadline | BLOCKED / NOT RUN |
| Worker bypass resistance at port 11435 | BLOCKED / NOT RUN |
| Gateway-only fixed upstream access | BLOCKED / NOT RUN |
| One harmless chat | NOT RUN; zero requests, no retry/model substitution |
| One harmless embedding | NOT RUN; zero requests, no retry/model substitution |

## Model inventory facts, separately verified

The preserved local cache manifests and all seven referenced config/layer blobs
passed SHA-256 and size checks during this attempt. This is static integrity,
not serving readiness or a live-model result.

| Intended canary | Cached manifest SHA-256 | Live status/dimension |
| --- | --- | --- |
| qwen3:8b chat | 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41 | NOT REQUESTED |
| qwen3-embedding:0.6b embed | ac6da0dfba84a81fdbfbaf330198c33cd77c4cdfc53e8bc50eb581914a15621d | NOT REQUESTED / dimension unresolved |

Candidate Ollama software pin remains the previously inspected
`ollama/ollama@sha256:6c76395793f40a5e78f120e880ca82c67e39eb908ad90eee8ce755535529d0ec`.
No new live version, API digest, request hash, response hash, status code,
generation timing, token measurement, output or embedding vector was produced.
Those fields are **N/A**, not empty successful values or synthetic measurements.

Model canary authorization remains bounded to exactly one benign chat and one
benign embed under the approved configuration. Once resource admission and
security tests permit execution, count the first actual request and do not retry
a failed canary. Never send the forensic package, expected labels or keys.
Audit evidence: `{RUN}\\preservation_receipt.json`, plus the original static
`functional_smoke_preparation_20261111_run01/local_model_pins.json`.
''')
write('service_compatibility_report.md','# Service compatibility report\n\n'+common+'''
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
''')
write('functional_smoke_readiness_decision.md','# Functional smoke readiness decision\n\n'+common+f'''
## Recommendation for Approval 2

**NO-GO. Approval 1 provisioning is BLOCKED at resource admission.**
Approval 2 should not be granted on the basis of this attempt: the expanded
runtime has not been provisioned or effectively tested. No inference or forensic
investigation occurred. Preparation documents remain designs, and the accepted
old synthetic preflight retains only its original scope.

| Gate | Decision |
| --- | --- |
| Resource integrity and parent-source preservation | PASS within recorded immutable scope; 31 mutable hashes deferred |
| Full approved-budget memory admission | BLOCKED: {memory['required_bytes']:,} required vs {memory['available_bytes']:,} available bytes |
| New worker/helper identities, namespaces, mounts, zero caps | BLOCKED / NOT RUN |
| Effective nft rules, allowed/denied services and 11435 denial | BLOCKED / NOT RUN |
| Bounded gateway/capture/abuse/bypass validation | BLOCKED / NOT RUN |
| Fresh service compatibility/empty-store/PDF/API initialization | BLOCKED / NOT RUN |
| One chat and one embedding canary | BLOCKED / both NOT RUN |
| Functional case execution | NO-GO / Approval 2 not granted |
| Empirical evaluation | NO-GO / not in scope |

## Blocker severity and remedy

Severity **BLOCKER**: conservative admission requires the approved 10,704 MiB
combined service caps to fit available VM RAM. Both observed samples fell short;
the lower reading gives a {memory['shortfall_bytes']/1024**2:.3f} MiB gap. This
budget check is not a measurement of actual service peaks or an observed OOM.
Swap and configured total RAM were not substituted for available RAM.

To resume the unchanged approved design, make adequate memory available and
rerun admission immediately before allocation. The agent has not stopped any
unrelated service/process, changed host/VM memory or freed/pruned data. A revised
component budget, subset architecture or less-conservative admission policy
requires explicit approval; none was silently selected.

After admission succeeds, Approval 1 already covers its authorized provisioning
scope: implement/build the reviewed helpers and fresh stack, prove effective
isolation/compatibility, execute exactly the two approved canaries without retry,
and stop the new services. Only then revisit a GO recommendation for Approval 2.
No new approval is requested merely to repeat authorized read-only checks.

## Audit records and final state

Five requested reports are in `{REPORTS}`. Raw command outputs,
memory_admission.json, preservation_receipt.json, evaluator_acl_check.json,
progress backup and artifact checksums are under `{RUN}`.
New volume/container/network identifiers: **none created**; retained new IDs `[]`.
No newly started service requires stopping, and no cleanup/deletion was performed.
All existing observed container IDs/states remained unchanged; running list empty.
Existing evaluator ACLs, original evidence/answers/mappings and Specula source
were preserved. No credentials or model release were generated/exposed.

The preservation/reporting oracle may PASS while provisioning remains BLOCKED:
such a PASS verifies only accurate blocked reporting and unchanged assets. It is
not a passed service, canary, gateway, functional smoke or empirical result.
''')
print(json.dumps({'reports_created':5,'provisioning':'BLOCKED','approval_2':'NO-GO','model_requests':0,'new_runtime_objects':0}))
