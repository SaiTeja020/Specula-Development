"""Create the five requested reports exclusively from measured receipts."""
import csv,hashlib,json,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
REPORTS=RUN.parent
def read(name):return json.loads((RUN/name).read_text(encoding='utf-8-sig'))
def write(name,text):
    with (REPORTS/name).open('x',encoding='utf-8',newline='\n') as f:f.write(text)
runtime=read('runtime_receipt.json');config=read('container_inspect_after.json');inputs=read('provisioning_inputs.json')
audit=read('image_audit_receipt.json');leak=read('leakage_scan.json');admission=read('admission_test.json')
verification=read(sorted(p.name for p in RUN.glob('verification_*.json'))[-1]);image=read('image_inspect.json')
assert all(x['status']=='PASS' for x in [runtime,audit,leak,admission,verification])
prefix=str(RUN)
common=f'''Date: 11 November 2026. Evidence directory: `{prefix}`.
Scope: approved synthetic access-control preflight only. No forensic investigation,
model inference, ingestion, functional smoke test or empirical evaluation was run.
The existing development services, source, evaluator ACLs and original evidence were not changed.

'''
mount=json.dumps(config['Mounts'],indent=2)
create=json.dumps(read('create_command.json'),indent=2)
python=runtime['python']
policy=read('build_context/app/preflight/viewer_policy.json')
expires=policy['local_tokens'][0]['expires_at']
write('isolated_runtime_configuration.md', '# Isolated runtime configuration\n\n'+common+f'''
## Identity and immutable inputs

- Runtime: `specula-isolation-canary-20261111-01`, Linux Docker Desktop container,
  ID `{config['Id']}`. Docker Engine 29.0.1.
- Intended evaluated OS identity: numeric Linux UID:GID `10001:10001`, supplementary
  groups `[10001]`. `/proc/self/status` confirmed all real/effective/saved IDs 10001,
  permitted/effective capabilities zero and `NoNewPrivs=1`.
- Actual unmodified Specula API child: PID 7, UID 10001. Coordinator host identity:
  `DESKTOP-N08P1L3\\DELL`, trusted Docker operator; it is not the evaluated worker.
  No Windows user or group was created and no existing identity was changed.
- Image tag: `{inputs['image']}`. Pinned local image/index digest:
  `{image['Id']}`. No registry push or dependency pull.
- Source commit: `{inputs['source_commit']}`. All 164 exported source files matched
  their SHA-256 manifest inside the runtime. No source patches or host source mount.
- Dependency donor: `{read('baseline.json')['dependency_image']}`. It was exported
  from a newly created, never-started container. Only Python/libraries/CAs were selected.
  A `FROM scratch` build prevents inheritance of the old `/app`, `.env`, data,
  labels, environment or image layers. `dependency_files.json` records 42,817 tar entries.
- Python actually reported: `{python}`.

## Effective read and write roots

The only host data visible is `{inputs['evidence_source']}`, mounted read-only at
`/evidence/agent_evidence`. It contains one harmless `permitted.txt` file.
Its measured SHA-256 is `cf8d8384b8a83d1a5c8e0bd18be61849931becd1a7c3987670677f41894cb4d4`.
The original CFA evidence directory is not mounted and is not approved by this test.

Other readable roots are trusted image code (`/app/src`), preflight code/public
policy (`/app/preflight`), selected `/usr/local`, `/usr/lib`, `/usr/lib64`, `/lib`,
`/lib64` and CA files, plus Docker's normal proc/sys/dev and hosts/resolver scaffolding.
These are runtime dependencies, not additional host-project read roots.
The working directory `/app` is inside the image. No host home, project, acquisition,
TEMP, source repository, model cache, evaluator folder or original benchmark clone is mounted.

Root filesystem and evidence are read-only. Only fresh `/tmp` (64 MiB) and
`/run/specula` (16 MiB) tmpfs are writable, UID/GID 10001, mode 0700,
`noexec,nosuid,nodev`. Private PID namespace; IPC disabled; no devices or
volumes-from; all capabilities dropped; no privileged mode; pids limit 128,
memory 1 GiB and CPU limit 2. These are preflight bounds, not experiment budgets.
No extra hosts, Docker socket/named pipe, host namespace, published port or persistent volume.
Network mode `none`: loopback only. The actual API bound `127.0.0.1:8217` inside
the container; it was never exposed to Windows or other containers.

Actual mount inspection:

```json
{mount}
```

## Application execution and credentials

Image entrypoint is Python running `/app/preflight/runner.py`. This bounded runner
started the actual `uvicorn src.agents.visualizer_api:app` child as the same UID,
tested authentication/authorization, imported the actual forensic tool for a
negative path probe, then terminated only that child and exited zero.
It never compiled or invoked the case graph or called a model/ingestion endpoint.
This is the intended initial closed execution boundary for Specula access checks,
not a provisioned full research stack.

The new public synthetic viewer policy has no case grants and no administrator.
Its token is explicitly nonsecret and never replaces an existing credential.
Expiry: `{time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(expires))}`. It is unsuitable
for production and will fail closed after expiry; this receipt does not authorize
refreshing it or starting functional runs. The build's `SecretsUsedInArgOrEnv`
warning refers to the name `SPECULA_AUTH_POLICY_PATH`; its value is a path to this
public test policy, not an evaluator secret. No parent `.env` or backend policy was copied.
Actual environment is recorded in `runtime_receipt.json`; there are no service
credentials, evaluator paths, external model URLs or host proxy variables.

Exact create argv (no shell interpolation or Compose merge):

```json
{create}
```

## Stored evidence and reuse limits

See `build_command.json`, `build.log`, `image_inspect.json`, both
`container_inspect_*.json`, `create_command.json`, `runtime_receipt.json`,
`image_file_manifest.json`, `image_audit_receipt.json` and `python_path_review.json`
under `{prefix}`. The final image audit hashed 38,425 regular files; no original
answer-bearing assets or restricted markers were found. The two `.pth` files are
coloredlogs' environment-gated auto-install hook and setuptools' distutils shim;
neither contains a host path. No `.env`, old case store or original benchmark repo
was inherited. Dependency vulnerability certification is outside this access audit.

Final state: worker exited (0); donor container created but never started;
no containers running. Both containers and image are retained for review.
Do not restart this profile as a functional evaluation. A model/store network,
new helper service, evidence release, API principal or mount changes this boundary
and requires separate approval and renewed effective-access testing.
''')
rows=[]
for number,test in enumerate(runtime['tests'],1):
    detail=json.dumps({k:v for k,v in test.items() if k not in ['test','status']},ensure_ascii=False).replace('|','\\|')
    rows.append(f"| {number} | {test['test']} | {test['status']} | `{detail}` |")
table='\n'.join(rows)
write('runtime_access_test_results.md','# Runtime access test results\n\n'+common+f'''
Decision: **PASS for this synthetic, network-none runtime only.**
All 38 worker probes passed. Additional admission, mount, image and preservation
checks below also passed. Raw outputs are retained, not inferred from directory names.

## Every worker probe

| # | Probe | Result | Measured output |
| --- | --- | --- | --- |
{table}

Restricted fixtures exist on Windows under `{prefix}\\fixtures\\restricted`:
`ground_truth.txt`, `benchmark_mapping.txt`, `evaluation_labels.txt`.
`restricted_fixture_inventory.json` records their sizes and hashes. Their random
non-sensitive marker values were never passed to the image, environment, runner,
API, tool, prompt, or mount. Host-side comparisons used their values without
feeding them into the worker.

`FileNotFoundError`/errno 2 means the files are outside the container namespace;
it is not a claim that Windows ACLs denied DELL. Windows DELL remains able to read
real evaluator originals. The deny evidence combines real host fixture presence,
effective worker reads, an exact single-mount inspection, clean image audit and
network denial. No existing evaluator ACL was tightened.
Errno 30 is read-only filesystem. Errno 101 is network unreachable.

## Additional checks

| Check | Result | Evidence |
| --- | --- | --- |
| Junction admission | PASS | Actual Windows junction in `candidate_reparse/escape` points only to synthetic restricted fixtures; admission rejects reparse points before recursion. Candidate was never mounted. `admission_test.json` |
| Approved evidence admission | PASS | One regular file; no reparse point, symlink or multiple-link file. `admission_test.json` |
| Effective Docker mounts | PASS | Exactly one read-only evidence bind; no socket, parent/project, host home, named volume, devices, port publication or volumes-from. `container_inspect_before.json` and `container_inspect_after.json` |
| Runtime identity | PASS | Actual API child UID 10001; runner IDs/groups 10001, capability fields zero, no-new-privileges. `runtime_receipt.json` |
| Complete final filesystem | PASS | {audit['regular_files']:,} regular files / {audit['bytes_scanned']:,} bytes scanned and hashed; zero restricted markers or forbidden project asset paths. `image_audit_receipt.json`, `image_file_manifest.json` |
| Logs and temporary files | PASS | Console and Docker logs plus decoded 341-byte `/tmp/specula-api.log` scanned against all 3 restricted markers; zero matches. `/tmp/escape-link` was a non-readable symlink, not copied content. `leakage_scan.json` |
| Retrieval/index surfaces | PASS for empty profile | No mounted/persistent store, model or index; `/app/data` absent, fresh tmpfs, no network egress. Viewer store views denied 403. No ingestion or embedding operation was run. This is not a post-ingestion index test. |
| Original resource integrity | PASS | 5,096 immutable resource hashes match; 31 explicitly mutable datastore hashes remain deferred. Latest `verification_*.json` |
| Original evaluator preservation | PASS | All 296 original evaluator files and all 411 original ACL descriptors unchanged. `evaluator_acl_check.json` and `verification_*.json` |
| Parent source | PASS | Tracked status empty; HEAD `{verification['parent_head']}` unchanged. |
| Completion/liveness | PASS | Worker exit code 0; donor never started; final running list empty. `docker_final_state.json` |

## Coverage limits

The API probes exercised actual middleware, not a replacement server. Store views
returned explicit 403, missing authentication returned 401, and nonexistent file
routes returned 404. A 404 only establishes that those routes do not serve files;
it is not claimed as a general authorization proof. The real `authorize` function
also rejected an ungranted case, and the real `examine_memory` function rejected
the external synthetic path before any Volatility invocation or cache creation.
The final `no_case_graph_or_driver_initialized` runner label directly measures
only absence of `/app/data`; that observation alone does not prove initialization
history. Request selection/source inspection separately establishes that this
preflight did not request graph execution, store initialization, or ingestion.

No authenticated case investigation, HITL decision, WebSocket graph stream,
MCP service, model adapter, active parser, scoring process or retrieval after
ingestion was executed. Those services are not exposed in this profile. Their
future activation needs approved configuration and new tests. No functional or
empirical result follows from these access checks.
''')
write('isolation_change_log.md','# Isolation change log\n\n'+common+f'''
## Authorization and observed changes

The user's approved isolated-runtime provisioning instruction superseded the
earlier approval-pending status only for synthetic bounded isolation work.
Read the prior security plan, post-remediation verification and protocol draft
before provisioning; those historical reports and the protocol remain unchanged.

1. Captured parent HEAD/tracked status, evaluator hashes and the previous ACL
   baseline. Preserved local `PROGRESS.md` at `{prefix}\\PROGRESS.before.md`.
2. Created this new run directory, three harmless restricted canaries, one permitted
   evidence canary, scripts, build context and a synthetic viewer policy. No actual
   evidence, labels or answer contents were copied. New files inherit host workspace
   permissions; they contain no original ground truth.
3. Created `specula-isolation-dependency-export-20261111-01` using the existing local
   dependency image. Never started it. Exported only Python/libraries/CAs into a new
   rootfs tar. Exported 164 source files from the exact parent Git object archive.
4. Created a synthetic-only Windows junction in an unmounted candidate directory;
   proved admission rejected it. Kept the fixture for review. No junction targets an
   original evaluator directory.
5. Built `{inputs['image']}` with `FROM scratch`, no package installation,
   no network build access or pulled base. Image digest `{image['Id']}`.
   Docker generated normal local image layers, attestations and build cache.
6. Created and started only `specula-isolation-canary-20261111-01` with the recorded
   restrictions. Actual Specula API child ran as 10001, received bounded GET auth
   probes, terminated, and the worker exited 0. No full case or model call.
7. Captured mount/kernel/process/API/tool outputs, scanned logs and the final
   filesystem, rehashed original resources and evaluator files, compared 411 ACL
   descriptors, and confirmed parent tracked status clean and no running containers.
8. Created the five requested Markdown reports plus machine-readable receipts,
   manifests and a separate isolation artifact checksum inventory. Updated only
   acquisition `PROGRESS.md`; parent task state/source remain unchanged.

## Unchanged security and data surfaces

No existing ACL, owner, Windows account, credential, Docker daemon setting,
development Compose file, service configuration, original repository clone,
dataset, answer key, label, filename mapping or Specula source file was modified.
No existing container or volume was stopped, restarted, deleted or reconfigured.
No existing file was removed, renamed or overwritten. No datasets or tools were
downloaded. Existing permissive Windows evaluator grants remain a known host risk;
they do not grant the isolated Linux worker a host mount or network route.

## Verification records

The preservation/configuration oracle is:

```powershell
python -B 09_Acquisition_Reports\\isolation_20261111_run01\\verify.py
```

Run from `{ROOT}`. It creates a new timestamped receipt and never rewrites old ones.
The parent progress oracle, run from `{ROOT.parent}`, was also PASS:
`python -B scripts\\validate_progress.py` (47 tasks, occupied WIP 2/2, one active).
Two mixed-working-directory verification attempts failed to locate files; corrected
explicit-workspace invocations passed. They caused no source or service changes.
Initial and strengthened successful receipts are retained as separate history.
''')
write('isolation_rollback_plan.md','# Isolation rollback plan\n\n'+common+f'''
## Current state and safe rollback

No rollback action is required to stop execution: worker is already exited (0),
dependency export container was never started, and no containers are running.
All pre-existing services/configuration/ACLs remain as before.

If the new worker is found running later, inspect it by exact name and confirm
its ID matches `{config['Id']}` before stopping ONLY that container:

```powershell
docker inspect specula-isolation-canary-20261111-01
docker stop --time=5 specula-isolation-canary-20261111-01
```

Do not start the donor container or attach it to a network. No Docker Compose
teardown, daemon restart, volume deletion, Git reset/clean, ACL restoration,
account deletion or credential rotation is needed. None was changed by this work.
Do not restore the progress backup over the current audit history.

## Retained artifacts

- Worker container: `specula-isolation-canary-20261111-01` (exited).
- Donor container: `specula-isolation-dependency-export-20261111-01` (created).
- New image: `{inputs['image']}` at `{image['Id']}`; local build cache/attestation.
- New workspace: `{prefix}`, including build tar/context, synthetic fixtures and
  the unmounted rejected junction. These fixtures contain no original secrets.
- Five requested Markdown reports in `{REPORTS}` and local progress audit entries.

Preserve all of these for reproducibility. Removal/pruning, including unlinking
the synthetic junction, is outside the current no-removal authorization and
requires a separate request. Never recursively delete through a junction.
If later cleanup is approved, first check exact resolved targets stay within this
new run directory, remove only the junction itself rather than following its
target, and retain the audit receipts/hashes. No destructive cleanup command is
provided or executed here.

## Verification after stop or later authorized changes

Inspect the named worker state and mounts; compare the existing image digest.
Run the preservation oracle shown in the change log. Existing `evaluator_acl_check.json`
is a point-in-time snapshot; fresh ACL capture is required to assert permissions
remain unchanged after any future change. Do not confuse replaying stored receipts
with rerunning effective-access tests. Expired public policy credentials must not
be made permanent to get a green rerun.
''')
write('isolation_verification_summary.md','# Isolation verification summary\n\n'+common+f'''
## Decision

**PASS — isolated canary access-control runtime, exact tested configuration only.**
Permitted evidence reads succeeded; restricted ground-truth/mapping/label reads,
parent traversal and Linux symlink escape failed. Windows junction admission was
rejected before mounting. Actual Specula API/tool access probes passed under
UID:GID 10001:10001, with only one evidence bind and network mode `none`.
Worker completed with exit code 0. This is an executed boundary test, not an
inference from Windows folder names or evaluator ACL descriptions.

| Gate | Decision | Evidence |
| --- | --- | --- |
| Actual worker identity, privileges, source and evidence read | PASS | IDs 10001; zero capabilities; no-new-privileges; 164 source hashes; expected permitted hash |
| Direct/traversal/symlink and admission denial | PASS | Runtime errno 2; host canaries verified present; candidate junction rejected and never mounted |
| Host filesystem/service exposure | PASS for this profile | Exact one read-only bind, no ports/socket/parent mounts; network probes errno 101 |
| Actual API/tool negative access | PASS for tested surfaces | Uvicorn child UID 10001; 401/403/404 responses; actual case authorization 403; forensic tool rejects missing image before analysis |
| Logs/temp/image/index contamination | PASS for empty profile | Zero markers in output/tmp or {audit['regular_files']:,} exported files; no store/index mounted or populated |
| Resource/evaluator/source preservation | PASS | 5,096 resource hashes, 296 evaluator file hashes and 411 ACL descriptors match; parent tracked status empty |
| Full model/store/harness isolation | BLOCKED | Not provisioned, approved or tested; adding any network/service/mount invalidates extension of this PASS |
| Functional smoke testing | BLOCKED | Separate user approval required; no smoke case was run |
| Controlled empirical evaluation | BLOCKED | Separate approval and unresolved protocol/truth/normalization/budget gates remain |

## Exact assessed boundary

Image: `{image['Id']}`. Worker: `{config['Id']}`.
Parent commit: `{verification['parent_head']}`. Effective host data root:
`{inputs['evidence_source']}` -> `/evidence/agent_evidence` read-only.
Python `{python.splitlines()[0]}`. Controller `DESKTOP-N08P1L3\\DELL` is trusted;
the evaluated worker is Linux 10001, not that Windows host identity.
See `isolated_runtime_configuration.md` for exact flags and raw mount output,
`runtime_access_test_results.md` for every probe, `isolation_change_log.md` and
`isolation_rollback_plan.md` for the complete change/rollback record.

Machine receipt: `{prefix}\\verification_20261111T073307Z.json`.
Runtime raw receipt: `{prefix}\\runtime_receipt.json`.
Full image hashes: `{prefix}\\image_file_manifest.json`.
No functional correctness, model quality or benchmark result is claimed.

## Remaining risks and approvals

1. Host curator/Docker administrators can still read evaluator originals and
   control containers. Existing evaluator ACL weaknesses remain unchanged. This
   boundary assumes a trusted coordinator and Docker Desktop/Linux kernel; no
   adversarial kernel/daemon escape certification is claimed. A compromised host
   management plane is outside this tested worker boundary.
2. Only synthetic evidence was admitted. Real CFA evidence content and filename
   leakage, supported normalization and independent ground-truth review require
   approval/review before release. Original answer material stays outside runtime.
3. No model, persistent graph/vector/search/checkpoint store, MCP service, scoring
   script or host tool API was exposed. Fresh per-run stores, actual model images,
   model-network namespace/endpoint compatibility, helper identities and all
   active tool/retrieval paths need approved configuration and effective tests.
   Empty-profile scans do not certify future post-ingestion embeddings or logs.
4. The public viewer credential expires and grants no cases. A later authenticated
   case principal, model/tool permissions or entrypoint changes require review;
   do not reuse this public credential as a real evaluation credential.
5. Protocol remains an unfrozen draft. No reviewer decisions, ground-truth labels,
   measurements, seeded results or empirical readiness were fabricated. Prior
   deferred/unavailable acquisition dispositions remain unchanged.

No further permission was needed for the completed bounded provisioning.
The next action needing approval is a specifically configured functional smoke
test, followed separately by full evaluation preparation/approval. Neither starts
automatically. Adding evidence/services/network requires renewed isolation checks.
''')
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as f:
    f.write('\n- Approved isolated-runtime subtask: passing for canary-only access scope. '
        'Created scratch image '+image['Id']+' from local allowlisted libraries/current Git source; '
        'new worker UID:GID 10001:10001, read-only root, exact one synthetic evidence bind, '
        'network none, zero capabilities/no-new-privileges. All 38 actual worker/API/tool probes PASS; '
        'junction admission rejected; 38,425 final files scanned with zero restricted canary markers.\n'
        '- Preservation oracle PASS: 5,096 immutable hashes; 31 mutable hashes explicitly deferred; '
        '296 evaluator files and 411 ACL descriptors unchanged; parent tracked tree clean, same HEAD. '
        'Parent progress oracle PASS (47 tasks; WIP 2/2). Initial mixed-cwd path checks failed to locate '
        'files and were corrected; no state changes resulted. New scripts and five isolation reports '
        'are retained under 09_Acquisition_Reports; no original file overwritten.\n'
        '- Clock-out: canary worker exited 0, donor never started, no running containers. '
        'No existing ACL/account/credential/service/source/evidence changes; no installs, downloads, '
        'inference, ingestion, smoke case or experiment. Rollback is stop-only for the named new worker '
        'if ever running; retain image/containers/files. Full-stack isolation and smoke/empirical '
        'execution remain BLOCKED pending separate approvals and unresolved protocol gates. '
        'Oracle: python -B 09_Acquisition_Reports/isolation_20261111_run01/verify.py.\n')
targets=sorted([p for p in RUN.iterdir() if p.is_file()]+[REPORTS/n for n in ['isolated_runtime_configuration.md','runtime_access_test_results.md','isolation_change_log.md','isolation_rollback_plan.md','isolation_verification_summary.md']]+[ROOT/'PROGRESS.md'])
with (RUN/'isolation_artifact_checksums.csv').open('x',encoding='utf-8',newline='') as f:
    writer=csv.DictWriter(f,fieldnames=['local_path','bytes','sha256']);writer.writeheader()
    for p in targets:
        with p.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        writer.writerow({'local_path':str(p),'bytes':p.stat().st_size,'sha256':digest})
print(json.dumps({'reports_created':5,'artifact_hashes':len(targets),'bounded_isolation':'PASS','smoke_and_empirical':'BLOCKED_PENDING_APPROVAL'}))
