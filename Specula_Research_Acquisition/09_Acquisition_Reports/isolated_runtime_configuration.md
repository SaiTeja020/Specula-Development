# Isolated runtime configuration

Date: 11 November 2026. Evidence directory: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01`.
Scope: approved synthetic access-control preflight only. No forensic investigation,
model inference, ingestion, functional smoke test or empirical evaluation was run.
The existing development services, source, evaluator ACLs and original evidence were not changed.


## Identity and immutable inputs

- Runtime: `specula-isolation-canary-20261111-01`, Linux Docker Desktop container,
  ID `14304b75923a756ae9e10c4b32df19c4ad9891a5a1c6f3d25d8fdb58eae44c08`. Docker Engine 29.0.1.
- Intended evaluated OS identity: numeric Linux UID:GID `10001:10001`, supplementary
  groups `[10001]`. `/proc/self/status` confirmed all real/effective/saved IDs 10001,
  permitted/effective capabilities zero and `NoNewPrivs=1`.
- Actual unmodified Specula API child: PID 7, UID 10001. Coordinator host identity:
  `DESKTOP-N08P1L3\DELL`, trusted Docker operator; it is not the evaluated worker.
  No Windows user or group was created and no existing identity was changed.
- Image tag: `specula-isolation-canary:20261111-01`. Pinned local image/index digest:
  `sha256:bf00809a2e299cac191e08996957da0630b56af6f442296e9a9bc14ce62258e3`. No registry push or dependency pull.
- Source commit: `b9b2012edaed8da5062113ddc9982e3c33b27983`. All 164 exported source files matched
  their SHA-256 manifest inside the runtime. No source patches or host source mount.
- Dependency donor: `sha256:51b60fd7b1eba332efcfbbce0eff039bb12b2e31ddefd171ff67f5eca5e58b69`. It was exported
  from a newly created, never-started container. Only Python/libraries/CAs were selected.
  A `FROM scratch` build prevents inheritance of the old `/app`, `.env`, data,
  labels, environment or image layers. `dependency_files.json` records 42,817 tar entries.
- Python actually reported: `3.10.22 (main, Oct  6 2026, 02:05:33) [GCC 14.2.0]`.

## Effective read and write roots

The only host data visible is `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01\fixtures\evidence`, mounted read-only at
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
[
  {
    "Type": "bind",
    "Source": "C:\\Users\\DELL\\Specula-skeleton\\Specula_Research_Acquisition\\09_Acquisition_Reports\\isolation_20261111_run01\\fixtures\\evidence",
    "Destination": "/evidence/agent_evidence",
    "Mode": "",
    "RW": false,
    "Propagation": "rprivate"
  }
]
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
Expiry: `2026-11-11T08:25:47Z`. It is unsuitable
for production and will fail closed after expiry; this receipt does not authorize
refreshing it or starting functional runs. The build's `SecretsUsedInArgOrEnv`
warning refers to the name `SPECULA_AUTH_POLICY_PATH`; its value is a path to this
public test policy, not an evaluator secret. No parent `.env` or backend policy was copied.
Actual environment is recorded in `runtime_receipt.json`; there are no service
credentials, evaluator paths, external model URLs or host proxy variables.

Exact create argv (no shell interpolation or Compose merge):

```json
[
  "docker",
  "create",
  "--name",
  "specula-isolation-canary-20261111-01",
  "--pull=never",
  "--user=10001:10001",
  "--network=none",
  "--read-only",
  "--cap-drop=ALL",
  "--security-opt=no-new-privileges:true",
  "--pids-limit=128",
  "--memory=1g",
  "--cpus=2",
  "--ipc=none",
  "--restart=no",
  "--workdir=/app",
  "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700",
  "--tmpfs=/run/specula:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700",
  "--mount=type=bind,source=C:\\Users\\DELL\\Specula-skeleton\\Specula_Research_Acquisition\\09_Acquisition_Reports\\isolation_20261111_run01\\fixtures\\evidence,target=/evidence/agent_evidence,readonly",
  "specula-isolation-canary:20261111-01"
]
```

## Stored evidence and reuse limits

See `build_command.json`, `build.log`, `image_inspect.json`, both
`container_inspect_*.json`, `create_command.json`, `runtime_receipt.json`,
`image_file_manifest.json`, `image_audit_receipt.json` and `python_path_review.json`
under `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01`. The final image audit hashed 38,425 regular files; no original
answer-bearing assets or restricted markers were found. The two `.pth` files are
coloredlogs' environment-gated auto-install hook and setuptools' distutils shim;
neither contains a host path. No `.env`, old case store or original benchmark repo
was inherited. Dependency vulnerability certification is outside this access audit.

Final state: worker exited (0); donor container created but never started;
no containers running. Both containers and image are retained for review.
Do not restart this profile as a functional evaluation. A model/store network,
new helper service, evidence release, API principal or mount changes this boundary
and requires separate approval and renewed effective-access testing.
