# Isolation change log

Date: 11 November 2026. Evidence directory: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01`.
Scope: approved synthetic access-control preflight only. No forensic investigation,
model inference, ingestion, functional smoke test or empirical evaluation was run.
The existing development services, source, evaluator ACLs and original evidence were not changed.


## Authorization and observed changes

The user's approved isolated-runtime provisioning instruction superseded the
earlier approval-pending status only for synthetic bounded isolation work.
Read the prior security plan, post-remediation verification and protocol draft
before provisioning; those historical reports and the protocol remain unchanged.

1. Captured parent HEAD/tracked status, evaluator hashes and the previous ACL
   baseline. Preserved local `PROGRESS.md` at `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01\PROGRESS.before.md`.
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
5. Built `specula-isolation-canary:20261111-01` with `FROM scratch`, no package installation,
   no network build access or pulled base. Image digest `sha256:bf00809a2e299cac191e08996957da0630b56af6f442296e9a9bc14ce62258e3`.
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
python -B 09_Acquisition_Reports\isolation_20261111_run01\verify.py
```

Run from `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition`. It creates a new timestamped receipt and never rewrites old ones.
The parent progress oracle, run from `C:\Users\DELL\Specula-skeleton`, was also PASS:
`python -B scripts\validate_progress.py` (47 tasks, occupied WIP 2/2, one active).
Two mixed-working-directory verification attempts failed to locate files; corrected
explicit-workspace invocations passed. They caused no source or service changes.
Initial and strengthened successful receipts are retained as separate history.
