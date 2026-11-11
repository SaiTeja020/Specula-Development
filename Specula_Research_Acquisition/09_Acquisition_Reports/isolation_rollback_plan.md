# Isolation rollback plan

Date: 11 November 2026. Evidence directory: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01`.
Scope: approved synthetic access-control preflight only. No forensic investigation,
model inference, ingestion, functional smoke test or empirical evaluation was run.
The existing development services, source, evaluator ACLs and original evidence were not changed.


## Current state and safe rollback

No rollback action is required to stop execution: worker is already exited (0),
dependency export container was never started, and no containers are running.
All pre-existing services/configuration/ACLs remain as before.

If the new worker is found running later, inspect it by exact name and confirm
its ID matches `14304b75923a756ae9e10c4b32df19c4ad9891a5a1c6f3d25d8fdb58eae44c08` before stopping ONLY that container:

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
- New image: `specula-isolation-canary:20261111-01` at `sha256:bf00809a2e299cac191e08996957da0630b56af6f442296e9a9bc14ce62258e3`; local build cache/attestation.
- New workspace: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01`, including build tar/context, synthetic fixtures and
  the unmounted rejected junction. These fixtures contain no original secrets.
- Five requested Markdown reports in `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports` and local progress audit entries.

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
