# Functional runtime provisioning report

11 November 2026. Approval 1 authorized provisioning and exactly one benign
chat plus one benign embedding request. **OVERALL BLOCKED: memory admission.**
No new runtime was built, created or started; no model request or investigation
was issued. Approval 2 remains ungranted. Audit directory: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_provisioning_20261111_run01`.


## Admission decision and interpretation

**BLOCKED before allocation.** The approved component limits total
10,704 MiB / 11,223,957,504 bytes
(10.453 GiB). The lower fresh Docker VM available
reading was 10,677,198,848 bytes (9.944 GiB).
The shortfall was 546,758,656 bytes
(521.430 MiB).

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
| 1 | 2026-11-11T09:38:06Z | 10,678,194,176 | 10,183.520 |
| 2 | 2026-11-11T09:38:06Z | 10,677,198,848 | 10,182.570 |

Docker's configured/visible total is 12,539,568,128
bytes and 20 CPUs. Total memory is not free memory.
VM MemAvailable already accounts for reclaimable cache; cache was not added a
second time. Available swap 34,359,738,368 bytes
was not counted as RAM. Host WMI observation: total physical
16,454,352 KiB, available/free
physical 3,845,048 KiB. Windows and
VM memory were not added together, which would risk double counting. CPU count
is an inventory fact; no CPU-load/canary-performance suitability was proven.

| Approved component | Cap MiB |
| --- | ---: |
| ollama | 7,168 |
| worker | 1,024 |
| neo4j | 768 |
| kafka | 768 |
| chroma | 384 |
| quickwit | 384 |
| redis | 64 |
| gateway | 64 |
| coordinator | 64 |
| anchor | 16 |

## Actual actions and exact commands

Read approved runtime design/checklist, local progress and parent decisions.
Parent progress validator passed: `python -B scripts\validate_progress.py`
from `C:\Users\DELL\Specula-skeleton` (47 tasks, WIP 2/2, one active).
Acquisition script entrypoints, run from `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition`:

```powershell
python -B 09_Acquisition_Reports\functional_provisioning_20261111_run01\check_admission.py
python -B 09_Acquisition_Reports\functional_provisioning_20261111_run01\check_preservation.py
```

Underlying successful read-only admission commands (raw stdout/stderr/exit codes
retained in `command_outputs.json`):

- `powershell -NoProfile -NonInteractive -Command 'Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,FreeVirtualMemory,TotalVirtualMemorySize | ConvertTo-Json'` (exit 0)
- `wsl.exe -d docker-desktop -- cat /proc/meminfo` (exit 0)
- `wsl.exe -d docker-desktop -- cat /proc/meminfo` (exit 0)
- `docker info --format '{"memory_bytes":{{.MemTotal}},"cpus":{{.NCPU}}}'` (exit 0)
- `docker ps -a --format '{{json .}}'` (exit 0)

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
- Existing container ID/state comparison against preparation: `{"new_ids": [], "removed_ids": [], "state_changes": []}`.
  Running containers: `[]`. No existing service was changed or stopped.

## Preservation and cleanup

Read-only verification PASS: 5,096
immutable resource hashes; 31 mutable datastore
hashes explicitly deferred; 296 evaluator files and 411 ACL descriptors unchanged;
two model manifests/seven referenced blob entries verified; source ZIP/key,
prepared derivative and four reference copies unchanged.
Parent tracked tree clean at `b9b2012edaed8da5062113ddc9982e3c33b27983`.
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
