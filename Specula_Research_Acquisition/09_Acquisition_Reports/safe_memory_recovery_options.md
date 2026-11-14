# Safe memory recovery options

11 November 2026. READ-ONLY diagnostic; no recovery action or configuration
proposal was applied. No process/service/model/container/distro was stopped or
started. No cache was cleared, file deleted, host/WSL setting changed or forensic
investigation run. Only new diagnostic/report files and acquisition progress
metadata were written. Evidence: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\memory_diagnostic_20261111_run01`.


## What can safely be concluded

**No application was proven safe to close automatically.** Memory accounting
cannot establish whether a tab, document, IDE window, message session or background
task is unused. Read-only probes cannot certify no impact on unrelated work.
The user can choose ordinary application exits after saving work; the agent must
obtain explicit permission before any closure or runtime/settings action.

Current original-budget admission gap is 517.512 MiB **inside the VM**.
Windows application closure can help the host avoid paging, but does not create
guest capacity above the fixed WSL ceiling. Any recovery must be verified by new
Windows and guest samples, not inferred from the process that was closed.

## Reviewable options — nothing applied

| Option | Expected benefit / evidence | Risk and affected workloads | Approval required |
| --- | --- | --- | --- |
| User closes only confirmed-unused Brave tabs/windows | Whole group currently 607.5 MiB private resident; tab-level savings unknown; helps Windows backing/commit, not guaranteed guest admission | Could lose forms/downloads/browser work; user must save and identify unused tabs. No Specula impact if truly unrelated, but cannot certify that here | User may choose manual exits; explicit new instruction required for agent action |
| User closes only unrelated saved Code windows | Whole 16-process Code group 1,069.5 MiB private resident; per-window recovery cannot be assigned | Code may host Specula/current work, terminals or unsaved edits. Preserve Specula IDE and current agent; do not close entire group blindly | User confirmation of exact unrelated window; agent closure needs explicit approval |
| Preserve current ChatGPT/codex session; optionally close other idle user apps | ChatGPT group 535.1 MiB private resident is observed, not a shutdown recommendation; other apps vary | Closing current session interrupts this work. Only user can identify truly idle unrelated application windows | User decision; agent action requires approval |
| Stop optional local Docker Desktop Kubernetes through supported UI, if user confirms unused | Named related processes 851.9 MiB PSS / 435.9 MiB private dirty; actual guest MemAvailable gain unknown and may be smaller than PSS | Stops Kubernetes API/DNS/storage/control plane; may affect external clients or future saved cluster work. Only system pods/no PVCs observed. Approved Specula Compose design does not require Kubernetes, but other usage cannot be excluded | **Separate explicit approval**, exact supported Stop action/state preservation reviewed; no reset/delete/kill |
| Keep Docker Engine/containerd and stopped Specula containers intact | No RAM credit from deleting dormant containers/images/volumes; preserves required provisioning platform and evidence | Stopping Docker/WSL would remove the platform needed for Approval 1 and interrupt Kubernetes | Not recommended as a lasting capacity remedy; any restart/stop needs approval |
| Do not clear guest/host caches or prune disk assets | MemAvailable already estimates usable cache; zero additional cache-sized budget credit | Cache clearing increases cold I/O; pruning deletes reproducibility assets; forbidden in current task | Not proposed; not authorized |
| Do not stop Memory Compression, Defender, svchost or vendor/system agents | No approved recovery benefit assigned | Security/stability/driver/management impact; transient high readings are not proof of a leak | Not proposed; no permission inferred |
| Leave existing WSL/Docker resource settings unchanged | autoMemoryReclaim already configured; merely enabling Resource Saver on WSL is not a RAM-capacity solution | WSL restarts/config changes affect shared VM and Kubernetes; pageReporting flag semantics unverified on this version | Any future settings/restart proposal needs separate approval |
| Review reduced 9,680 MiB cap proposal only if original path remains infeasible | Lowers admission threshold by 1,024 MiB; does not measure or free that much resident RAM | Lower worker/JVM/index caps increase startup/OOM risk; actual code/model settings unchanged; future startup validation required | **Explicit revised-budget approval**; currently unapproved |
| Use an existing larger-memory dedicated host if current work must remain open | Capacity can be sized as budget + measured host/core baseline + 1–2 GiB reserve | Migration/setup/security/reproducibility work; no benchmark-performance equivalence assumed | Explicit destination/provisioning approval; no purchase or migration performed |

Docker documents a supported Stop action for its Kubernetes view; do not substitute
Reset/Delete or terminate individual kube processes. Review the installed UI and
state-preservation behavior before any approved action. See [Docker's Kubernetes
view documentation](https://docs.docker.com/desktop/use-desktop/kubernetes/).
Its [Resource Saver documentation](https://docs.docker.com/desktop/use-desktop/resource-saver/)
explains that WSL Resource Saver pauses the engine rather than reclaiming the VM's
memory. This is why toggling the disabled setting is not credited as a RAM fix.

## Recommended order to safely resume Approval 1

1. Keep provisioning blocked. User saves work and manually exits only confirmed
   idle, unrelated Windows applications. Preserve Specula/Code workspaces,
   ChatGPT/codex session, security services and Docker core. Recheck Windows
   physical availability/commit/paging; do not promise guest recovery from this.
2. If the user confirms the local cluster is not needed, separately approve a
   **supported Kubernetes Stop only**, leaving cluster data and all Docker/Specula
   state intact. Current observations justify considering it, not acting on it.
3. After any user-authorized recovery, collect new VM MemAvailable, Windows
   available/commit/page-input and Linux PSI/swap samples. Require the original
   10,704 MiB threshold for unchanged Approval 1. Prefer 1 GiB operational VM/host
   reserve where feasible, but distinguish that recommendation from the existing
   admission-only threshold. A threshold-only PASS is not proof of paging-free use.
4. If original admission still fails or headroom is too thin, review the unapplied
   R1 budget as a controlled alternative. No mandatory service/model removal,
   silent cap reduction, source change, root fallback or new model download.
   R1 alone currently supplies only 506.5 MiB VM headroom, below 1 GiB.
5. If safe application/Kubernetes recovery plus an approved bounded profile cannot
   meet capacity without disrupting other work, use a larger-memory host. Do not
   increase the WSL ceiling on this 16 GiB machine and assume physical RAM appeared.
6. Only after fresh admission and explicit authorization to act, resume Approval 1
   provisioning/security checks and exactly its two benign canaries. No Approval 2
   or eight-record investigation is authorized by this diagnostic.

No shutdown, setting change, cache manipulation, volume deletion, model request,
revised cap or provisioning action was implemented. Expected benefits are planning
estimates/observed footprints; no recovery measurement is fabricated.
