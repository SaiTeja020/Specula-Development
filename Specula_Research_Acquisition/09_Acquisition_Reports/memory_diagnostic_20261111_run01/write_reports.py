"""Calculate from read-only observations and write unapplied recommendations."""
import collections,json
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
OUT=RUN.parent
def load(name):return json.loads((RUN/name).read_text(encoding='utf-8'))
def put(name,value):
    with (RUN/name).open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2)
def report(name,text):
    with (OUT/name).open('x',encoding='utf-8',newline='\n') as stream:stream.write(text)
samples=load('memory_samples.json');host=load('windows_memory_and_processes.json')
processes=load('wsl_pss_supplement.json')['processes'];engine=load('docker_engine.json')
old=json.loads((OUT/'functional_provisioning_20261111_run01/memory_admission.json').read_text())['component_caps_MiB']
proposal={**old,'worker':768,'neo4j':512,'kafka':512,'chroma':256,'quickwit':256}
assert sum(old.values())==10704 and sum(proposal.values())==9680
available=min(x['linux_meminfo_bytes']['MemAvailable'] for x in samples)/1024**2
vm_total=samples[-1]['linux_meminfo_bytes']['MemTotal']/1024**2
host_total=host['OS']['TotalVisibleMemorySize']/1024**2
windows_available=[x['windows']['OS']['FreePhysicalMemory']/1024**2 for x in samples]
kube=[x for x in processes if x['comm'].startswith('kube') or x['comm'] in ['etcd','coredns','cri-dockerd','storage-provisi']]
kube_pss=sum(x['Pss_KiB'] for x in kube)/1024
kube_dirty=sum(x['Private_Dirty_KiB'] for x in kube)/1024
kube_clean=sum(x['Private_Clean_KiB'] for x in kube)/1024
groups=collections.defaultdict(lambda:{'count':0,'rss':0,'private_rss':0,'private_commit':0,'specula_window':False,'private_samples':0})
for p in host['Processes']:
    row=groups[p['Name']];row['count']+=1;row['rss']+=p['WorkingSetBytes'];row['private_commit']+=p['PrivateCommittedBytes']
    row['specula_window']|=p['WindowMentionsSpecula']
    if p['PrivateResidentBytes'] is not None:row['private_rss']+=p['PrivateResidentBytes'];row['private_samples']+=1
nonvm_private=sum((p['PrivateResidentBytes'] or 0) for p in host['Processes'] if p['Name']!='vmmemWSL')/1024**3
gap={str(h):max(0,10704+h-available) for h in [0,1024,2048]}
calc={'budget_MiB':10704,'VM_MemAvailable_min_MiB':available,'VM_MemTotal_MiB':vm_total,
      'required_extra_MiB':gap,'budget_plus_1GiB_MiB':11728,'budget_plus_2GiB_MiB':12752,
      'VM_room_after_budget_plus_1GiB_MiB':vm_total-11728,'VM_deficit_even_if_empty_for_2GiB_MiB':12752-vm_total,
      'kubernetes_processes':len(kube),'kubernetes_PSS_MiB':kube_pss,'kubernetes_private_dirty_MiB':kube_dirty,
      'kubernetes_private_clean_MiB':kube_clean,'Windows_usable_GiB':host_total,
      'Windows_available_samples_GiB':windows_available,'nonVM_private_resident_GiB':nonvm_private,
      'physical_remainder_for_host_baseline_with_1GiB_headroom_GiB':host_total-10704/1024-1,
      'physical_remainder_for_host_baseline_with_2GiB_headroom_GiB':host_total-10704/1024-2,
      'proposal_total_MiB':9680,'proposal_budget_reduction_MiB':1024,
      'proposal_current_VM_headroom_MiB':available-9680,'proposal_extra_for_1GiB_headroom_MiB':max(0,10704-available),
      'provisioning':'BLOCKED','actions_applied':[]}
put('capacity_calculations.json',calc)
put('windows_process_groups.json',dict(groups))
put('revised_budget_PROPOSED.json',{'status':'UNAPPROVED / NOT APPLIED / TRIAL ONLY','component_caps_MiB':proposal,
    'total_MiB':9680,'preserved':'All mandatory services, identities, network restrictions, image/model pins, Ollama 7168 MiB, context 8192, output limits, CPU placement, model names, retrieval and HITL behavior.',
    'changes':{k:{'approved_MiB':old[k],'proposed_MiB':proposal[k]} for k in old if old[k]!=proposal[k]},
    'runtime_settings_to_validate':'Per-service supported heap/cache limits and actual non-root startup at pinned software versions; no existing service change permitted.',
    'execution_authorized':False,'model_canary_limit':'Unchanged: one benign chat and one benign embedding; no retry or forensic case.'})
common=f'''11 November 2026. READ-ONLY diagnostic; no recovery action or configuration
proposal was applied. No process/service/model/container/distro was stopped or
started. No cache was cleared, file deleted, host/WSL setting changed or forensic
investigation run. Only new diagnostic/report files and acquisition progress
metadata were written. Evidence: `{RUN}`.

'''
sample_table='\n'.join(f"| {x['windows']['TimeUTC']} | {x['windows']['OS']['FreePhysicalMemory']/1024:,.1f} | {x['linux_meminfo_bytes']['MemAvailable']/1024**2:,.1f} | {x['windows']['Memory']['PagesInputPersec']} / {x['windows']['Memory']['PagesOutputPersec']} |" for x in samples)
report('memory_capacity_diagnostic.md','# Memory capacity diagnostic\n\n'+common+f'''
## Decision

**Approval 1 remains BLOCKED at the existing conservative admission rule.**
Three formal samples show {available:,.3f}–{max(x['linux_meminfo_bytes']['MemAvailable'] for x in samples)/1024**2:,.3f}
MiB VM available against the approved 10,704 MiB budget. Minimum deficit:
**{gap['0']:,.3f} MiB**. Limits are upper bounds, not measurements of actual demand;
no model or service was run to find its peak. No new capacity PASS is claimed.

| Sample UTC | Windows available MiB (WMI) | VM MemAvailable MiB | Windows pages input/output per second |
| --- | ---: | ---: | --- |
{sample_table}

The three samples were separated by at least five seconds, plus query overhead.
They are a brief idle-system observation, not a load test. Windows values changed
naturally; no recovery action was taken between readings.

## Windows physical memory and paging

Usable physical RAM: **{host_total:.3f} GiB** (16 GiB class machine).
Formal available range: {min(windows_available):.3f}–{max(windows_available):.3f} GiB.
The process snapshot reports {host['OS']['FreePhysicalMemory']/1024**2:.3f} GiB available,
with the rest {host_total-host['OS']['FreePhysicalMemory']/1024**2:.3f} GiB not immediately
available. This is not all private application memory.
Snapshot commit: {host['Memory']['CommittedBytes']/1024**3:.3f} GiB of
{host['Memory']['CommitLimit']/1024**3:.3f} GiB limit. Windows pagefile:
{host['Pagefiles'][0]['AllocatedBaseSize']:,} MiB configured,
{host['Pagefiles'][0]['CurrentUsage']:,} MiB used, {host['Pagefiles'][0]['PeakUsage']:,} MiB peak.

Pagefile allocation/occupancy is not evidence of current thrashing by itself.
Hard-fault input counters can include mapped files; they are not exclusively
pagefile I/O. This short interval shows some page input, no sampled page output,
and does not establish excessive paging. It also cannot establish paging-free
capacity for an additional model stack. See [Microsoft's pagefile guidance](https://learn.microsoft.com/en-GB/troubleshoot/windows-client/performance/how-to-determine-the-appropriate-page-file-size-for-64-bit-versions-of-windows).

## WSL/Docker configuration and effective observations

`C:\\Users\\DELL\\.wslconfig` contains `memory=12GB`, `swap=32GB`,
`pageReporting=false`, `localhostForwarding=true`, and
`autoMemoryReclaim=dropcache`. WSL version 2.7.12.0, kernel 6.18.33.2.
Observed VM usable total: **{vm_total:,.3f} MiB** ({vm_total/1024:.3f} GiB),
consistent with a 12 GiB ceiling minus reserved/guest overhead. Docker reports
{engine['memory_bytes']:,} total bytes / {engine['cpus']} CPUs. A ceiling is not
a reservation or extra physical RAM. WSL settings are shared VM settings, as
described in [Microsoft's configuration reference](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).

Ubuntu was stopped and was not started to inspect it. `docker-desktop` was already
running. Selected Docker settings: KubernetesEnabled=true, UseResourceSaver=false,
EnableIntegrationWithDefaultWslDistro=false. No unrelated Docker settings, keys or
credentials were exported. `pageReporting=false` is a configured value; its
effective behavior/support was not separately established, so no presumed fix is
based on changing it. `autoMemoryReclaim` is already configured; do not treat
enabling it as a new recovery action. No setting was changed.

VM sample: Cached={samples[-1]['linux_meminfo_bytes']['Cached']/1024**3:.3f} GiB,
MemFree={samples[-1]['linux_meminfo_bytes']['MemFree']/1024**3:.3f} GiB,
MemAvailable={available/1024:.3f} GiB. **Do not add file cache to MemAvailable**:
that estimate already includes usable reclaimable memory. Clearing caches cannot
be credited as an additional cache-sized capacity gain. This distinction follows
the [Linux meminfo definitions](https://docs.kernel.org/filesystems/proc.html).

VM swap: 32 GiB total, zero used in every sample; pswpin/pswpout and oom_kill
remain zero; direct reclaim/allocation-stall counters remain zero. Memory PSI
some/full averages and totals are zero. No current guest memory-stall or swap
pressure was observed. These facts do not cover Windows paging or future load.

## Required additional memory and headroom

| Target | Required VM available MiB | Additional over sampled minimum MiB | Feasibility under current ceiling |
| --- | ---: | ---: | --- |
| Existing admission only | 10,704 | {gap['0']:,.3f} | Not met; targeted VM recovery may help, unmeasured |
| Budget + 1 GiB | 11,728 | {gap['1024']:,.3f} | Leaves only {vm_total-11728:,.3f} MiB for all guest/kernel/Docker baseline; not credible with current required core overhead |
| Budget + 2 GiB | 12,752 | {gap['2048']:,.3f} | Exceeds VM total by {12752-vm_total:,.3f} MiB, impossible under current ceiling even with no baseline |

Windows application shutdown can improve physical backing/commit headroom; it
does **not** automatically increase guest MemAvailable past a fixed ceiling.
Windows and guest availability are not independent RAM pools and must not be added.
Likewise, shutting down a process whose clean file pages were already reclaimable
cannot be credited with its entire RSS/PSS as newly available VM memory.

## Physical host sufficiency

If the full 10.453 GiB cap budget became resident, usable physical RAM would leave
only {host_total-10704/1024-1:.3f} GiB for Windows, host applications and guest/core
overhead with a 1 GiB operational reserve ({host_total-10704/1024-2:.3f} GiB with 2 GiB).
The current **non-VM private-resident process sum alone is {nonvm_private:.3f} GiB**,
before shared pages and much kernel memory. This is a planning comparison, not a
predicted peak: current processes can trim/change, and caps need not all be used.
Still, the current desktop workload does not substantiate a full-budget,
headroom-preserving, paging-light deployment. Existing large commit/pagefile use
reinforces caution; it does not prove active thrashing.

The host may support a tightly bounded idle-desktop canary stack after recovery
and/or reviewed limits, but this has not been demonstrated. If unrelated work
must stay resident, prefer a larger-memory dedicated host sized for approved
budget + measured host/core baseline + headroom, rather than allocating still
more of this 16 GiB host to WSL. No hardware purchase or VM change is authorized.

## Path to resume

Read `safe_memory_recovery_options.md`: user-selected ordinary application closure
can help Windows; optional local Kubernetes is the clearest VM-side candidate.
Its shutdown requires separate approval and workload confirmation. Remeasure both
layers before any allocation. If the original budget still does not fit, review
`revised_budget_proposal.md` separately; it is not applied or proven safe.
The current diagnostic does not authorize provisioning or Approval 2 execution.
''')
top_groups=sorted(groups.items(),key=lambda x:x[1]['private_rss'],reverse=True)[:18]
group_table='\n'.join(f"| {name} | {x['count']} | {x['rss']/1024**2:,.1f} | {x['private_rss']/1024**2:,.1f} | {x['private_commit']/1024**2:,.1f} |" for name,x in top_groups)
top_proc=sorted(host['Processes'],key=lambda x:x['PrivateResidentBytes'] or 0,reverse=True)[:15]
proc_table='\n'.join(f"| {x['Name']} | {x['Id']} | {x['WorkingSetBytes']/1024**2:,.1f} | {(x['PrivateResidentBytes'] or 0)/1024**2:,.1f} |" for x in top_proc)
wsl_table='\n'.join(f"| {x['comm']} | {x['pid']} | {x['Rss_KiB']/1024:,.1f} | {x['Pss_KiB']/1024:,.1f} | {x['Private_Dirty_KiB']/1024:,.1f} |" for x in sorted(processes,key=lambda x:x['Pss_KiB'],reverse=True)[:18])
report('memory_consumers_report.md','# Memory consumers report\n\n'+common+f'''
## Interpretation of counters

Working set includes shared and private resident pages; summing it across processes
can double count. Private committed bytes are not resident RAM or guaranteed
recoverable physical memory. Windows process groups below use matched PID
`WorkingSetPrivate` counters for the private-resident column; missing matches are
omitted from that sum, not assumed fully measured. See [Microsoft's working-set
definition](https://learn.microsoft.com/en-us/windows/win32/procthread/process-working-set).
PID/name-only and memory metrics were collected; no process command lines,
environment blocks, credentials or document/window titles were exported.

## Largest Windows process groups

| Process name group | Count | Working set MiB | Private resident MiB | Private committed MiB |
| --- | ---: | ---: | ---: | ---: |
{group_table}

All figures are the same saved process snapshot, not promises of shutdown savings.
Shared browser/IDE subprocess ownership cannot be safely assigned to an unused
tab/window from these counters alone. Code may be the Specula workspace/current
development; ChatGPT/codex support this session. They are not automatic kill targets.
Memory Compression, Defender/MsMpEng, svchost and vendor service processes must not
be classified as disposable applications. The initially high AWPerformance reading
varied between observations; this diagnostic does not establish a memory leak.

## Largest individual Windows processes

| Name | PID | Working set MiB | Private resident MiB |
| --- | ---: | ---: | ---: |
{proc_table}

`vmmemWSL` private commit is a guest-related virtual accounting value, not extra
physical RAM to add to Windows usage or VM MemAvailable. Current Windows WMI and
guest /proc counters measure different layers and are not an exact one-to-one
resident attribution. Do not diagnose a 10 GiB resident leak from that commit figure.

## Docker VM processes: proportional residency

| Linux comm | PID | RSS MiB | PSS MiB | Private dirty MiB |
| --- | ---: | ---: | ---: | ---: |
{wsl_table}

PSS apportions shared pages; private dirty pages are a more conservative indicator
of active private memory than total RSS. Initial shell-loop collection returned
no rows; that failed observation is retained, not treated as zero usage. Direct
read-only `smaps_rollup` reads then collected {len(processes)} processes; three
short-lived collection helpers had exited. No permissions or process state were
changed. Raw rows and exact argv are in `wsl_pss_supplement.json`.

## Resources contributing despite no Docker application containers

`docker ps` shows zero running application containers. Nevertheless, the local
Docker Desktop Kubernetes cluster runs nine kube-system pods: API server,
controller, scheduler, etcd, kube-proxy, two CoreDNS pods, storage provisioner and
vpnkit controller. Kubelet/cri-dockerd and container shims add supporting overhead.
Read-only queries found no non-system pods, deployments, StatefulSets, jobs or
cronjobs, and no PVCs. This does not prove the cluster is unneeded for future work,
external clients or retained Kubernetes objects; user confirmation is required.
Only the explicit `docker-desktop` context was queried; current-context was unset
and was not changed. No remote cluster or secret was queried.

The named Kubernetes-related processes total **{kube_pss:,.3f} MiB PSS**, including
**{kube_dirty:,.3f} MiB private dirty** and {kube_clean:,.3f} MiB private clean.
This excludes unallocated shared daemon/shim/kernel attribution. These are measured
footprints, **not additive guaranteed recovery**: clean mapped pages may already
contribute to MemAvailable. Kernel/dependency changes after a supported stop are
also unmeasured. Do not promise that {kube_pss:,.0f} MiB will become newly available.

Ubuntu is stopped and has no active process workload to recover. Stopped Docker
containers, cached images, build layers and volumes chiefly occupy disk; deleting
them is neither necessary nor authorized for this RAM diagnosis. The ~7.5 GiB
guest cache is not an independent uncounted memory pool.

## Protection boundary

Preserve Docker's daemon/containerd/bootstrap, all original Specula services and
data, Windows security/system/vendor services and the active research session.
Any optional Kubernetes stop is a separately approved subsystem action, not a
license to terminate individual system processes. No shutdown occurred here.
''')
brave=groups['brave']['private_rss']/1024**2
code=groups['Code']['private_rss']/1024**2
chat=groups['ChatGPT']['private_rss']/1024**2
report('safe_memory_recovery_options.md','# Safe memory recovery options\n\n'+common+f'''
## What can safely be concluded

**No application was proven safe to close automatically.** Memory accounting
cannot establish whether a tab, document, IDE window, message session or background
task is unused. Read-only probes cannot certify no impact on unrelated work.
The user can choose ordinary application exits after saving work; the agent must
obtain explicit permission before any closure or runtime/settings action.

Current original-budget admission gap is {gap['0']:,.3f} MiB **inside the VM**.
Windows application closure can help the host avoid paging, but does not create
guest capacity above the fixed WSL ceiling. Any recovery must be verified by new
Windows and guest samples, not inferred from the process that was closed.

## Reviewable options — nothing applied

| Option | Expected benefit / evidence | Risk and affected workloads | Approval required |
| --- | --- | --- | --- |
| User closes only confirmed-unused Brave tabs/windows | Whole group currently {brave:,.1f} MiB private resident; tab-level savings unknown; helps Windows backing/commit, not guaranteed guest admission | Could lose forms/downloads/browser work; user must save and identify unused tabs. No Specula impact if truly unrelated, but cannot certify that here | User may choose manual exits; explicit new instruction required for agent action |
| User closes only unrelated saved Code windows | Whole 16-process Code group {code:,.1f} MiB private resident; per-window recovery cannot be assigned | Code may host Specula/current work, terminals or unsaved edits. Preserve Specula IDE and current agent; do not close entire group blindly | User confirmation of exact unrelated window; agent closure needs explicit approval |
| Preserve current ChatGPT/codex session; optionally close other idle user apps | ChatGPT group {chat:,.1f} MiB private resident is observed, not a shutdown recommendation; other apps vary | Closing current session interrupts this work. Only user can identify truly idle unrelated application windows | User decision; agent action requires approval |
| Stop optional local Docker Desktop Kubernetes through supported UI, if user confirms unused | Named related processes {kube_pss:,.1f} MiB PSS / {kube_dirty:,.1f} MiB private dirty; actual guest MemAvailable gain unknown and may be smaller than PSS | Stops Kubernetes API/DNS/storage/control plane; may affect external clients or future saved cluster work. Only system pods/no PVCs observed. Approved Specula Compose design does not require Kubernetes, but other usage cannot be excluded | **Separate explicit approval**, exact supported Stop action/state preservation reviewed; no reset/delete/kill |
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
   R1 alone currently supplies only {available-9680:,.1f} MiB VM headroom, below 1 GiB.
5. If safe application/Kubernetes recovery plus an approved bounded profile cannot
   meet capacity without disrupting other work, use a larger-memory host. Do not
   increase the WSL ceiling on this 16 GiB machine and assume physical RAM appeared.
6. Only after fresh admission and explicit authorization to act, resume Approval 1
   provisioning/security checks and exactly its two benign canaries. No Approval 2
   or eight-record investigation is authorized by this diagnostic.

No shutdown, setting change, cache manipulation, volume deletion, model request,
revised cap or provisioning action was implemented. Expected benefits are planning
estimates/observed footprints; no recovery measurement is fabricated.
''')
budget_table='\n'.join(f"| {name} | {old[name]:,} | {proposal[name]:,} | {old[name]-proposal[name]:,} |" for name in old)
report('revised_budget_proposal.md','# Revised budget proposal — R1\n\n'+common+f'''
## Necessity, status and recommendation

The unchanged approved stack remains {gap['0']:,.3f} MiB short at sampled VM
minimum, so this separately reviewable fallback is necessary to document.
**UNAPPROVED, UNAPPLIED, UNTESTED.** Prefer user-confirmed harmless recovery first.
R1 is not a claim that services fit or a license to proceed past a failed startup.
No revised containers/configuration were created. Machine-readable proposal:
`{RUN}\\revised_budget_PROPOSED.json` (budget data only, not a deployment file).

## Proposed caps, preserving all mandatory services

| Component | Approved MiB | Proposed R1 MiB | Reduction MiB |
| --- | ---: | ---: | ---: |
{budget_table}
| **Total** | **10,704** | **9,680** | **1,024** |

Ollama remains 7,168 MiB. Both exact model manifests/weights, local-only backend,
generation context 8192, generic/structured output caps 1024/2048, temperature 0,
think=false, embedding CPU placement and retrieval settings remain unchanged.
All service/software pins, non-root UIDs, evidence-only mount, fresh datastores,
network policy, model gateway/capture, case authorization, HITL and integrity
requirements remain mandatory. SQLite/DuckDB remain in worker storage; nothing
is replaced by a stub or shared development store. Approval 1's one-chat/one-embed
limit, no retries and no forensic investigation remain unchanged.

## Justification and per-change risks

| Change | Reason / expected benefit | Risks / affected work | Approval and validation |
| --- | --- | --- | --- |
| Worker 1024 -> 768 MiB | Small eight-record future smoke and current canary scope justify considering a tighter Python cap; 256 MiB less maximum budget | Full current module imports/PDF/graph memory have not been measured; may OOM. Only new runtime, not existing Specula, would be affected | New approval; actual non-root API/PDF/import health and RSS/peak checks before any case; no root/model fallback |
| Neo4j 768 -> 512 MiB | Empty/single-case disposable graph, 256 MiB lower budget | JVM heap/pagecache/native memory need explicit supported sizing; startup could fail. Smaller cache may alter latency | New approval; review pinned image's heap/cache configuration; run bounded empty-store readiness; stop if minimum unsupported |
| Kafka 768 -> 512 MiB | Single broker/topic for tiny normalized stream, 256 MiB lower budget | KRaft/JVM/native overhead may exceed cap; delivery must remain acknowledged, never buffered fallback | New approval; review heap/native settings and actual broker/controller health under non-root identity |
| Chroma 384 -> 256 MiB | Tiny one-case vector collection, embeddings served by unchanged Ollama; 128 MiB lower budget | Server version/native caches may need more memory; no dimension/model change permitted | New approval; real client/server/case-filter checks; no automatic model download or embedding substitution |
| Quickwit 384 -> 256 MiB | Few serialized records, 128 MiB lower budget | Indexer heap/cache defaults may not fit; preservation must remain durable | New approval; verify supported pinned-version internal budget and commit/read receipt; no ignoring failed preservation |

These caps are **trial design limits, not verified minimums or measured savings**.
Internal heap/cache values and exact version-supported options remain unresolved
until reviewed; no guessed flags are represented as a validated configuration.
If a required process cannot start non-root within approved R1 limits, report
BLOCKED and stop. Do not raise limits, remove services, change context/model,
enable swap-dependent execution or patch original source to manufacture a PASS.

## Capacity arithmetic for R1

| Target | VM available required MiB | Difference vs sampled available |
| --- | ---: | --- |
| R1 admission | 9,680 | {available-9680:,.3f} MiB remains at current minimum |
| R1 + 1 GiB | 10,704 | Additional {max(0,10704-available):,.3f} MiB needed |
| R1 + 2 GiB | 11,728 | Additional {max(0,11728-available):,.3f} MiB needed; only {vm_total-11728:,.3f} MiB allowed for VM/core baseline |

R1 would satisfy the numerical cap-only check in this snapshot, **but alone
still misses the 1 GiB operational target**. Optional approved Kubernetes recovery
could help; its {kube_pss:,.1f} MiB PSS is not guaranteed additional RAM, and the
{kube_dirty:,.1f} MiB private-dirty footprint alone is less than that remaining
target gap. Remeasure; do not add all PSS or page cache to availability.
Two GiB reserve is still not credible at this ceiling with required Docker/core
overhead. Windows physical-backing and paging concerns remain even when guest
arithmetic fits; host application closure or a larger-memory host may be needed.

## Separate review/approval conditions

- Explicitly approve these five changed caps and future pinned-version internal
  heap/cache configuration. All other approved controls/model settings stay fixed.
- Record post-recovery Windows and guest capacity/pressure and a fresh admission
  decision. Do not treat a lower cap sum as observed resident-memory recovery.
- Provision only new isolation containers/volumes after authorization; collect
  effective UID/mount/capability/rule/service/gateway evidence, then exactly the
  approved benign model requests without retry. Stop new services afterward.
- Any OOM, sustained paging/PSI, incomplete logging, forbidden access, failed
  service or model canary blocks further work. Do not relabel a failed smaller
  configuration as equivalent to the original accepted runtime.
- Changes affect prospective runtime resource ceilings and potentially timing;
  do not mix later performance measurements across budgets without recording
  this confound. This is functional preparation, not an empirical result.
- Approval 2 remains separately required; no case intake or investigation here.

Recommendation: consider R1 only if recovery cannot safely fund the original
profile. For unrelated work that must remain open, a suitably sized dedicated
host is preferable to further speculative reductions below R1.
''')
print(json.dumps({'reports_created':4,'admission_gap_MiB':gap['0'],'kubernetes_PSS_MiB':kube_pss,
    'kubernetes_private_dirty_MiB':kube_dirty,'proposal_MiB':9680,'applied_changes':[]}))
