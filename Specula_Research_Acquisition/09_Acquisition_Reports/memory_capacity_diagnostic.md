# Memory capacity diagnostic

11 November 2026. READ-ONLY diagnostic; no recovery action or configuration
proposal was applied. No process/service/model/container/distro was stopped or
started. No cache was cleared, file deleted, host/WSL setting changed or forensic
investigation run. Only new diagnostic/report files and acquisition progress
metadata were written. Evidence: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\memory_diagnostic_20261111_run01`.


## Decision

**Approval 1 remains BLOCKED at the existing conservative admission rule.**
Three formal samples show 10,186.488–10,199.953
MiB VM available against the approved 10,704 MiB budget. Minimum deficit:
**517.512 MiB**. Limits are upper bounds, not measurements of actual demand;
no model or service was run to find its peak. No new capacity PASS is claimed.

| Sample UTC | Windows available MiB (WMI) | VM MemAvailable MiB | Windows pages input/output per second |
| --- | ---: | ---: | --- |
| 2026-11-11T09:59:43.1923800Z | 4,101.1 | 10,200.0 | 122 / 0 |
| 2026-11-11T09:59:49.8459961Z | 4,111.4 | 10,188.4 | 61 / 0 |
| 2026-11-11T09:59:56.5960999Z | 4,226.9 | 10,186.5 | 7 / 0 |

The three samples were separated by at least five seconds, plus query overhead.
They are a brief idle-system observation, not a load test. Windows values changed
naturally; no recovery action was taken between readings.

## Windows physical memory and paging

Usable physical RAM: **15.692 GiB** (16 GiB class machine).
Formal available range: 4.005–4.128 GiB.
The process snapshot reports 4.115 GiB available,
with the rest 11.577 GiB not immediately
available. This is not all private application memory.
Snapshot commit: 32.678 GiB of
40.692 GiB limit. Windows pagefile:
25,600 MiB configured,
6,002 MiB used, 6,228 MiB peak.

Pagefile allocation/occupancy is not evidence of current thrashing by itself.
Hard-fault input counters can include mapped files; they are not exclusively
pagefile I/O. This short interval shows some page input, no sampled page output,
and does not establish excessive paging. It also cannot establish paging-free
capacity for an additional model stack. See [Microsoft's pagefile guidance](https://learn.microsoft.com/en-GB/troubleshoot/windows-client/performance/how-to-determine-the-appropriate-page-file-size-for-64-bit-versions-of-windows).

## WSL/Docker configuration and effective observations

`C:\Users\DELL\.wslconfig` contains `memory=12GB`, `swap=32GB`,
`pageReporting=false`, `localhostForwarding=true`, and
`autoMemoryReclaim=dropcache`. WSL version 2.7.12.0, kernel 6.18.33.2.
Observed VM usable total: **11,958.664 MiB** (11.678 GiB),
consistent with a 12 GiB ceiling minus reserved/guest overhead. Docker reports
12,539,568,128 total bytes / 20 CPUs. A ceiling is not
a reservation or extra physical RAM. WSL settings are shared VM settings, as
described in [Microsoft's configuration reference](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).

Ubuntu was stopped and was not started to inspect it. `docker-desktop` was already
running. Selected Docker settings: KubernetesEnabled=true, UseResourceSaver=false,
EnableIntegrationWithDefaultWslDistro=false. No unrelated Docker settings, keys or
credentials were exported. `pageReporting=false` is a configured value; its
effective behavior/support was not separately established, so no presumed fix is
based on changing it. `autoMemoryReclaim` is already configured; do not treat
enabling it as a new recovery action. No setting was changed.

VM sample: Cached=7.489 GiB,
MemFree=1.937 GiB,
MemAvailable=9.948 GiB. **Do not add file cache to MemAvailable**:
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
| Existing admission only | 10,704 | 517.512 | Not met; targeted VM recovery may help, unmeasured |
| Budget + 1 GiB | 11,728 | 1,541.512 | Leaves only 230.664 MiB for all guest/kernel/Docker baseline; not credible with current required core overhead |
| Budget + 2 GiB | 12,752 | 2,565.512 | Exceeds VM total by 793.336 MiB, impossible under current ceiling even with no baseline |

Windows application shutdown can improve physical backing/commit headroom; it
does **not** automatically increase guest MemAvailable past a fixed ceiling.
Windows and guest availability are not independent RAM pools and must not be added.
Likewise, shutting down a process whose clean file pages were already reclaimable
cannot be credited with its entire RSS/PSS as newly available VM memory.

## Physical host sufficiency

If the full 10.453 GiB cap budget became resident, usable physical RAM would leave
only 4.239 GiB for Windows, host applications and guest/core
overhead with a 1 GiB operational reserve (3.239 GiB with 2 GiB).
The current **non-VM private-resident process sum alone is 5.105 GiB**,
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
