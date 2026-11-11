# Memory consumers report

11 November 2026. READ-ONLY diagnostic; no recovery action or configuration
proposal was applied. No process/service/model/container/distro was stopped or
started. No cache was cleared, file deleted, host/WSL setting changed or forensic
investigation run. Only new diagnostic/report files and acquisition progress
metadata were written. Evidence: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\memory_diagnostic_20261111_run01`.


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
| vmmemWSL | 1 | 1,201.6 | 1,200.9 | 10,435.3 |
| Code | 16 | 1,527.0 | 1,069.5 | 2,595.3 |
| brave | 11 | 890.1 | 607.5 | 1,538.2 |
| ChatGPT | 14 | 779.9 | 535.1 | 1,572.1 |
| Memory Compression | 1 | 471.7 | 471.7 | 12.9 |
| msedgewebview2 | 13 | 616.4 | 379.8 | 1,053.6 |
| svchost | 93 | 864.7 | 291.2 | 682.2 |
| MsMpEng | 1 | 376.8 | 271.7 | 623.5 |
| AWPerformance.SCSubAgent | 1 | 380.1 | 154.3 | 597.6 |
| codex | 5 | 224.1 | 123.1 | 253.7 |
| com.docker.backend | 2 | 264.9 | 118.2 | 352.9 |
| Docker Desktop | 4 | 166.1 | 102.9 | 331.0 |
| explorer | 1 | 229.8 | 79.6 | 355.5 |
| NVIDIA Overlay | 5 | 164.9 | 77.8 | 511.3 |
| WmiPrvSE | 3 | 119.6 | 76.9 | 121.3 |
| Dell.TechHub.Instrumentation.SubAgent | 1 | 146.5 | 75.6 | 213.8 |
| Secure System | 1 | 66.0 | 66.0 | 0.2 |
| powershell | 2 | 154.1 | 56.7 | 118.3 |

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
| vmmemWSL | 38964 | 1,201.6 | 1,200.9 |
| Memory Compression | 3400 | 471.7 | 471.7 |
| brave | 36448 | 484.6 | 414.1 |
| Code | 33424 | 345.5 | 296.7 |
| Code | 34736 | 331.9 | 275.6 |
| MsMpEng | 5600 | 376.8 | 271.7 |
| msedgewebview2 | 25540 | 331.3 | 270.5 |
| Code | 19604 | 301.8 | 268.8 |
| ChatGPT | 32456 | 222.5 | 188.8 |
| AWPerformance.SCSubAgent | 22944 | 380.1 | 154.3 |
| ChatGPT | 18752 | 177.5 | 148.1 |
| ChatGPT | 2272 | 172.9 | 108.3 |
| codex | 7144 | 169.5 | 108.2 |
| com.docker.backend | 17228 | 239.0 | 103.0 |
| brave | 33556 | 175.9 | 93.4 |

`vmmemWSL` private commit is a guest-related virtual accounting value, not extra
physical RAM to add to Windows usage or VM MemAvailable. Current Windows WMI and
guest /proc counters measure different layers and are not an exact one-to-one
resident attribution. Do not diagnose a 10 GiB resident leak from that commit figure.

## Docker VM processes: proportional residency

| Linux comm | PID | RSS MiB | PSS MiB | Private dirty MiB |
| --- | ---: | ---: | ---: | ---: |
| kube-apiserver | 1239 | 271.5 | 271.5 | 201.8 |
| initd | 56 | 172.8 | 155.8 | 128.9 |
| dockerd | 159 | 121.3 | 119.6 | 59.2 |
| kube-controller | 1389 | 104.6 | 104.6 | 47.4 |
| kubelet | 979 | 94.3 | 93.0 | 43.3 |
| containerd | 122 | 87.3 | 86.0 | 46.9 |
| etcd | 1513 | 84.0 | 84.0 | 45.5 |
| kube-scheduler | 1241 | 61.4 | 61.4 | 22.7 |
| cri-dockerd | 908 | 55.2 | 55.2 | 20.4 |
| kube-proxy | 2176 | 47.5 | 47.5 | 13.2 |
| coredns | 2290 | 63.1 | 39.6 | 14.7 |
| coredns | 2293 | 62.3 | 38.8 | 14.4 |
| containerd-star | 118 | 38.9 | 37.8 | 8.2 |
| initd | 43 | 46.6 | 29.7 | 12.5 |
| storage-provisi | 3045 | 28.6 | 28.6 | 6.7 |
| kube-vpnkit-for | 2175 | 27.9 | 27.9 | 5.7 |
| wsl-bootstrap | 12 | 19.2 | 19.2 | 5.7 |
| vpnkit-bridge | 10 | 8.6 | 8.6 | 3.0 |

PSS apportions shared pages; private dirty pages are a more conservative indicator
of active private memory than total RSS. Initial shell-loop collection returned
no rows; that failed observation is retained, not treated as zero usage. Direct
read-only `smaps_rollup` reads then collected 57 processes; three
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

The named Kubernetes-related processes total **851.941 MiB PSS**, including
**435.898 MiB private dirty** and 368.895 MiB private clean.
This excludes unallocated shared daemon/shim/kernel attribution. These are measured
footprints, **not additive guaranteed recovery**: clean mapped pages may already
contribute to MemAvailable. Kernel/dependency changes after a supported stop are
also unmeasured. Do not promise that 852 MiB will become newly available.

Ubuntu is stopped and has no active process workload to recover. Stopped Docker
containers, cached images, build layers and volumes chiefly occupy disk; deleting
them is neither necessary nor authorized for this RAM diagnosis. The ~7.5 GiB
guest cache is not an independent uncounted memory pool.

## Protection boundary

Preserve Docker's daemon/containerd/bootstrap, all original Specula services and
data, Windows security/system/vendor services and the active research session.
Any optional Kubernetes stop is a separately approved subsystem action, not a
license to terminate individual system processes. No shutdown occurred here.
