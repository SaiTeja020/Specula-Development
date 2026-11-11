# Updated memory admission report

11 November 2026. Read-only follow-up after the user explicitly confirmed
“Finished; take fresh readings.” Original budget **10,704 MiB retained**;
9,680 MiB alternative **not applied**. No process, Kubernetes service, setting,
resource limit, container, model or investigation was started/stopped/changed.

## Admission after user-performed recovery

| UTC | Windows physical available MiB | Docker VM MemAvailable MiB |
| --- | ---: | ---: |
| 2026-11-11T10:16:52.6324497Z | 4,693.078 | 10,188.672 |
| 2026-11-11T10:16:59.4367390Z | 4,674.625 | 10,184.590 |
| 2026-11-11T10:17:06.0999240Z | 4,649.000 | 10,182.543 |

| Target | Required MiB | Deficit at minimum VM reading |
| --- | ---: | ---: |
| Original admission | 10,704 | **521.457 MiB** |
| Original + preferred 1,024 MiB reserve | 11,728 | **1,545.457 MiB** |

**Result: BLOCKED.** Lowest VM availability:
**10,182.543 MiB**. Windows available range:
4.540–4.583 GiB. User recovery improved the
host-side opportunity for physical backing, but these readings still do not
satisfy guest admission. Exact changes cannot be attributed solely to individual
application exits; no agent-performed recovery occurred. Windows and guest RAM
are not additive pools, and file cache is not extra capacity on top of MemAvailable.
This remains a conservative full-cap-budget comparison, not an observed OOM.

## Kubernetes requirement and impact decision

- Docker Desktop **KubernetesEnabled=true**. Nine running pods are all in
  `kube-system`: API server, controller manager, scheduler, etcd, kube-proxy,
  two CoreDNS pods, storage provisioner and vpnkit controller. Only the system
  CoreDNS Deployment and kube-proxy DaemonSet were listed. No non-system pods,
  deployments, StatefulSets, jobs or cronjobs were observed. Docker's application
  container running list is empty. Ubuntu remains stopped.
- **Current/approved Specula runtime does not require this live cluster.** Its
  deployment is Docker Compose; the approved design uses a separate Docker
  namespace, not Kubernetes. Inspected `kubernetes_audit.py` and
  `kubernetes_normalizer.py` analyze captured records. Selected tracked source,
  scripts and Compose files had no live kubectl/KUBECONFIG/Kubernetes-client/Helm
  startup dependency matches. This is scoped to inspected runtime paths, not a
  proof about every possible external integration or future forensic case.
- **Other current workload requirement:** only Kubernetes' own system workloads
  were detected; no active application requirement was found. External clients,
  future plans and unrelated user reliance cannot be ruled out from inventories.
- **Stopping/disabling Kubernetes would affect running services:** all nine
  system pods/control-plane, cluster API, cluster DNS and provisioner integrations
  would become unavailable. No currently running Specula/application pod was
  identified to interrupt. Docker core must remain available for later provisioning;
  any UI action that also restarts Docker needs its impact reviewed first.
- **Stored data:** no Kubernetes PV or PVC resources were listed. This does
  **not** mean there is no stored cluster data: etcd retains configuration and
  cluster state, and external/unclaimed storage was not exhaustively audited.
  Data preservation depends on the exact supported Stop/Disable operation.
  Do not use Reset/Delete or assume state will be preserved without reviewing
  the installed control. No secret/configmap/etcd contents were queried.

**Decision:** optional Kubernetes Stop is a reasonable recovery candidate, but
requires explicit approval plus confirmation it is not needed for other work.
Use a supported [Docker Kubernetes Stop control](https://docs.docker.com/desktop/use-desktop/kubernetes/),
not individual process kills. Earlier diagnostic footprint (~852 MiB PSS,
~436 MiB private dirty) is historical attribution, not a guaranteed new memory
gain: some clean pages were already reclaimable. A stop might still not cover
the 521.457 MiB deficit; remeasurement is mandatory.

## Manual application options

No remaining application was certified unused or safe for automatic closure.
You may manually exit only windows/tabs you identify as idle, after saving work:

| Candidate | Current observation / possible benefit | Risk / permission |
| --- | --- | --- |
| Brave unused tabs/windows | 11 processes; 735.8 MiB group private resident. Per-tab or actual release unknown; helps Windows, not guaranteed VM gain | Browser work/downloads/forms may be active; user chooses exact tabs. Agent closure requires explicit approval |
| Code unrelated saved windows only | 16 processes; 972.9 MiB group private resident | Previously a Specula window was observed. Preserve project IDE/terminals; no assertion all current windows are unrelated. Agent closure requires explicit approval |
| WhatsApp/other nonessential user apps | WhatsApp.Root and ChatGPT absent from the matched final snapshot; no further saving assigned to absent processes | Do not claim which exit caused the memory change. Keep the active codex/session and system/security/vendor services running |

Process footprints are observations, not promised recovery amounts; shared pages,
work ownership and future working-set behavior prevent safe automatic selection.

## Recommended next action

**Retain BLOCKED.** Do not provision under this read-only turn. The next targeted
VM-side option is a separately approved, state-preserving Kubernetes Stop after
you confirm the local cluster is unneeded. Do not disable it automatically and
do not apply the reduced budget. Then rerun these same Windows/VM readings.

If minimum VM availability reaches **10,704 MiB**, report admission PASS and that
Approval 1 provisioning **may resume under all unchanged conditions**, including
actual isolation/compatibility checks and exactly its two benign canaries. Report
the preferred 11,728 MiB reserve separately; admission alone is not a load-test or
paging-free guarantee. No Approval 2 or forensic investigation follows automatically.

Evidence: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\memory_recovery_followup_20261111_run01` — `admission_receipt.json`, three post-recovery samples,
Kubernetes inventory, source inspection/search, application snapshot and exact
read-only argv/stdout/stderr in `command_outputs.json`. No live runtime tests were
performed; parent tracked tree and existing Docker container IDs/states are unchanged.
