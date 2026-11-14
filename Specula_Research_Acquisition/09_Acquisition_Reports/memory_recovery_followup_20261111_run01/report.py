"""Summarize verified post-user-recovery observations; do not implement recovery."""
import collections,hashlib,json,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
def load(name):return json.loads((RUN/name).read_text(encoding='utf-8'))
receipt=load('admission_receipt.json');samples=load('post_user_recovery_samples.json')
assert receipt['budget_MiB']==10704 and receipt['preferred_MiB']==11728 and not receipt['R1_applied']
minimum=min(x['VM_available_MiB'] for x in samples)
assert receipt['minimum_VM_available_MiB']==minimum
assert receipt['admission_deficit_MiB']==max(0,10704-minimum)
assert receipt['preferred_deficit_MiB']==max(0,11728-minimum)
assert receipt['actions_implemented']==[] and not receipt['provisioning_executed']
pods=receipt['observed_pods']
assert len(pods)==9 and all(x[0]=='kube-system' and x[2]=='Running' for x in pods)
groups=collections.defaultdict(lambda:{'count':0,'private_bytes':0})
for row in load('user_application_observation.json'):
    groups[row['Name']]['count']+=1;groups[row['Name']]['private_bytes']+=row['PrivateResidentBytes'] or 0
windows=[x['windows']['OS']['FreePhysicalMemory']/1024 for x in samples]
rows='\n'.join(f"| {x['windows']['TimeUTC']} | {x['windows']['OS']['FreePhysicalMemory']/1024:,.3f} | {x['VM_available_MiB']:,.3f} |" for x in samples)
out=RUN.parent/'updated_memory_admission_report.md'
with out.open('x',encoding='utf-8',newline='\n') as stream:
    stream.write(f'''# Updated memory admission report

11 November 2026. Read-only follow-up after the user explicitly confirmed
“Finished; take fresh readings.” Original budget **10,704 MiB retained**;
9,680 MiB alternative **not applied**. No process, Kubernetes service, setting,
resource limit, container, model or investigation was started/stopped/changed.

## Admission after user-performed recovery

| UTC | Windows physical available MiB | Docker VM MemAvailable MiB |
| --- | ---: | ---: |
{rows}

| Target | Required MiB | Deficit at minimum VM reading |
| --- | ---: | ---: |
| Original admission | 10,704 | **{receipt['admission_deficit_MiB']:,.3f} MiB** |
| Original + preferred 1,024 MiB reserve | 11,728 | **{receipt['preferred_deficit_MiB']:,.3f} MiB** |

**Result: {receipt['admission']}.** Lowest VM availability:
**{minimum:,.3f} MiB**. Windows available range:
{min(windows)/1024:.3f}–{max(windows)/1024:.3f} GiB. User recovery improved the
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
the {receipt['admission_deficit_MiB']:,.3f} MiB deficit; remeasurement is mandatory.

## Manual application options

No remaining application was certified unused or safe for automatic closure.
You may manually exit only windows/tabs you identify as idle, after saving work:

| Candidate | Current observation / possible benefit | Risk / permission |
| --- | --- | --- |
| Brave unused tabs/windows | {groups['brave']['count']} processes; {groups['brave']['private_bytes']/1024**2:,.1f} MiB group private resident. Per-tab or actual release unknown; helps Windows, not guaranteed VM gain | Browser work/downloads/forms may be active; user chooses exact tabs. Agent closure requires explicit approval |
| Code unrelated saved windows only | {groups['Code']['count']} processes; {groups['Code']['private_bytes']/1024**2:,.1f} MiB group private resident | Previously a Specula window was observed. Preserve project IDE/terminals; no assertion all current windows are unrelated. Agent closure requires explicit approval |
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

Evidence: `{RUN}` — `admission_receipt.json`, three post-recovery samples,
Kubernetes inventory, source inspection/search, application snapshot and exact
read-only argv/stdout/stderr in `command_outputs.json`. No live runtime tests were
performed; parent tracked tree and existing Docker container IDs/states are unchanged.
''')
# Static verification of report and preserved source/configuration inputs.
for item in load('source_inspection.json'):
    assert hashlib.sha256(Path(item['path']).read_bytes()).hexdigest()==item['sha256']
cfg=json.loads((ROOT/'09_Acquisition_Reports/memory_diagnostic_20261111_run01/wslconfig_fingerprint.json').read_text())
assert hashlib.sha256(Path(cfg['path']).read_bytes()).hexdigest()==cfg['sha256']
verification={'reporting':'PASS','admission':receipt['admission'],'budget_MiB':10704,
    'VM_minimum_MiB':minimum,'deficit_MiB':receipt['admission_deficit_MiB'],
    'preferred_deficit_MiB':receipt['preferred_deficit_MiB'],'R1_applied':False,
    'read_only_source_and_wslconfig_checks':'PASS','recovery_by_agent':False,
    'report_path':str(out),'report_sha256':hashlib.sha256(out.read_bytes()).hexdigest()}
with (RUN/'report_verification.json').open('x',encoding='utf-8') as stream:json.dump(verification,stream,indent=2)
print(json.dumps(verification))
