"""Record completed diagnostic evidence and checksum only newly authored artifacts."""
import csv,hashlib,json,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
check=sorted(RUN.glob('verification_*.json'))[-1]
assert json.loads(check.read_text())['diagnostic_artifact_verification']=='PASS'
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('- Memory diagnostic completed, Approval 1 provisioning remains blocked (held '
        'WIP slot; no new active task). Read-only Windows/WSL/settings/process/Kubernetes '
        'observations collected; 3 timed samples. VM minimum available 10,186.488 MiB versus '
        '10,704 MiB approved budget: 517.512 MiB short. Budget+1 GiB needs 1,541.512 MiB more; '
        'budget+2 GiB exceeds VM total even before baseline overhead. No measured stack peak '
        'or out-of-memory result claimed.\n'
        '- Hidden background consumer identified: Docker Kubernetes enabled, nine kube-system '
        'pods and no non-system application workloads/PVCs observed; Ubuntu already stopped; '
        'no Docker application containers running. Named Kubernetes processes 851.941 MiB PSS '
        '/435.898 MiB private dirty, not guaranteed additive recovery. Guest page cache already '
        'included in MemAvailable; swap unused and memory PSI zero. Windows pagefile occupied '
        'with low variable page-in counters, not proof of thrashing or future paging-free capacity.\n'
        '- Four requested diagnostic/recovery/proposal reports created. R1 is separately '
        'reviewable UNAPPROVED/UNAPPLIED, 9,680 MiB total, mandatory services/models/settings '
        'retained; only five future worker/service caps reduced, untested OOM/startup risks '
        'explicit. Current R1 arithmetic leaves only 506.488 MiB reserve, not 1 GiB.\n'
        '- Diagnostic oracle verify.py PASS: arithmetic/report scope only; 366 Windows process '
        'records, 57 direct WSL PSS rows; initial empty shell-loop collection retained and '
        'corrected without permission changes. Original WSL config fingerprint, selected Docker '
        'settings, Docker container IDs/states, Kubernetes pod names/phases and parent tracked '
        'source unchanged. Parent progress oracle PASS (47 tasks; WIP 2/2).\n'
        '- Clock-out: no shutdown/start/termination, cache clearing, settings/service/source '
        'change, deletion, model request, provisioning or Approval 2. Diagnostic outputs and '
        'progress metadata only. Recommended next: user-selected unrelated app closure, '
        'separately approved Kubernetes Stop if unused, then fresh two-layer capacity check; '
        'if insufficient review R1 or a larger-memory host. Do not implement automatically.\n')
names=['memory_capacity_diagnostic.md','memory_consumers_report.md','safe_memory_recovery_options.md','revised_budget_proposal.md']
targets=sorted([p for p in RUN.iterdir() if p.is_file()]+[RUN.parent/name for name in names]+[ROOT/'PROGRESS.md'])
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
manifest=RUN/'diagnostic_artifact_checksums.csv'
with manifest.open('x',encoding='utf-8',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=['local_path','bytes','sha256']);writer.writeheader()
    for path in targets:writer.writerow({'local_path':str(path),'bytes':path.stat().st_size,'sha256':sha(path)})
with manifest.open(encoding='utf-8',newline='') as stream:rows=list(csv.DictReader(stream))
assert all(Path(row['local_path']).stat().st_size==int(row['bytes']) and sha(Path(row['local_path']))==row['sha256'] for row in rows)
receipt={'diagnostic_artifacts':'PASS','time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
    'artifact_hashes_verified':len(rows),'manifest_sha256':sha(manifest),'runtime_changes':[],
    'provisioning':'BLOCKED','revised_budget':'UNAPPROVED / NOT APPLIED','approval_2':'NOT AUTHORIZED'}
with (RUN/'final_diagnostic_receipt.json').open('x',encoding='utf-8') as stream:json.dump(receipt,stream,indent=2)
print(json.dumps(receipt))
