"""Close out this read-only follow-up; retain the original budget and blocked state."""
import csv,hashlib,json,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
receipt=json.loads((RUN/'report_verification.json').read_text())
assert receipt['reporting']=='PASS' and receipt['admission']=='BLOCKED' and not receipt['R1_applied']
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('- Memory recovery follow-up clock-out: user explicitly confirmed manual app '
        'recovery finished before three fresh samples. Windows available 4,649.000–4,693.078 MiB; '
        'VM minimum 10,182.543 MiB. Original 10,704 MiB admission remains BLOCKED by '
        '521.457 MiB; preferred 11,728 MiB target short by 1,545.457 MiB. R1 NOT applied. '
        'No original resource limit or model setting changed.\n'
        '- Kubernetes remains enabled with 9 running kube-system pods only; no active '
        'application workloads/PV/PVC resources observed. Current Specula Compose/approved '
        'runtime has no detected live Kubernetes requirement; offline Kubernetes audit '
        'normalizers are not a deployment dependency. External/future clients and stored '
        'etcd configuration cannot be declared absent; any supported Stop needs explicit '
        'approval and data-preservation review. No Kubernetes action performed.\n'
        '- Updated memory admission report and raw receipts retained under '
        'memory_recovery_followup_20261111_run01. Reporting/arithmetic/source/WSL-config '
        'oracle PASS; parent progress validation PASS (47 tasks; WIP 2/2); parent tracked '
        'tree clean and existing Docker container IDs/states unchanged. No active task '
        'added; Approval 1 blocked slot retained. Next recommended decision: separately '
        'approve optional Kubernetes Stop if unneeded, then repeat readings. No provisioning, '
        'new container, process/service stop, setting change, model launch or investigation.\n')
targets=sorted([p for p in RUN.iterdir() if p.is_file()]+[RUN.parent/'updated_memory_admission_report.md',ROOT/'PROGRESS.md'])
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
manifest=RUN/'followup_artifact_checksums.csv'
with manifest.open('x',encoding='utf-8',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=['local_path','bytes','sha256']);writer.writeheader()
    for path in targets:writer.writerow({'local_path':str(path),'bytes':path.stat().st_size,'sha256':sha(path)})
with manifest.open(encoding='utf-8',newline='') as stream:rows=list(csv.DictReader(stream))
assert all(Path(row['local_path']).stat().st_size==int(row['bytes']) and sha(Path(row['local_path']))==row['sha256'] for row in rows)
final={'report_artifacts':'PASS','time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
    'artifact_hashes_verified':len(rows),'manifest_sha256':sha(manifest),'admission':'BLOCKED',
    'budget_MiB':10704,'deficit_MiB':521.45703125,'R1_applied':False,
    'actions_implemented':[],'provisioning_executed':False,'approval_2':'NOT AUTHORIZED'}
with (RUN/'final_followup_receipt.json').open('x',encoding='utf-8') as stream:json.dump(final,stream,indent=2)
print(json.dumps(final))
