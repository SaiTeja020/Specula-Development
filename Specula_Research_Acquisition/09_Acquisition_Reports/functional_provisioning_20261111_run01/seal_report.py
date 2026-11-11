"""Preserve the BLOCKED state and hash the completed reporting artifacts."""
import csv,hashlib,json,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
latest=sorted(RUN.glob('report_verification_*.json'))[-1]
assert json.loads(latest.read_text())['reporting_oracle']=='PASS'
assert json.loads((RUN/'final_container_observation.json').read_text())['status']=='PASS'
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('- Approval 1 clock-out: provisioning remains blocked and holds its local WIP slot '
        '(acquisition active + provisioning blocked = 2). Approved component caps total '
        '11,223,957,504 bytes; lower fresh VM MemAvailable 10,677,198,848 bytes; conservative '
        'full-budget shortfall 546,758,656 bytes (521.430 MiB). No measured OOM is claimed. '
        'No component omitted, limit changed or swap/host reconfiguration substituted.\n'
        '- Read-only preservation oracle PASS: 5,096 immutable hashes, 31 mutable hashes deferred, '
        '296 evaluator files, 411 ACL descriptors, two model manifests/seven blob entries, original '
        'ZIP/key, derived ZIP/reference copies and clean parent tracked tree verified. Parent '
        'progress oracle PASS (47 tasks, WIP 2/2). Existing container IDs/states unchanged on final '
        'check, none running. No runtime object built/created/started, no credential/model release/'
        'policy/gateway created, zero model/case requests.\n'
        '- Five required provisioning/security/gateway/service/readiness reports created. '
        'verify_blocked_report.py PASS only for truthful blocked reporting and integrity evidence; '
        'all expanded runtime security/service/model checks remain NOT RUN/BLOCKED. Approval 2 '
        'recommendation NO-GO. Audit receipts and new artifact hashes retained under '
        'functional_provisioning_20261111_run01. Resume unchanged Approval 1 only after fresh '
        'budget admission; revised limits/profile/admission policy require explicit approval. '
        'No forensic case, source/evidence/evaluator/ACL or existing-service change.\n')
names=['functional_runtime_provisioning_report.md','functional_isolation_results.md','model_gateway_validation.md',
       'service_compatibility_report.md','functional_smoke_readiness_decision.md']
targets=sorted([p for p in RUN.iterdir() if p.is_file()]+[RUN.parent/n for n in names]+[ROOT/'PROGRESS.md'])
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
manifest=RUN/'provisioning_report_checksums.csv'
with manifest.open('x',encoding='utf-8',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=['local_path','bytes','sha256']);writer.writeheader()
    for path in targets:writer.writerow({'local_path':str(path),'bytes':path.stat().st_size,'sha256':sha(path)})
with manifest.open(encoding='utf-8',newline='') as stream:rows=list(csv.DictReader(stream))
assert all(Path(row['local_path']).stat().st_size==int(row['bytes']) and sha(Path(row['local_path']))==row['sha256'] for row in rows)
receipt={'report_artifacts':'PASS','provisioning':'BLOCKED','approval_2':'NO-GO','artifact_hashes_verified':len(rows),
         'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'manifest_sha256':sha(manifest),
         'runtime_tests':'NOT RUN','chat_requests':0,'embedding_requests':0,'case_requests':0,
         'new_volume_ids':[],'new_container_ids':[],'new_network_ids':[]}
with (RUN/'final_report_receipt.json').open('x',encoding='utf-8') as stream:json.dump(receipt,stream,indent=2)
print(json.dumps(receipt))
