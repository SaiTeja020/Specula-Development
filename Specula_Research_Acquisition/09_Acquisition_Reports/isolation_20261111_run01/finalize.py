"""Record completed checks and seal a final point-in-time artifact manifest."""
import csv,hashlib,json,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
receipt=RUN/'verification_20261111T073829Z.json'
assert json.loads(receipt.read_text())['status']=='PASS'
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('- Final isolation checkpoint: fresh post-test ACL capture again matches all 411 '
        'descriptors; strengthened verification_20261111T073829Z.json PASS, including full image '
        'scan and preservation checks. Five Markdown deliverables inspected (52–129 lines); '
        'initial 37-artifact checksum checkpoint passed before final oracle/ACL receipt additions. '
        'New final_artifact_checksums.csv supersedes that point-in-time inventory for current '
        'report/script/progress hashes. No functional or empirical approval inferred.\n')
with (RUN.parent/'isolation_verification_summary.md').open('a',encoding='utf-8') as stream:
    stream.write('\n## Final checkpoint\n\nFresh post-test `evaluator_acl_final_check.json` again matches all 411 '
        'original descriptors. Strengthened `verification_20261111T073829Z.json` is PASS. '
        'The current report/script/progress hash inventory is '
        '`isolation_20261111_run01/final_artifact_checksums.csv`; '
        '`final_artifact_receipt.json` records its digest and validation. '
        'Earlier inventories/receipts remain historical snapshots and are not overwritten.\n')
names=['isolated_runtime_configuration.md','runtime_access_test_results.md','isolation_change_log.md','isolation_rollback_plan.md','isolation_verification_summary.md']
targets=sorted([p for p in RUN.iterdir() if p.is_file()]+[RUN.parent/n for n in names]+[ROOT/'PROGRESS.md'])
def sha(p):
    with p.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
manifest=RUN/'final_artifact_checksums.csv'
with manifest.open('x',encoding='utf-8',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=['local_path','bytes','sha256']);writer.writeheader()
    for p in targets:writer.writerow({'local_path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)})
with manifest.open(encoding='utf-8',newline='') as stream:rows=list(csv.DictReader(stream))
assert all(Path(x['local_path']).stat().st_size==int(x['bytes']) and sha(Path(x['local_path']))==x['sha256'] for x in rows)
final={'status':'PASS','time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
       'artifacts_verified':len(rows),'manifest_sha256':sha(manifest),
       'preservation_receipt':str(receipt),'initial_inventory':'historical snapshot, superseded by final_artifact_checksums.csv',
       'scope':'synthetic access isolation only; no functional or empirical execution authorized'}
with (RUN/'final_artifact_receipt.json').open('x',encoding='utf-8') as stream:json.dump(final,stream,indent=2)
print(json.dumps(final))
