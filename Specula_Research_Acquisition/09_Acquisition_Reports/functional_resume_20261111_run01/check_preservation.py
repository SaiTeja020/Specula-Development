"""Preservation audit only; does not provision, import Specula, or invoke a model."""
import csv,hashlib,json,os,subprocess,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
PREP=ROOT/'09_Acquisition_Reports/functional_smoke_preparation_20261111_run01'
def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
errors=[];verified=0;deferred=0;seen=set()
with (ROOT/'08_Checksums_And_Manifests/resource_checksums.csv').open(encoding='utf-8-sig',newline='') as stream:
    for row in csv.DictReader(stream):
        path=Path(row['local_path'])
        if str(path) in seen:continue
        seen.add(str(path))
        if 'mutable' in row['verification_status'].lower():deferred+=1;continue
        try:
            if path.stat().st_size!=int(row['actual_size_bytes']) or sha(path)!=row['sha256']:
                errors.append({'type':'resource_changed','path':str(path)})
            else:verified+=1
        except OSError as exc:errors.append({'type':'resource_unreadable','path':str(path),'error':str(exc)})
models=json.loads((PREP/'local_model_pins.json').read_text())
blobs=0
for model in models:
    if sha(model['manifest_path'])!=model['manifest_sha256']:errors.append({'type':'model_manifest','name':model['name']})
    for blob in model['blobs']:
        if Path(blob['path']).stat().st_size!=blob['bytes'] or 'sha256:'+sha(blob['path'])!=blob['digest']:
            errors.append({'type':'model_blob','path':blob['path']})
        blobs+=1
case=json.loads((PREP/'case_derivation.json').read_text())
for path,item in case['original'].items():
    if Path(path).stat().st_size!=item['bytes'] or sha(path)!=item['sha256']:errors.append({'type':'source_case_changed','path':path})
if sha(case['derived_path'])!=case['derived_sha256']:errors.append({'type':'derivative_changed'})
reference=json.loads((PREP/'reference_preparation_receipt.json').read_text())
for item in reference['files']:
    if not sha(item['source'])==sha(item['local_path'])==item['sha256']:errors.append({'type':'reference_changed','path':item['local_path']})
evals=json.loads((ROOT/'09_Acquisition_Reports/remediation_20261111T064220Z/immutable_evaluator_snapshot.json').read_text())
for item in evals:
    if Path(item['path']).stat().st_size!=item['bytes'] or sha(item['path'])!=item['sha256']:
        errors.append({'type':'evaluator_changed','path':item['path']})
acls=json.loads((RUN/'evaluator_acl_check.json').read_text(encoding='utf-8-sig'))
if len(acls)!=411 or not all(x['MatchesBaseline'] for x in acls):errors.append({'type':'evaluator_acl_changed'})
env=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1')
status=subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT.parent),'status','--porcelain=v1','-uno'],env=env,text=True)
head=subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT.parent),'rev-parse','HEAD'],env=env,text=True).strip()
if status or head!='b9b2012edaed8da5062113ddc9982e3c33b27983':errors.append({'type':'parent_repo_changed','status':status,'head':head})
receipt={'status':'PASS' if not errors else 'FAIL','scope':'read-only integrity/preservation only; provisioning remains BLOCKED',
         'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'immutable_resource_hashes_verified':verified,
         'mutable_hashes_deferred':deferred,'model_manifests_verified':len(models),'model_blob_entries_verified':blobs,
         'original_case_and_key_unchanged':True if not any(x['type']=='source_case_changed' for x in errors) else False,
         'reference_files_verified':len(reference['files']),'evaluator_files_verified':len(evals),'evaluator_acl_descriptors_checked':len(acls),
         'parent_head':head,'parent_tracked_status':status,'errors':errors}
with (RUN/'preservation_receipt.json').open('x',encoding='utf-8') as stream:json.dump(receipt,stream,indent=2)
print(json.dumps(receipt))
assert not errors
