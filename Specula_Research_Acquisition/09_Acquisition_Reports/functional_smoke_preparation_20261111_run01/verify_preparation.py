"""Static preparation oracle only. No application/model/service invocation."""
import csv,hashlib,json,os,stat,subprocess,sys,time,zipfile
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
PARENT=ROOT.parent
sys.path.insert(0,str(PARENT))
from src.ingestion.upload_archive import validate_archive,records_from_bytes
def read(name):return json.loads((RUN/name).read_text(encoding='utf-8-sig'))
def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
case=read('case_derivation.json');prep=read('preparation_receipt.json')
for path,item in case['original'].items():
    assert Path(path).stat().st_size==item['bytes'] and sha(path)==item['sha256'],path
source=next(Path(p) for p in case['original'] if p.endswith('.zip'))
package=Path(case['derived_path'])
assert package.stat().st_size==2750 and sha(package)==case['derived_sha256']
inventory=validate_archive(package.read_bytes())
assert sum(x['records'] for x in inventory['files'])==8 and len(inventory['files'])==5
with zipfile.ZipFile(source) as original,zipfile.ZipFile(package) as derived:
    assert original.testzip() is None and derived.testzip() is None
    assert set(original.namelist())==set(derived.namelist())
    assert set(json.loads(derived.read('manifest.json')))=={'files'}
    for name in original.namelist():
        if name=='manifest.json':continue
        before=records_from_bytes(original.read(name),name)
        after=records_from_bytes(derived.read(name),name)
        assert after==[{k:v for k,v in x.items() if k!='synthetic'} for x in before],name
for item in read('reference_preparation_receipt.json')['files']:
    assert sha(item['source'])==item['sha256']==sha(item['local_path'])
models=read('local_model_pins.json')
for model in models:
    assert sha(model['manifest_path'])==model['manifest_sha256']
    for blob in model['blobs']:
        assert Path(blob['path']).stat().st_size==blob['bytes']
        assert 'sha256:'+sha(blob['path'])==blob['digest']
for item in read('inspected_source_hashes.json'):assert sha(item['path'])==item['sha256'],item['path']
def admission(path):
    info=path.lstat()
    assert not getattr(info,'st_file_attributes',0)&0x400 and not stat.S_ISLNK(info.st_mode),str(path)
    if path.is_file():assert info.st_nlink==1,str(path)
    else:
        for child in path.iterdir():admission(child)
admission(RUN/'agent_evidence')
allowed={'case-input.zip','package.sha256','reference_only/build_manifest.json','reference_only/faiss_id_map.json',
         'reference_only/faiss_index.bin','reference_only/metadata_store.json'}
assert {p.relative_to(RUN/'agent_evidence').as_posix() for p in (RUN/'agent_evidence').rglob('*') if p.is_file()}==allowed
assert not prep['runtime_provisioned'] and not prep['investigation_started'] and prep['functional_results'] is None
reports=['functional_smoke_test_plan.md','functional_runtime_design.md','selected_synthetic_case_manifest.md',
         'functional_isolation_test_plan.md','smoke_test_approval_checklist.md']
for name in reports:
    text=(RUN.parent/name).read_text(encoding='utf-8')
    assert len(text)>2500 and 'PREPARATION ONLY' in text and text.count('```')%2==0,name
env=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1')
status=subprocess.check_output(['git','--no-optional-locks','-C',str(PARENT),'status','--porcelain=v1','-uno'],env=env,text=True)
head=subprocess.check_output(['git','--no-optional-locks','-C',str(PARENT),'rev-parse','HEAD'],env=env,text=True).strip()
assert status=='' and head=='b9b2012edaed8da5062113ddc9982e3c33b27983'
state=read('runtime_state_observation.json')
assert state['new_container_ids']==[] and state['removed_container_ids']==[] and state['state_changes']==[]
assert state['running']==[]
receipt={'status':'PASS','scope':'preparation artifact/static input and preservation checks ONLY',
    'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'source_records':8,'source_files':5,
    'derivative_sha256':sha(package),'original_zip_and_key_unchanged':True,'other_source_values_preserved':True,
    'model_manifests_verified':len(models),'model_blob_entries_verified':sum(len(x['blobs']) for x in models),
    'reference_files_verified':4,'reference_records':873,'read_root_reparse_free':True,
    'reports_present':len(reports),'parent_head':head,'parent_tracked_status':status,
    'no_runtime_objects_created_removed_or_reconfigured':True,'runtime_tests':'NOT RUN','model_inference':'NOT RUN',
    'functional_investigation':'NOT RUN','provisioning_recommendation':'GO after explicit approval for isolation-validation provisioning only'}
path=RUN/('verification_'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.json')
with path.open('x',encoding='utf-8') as stream:json.dump(receipt,stream,indent=2)
print(json.dumps(receipt))
