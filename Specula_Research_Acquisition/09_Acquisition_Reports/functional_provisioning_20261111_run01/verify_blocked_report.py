"""Reporting/preservation oracle. A zero exit is NEVER provisioning PASS."""
import hashlib,json,os,subprocess,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
memory=json.loads((RUN/'memory_admission.json').read_text())
preservation=json.loads((RUN/'preservation_receipt.json').read_text())
assert memory['status']=='BLOCKED' and preservation['status']=='PASS'
assert sum(memory['component_caps_MiB'].values())==10704
assert memory['required_bytes']==10704*1024**2
assert len(memory['samples'])==2 and all(x['MemAvailable_bytes']<memory['required_bytes'] for x in memory['samples'])
assert memory['available_bytes']==min(x['MemAvailable_bytes'] for x in memory['samples'])
assert memory['shortfall_bytes']==memory['required_bytes']-memory['available_bytes']
assert not memory['running_containers'] and not any(memory['container_delta_vs_preparation'].values())
assert all(memory[k]==0 for k in ['runtime_allocations','new_images_built','chat_requests','embedding_requests','investigation_requests'])
assert all(memory[k]==[] for k in ['new_volume_ids','new_container_ids','new_network_ids'])
assert not any(memory[k] for k in ['credentials_generated','gateway_implemented_or_run','model_release_created','nft_rules_applied'])
assert preservation['immutable_resource_hashes_verified']==5096 and preservation['mutable_hashes_deferred']==31
assert preservation['evaluator_files_verified']==296 and preservation['evaluator_acl_descriptors_checked']==411
assert preservation['errors']==[]
reports=['functional_runtime_provisioning_report.md','functional_isolation_results.md','model_gateway_validation.md',
         'service_compatibility_report.md','functional_smoke_readiness_decision.md']
hashes=[]
for name in reports:
    path=RUN.parent/name
    data=path.read_bytes();text=data.decode('utf-8')
    assert 'BLOCKED' in text and len(text)>1500,name
    assert text.count('```')%2==0,name
    hashes.append({'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
env=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1')
status=subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT.parent),'status','--porcelain=v1','-uno'],text=True,env=env)
assert not status
progress=(ROOT/'PROGRESS.md').read_text(encoding='utf-8')
assert '| Approval 1 functional runtime provisioning | blocked |' in progress
receipt={'reporting_oracle':'PASS','provisioning':'BLOCKED','approval_2':'NO-GO',
         'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'reports':hashes,
         'scope':'Consistency of retained admission/preservation receipts and blocked-status reports; no new runtime tests',
         'parent_tracked_status':status,'model_requests':0,'investigation_requests':0}
path=RUN/('report_verification_'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.json')
with path.open('x',encoding='utf-8') as stream:json.dump(receipt,stream,indent=2)
print(json.dumps({'reporting_oracle':'PASS','provisioning':'BLOCKED','approval_2':'NO-GO','reports_verified':len(reports),'receipt':str(path)}))
