"""Read-only preservation/configuration oracle; creates a NEW receipt only."""
import csv, hashlib, json, os, subprocess, sys, time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
OLD=ROOT/'09_Acquisition_Reports/remediation_20261111T064220Z'
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
errors=[]
with (ROOT/'08_Checksums_And_Manifests/resource_checksums.csv').open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
seen=set();verified=0;deferred=0
for row in rows:
    path=Path(row['local_path'])
    if str(path) in seen:continue
    seen.add(str(path))
    if 'mutable' in row['verification_status'].lower():deferred+=1;continue
    try:
        if path.stat().st_size!=int(row['actual_size_bytes']) or sha(path)!=row['sha256']:
            errors.append({'type':'resource_changed','path':str(path)})
        else:verified+=1
    except OSError as exc:errors.append({'type':'resource_unreadable','path':str(path),'error':str(exc)})
evaluator=json.loads((OLD/'immutable_evaluator_snapshot.json').read_text())
for item in evaluator:
    path=Path(item['path'])
    if not path.is_file() or path.stat().st_size!=item['bytes'] or sha(path)!=item['sha256']:
        errors.append({'type':'evaluator_changed','path':str(path)})
acl_file=RUN/'evaluator_acl_final_check.json'
if not acl_file.exists():acl_file=RUN/'evaluator_acl_check.json'
acls=json.loads(acl_file.read_text(encoding='utf-8-sig'))
if len(acls)!=411 or not all(x['MatchesBaseline'] for x in acls):errors.append({'type':'acl_changed'})
env=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1')
status=subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT.parent),'status','--porcelain=v1','-uno'],env=env,text=True)
head=subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT.parent),'rev-parse','HEAD'],env=env,text=True).strip()
baseline=json.loads((RUN/'baseline.json').read_text())
if status or head!=baseline['head']:errors.append({'type':'parent_source_changed','status':status,'head':head})
runtime=json.loads((RUN/'runtime_receipt.json').read_text())
leak=json.loads((RUN/'leakage_scan.json').read_text())
admission=json.loads((RUN/'admission_test.json').read_text())
config=json.loads((RUN/'container_inspect_after.json').read_text())
hc=config['HostConfig'];mounts=config['Mounts']
config_ok=(config['Config']['User']=='10001:10001' and hc['NetworkMode']=='none' and hc['ReadonlyRootfs']
    and not hc['Privileged'] and hc['CapDrop']==['ALL'] and not hc.get('PortBindings') and not hc.get('ExtraHosts')
    and not hc.get('Devices') and not hc.get('Binds') and not hc.get('VolumesFrom')
    and hc['PidMode']=='' and hc['IpcMode']=='none' and not config['Config'].get('Volumes')
    and len(mounts)==1 and mounts[0]['Type']=='bind' and not mounts[0]['RW']
    and mounts[0]['Destination']=='/evidence/agent_evidence'
    and mounts[0]['Source'].replace('\\','/').lower().endswith('/isolation_20261111_run01/fixtures/evidence'))
if not config_ok:errors.append({'type':'runtime_config'})
if runtime['status']!='PASS':errors.append({'type':'runtime_tests','failures':[x for x in runtime['tests'] if x['status']!='PASS']})
if config['State']['Running'] or config['State']['ExitCode']!=0:errors.append({'type':'runtime_not_cleanly_completed'})
if leak['status']!='PASS' or admission['status']!='PASS':errors.append({'type':'leakage_or_admission'})
image_audit=json.loads((RUN/'image_audit_receipt.json').read_text())
if image_audit['status']!='PASS':errors.append({'type':'image_audit'})
final=json.loads((RUN/'docker_final_state.json').read_text(encoding='utf-8-sig'))
if final['Running']:errors.append({'type':'unexpected_running_containers','names':final['Running']})
receipt={'status':'PASS' if not errors else 'FAIL','scope':'actual non-root network-none Specula API/tool synthetic access preflight ONLY',
    'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'resource_hashes_verified':verified,'mutable_hashes_deferred':deferred,
    'evaluator_files_preserved':len(evaluator),'evaluator_acl_descriptors_unchanged':len(acls),
    'parent_head':head,'parent_tracked_status':status,'runtime_tests':len(runtime['tests']),
    'runtime_image':config['Image'],'runtime_user':config['Config']['User'],
    'image_files_scanned':image_audit['regular_files'],'running_containers':final['Running'],'errors':errors,
    'functional_or_empirical_readiness':'NOT AUTHORIZED / NOT ESTABLISHED'}
target=RUN/('verification_'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.json')
with target.open('x',encoding='utf-8') as f:json.dump(receipt,f,indent=2)
print(json.dumps(receipt))
sys.exit(0 if not errors else 1)
