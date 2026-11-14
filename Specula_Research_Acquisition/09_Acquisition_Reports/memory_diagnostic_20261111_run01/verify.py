"""Verify diagnostic arithmetic/artifacts and read-only state preservation."""
import hashlib,json,os,subprocess,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
def load(name):return json.loads((RUN/name).read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
calc=load('capacity_calculations.json');samples=load('memory_samples.json')
assert len(samples)==3
assert calc['VM_MemAvailable_min_MiB']==min(x['linux_meminfo_bytes']['MemAvailable'] for x in samples)/1024**2
for headroom in [0,1024,2048]:
    assert calc['required_extra_MiB'][str(headroom)]==max(0,10704+headroom-calc['VM_MemAvailable_min_MiB'])
assert calc['required_extra_MiB']['0']>0 and calc['VM_deficit_even_if_empty_for_2GiB_MiB']>0
assert calc['actions_applied']==[] and calc['provisioning']=='BLOCKED'
proposal=load('revised_budget_PROPOSED.json')
assert sum(proposal['component_caps_MiB'].values())==9680 and proposal['component_caps_MiB']['ollama']==7168
assert not proposal['execution_authorized'] and proposal['status'].startswith('UNAPPROVED')
pss=load('wsl_pss_supplement.json')
assert pss['status']=='PASS' and len(pss['processes'])==57
assert len(pss['missing_pids'])==3
assert all(x['Rss_KiB']>=x['Pss_KiB'] and x['Swap_KiB']==0 for x in pss['processes'])
assert 'kube-system' in (RUN/'kubernetes_pods.txt').read_text()
assert all(line.split()[0]=='kube-system' for line in (RUN/'kubernetes_pods.txt').read_text().splitlines()[1:] if line.strip())
cfg=load('wslconfig_fingerprint.json')
assert sha(cfg['path'])==cfg['sha256'],'WSL config changed'
before=load('docker_resource_settings.json')
query=r"""$s=Get-Content -LiteralPath 'C:\Users\DELL\AppData\Roaming\Docker\settings-store.json' -Raw | ConvertFrom-Json;
$result=@{}; $s.PSObject.Properties | Where-Object {$_.Name -match '(?i)memory|swap|cpu|wsl|resource.?saver|auto.*reclaim|kubernetes'} | ForEach-Object {$result[$_.Name]=$_.Value}; ConvertTo-Json -InputObject $result -Depth 5"""
after=json.loads(subprocess.check_output(['powershell','-NoProfile','-NonInteractive','-Command',query],text=True))
assert after==before,'Selected Docker settings changed'
old={x['ID']:x for x in load('docker_containers.json')}
new={x['ID']:x for x in [json.loads(line) for line in subprocess.check_output(['docker','ps','-a','--format','{{json .}}'],text=True).splitlines()]}
assert old.keys()==new.keys() and all(old[k]['State']==new[k]['State'] for k in old)
assert not any(x['State']=='running' for x in new.values())
pods=subprocess.check_output(['kubectl','--context','docker-desktop','--request-timeout=10s','get','pods','--all-namespaces','-o','custom-columns=NS:.metadata.namespace,NAME:.metadata.name,PHASE:.status.phase'],text=True)
assert pods.split()==(RUN/'kubernetes_pods.txt').read_text().split(),'Kubernetes pod names/phases changed'
env=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1')
status=subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT.parent),'status','--porcelain=v1','-uno'],env=env,text=True)
head=subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT.parent),'rev-parse','HEAD'],env=env,text=True).strip()
assert status=='' and head=='b9b2012edaed8da5062113ddc9982e3c33b27983'
reports=['memory_capacity_diagnostic.md','memory_consumers_report.md','safe_memory_recovery_options.md','revised_budget_proposal.md']
for name in reports:
    text=(RUN.parent/name).read_text(encoding='utf-8')
    assert len(text)>2000 and 'READ-ONLY' in text and text.count('```')%2==0,name
receipt={'diagnostic_artifact_verification':'PASS','scope':'arithmetic, source observations, unchanged runtime/config and meaningful reports; not provisioning or a load test',
    'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'reports_verified':4,
    'windows_process_records':len(load('windows_memory_and_processes.json')['Processes']),
    'WSL_PSS_process_records':len(pss['processes']),'unchanged_wslconfig_sha256':cfg['sha256'],
    'selected_docker_settings_unchanged':True,'docker_container_ids_and_states_unchanged':True,
    'kubernetes_pod_names_and_phases_unchanged':True,'parent_head':head,'parent_tracked_status':status,
    'recovery_actions_executed':[],'revised_budget_applied':False,'provisioning':'BLOCKED','approval_2':'NOT AUTHORIZED'}
path=RUN/('verification_'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.json')
with path.open('x',encoding='utf-8') as stream:json.dump(receipt,stream,indent=2)
print(json.dumps(receipt))
