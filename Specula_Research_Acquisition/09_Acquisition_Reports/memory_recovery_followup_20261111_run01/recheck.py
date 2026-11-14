"""Read-only, post-user-recovery admission check. Never provision or stop resources."""
import hashlib,json,os,shutil,subprocess,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
outputs=[]
def put(name,data):
    with (RUN/name).open('x',encoding='utf-8') as stream:
        stream.write(data if isinstance(data,str) else json.dumps(data,indent=2))
def call(args,required=True):
    proc=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def decode(data):
        return data.decode('utf-16le',errors='replace').lstrip('\ufeff') if b'\0' in data[:100] else data.decode('utf-8-sig',errors='replace')
    out,err=decode(proc.stdout),decode(proc.stderr)
    outputs.append({'argv':args,'exit_code':proc.returncode,'stdout':out,'stderr':err})
    if required:assert proc.returncode==0,err
    return out
def ps(script):return json.loads(call(['powershell','-NoProfile','-NonInteractive','-Command',script]))
shutil.copy2(ROOT/'PROGRESS.md',RUN/'PROGRESS.before.md')
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('\n- Memory recovery follow-up clock-in under held Approval 1 scope: user retains '
        'original 10,704 MiB budget and rejects applying R1. User confirmed manual recovery '
        'finished; taking fresh read-only readings. No runtime/model/service/settings action '
        'authorized; no new active WIP slot. Parent progress oracle PASS (47 tasks; WIP 2/2).\n')
states=call(['wsl.exe','--list','--verbose'])
assert 'docker-desktop' in states and 'Running' in states
put('wsl_states.txt',states)
settings=ps(r"""$s=Get-Content -LiteralPath 'C:\Users\DELL\AppData\Roaming\Docker\settings-store.json' -Raw | ConvertFrom-Json;
[pscustomobject]@{KubernetesEnabled=$s.KubernetesEnabled;UseResourceSaver=$s.UseResourceSaver} | ConvertTo-Json""")
put('docker_settings.json',settings)
base=['kubectl','--context','docker-desktop','--request-timeout=10s','get']
pods=call(base+['pods','--all-namespaces','-o','custom-columns=NS:.metadata.namespace,NAME:.metadata.name,PHASE:.status.phase'])
workloads=call(base+['deployments,statefulsets,daemonsets,jobs,cronjobs','--all-namespaces'])
pvc=call(base+['pvc','--all-namespaces']);pv=call(base+['pv'])
put('kubernetes_inventory.json',{'pods':pods,'workloads':workloads,'PVC_stdout':pvc,'PV_stdout':pv,
    'limitations':'Read-only resource inventories; no secret/configmap/etcd content inspected. Existing stored cluster state/future clients cannot be ruled out.'})
containers=[json.loads(x) for x in call(['docker','ps','-a','--format','{{json .}}']).splitlines()]
put('docker_containers.json',containers)
apps=ps("""$names=@('Code','brave','WhatsApp.Root','ChatGPT','codex');
$perf=@{}; Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Where-Object {$_.IDProcess -gt 0} | ForEach-Object {$perf[[int]$_.IDProcess]=$_};
$rows=@(Get-Process | Where-Object {$_.ProcessName -in $names} | ForEach-Object {$p=$_;$q=$perf[[int]$p.Id];
[pscustomobject]@{Name=$p.ProcessName;PID=$p.Id;WorkingSetBytes=$p.WorkingSet64;
PrivateResidentBytes=$(if($null -ne $q){[long]$q.WorkingSetPrivate}else{$null});
WindowMentionsSpecula=([bool]($p.MainWindowTitle -match 'Specula'))}});
ConvertTo-Json -InputObject $rows -Depth 3""")
put('user_application_observation.json',apps)
source=[]
for relative in ['docker-compose.yml','docker-compose.local.yml','src/agents/kubernetes_audit.py',
                 'src/ingestion/normalization/kubernetes_normalizer.py']:
    path=ROOT.parent/relative
    source.append({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
put('source_inspection.json',source)
env=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1')
grep=subprocess.run(['git','--no-optional-locks','-C',str(ROOT.parent),'grep','-n','-I','-E',
    'kubectl|KUBECONFIG|kubernetes.client|minikube|helm ','--','src','scripts','docker-compose.local.yml','docker-compose.yml','README.md'],
    capture_output=True,text=True,env=env)
put('tracked_runtime_dependency_search.json',{'exit_code':grep.returncode,'stdout':grep.stdout,'stderr':grep.stderr,
    'scope':'Selected tracked source/scripts/Compose/README; no match is supporting evidence, not proof about unknown external work.'})
samples=[]
for index in range(3):
    windows=ps("""[pscustomobject]@{TimeUTC=[DateTime]::UtcNow.ToString('o');
OS=(Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory);
Memory=(Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | Select-Object AvailableMBytes,CommittedBytes,CommitLimit,PagesInputPersec,PagesOutputPersec)} | ConvertTo-Json -Depth 4""")
    raw=call(['wsl.exe','-d','docker-desktop','--','cat','/proc/meminfo'])
    mem={k:int(v.strip().split()[0])*1024 for k,v in (line.split(':',1) for line in raw.splitlines() if ':' in line)}
    pressure=call(['wsl.exe','-d','docker-desktop','--','cat','/proc/pressure/memory'])
    available=mem['MemAvailable']/1024**2
    samples.append({'windows':windows,'linux_meminfo_bytes':mem,'linux_pressure':pressure,
        'VM_available_MiB':available,'admission_deficit_MiB':max(0,10704-available),
        'preferred_deficit_MiB':max(0,11728-available)})
    if index<2:time.sleep(5)
put('post_user_recovery_samples.json',samples)
minimum=min(x['VM_available_MiB'] for x in samples)
status=call(['git','--no-optional-locks','-C',str(ROOT.parent),'status','--porcelain=v1','-uno'])
assert not status
old=json.loads((ROOT/'09_Acquisition_Reports/memory_diagnostic_20261111_run01/docker_containers.json').read_text())
a={x['ID']:x for x in old};b={x['ID']:x for x in containers}
assert a.keys()==b.keys() and all(a[k]['State']==b[k]['State'] for k in a)
receipt={'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
    'user_recovery':'User explicitly confirmed finished closing unused applications; exact closures not independently attributed.',
    'budget_MiB':10704,'reserve_MiB':1024,'preferred_MiB':11728,'minimum_VM_available_MiB':minimum,
    'admission':'PASS' if minimum>=10704 else 'BLOCKED','admission_deficit_MiB':max(0,10704-minimum),
    'preferred_target':'PASS' if minimum>=11728 else 'NOT MET','preferred_deficit_MiB':max(0,11728-minimum),
    'KubernetesEnabled':settings['KubernetesEnabled'],'observed_pods':[line.split() for line in pods.splitlines()[1:] if line.strip()],
    'running_docker_containers':[x['Names'] for x in containers if x['State']=='running'],
    'container_IDs_and_states_unchanged':True,'parent_tracked_status':status,
    'resource_limits_changed':False,'R1_applied':False,'actions_implemented':[],'provisioning_executed':False}
put('admission_receipt.json',receipt)
put('command_outputs.json',outputs)
print(json.dumps(receipt))
