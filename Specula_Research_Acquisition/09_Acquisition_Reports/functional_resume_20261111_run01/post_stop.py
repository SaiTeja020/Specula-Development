"""Verify the user-performed supported stop and take settled admission samples."""
import hashlib,json,subprocess,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
records=[]
def put(name,value):
    with (RUN/name).open('x',encoding='utf-8') as stream:stream.write(value if isinstance(value,str) else json.dumps(value,indent=2))
def call(args):
    proc=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def decode(data):return data.decode('utf-16le',errors='replace').lstrip('\ufeff') if b'\0' in data[:100] else data.decode('utf-8-sig',errors='replace')
    out,err=decode(proc.stdout),decode(proc.stderr)
    records.append({'argv':args,'exit_code':proc.returncode,'stdout':out,'stderr':err})
    return out,proc.returncode
def ps(script):
    out,code=call(['powershell','-NoProfile','-NonInteractive','-Command',script]);assert code==0;return json.loads(out)
settings=ps(r"""$s=Get-Content -LiteralPath 'C:\Users\DELL\AppData\Roaming\Docker\settings-store.json' -Raw | ConvertFrom-Json;
$out=@{}; $s.PSObject.Properties | Where-Object {$_.Name -match '(?i)kubernetes|wsl|memory|swap|cpu|resource.?saver'} | ForEach-Object {$out[$_.Name]=$_.Value}; ConvertTo-Json -InputObject $out -Depth 6""")
put('post_stop_docker_settings.json',settings)
assert settings['KubernetesEnabled'] is False
api,api_code=call(['kubectl','--context','docker-desktop','--request-timeout=3s','get','--raw=/readyz'])
assert api_code!=0,'Kubernetes API still ready; do not assume stopped'
processes,code=call(['wsl.exe','-d','docker-desktop','--','ps','-o','pid,ppid,user,rss,vsz,comm']);assert code==0
put('post_stop_processes.txt',processes)
assert not any(token in processes for token in ['kube-apiserver','kube-controller','kube-scheduler','kubelet','cri-dockerd','coredns','etcd'])
after={}
for key,cmd in [('containers',['docker','ps','-a','--format','{{json .}}']),
                ('volumes',['docker','volume','ls','--format','{{json .}}']),
                ('networks',['docker','network','ls','--format','{{json .}}'])]:
    text,code=call(cmd);assert code==0
    after[key]=[json.loads(line) for line in text.splitlines()]
    put('post_stop_'+key+'.json',after[key])
pre_containers=json.loads((RUN/'pre_stop_containers.json').read_text())
a={x['ID']:x for x in pre_containers};b={x['ID']:x for x in after['containers']}
delta={'new_container_ids':sorted(b.keys()-a.keys()),'removed_container_ids':sorted(a.keys()-b.keys()),
       'container_state_changes':[k for k in a.keys()&b.keys() if a[k]['State']!=b[k]['State']]}
old_vol={x['Name'] for x in json.loads((RUN/'pre_stop_volumes.json').read_text())}
new_vol={x['Name'] for x in after['volumes']}
delta.update({'removed_volume_names':sorted(old_vol-new_vol),'new_volume_names':sorted(new_vol-old_vol)})
assert not any(delta.values()),delta
cfg=json.loads((RUN/'wslconfig_fingerprint.json').read_text())
assert hashlib.sha256(Path(cfg['path']).read_bytes()).hexdigest()==cfg['sha256']
samples=[]
for number in range(3):
    windows=ps("""[pscustomobject]@{TimeUTC=[DateTime]::UtcNow.ToString('o');
OS=(Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory);
Memory=(Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | Select-Object AvailableMBytes,CommittedBytes,CommitLimit,PagesInputPersec,PagesOutputPersec)} | ConvertTo-Json -Depth 4""")
    raw,code=call(['wsl.exe','-d','docker-desktop','--','cat','/proc/meminfo']);assert code==0
    values={k:int(v.strip().split()[0])*1024 for k,v in (line.split(':',1) for line in raw.splitlines() if ':' in line)}
    pressure,_=call(['wsl.exe','-d','docker-desktop','--','cat','/proc/pressure/memory'])
    samples.append({'windows':windows,'VM_meminfo_bytes':values,'VM_available_MiB':values['MemAvailable']/1024**2,'pressure':pressure})
    if number<2:time.sleep(10)
put('post_stop_memory_samples.json',samples)
minimum=min(x['VM_available_MiB'] for x in samples)
previous=json.loads((ROOT/'09_Acquisition_Reports/memory_recovery_followup_20261111_run01/admission_receipt.json').read_text())['minimum_VM_available_MiB']
receipt={'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
    'stop_actor':'User via supported Docker Desktop UI, explicitly confirmed stopped; independently verified settings/API/process effects',
    'KubernetesEnabled':False,'Kubernetes_API_unavailable':True,'Kubernetes_processes_absent':True,
    'existing_container_and_volume_delta':delta,'WSL_config_unchanged':True,'Docker_engine_available':True,
    'minimum_VM_available_MiB':minimum,'previous_minimum_MiB':previous,'increase_vs_previous_minimum_MiB':minimum-previous,
    'approved_budget_MiB':10704,'admission':'PASS' if minimum>=10704 else 'BLOCKED',
    'approved_budget_deficit_MiB':max(0,10704-minimum),'preferred_total_MiB':11728,
    'preferred_deficit_MiB':max(0,11728-minimum),
    'R1_budget_MiB':9680,'R1_cap_only_admission':'PASS' if minimum>=9680 else 'BLOCKED',
    'R1_remaining_headroom_MiB':minimum-9680,'R1_1GiB_reserve_met':minimum>=10704,
    'R1_1GiB_reserve_deficit_MiB':max(0,10704-minimum),'R1_applied':False,
    'new_runtime_objects':[],'models_started':False,'model_canary_requests':0,'forensic_investigations':0,
    'storage_limit':'Docker volume names unchanged; cluster data not deleted by agent. Stop inventory is not an etcd backup; stored cluster content not re-read while stopped.'}
put('post_stop_receipt.json',receipt);put('post_stop_commands.json',records)
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('- User confirmed supported Kubernetes UI shutdown after UI-helper technical '
        'handoff. Verified KubernetesEnabled=false, API unavailable and system processes absent; '
        'Docker Engine available, existing container IDs/states and volume names unchanged, '
        'WSL configuration hash unchanged. Three settled post-stop samples captured; original '
        'budget admission '+receipt['admission']+'. No unrelated stop or R1 application.\n')
print(json.dumps(receipt))
