"""Read-only resource admission. Creates audit files, never runtime objects."""
import json,os,shutil,subprocess,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
def write(name,value):
    with (RUN/name).open('x',encoding='utf-8') as stream:
        stream.write(value if isinstance(value,str) else json.dumps(value,indent=2))
def command(args):
    proc=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',errors='replace')
    records.append({'argv':args,'exit_code':proc.returncode,'stdout':proc.stdout,'stderr':proc.stderr})
    assert proc.returncode==0,proc.stderr
    return proc.stdout
records=[]
shutil.copy2(ROOT/'PROGRESS.md',RUN/'PROGRESS.before.md')
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('\n- Approval 1 provisioning clock-in: user authorized new standalone runtime and '
        'one chat/one embedding canary, with mandatory stop conditions. Read approved runtime '
        'design/checklist, current progress and parent decisions; parent progress oracle PASS '
        '(47 tasks; WIP 2/2). Existing source clean. Resource admission precedes all allocations; '
        'no case/ingestion/graph or Approval 2 execution authorized. Progress backed up.\n')
caps={'ollama':7168,'worker':1024,'neo4j':768,'kafka':768,'chroma':384,'quickwit':384,
      'redis':64,'gateway':64,'coordinator':64,'anchor':16}
required=sum(caps.values())*1024**2
host=command(['powershell','-NoProfile','-NonInteractive','-Command',
    'Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,FreeVirtualMemory,TotalVirtualMemorySize | ConvertTo-Json'])
host=json.loads(host)
samples=[]
for number in range(2):
    raw=command(['wsl.exe','-d','docker-desktop','--','cat','/proc/meminfo'])
    parsed={}
    for line in raw.splitlines():
        key,value=line.split(':',1)
        parsed[key]=int(value.strip().split()[0])*1024
    samples.append({'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                    'MemTotal_bytes':parsed['MemTotal'],'MemAvailable_bytes':parsed['MemAvailable'],
                    'MemFree_bytes':parsed['MemFree'],'Cached_bytes':parsed['Cached'],
                    'SwapTotal_bytes':parsed['SwapTotal'],'SwapFree_bytes':parsed['SwapFree']})
engine=json.loads(command(['docker','info','--format','{"memory_bytes":{{.MemTotal}},"cpus":{{.NCPU}}}']))
containers=[json.loads(x) for x in command(['docker','ps','-a','--format','{{json .}}']).splitlines()]
running=[x['Names'] for x in containers if x['State']=='running']
before=ROOT/'09_Acquisition_Reports/functional_smoke_preparation_20261111_run01/runtime_state_observation.json'
prior=json.loads(before.read_text(encoding='utf-8'))['containers']
a={x['ID']:x for x in prior};b={x['ID']:x for x in containers}
delta={'new_ids':sorted(b.keys()-a.keys()),'removed_ids':sorted(a.keys()-b.keys()),
       'state_changes':[k for k in a.keys()&b.keys() if a[k]['State']!=b[k]['State']]}
available=min(x['MemAvailable_bytes'] for x in samples)
blocked=available<required
receipt={'status':'BLOCKED' if blocked else 'ADMITTED','time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
    'reason':'Available Docker VM memory does not cover the full approved component-limit budget.' if blocked else 'Approved budget fits available VM memory.',
    'admission_policy':'Conservative preallocation check: sum of approved component memory caps must fit MemAvailable; no swap credit and no extra reserve imposed.',
    'not_a_measurement_of_peak':'Caps are upper bounds, not measured demand; this check does not claim a model or service actually ran out of memory.',
    'component_caps_MiB':caps,'required_bytes':required,'required_MiB':sum(caps.values()),
    'available_bytes':available,'shortfall_bytes':max(0,required-available),'samples':samples,
    'host_observation_KiB':host,'docker_engine':engine,'running_containers':running,'container_delta_vs_preparation':delta,
    'containers':containers,'runtime_allocations':0,'new_images_built':0,'new_volume_ids':[],
    'new_container_ids':[],'new_network_ids':[],'chat_requests':0,'embedding_requests':0,
    'investigation_requests':0,'credentials_generated':False,'gateway_implemented_or_run':False,
    'model_release_created':False,'nft_rules_applied':False}
write('command_outputs.json',records)
write('memory_admission.json',receipt)
assert blocked,'Admission now passes; stop this reporting-only script and reassess before provisioning.'
assert not running and not any(delta.values()),delta
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('- Approval 1 mandatory admission stop: BLOCKED. Two fresh Docker VM samples '
        'do not cover the approved 10,704 MiB component-cap budget; exact available/shortfall '
        'bytes and original command outputs are in functional_provisioning_20261111_run01/'
        'memory_admission.json. Conservative full-budget admission, not a measured OOM. '
        'No runtime object, image build, volume, model release, policy/credential or inference '
        'was created or started; existing container IDs/states unchanged, none running. '
        'Only preservation verification and requested blocked-status reporting continue.\n')
print(json.dumps({k:receipt[k] for k in ['status','required_bytes','available_bytes','shortfall_bytes','chat_requests','embedding_requests','runtime_allocations']}))
