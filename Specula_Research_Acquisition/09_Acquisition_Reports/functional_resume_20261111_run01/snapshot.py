"""Record pre-stop configuration/state and backups; never issue a stop or build."""
import hashlib,json,shutil,subprocess,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
records=[]
def put(name,value):
    with (RUN/name).open('x',encoding='utf-8') as stream:stream.write(value if isinstance(value,str) else json.dumps(value,indent=2))
def call(args,required=True):
    proc=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def decode(data):return data.decode('utf-16le',errors='replace').lstrip('\ufeff') if b'\0' in data[:100] else data.decode('utf-8-sig',errors='replace')
    out,err=decode(proc.stdout),decode(proc.stderr)
    records.append({'argv':args,'exit_code':proc.returncode,'stdout':out,'stderr':err})
    if required:assert proc.returncode==0,err
    return out
backup=RUN/'backup';backup.mkdir()
names=['functional_runtime_provisioning_report.md','functional_isolation_results.md','model_gateway_validation.md',
       'service_compatibility_report.md','functional_smoke_readiness_decision.md']
manifest=[]
for path in [ROOT/'PROGRESS.md',*[ROOT/'09_Acquisition_Reports'/name for name in names]]:
    dest=backup/path.name
    with dest.open('xb') as stream:stream.write(path.read_bytes())
    manifest.append({'source':str(path),'backup':str(dest),'sha256':hashlib.sha256(dest.read_bytes()).hexdigest()})
put('backup_manifest.json',manifest)
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('\n- Authorized Kubernetes stop/Approval 1 resume clock-in: final inspection '
        'still shows system-only cluster and no PV/PVC/application workload. Original '
        '10,704 MiB budget retained; no R1 applied. Parent progress oracle PASS (47 tasks; '
        'WIP 2/2), source clean. Five previous reports/progress backed up. Supported CLI '
        'has no Kubernetes Stop; UI native helper failed three list_apps attempts '
        'including retry/reset. No stop/input/settings/runtime action has occurred.\n')
put('supported_cli_help.txt',call(['docker','desktop','--help'])+call(['docker','desktop','kubernetes','--help'])+call(['docker','desktop','disable','--help']))
put('docker_desktop_cli_version.txt',call(['docker','desktop','version'],required=False))
ps=r"""$s=Get-Content -LiteralPath 'C:\Users\DELL\AppData\Roaming\Docker\settings-store.json' -Raw | ConvertFrom-Json;
$out=@{}; $s.PSObject.Properties | Where-Object {$_.Name -match '(?i)kubernetes|wsl|memory|swap|cpu|resource.?saver'} | ForEach-Object {$out[$_.Name]=$_.Value}; ConvertTo-Json -InputObject $out -Depth 6"""
put('pre_stop_docker_settings.json',json.loads(call(['powershell','-NoProfile','-NonInteractive','-Command',ps])))
base=['kubectl','--context','docker-desktop','--request-timeout=10s']
for label,args in {
    'pods':['get','pods','--all-namespaces','-o','custom-columns=NS:.metadata.namespace,NAME:.metadata.name,UID:.metadata.uid,PHASE:.status.phase'],
    'workloads':['get','deployments,statefulsets,daemonsets,jobs,cronjobs','--all-namespaces'],
    'pvc':['get','pvc','--all-namespaces'],'pv':['get','pv'],
    'nodes':['get','nodes','-o','wide'],'namespaces':['get','namespaces'],
    'api_version':['version','-o','json'],
    }.items():put('pre_stop_kubernetes_'+label+'.txt',call(base+args))
put('pre_stop_containers.json',[json.loads(line) for line in call(['docker','ps','-a','--format','{{json .}}']).splitlines()])
put('pre_stop_volumes.json',[json.loads(line) for line in call(['docker','volume','ls','--format','{{json .}}']).splitlines()])
put('pre_stop_networks.json',[json.loads(line) for line in call(['docker','network','ls','--format','{{json .}}']).splitlines()])
cfg=Path(r'C:\Users\DELL\.wslconfig')
put('wslconfig_fingerprint.json',{'path':str(cfg),'sha256':hashlib.sha256(cfg.read_bytes()).hexdigest()})
put('ui_connection_failure.json',{'package':'@oai/sky','operation':'sky.list_apps()',
    'attempts':3,'session_resets':1,'target_window_acquired':False,'UI_inputs_issued':0,
    'error':'Computer Use native pipe is unavailable: failed to connect native pipe: The system cannot find the file specified. (os error 2)',
    'scope':'Technical helper availability failure, not an approval rejection; no account/authentication interaction attempted.'})
put('pre_stop_commands.json',records)
put('pre_stop_receipt.json',{'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
    'supported_shutdown_authorized':True,'safety_inventory':'system-only pods, no application workload/PV/PVC observed',
    'stored_state_caveat':'etcd cluster state/configuration exists; inventory is not a restorable etcd snapshot and does not authorize reset/deletion',
    'shutdown_executed':False,'reason':'Supported CLI has no stop control; native UI helper unavailable',
    'budget_MiB':10704,'R1_applied':False,'new_runtime_objects':[]})
print(json.dumps({'snapshot':'complete','reports_backed_up':5,'shutdown_executed':False,'UI_available':False}))
