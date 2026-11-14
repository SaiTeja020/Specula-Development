"""Read-only memory diagnostic. Never start/stop containers, models or distributions."""
import hashlib,json,shutil,subprocess,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
commands=[]
def put(name,value):
    with (RUN/name).open('x',encoding='utf-8') as stream:
        stream.write(value if isinstance(value,str) else json.dumps(value,indent=2))
def run(args,required=True):
    proc=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def decode(data):
        return data.decode('utf-16le',errors='replace').lstrip('\ufeff') if b'\x00' in data[:100] else data.decode('utf-8-sig',errors='replace')
    out,err=decode(proc.stdout),decode(proc.stderr)
    commands.append({'argv':args,'exit_code':proc.returncode,'stdout':out,'stderr':err})
    if required:assert proc.returncode==0,err
    return out
def ps(script):return json.loads(run(['powershell','-NoProfile','-NonInteractive','-Command',script]))
def wsl(script):return run(['wsl.exe','-d','docker-desktop','--','sh','-c',script])
shutil.copy2(ROOT/'PROGRESS.md',RUN/'PROGRESS.before.md')
with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
    stream.write('\n- Read-only memory diagnostic clock-in under held Approval 1 blocked scope; '
        'no new active WIP slot. Parent progress oracle PASS (47 tasks; WIP 2/2); '
        'parent tracked source clean. Reports/new audit files and progress metadata only. '
        'No process termination, cache clearing, settings/service/model/runtime change.\n')
states=run(['wsl.exe','--list','--verbose'])
assert 'docker-desktop' in states and 'Running' in states
# Never query stopped Ubuntu through wsl -d, which would start it.
put('wsl_distributions.txt',states)
put('wsl_version.txt',run(['wsl.exe','--version']))
settings=ps(r"""$result=@{}; $p='C:\Users\DELL\AppData\Roaming\Docker\settings-store.json';
if(Test-Path -LiteralPath $p){$s=Get-Content -LiteralPath $p -Raw | ConvertFrom-Json;
$s.PSObject.Properties | Where-Object {$_.Name -match '(?i)memory|swap|cpu|wsl|resource.?saver|auto.*reclaim|kubernetes'} | ForEach-Object {$result[$_.Name]=$_.Value}}
ConvertTo-Json -InputObject $result -Depth 5""")
put('docker_resource_settings.json',settings)
cfg=Path(r'C:\Users\DELL\.wslconfig')
if cfg.exists():
    raw=cfg.read_bytes();put('wslconfig_observation.txt',raw.decode('utf-8-sig'))
    put('wslconfig_fingerprint.json',{'path':str(cfg),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
host=ps("""$os=Get-CimInstance Win32_OperatingSystem;
$metrics=Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory;
$perf=@{}; Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Where-Object {$_.IDProcess -gt 0} | ForEach-Object {$perf[[int]$_.IDProcess]=$_};
$procs=@(Get-Process | ForEach-Object {$p=$_; $q=$perf[[int]$p.Id];
[pscustomobject]@{Name=$p.ProcessName;Id=$p.Id;WorkingSetBytes=$p.WorkingSet64;PrivateCommittedBytes=$p.PrivateMemorySize64;
PrivateResidentBytes=$(if($null -ne $q){[long]$q.WorkingSetPrivate}else{$null});HasWindow=([bool]$p.MainWindowHandle);
WindowMentionsSpecula=([bool]($p.MainWindowTitle -match 'Specula'))}});
$services=@(Get-CimInstance Win32_Service | Where-Object {$_.ProcessId -gt 0} | Select-Object Name,DisplayName,ProcessId,State,StartMode);
[pscustomobject]@{TimeUTC=[DateTime]::UtcNow.ToString('o');
OS=($os | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,FreeVirtualMemory,TotalVirtualMemorySize);
Memory=($metrics | Select-Object AvailableMBytes,CommittedBytes,CommitLimit,PagesInputPersec,PagesOutputPersec,PageReadsPersec,PageWritesPersec,PoolPagedBytes,PoolNonpagedBytes);
Pagefiles=@(Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage);
Processes=$procs;Services=$services} | ConvertTo-Json -Depth 6""")
put('windows_memory_and_processes.json',host)
put('wsl_process_summary.txt',wsl('ps -o pid,ppid,user,rss,vsz,comm'))
# Only numerical memory fields and comm; no command lines/environments.
shell=r'''for d in /proc/[0-9]*; do
  [ -r "$d/smaps_rollup" ] || continue
  pid=${d##*/}
  name=$(cat "$d/comm" 2>/dev/null) || continue
  ppid=$(awk '/^PPid:/ {print $2}' "$d/status" 2>/dev/null)
  awk -v pid="$pid" -v name="$name" -v ppid="$ppid" '
    /^Rss:/ {rss=$2} /^Pss:/ {pss=$2}
    /^Private_Clean:/ {private+=$2} /^Private_Dirty:/ {private+=$2}
    /^Swap:/ {swap=$2}
    END {printf "%s\t%s\t%s\t%d\t%d\t%d\t%d\n",pid,ppid,name,rss,pss,private,swap}
  ' "$d/smaps_rollup" 2>/dev/null
done'''
rollup=wsl(shell)
put('wsl_smaps_rollup.tsv','pid\tppid\tcomm\trss_KiB\tpss_KiB\tprivate_KiB\tswap_KiB\n'+rollup)
processes=[]
for line in rollup.splitlines():
    cols=line.split('\t')
    if len(cols)==7:
        processes.append(dict(zip(['pid','ppid','comm','rss_KiB','pss_KiB','private_KiB','swap_KiB'],
            [int(cols[0]),int(cols[1]),cols[2],*[int(x) for x in cols[3:]]])))
put('wsl_process_memory.json',processes)
local_args=['kubectl','--context','docker-desktop','--request-timeout=10s']
put('kubernetes_pods.txt',run(local_args+['get','pods','--all-namespaces','-o','custom-columns=NS:.metadata.namespace,NAME:.metadata.name,PHASE:.status.phase']))
put('kubernetes_workloads.txt',run(local_args+['get','deployments,statefulsets,daemonsets,jobs,cronjobs','--all-namespaces']))
put('kubernetes_storage.txt',run(local_args+['get','pvc','--all-namespaces'],required=False))
put('kubernetes_nodes.txt',run(local_args+['get','nodes','-o','wide']))
put('docker_containers.json',[json.loads(line) for line in run(['docker','ps','-a','--format','{{json .}}']).splitlines()])
put('docker_engine.json',json.loads(run(['docker','info','--format','{"memory_bytes":{{.MemTotal}},"cpus":{{.NCPU}}}'])))
samples=[]
for index in range(3):
    windows=ps("""[pscustomobject]@{TimeUTC=[DateTime]::UtcNow.ToString('o');
OS=(Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory);
Memory=(Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | Select-Object AvailableMBytes,CommittedBytes,CommitLimit,PagesInputPersec,PagesOutputPersec,PageReadsPersec,PageWritesPersec)} | ConvertTo-Json -Depth 4""")
    raw=wsl('cat /proc/meminfo; printf "\\n---PSI---\\n"; cat /proc/pressure/memory; printf "\\n---VMSTAT---\\n"; cat /proc/vmstat')
    meminfo,tail=raw.split('---PSI---');pressure,vmstat=tail.split('---VMSTAT---')
    parsed={k:int(v.strip().split()[0])*1024 for k,v in (line.split(':',1) for line in meminfo.splitlines() if ':' in line)}
    vm={k:int(v) for k,v in (line.split() for line in vmstat.splitlines() if line.strip())}
    samples.append({'windows':windows,'linux_meminfo_bytes':parsed,'linux_pressure':pressure.strip(),
                    'linux_vmstat':{k:vm[k] for k in ['pswpin','pswpout','pgmajfault','oom_kill','allocstall_normal','pgscan_direct','pgscan_kswapd'] if k in vm}})
    if index<2:time.sleep(5)
put('memory_samples.json',samples)
put('command_outputs.json',commands)
running=[x for x in json.loads((RUN/'docker_containers.json').read_text()) if x['State']=='running']
print(json.dumps({'samples':len(samples),'wsl_processes':len(processes),'host_processes':len(host['Processes']),
    'VM_available_MiB':[round(x['linux_meminfo_bytes']['MemAvailable']/1024**2,3) for x in samples],
    'Windows_available_MiB':[x['windows']['OS']['FreePhysicalMemory']/1024 for x in samples],
    'running_docker_containers':len(running),'runtime_changes':False}))
