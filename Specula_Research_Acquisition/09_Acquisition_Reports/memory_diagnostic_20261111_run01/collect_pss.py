"""Supplement the empty shell-loop observation with direct read-only proc reads."""
import json,subprocess
from pathlib import Path
RUN=Path(__file__).resolve().parent
args=['wsl.exe','-d','docker-desktop','--']
summary=subprocess.check_output(args+['ps','-o','pid,ppid,user,rss,vsz,comm'],text=True)
rows={}
for line in summary.splitlines()[1:]:
    cols=line.split()
    if len(cols)>=6:rows[int(cols[0])]={'pid':int(cols[0]),'ppid':int(cols[1]),'comm':cols[-1],'user':cols[2]}
paths=[f'/proc/{pid}/smaps_rollup' for pid in rows]
command=args+['grep','-H','-e','^Rss:','-e','^Pss:','-e','^Private_Clean:','-e','^Private_Dirty:','-e','^Swap:',*paths]
proc=subprocess.run(command,capture_output=True,text=True)
for line in proc.stdout.splitlines():
    path,key,value=line.split(':',2)
    pid=int(path.split('/')[2]);rows[pid][key+'_KiB']=int(value.strip().split()[0])
parsed=[x for x in rows.values() if 'Pss_KiB' in x]
for row in parsed:row['Private_KiB']=row.get('Private_Clean_KiB',0)+row.get('Private_Dirty_KiB',0)
receipt={'status':'PASS' if parsed else 'BLOCKED','method':'Direct grep of selected numeric smaps_rollup fields; no process attachment or permissions change.',
    'initial_shell_loop':'Returned no rows; retained as unsuccessful collection, not used as evidence of zero process memory.',
    'argv':command,'exit_code':proc.returncode,'stdout':proc.stdout,'stderr':proc.stderr,
    'process_summary':summary,'processes':parsed,'missing_pids':[x for x in rows if 'Pss_KiB' not in rows[x]]}
with (RUN/'wsl_pss_supplement.json').open('x',encoding='utf-8') as stream:json.dump(receipt,stream,indent=2)
assert parsed
print(json.dumps({'collected':len(parsed),'missing_pids':receipt['missing_pids'],'total_PSS_MiB':sum(x['Pss_KiB'] for x in parsed)/1024,
    'top':sorted(parsed,key=lambda x:x['Pss_KiB'],reverse=True)[:12]}))
