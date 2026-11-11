"""Clone only checklist pilot references; do not execute their code."""
import json
import subprocess
from pathlib import Path
from fetch_official import ROOT

metadata=ROOT/'09_Acquisition_Reports/source_metadata'
jobs=[
 ('DFIR-Metric/DFIR-Metric','main','dfir','07_Evaluation_Artifacts/evaluator_only/DFIR-Metric',None),
 ('ocsf/ocsf-schema','v1.9.0','ocsf','05_Standards_Documentation/ocsf-schema-1.9.0',None),
 ('log2timeline/plaso','main','plaso','04_Software_Repositories/plaso',['plaso','tools','docs','config','examples']),
 ('google/timesketch','master','timesketch','04_Software_Repositories/timesketch',['timesketch','docs']),
 ('SmartData-Polito/CFA-bench','main','cfa_official','07_Evaluation_Artifacts/evaluator_only/CFA-bench',None),
 ('stefanofumero/LLM_Agent_Cybersecurity_Forensic','main','cybersleuth','07_Evaluation_Artifacts/evaluator_only/CyberSleuth',['src','architecture']),
]
for repo,branch,key,relative,sparse in jobs:
    dest=ROOT/relative
    git=['git','-c','safe.directory='+str(dest),'-C',str(dest)]
    expected=json.loads((metadata/(key+'_commit.json')).read_text())['sha']
    if dest.exists():
        head=subprocess.run(git+['rev-parse','--verify','HEAD'],capture_output=True,text=True)
        if head.returncode==0:
            print('PRESERVED existing',relative,flush=True)
            continue
        if not (dest/'.git').is_dir() or any(p.name!='.git' for p in dest.iterdir()):
            raise RuntimeError('Refusing to change unknown existing directory: '+str(dest))
    dest.parent.mkdir(parents=True,exist_ok=True)
    # Fetch exact observed commit, avoiding default-branch races.
    subprocess.run(['git','init',str(dest)],check=True,capture_output=True)
    subprocess.run(git+['remote','add','origin','https://github.com/'+repo+'.git'],check=True)
    if sparse:
        subprocess.run(git+['config','remote.origin.promisor','true'],check=True)
        subprocess.run(git+['config','remote.origin.partialclonefilter','blob:none'],check=True)
    command=git+['fetch','--depth=1']
    if sparse: command.append('--filter=blob:none')
    subprocess.run(command+['origin',expected],check=True,timeout=240)
    if sparse:
        subprocess.run(git+['sparse-checkout','init','--cone'],check=True)
        subprocess.run(git+['sparse-checkout','set',*sparse],check=True)
    subprocess.run(git+['checkout','--detach',expected],check=True,timeout=240)
    actual=subprocess.check_output(git+['rev-parse','HEAD'],text=True).strip()
    assert actual==expected
    subprocess.run(git+['fsck','--connectivity-only'],check=True,capture_output=True)
    record={'repository':repo,'source':'https://github.com/'+repo,'commit':actual,'path':str(dest),'sparse_paths':sparse,
            'status':'PINNED_SPARSE_CLONE' if sparse else 'PINNED_CLONE','note':'No setup or reference code executed; sparse clones omit large fixtures and are not complete benchmark corpora'}
    with (ROOT/'09_Acquisition_Reports/clone_receipts.jsonl').open('a') as f:f.write(json.dumps(record)+'\n')
    print(json.dumps(record),flush=True)
