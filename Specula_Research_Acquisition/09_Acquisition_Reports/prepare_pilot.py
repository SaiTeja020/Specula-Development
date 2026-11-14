import json
from pathlib import Path
from urllib.parse import urljoin
from fetch_official import ROOT

meta=ROOT/'09_Acquisition_Reports/source_metadata'
commit=json.loads((meta/'optc_commit.json').read_text())['sha']
jobs=[]
def add(url,path,**extra): jobs.append(dict(url=url,relative=path,**extra))
base='https://cfreds-archive.nist.gov/'
for i in range(1,9):
    add(f'{base}images/hacking-dd/SCHARDT.{i:03}',f'01_Forensic_Datasets/NIST_Hacking_Case/SCHARDT.{i:03}',method='HEAD')
add(base+'images/hacking-dd/SCHARDT.LOG','01_Forensic_Datasets/NIST_Hacking_Case/SCHARDT.LOG')
add(base+'images/TestAnswers.pdf','07_Evaluation_Artifacts/evaluator_only/NIST_Hacking_Case/TestAnswers.pdf')
for file in ['README.md','ecar.md','errata.md','OpTCRedTeamGroundTruth.pdf']:
    folder='07_Evaluation_Artifacts/evaluator_only/OpTC' if file.endswith('.pdf') else '01_Forensic_Datasets/OpTC/documentation'
    add(f'https://raw.githubusercontent.com/FiveDirections/OpTC-data/{commit}/{file}',folder+'/'+file)
for repo,branch,name in [('DFIR-Metric/DFIR-Metric','main','dfir'),('mitre-attack/attack-stix-data','master','attack'),('ocsf/ocsf-schema','v1.9.0','ocsf'),('log2timeline/plaso','main','plaso'),('google/timesketch','master','timesketch')]:
    add(f'https://api.github.com/repos/{repo}/commits/{branch}',f'09_Acquisition_Reports/source_metadata/{name}_commit.json')
    add(f'https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1',f'09_Acquisition_Reports/source_metadata/{name}_tree.json')
add('https://arxiv.org/pdf/2505.19973v1','03_Research_Papers/DFIR-Metric/2505.19973v1.pdf')
add('https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf','05_Standards_Documentation/NIST_SP_800-86/nistspecialpublication800-86.pdf')
add('https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf','05_Standards_Documentation/NIST_SP_800-61r3/NIST.SP.800-61r3.pdf')
with (ROOT/'09_Acquisition_Reports/pilot_jobs.json').open('x') as f: json.dump(jobs,f,indent=2)
print(len(jobs),'jobs prepared')
