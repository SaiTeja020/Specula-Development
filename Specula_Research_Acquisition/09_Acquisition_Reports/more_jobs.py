import json,re,html
from fetch_official import ROOT
jobs=[]
def add(url,path,**kw):jobs.append(dict(url=url,relative=path,**kw))
for ident in ['2409.02572','2005.11401','2210.03629','2404.16130']:
 h=(ROOT/f'03_Research_Papers/{ident}/metadata.html').read_text()
 versions=re.findall(r'/abs/'+re.escape(ident)+r'v(\d+)',h)
 v=max(map(int,versions),default=1)
 add(f'https://arxiv.org/pdf/{ident}v{v}',f'03_Research_Papers/{ident}/{ident}v{v}.pdf')
d=json.loads((ROOT/'01_Forensic_Datasets/CERT/source.json').read_text())
for f in d['files']:
 if f['name'] in ['SEI_Insider_README.txt','CHECKSUMS-sha256.txt','CHECKSUMS-sha1.txt','answers.tar.bz2']:
  folder='07_Evaluation_Artifacts/evaluator_only/CERT' if f['name']=='answers.tar.bz2' else '01_Forensic_Datasets/CERT'
  add(f['download_url'],folder+'/'+f['name'])
h=(ROOT/'01_Forensic_Datasets/OpTC/documentation/public_drive_folder.html').read_text()
for m in re.finditer(r'data-id="([^"]+)"[^>]{0,400}data-tooltip="([^"]+)"',h):
 ident,name=m.groups()
 if name in ['ecar Shared folder','bro Shared folder']:
  add('https://drive.google.com/drive/folders/'+ident,'01_Forensic_Datasets/OpTC/documentation/drive_'+name.split()[0]+'.html')
add('https://api.crossref.org/works/10.1109/ACCESS.2025.3602681','03_Research_Papers/Hmimou/crossref_metadata.json')
add('https://doi.org/10.1109/ACCESS.2025.3602681','03_Research_Papers/Hmimou/publisher_source.html')
repos=['Velocidex/velociraptor','zeek/zeek','OISF/suricata','volatilityfoundation/volatility3','logpai/Drain3','langchain-ai/langgraph','neo4j/neo4j','facebookresearch/faiss','chroma-core/chroma','networkx/networkx','scikit-learn/scikit-learn','redcanaryco/atomic-red-team','mitre/caldera','SigmaHQ/sigma','kevoreilly/CAPEv2','VirusTotal/yara-x','giampaolo/psutil']
for repo in repos:
 add('https://api.github.com/repos/'+repo,'09_Acquisition_Reports/source_metadata/repo_'+repo.replace('/','_')+'.json')
for slug,url in [('Wireshark','https://www.wireshark.org/download.html'),('Zimmerman','https://ericzimmerman.github.io/'),('pytest','https://docs.pytest.org/'),('pandas','https://pandas.pydata.org/'),('SciPy','https://scipy.org/'),('statsmodels','https://www.statsmodels.org/'),('MLflow','https://mlflow.org/'),('DVC','https://dvc.org/'),('Daubert','https://supreme.justia.com/cases/federal/us/509/579/')]:
 add(url,'05_Standards_Documentation/tool_reference_pages/'+slug+'.html')
with (ROOT/'09_Acquisition_Reports/more_jobs.json').open('x') as f:json.dump(jobs,f,indent=2)
print(len(jobs),'jobs')
