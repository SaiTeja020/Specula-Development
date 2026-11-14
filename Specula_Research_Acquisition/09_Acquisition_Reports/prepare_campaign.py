"""Assemble truthful checklist ledger, templates, provenance and report inputs."""
import collections,csv,datetime as dt,hashlib,html,json,re,shutil,subprocess,zipfile
from pathlib import Path
from xml.etree import ElementTree as ET
from pypdf import PdfReader
from fetch_official import ROOT

NOW=dt.datetime.now(dt.timezone.utc).isoformat()
REPORT=ROOT/'09_Acquisition_Reports'
def digest(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(path,body):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('x',encoding='utf-8') as f:f.write(body)
def csvout(path,fields,rows):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('x',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def load(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def git(path,*args):
 return subprocess.check_output(['git','-c','safe.directory='+str(path),'-C',str(path),*args],text=True).strip()

# Preserve the initial reports as immutable predecessors before updating canonical names.
archive=REPORT/'preliminary_audit'
archive.mkdir(exist_ok=True)
for relative in ['00_Master_Inventory/master_acquisition_tracker.xlsx','08_Checksums_And_Manifests/dataset_manifest.csv','08_Checksums_And_Manifests/repository_manifest.csv','08_Checksums_And_Manifests/resource_checksums.csv','03_Research_Papers/research_paper_bibliography.csv','09_Acquisition_Reports/acquisition_summary.pdf','09_Acquisition_Reports/missing_resources_report.csv','09_Acquisition_Reports/restricted_resources_report.csv','README.md']:
 old=ROOT/relative
 if old.exists():
  target=archive/relative
  target.parent.mkdir(parents=True,exist_ok=True)
  assert not target.exists(),target
  assert old.resolve().is_relative_to(ROOT) and target.resolve().is_relative_to(ROOT)
  old.rename(target)

# Preserve rejected server responses separately from purported evidence.
relocations=[]
for relative in ['01_Forensic_Datasets/OpTC/network_subset/communication.00-01.2019-09-23.log.gz','03_Research_Papers/Hmimou/publisher_fulltext_response.bin']:
 old=ROOT/relative
 if old.exists():
  valid=old.read_bytes().startswith(b'%PDF-')
  target=old.with_name('ACCESS.2025.3602681.pdf') if valid else REPORT/'rejected_responses'/'OpTC_quota_exceeded.html'
  target.parent.mkdir(parents=True,exist_ok=True)
  assert not target.exists()
  old.rename(target)
  relocations.append({'original_path':str(old),'preserved_path':str(target),'sha256':digest(target),'status':'PDF_VERIFIED' if valid else 'REJECTED_HTML_NOT_DATASET'})
write(REPORT/'response_relocations.json',json.dumps(relocations,indent=2))

# Create evidence-only working copies. Remove label-bearing filenames, never change bytes.
cfa=ROOT/'07_Evaluation_Artifacts/evaluator_only/CFA-bench'
maps=[]
for source in sorted((cfa/'data/raw').rglob('*')):
 if not source.is_file() or source.suffix.lower() not in ['.pcap','.pcapng','.log']:continue
 relative=source.relative_to(cfa/'data/raw')
 case='case-'+hashlib.sha256(('da8a92fa16d6d6f30e702299c8e368cb6461d5f7/'+relative.parts[0]).encode()).hexdigest()[:12]
 siblings=sorted(p for p in source.parent.iterdir() if p.is_file() and p.suffix.lower() in ['.pcap','.pcapng','.log'])
 target=ROOT/'02_Benchmarks/CFA_Bench/agent_evidence'/case/f'artifact-{siblings.index(source)+1:03}{source.suffix.lower()}'
 target.parent.mkdir(parents=True,exist_ok=True)
 with source.open('rb') as original,target.open('xb') as copied:shutil.copyfileobj(original,copied)
 assert digest(source)==digest(target)
 maps.append({'original_path':str(source),'agent_evidence_path':str(target),'sha256':digest(target),'transformation':'filename pseudonymization only; bytes unchanged'})
csvout(ROOT/'07_Evaluation_Artifacts/evaluator_only/CFA_evidence_mapping.csv',list(maps[0]),maps)
write(ROOT/'02_Benchmarks/CFA_Bench/README.md','# CFA-Bench evidence boundary\n\nOnly raw PCAP/log bytes are copied to agent_evidence/. Label-bearing CVE/success/failure filenames are replaced by opaque names. The original pinned repository, tasks, results and filename mapping remain evaluator-only. Original archives/repository data are unchanged. Local copying is documented preprocessing, not a new dataset acquisition. Public-benchmark contamination and content-level label leakage still require review before experiments.\n')

# Verify acquired bytes, repository worktrees and formats before assigning statuses.
events=[json.loads(x) for x in (REPORT/'download_events.jsonl').read_text(encoding='utf-8').splitlines()]
relocation_by_path={x['original_path']:x['preserved_path'] for x in relocations}
files=[]
seen=set()
pdfs=[]
for event in events:
 if event['status'] not in ['SAVED_BYTES','EXISTING_PRESERVED']:continue
 p=Path(relocation_by_path.get(event['path'],event['path']))
 if str(p) in seen:continue
 seen.add(str(p));assert p.is_file(),p
 assert digest(p)==event['sha256'],p
 status='LOCAL_HASH_VERIFIED'
 note='HTTP bytes preserved; not automatically a complete checklist resource'
 if p.stat().st_size==0:status='EMPTY_RESPONSE_NOT_RESOURCE'
 elif 'rejected_responses' in p.parts:status='HTML_QUOTA_RESPONSE_NOT_EVIDENCE'
 elif p.suffix.lower()=='.pdf':
  assert p.read_bytes().startswith(b'%PDF-')
  reader=PdfReader(p,strict=True);assert len(reader.pages)>0
  for page in reader.pages: assert page.mediabox.width>0
  assert b'%%EOF' in p.read_bytes()[-2048:]
  status='PDF_STRUCTURE_HASH_VERIFIED';pdfs.append({'path':str(p),'pages':len(reader.pages),'first_page_text':reader.pages[0].extract_text()[:1200]})
 elif p.suffix=='.json':json.loads(p.read_text(encoding='utf-8'));status='JSON_PARSE_HASH_VERIFIED'
 elif p.suffix=='.zip':
  with zipfile.ZipFile(p) as z:assert z.testzip() is None
  status='ZIP_CRC_HASH_VERIFIED'
 files.append({'resource_name':p.name,'source_url':event['url'],'version':'see resource/repository manifest','expected_size_bytes':event.get('expected_bytes'),'actual_size_bytes':p.stat().st_size,'local_path':str(p),'sha256':event['sha256'],'verification_status':status,'acquired_at':event['checked_at'],'licence':'see original source documentation; no blanket redistribution permission','notes':note})

clones=[json.loads(x) for x in (REPORT/'clone_receipts.jsonl').read_text().splitlines()]
repo_manifest=[]
for clone in clones:
 p=Path(clone['path']);assert git(p,'rev-parse','HEAD')==clone['commit']
 assert not git(p,'status','--porcelain')
 git(p,'fsck','--connectivity-only')
 count=0;total=0
 for name in git(p,'ls-files').splitlines():
  f=p/name
  if not f.is_file():continue
  count+=1;total+=f.stat().st_size
  files.append({'resource_name':clone['repository']+'/'+name,'source_url':clone['source']+'/blob/'+clone['commit']+'/'+name,'version':clone['commit'],'expected_size_bytes':'','actual_size_bytes':f.stat().st_size,'local_path':str(f),'sha256':digest(f),'verification_status':'PINNED_GIT_CLEAN_LOCAL_HASH_VERIFIED','acquired_at':NOW,'licence':'See repository licence; absent licence is not permission','notes':clone['status']})
 licences=[f for f in p.iterdir() if f.is_file() and f.name.lower().startswith(('license','copying'))]
 requirements=[str(f.relative_to(p)) for f in p.iterdir() if f.is_file() and f.name in ['requirements.txt','pyproject.toml','setup.py','package.json','go.mod']]
 repo_manifest.append({**clone,'actual_worktree_bytes':total,'files_present':count,'licence_file':'; '.join(str(f) for f in licences) or 'No explicit top-level licence found; rights unconfirmed','dependencies':'; '.join(requirements) or 'See original README; not installed','verified_at':NOW})
for receipt in [json.loads(x) for x in (REPORT/'reference_archive_receipts.jsonl').read_text().splitlines()]:
 if receipt['status']=='SAVED_BYTES':
  p=Path(receipt['path'])
  with zipfile.ZipFile(p) as z:
   assert z.testzip() is None
   licence_names=[x.filename for x in z.infolist() if x.filename.count('/')==1 and x.filename.rsplit('/',1)[-1].lower().startswith(('license','copying'))]
  for f in files:
   if f['local_path']==str(p):f['version']=receipt['commit'];f['licence']='; '.join(licence_names) or 'No top-level licence found; rights unconfirmed'
  repo_manifest.append({**receipt,'source':'https://github.com/'+receipt['repository'],'actual_worktree_bytes':p.stat().st_size,'files_present':'archive','licence_file':'; '.join(licence_names),'dependencies':'Original archive includes README/build metadata; not installed','verified_at':NOW})

attack=ROOT/'02_Benchmarks/MITRE_ATTACK/enterprise-attack-19.2.json'
stix=load(attack);assert stix['type']=='bundle' and len(stix['objects'])==26086
tree=load(REPORT/'source_metadata/attack_tree.json')
entry=next(x for x in tree['tree'] if x['path']=='enterprise-attack/enterprise-attack-19.2.json')
raw=attack.read_bytes();assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==entry['sha']
assert load(ROOT/'05_Standards_Documentation/ocsf-schema-1.9.0/version.json')['version']=='1.9.0'
counts={}
for p in (ROOT/'07_Evaluation_Artifacts/evaluator_only/DFIR-Metric').glob('DFIR-Metric-*.json'):
 d=load(p);counts[p.stem]=len(d['questions'])
assert sorted(counts.values())==[150,510,713]
write(REPORT/'format_verification.json',json.dumps({'checked_at':NOW,'stix_objects':len(stix['objects']),'stix_git_blob_sha1':entry['sha'],'ocsf_version':'1.9.0','dfir_question_counts':counts,'cfa_evidence_files':len(maps),'cfa_cases':len({Path(x['agent_evidence_path']).parent.name for x in maps}),'pdfs':pdfs},indent=2))

# Every checklist checkbox gets an explicit row, including process/deliverable items.
checklist=(ROOT/'CHECKLIST.md').read_text(encoding='utf-8-sig')
rows=[];section='';priority='UNASSIGNED';current_source=''
for line_number,line in enumerate(checklist.splitlines(),1):
 if line.startswith('## '):section=line[3:];priority='UNASSIGNED'
 if line.startswith('### '):
  m=re.search(r'P[012]',line)
  if m:priority=m.group()
 if not re.match(r'\s*- \[ \]',line):continue
 name=re.sub(r'^\s*- \[ \]\s*','',line).replace('**','').replace('`','')
 urls=re.findall(r'https?://[^\s`]+',name)
 if not urls:
  for following in checklist.splitlines()[line_number:]:
   if re.match(r'\s*- \[ \]|^#',following):break
   found=re.findall(r'https?://[^\s`]+',following)
   if found:urls=found;break
 inline=re.search(r'\bP[012]\b',name)
 row={'resource_name':name,'category':section,'priority':inline.group() if inline else priority,'official_source':urls[0] if urls else '', 'download_url':'','version':'','release_date':'Unknown / see original metadata','expected_size_bytes':'','actual_size_bytes':'','acquisition_status':'PENDING','local_storage_path':'','sha256':'','licence_access_restrictions':'Not yet assessed','verification_status':'Not verified','date_checked':NOW,'notes':'Checklist line '+str(line_number)+'; no unverified acquisition claimed'}
 rows.append(row)

def mark(needle,status,note,path=None,version='',source='',priority=None):
 for r in rows:
  if needle.lower() in r['resource_name'].lower():
   r.update(acquisition_status=status,notes=r['notes']+'; '+note,version=version,official_source=source or r['official_source'])
   if priority:r['priority']=priority
   if path:
    p=ROOT/path;r['local_storage_path']=str(p)
    if p.is_file():r['sha256']=digest(p);r['actual_size_bytes']=p.stat().st_size
   if 'VERIFIED' in status:r['verification_status']='Executable local hash/format/commit checks passed; scientific validity not established'

mark('NIST CFReDS — Hacking','DEFERRED','P0 retained. User deferred 4,871,301,120-byte evidence; scenario/log/answers acquired separately. Dependent experiments pending.',source='https://cfreds-archive.nist.gov/Hacking_Case.html',priority='P0')
mark('1. One NIST CFReDS','DEFERRED','Hacking Case selected; user deferred raw evidence. Documentation is not a completed evidence acquisition.',priority='P0')
mark('Data Leakage','DEFERRED','Official scenario/checksum page preserved; PC raw archive 5.05 GB, evidence deferred under user instruction.',path='01_Forensic_Datasets/NIST_Data_Leakage/source.html',priority='P0')
mark('DARPA OpTC','PARTIALLY DOWNLOADED','Documentation/eCAR/errata and ground-truth PDF acquired at pinned commit; event payload unavailable/deferred.',path='01_Forensic_Datasets/OpTC/documentation/README.md',version='5b108604f11f767aa11ea79ff827595f3fad15fd',priority='P0')
mark('2. OpTC README','DOWNLOADED — VERIFIED','README, eCAR, errata and separate ground-truth PDF verified.',path='01_Forensic_Datasets/OpTC/documentation/README.md',version='5b108604f11f767aa11ea79ff827595f3fad15fd',priority='P0')
mark('3. A small documented OpTC','UNAVAILABLE','117 KB network-log attempt returned quota-exceeded HTML, rejected; endpoint archive inspected is 1.86 GB and deferred. No event subset acquired.',priority='P0')
mark('M57-Patents','RESTRICTED / DEFERRED','Public scenario page acquired; instructor solution keys restricted/encrypted; no access request or decryption attempted. Large evidence deferred.',path='01_Forensic_Datasets/M57-Patents/source.html',priority='P1')
mark('CERT Insider','PARTIALLY DOWNLOADED','v1 metadata confirms CC BY 4.0; 87,541,633-byte r1 and larger releases deferred. Small README/checksum/answer downloads returned HTTP 403.',path='01_Forensic_Datasets/CERT/source.json',version='Figshare article v1',priority='P1')
mark('CIC-IDS2017','UNAVAILABLE / DEFERRED','Official page reviewed via web; direct downloader TLS validation failed. PCAP days 7.8–13 GB deferred. No insecure TLS used.',source='https://www.unb.ca/cic/datasets/ids-2017.html',priority='P1')
mark('CSE-CIC-IDS2018','PENDING — CONDITIONAL','P2: coverage benefit not established; direct source TLS check failed; no large traffic corpus acquired.',priority='P2')
mark('DFIR-Metric benchmark','PARTIALLY DOWNLOADED','Pinned released datasets/generator notebooks acquired. Actual question counts 713/150/510 differ from README 700/150/500. Standalone evaluation runner not present in release.',path='07_Evaluation_Artifacts/evaluator_only/DFIR-Metric/README.md',version='a66a5cee515f7503d961e2160a5aced5eaf147da',priority='P0')
mark('4. DFIR-Metric evaluation','PARTIALLY DOWNLOADED','Released datasets/notebooks verified; a standalone runner is absent at pinned commit.',path='07_Evaluation_Artifacts/evaluator_only/DFIR-Metric/README.md',version='a66a5cee515f7503d961e2160a5aced5eaf147da',priority='P0')
mark('MITRE ATT&CK Enterprise STIX','DOWNLOADED — VERIFIED','53,835,637-byte bundle; 26,086 objects; official git blob SHA-1 matched; SHA-256 recorded. Existing XLSX is a different format.',path='02_Benchmarks/MITRE_ATTACK/enterprise-attack-19.2.json',version='19.2; commit a8db2f52eb933c9c99060c123e088b3326d3a607',source='https://github.com/mitre-attack/attack-stix-data',priority='P0')
mark('6. Versioned MITRE','DOWNLOADED — VERIFIED','Versioned STIX JSON checked against official pinned git tree.',path='02_Benchmarks/MITRE_ATTACK/enterprise-attack-19.2.json',version='19.2',priority='P0')
mark('offline MITRE','EXISTS — VERIFIED','Six existing v19.2-named XLSX archives pass CRC/hash checks; no offline STIX filename located in audited sources. Version label not official workbook authenticity.',path='../known_attacks/enterprise-attack-v19.2.xlsx')
mark('NIST CFTT / CFReDS','PENDING — CONDITIONAL','Official CFTT program documentation preserved; additional deterministic cases not selected for first pilot.',path='05_Standards_Documentation/CFTT/source.html',priority='P1')
mark('CFA-Bench','PARTIALLY DOWNLOADED','Official-paper-linked SmartData-Polito benchmark clone pinned; raw evidence copies use opaque names. DOI metadata verified. Author manuscript visible publicly but direct download blocked; paper not acquired.',path='07_Evaluation_Artifacts/evaluator_only/CFA-bench/README.md',version='da8a92fa16d6d6f30e702299c8e368cb6461d5f7',source='https://doi.org/10.1109/EuroSPW67616.2025.00031')
mark('CyberSleuth benchmark','PARTIALLY DOWNLOADED','Exact paper and author-linked sparse source clone verified; 199 MB full raw dataset excluded/deferred.',path='07_Evaluation_Artifacts/evaluator_only/CyberSleuth/README.md',version='9857644cd9c46687481787efb205b72a6d05e5bd',source='https://arxiv.org/abs/2508.20643')
mark('MADIK','NEEDS CONFIRMATION','Candidate DOI metadata preserved only. Owner must establish relevance to original proposal; not selected or downloaded.',path='03_Research_Papers/MADIK/candidate_crossref_metadata.json',source='https://doi.org/10.1007/978-3-540-88875-8_10')

paper_map=[('GenDFIR','2409.02572','2409.02572v4.pdf'),('Retrieval-Augmented Generation','2005.11401','2005.11401v4.pdf'),('ReAct:','2210.03629','2210.03629v3.pdf'),('GraphRAG:','2404.16130','2404.16130v2.pdf'),('Directed Acyclic','1806.04356','1806.04356v1.pdf'),('CyberSleuth original','CyberSleuth','2508.20643v2.pdf')]
for needle,folder,name in paper_map:mark(needle,'DOWNLOADED — VERIFIED','Actual arXiv PDF parsed and hashed; original metadata preserved.',path=f'03_Research_Papers/{folder}/{name}',version=Path(name).stem)
for needle in ['DFIR-Metric paper','DFIR-Metric research paper','DFIR-Metric — Cherif']:
 mark(needle,'DOWNLOADED — VERIFIED','Actual versioned paper PDF parsed and hashed.',path='03_Research_Papers/DFIR-Metric/2505.19973v1.pdf',version='2505.19973v1')
mark('Drain: An Online','DOWNLOADED — VERIFIED','2017 original, author-hosted copy, DOI metadata verified. Separate 2018 paper retained.',path='03_Research_Papers/Drain2017/ICWS17-author-copy.pdf',version='2017 author-hosted copy',source='https://doi.org/10.1109/ICWS.2017.13')
mark('A Multi-Agent System for Cybersecurity','DOWNLOADED — VERIFIED','Existing named local paper not found; official open IEEE PDF parsed (17 pages), DOI and CC BY 4.0 metadata verified.',path='03_Research_Papers/Hmimou/ACCESS.2025.3602681.pdf',version='IEEE version of record 2025',source='https://doi.org/10.1109/ACCESS.2025.3602681')
mark('Toward Generating','PENDING','Official UNB bibliography reviewed; full paper not acquired. TLS issue and no verified author PDF yet.',source='https://www.unb.ca/cic/datasets/ids-2017.html')
for needle,folder,filename,version in [('NIST SP 800-86','NIST_SP_800-86','nistspecialpublication800-86.pdf','Final August 2006'),('NIST SP 800-61','NIST_SP_800-61r3','NIST.SP.800-61r3.pdf','Revision 3 April 2025'),('NIST AI 600-1','NIST_AI_600-1','source.pdf','July 2024')]:
 mark(needle,'DOWNLOADED — VERIFIED','Official full PDF structure and SHA-256 checked; source documentation preserved.',path=f'05_Standards_Documentation/{folder}/{filename}',version=version)
for needle in ['ISO/IEC 27037','ISO/IEC 27041','ISO/IEC 27042','ISO/IEC 27043']:
 mark(needle,'RESTRICTED','Official site requests returned HTTP 403. No full text obtained; standards may require purchase/institutional access. No purchase or access request made.')
mark('Daubert v.','UNAVAILABLE','Listed source returned HTTP 403; no opinion text downloaded. No legal compliance claims.')
mark('MITRE ATT&CK documentation','DOWNLOADED — VERIFIED','Official landing page preserved; a page snapshot is not complete site documentation.',path='05_Standards_Documentation/MITRE_documentation/source.html')
mark('OCSF schema documentation','PARTIALLY DOWNLOADED','Official schema site page preserved; versioned schema clone complete but hosted documentation site not mirrored.',path='05_Standards_Documentation/OCSF_documentation/source.html')
mark('NIST Computer Forensics Tool','DOWNLOADED — VERIFIED','Official program page preserved; no extra test-image corpus implied.',path='05_Standards_Documentation/CFTT/source.html')
mark('OCSF Schema','DOWNLOADED — VERIFIED','v1.9.0 schema clone, version.json, licence and commit verified; not installed.',path='05_Standards_Documentation/ocsf-schema-1.9.0/version.json',version='1.9.0; 856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba')
mark('7. OCSF schema','DOWNLOADED — VERIFIED','Complete pinned schema source clone verified.',path='05_Standards_Documentation/ocsf-schema-1.9.0/version.json',version='1.9.0',priority='P0')
mark('Plaso','DOWNLOADED — VERIFIED','Pinned sparse source/docs clone; large fixture data omitted, not installed.',path='04_Software_Repositories/plaso/README.md',version='f75784eea92ce1f946e822a675836da45d91309c')
mark('Timesketch','DOWNLOADED — VERIFIED','Pinned sparse source/docs clone; omitted folders recorded in repository manifest; not installed.',path='04_Software_Repositories/timesketch/README.md',version='bb8cdc00a0faaba53100763a4a234a96a0c5581f')
mark('10. Plaso','DOWNLOADED — VERIFIED','Both pinned sparse source references verified; neither installed or benchmark-tested.',path='04_Software_Repositories/plaso/README.md',priority='P1')
packages=load(ROOT/'06_Existing_Project_Resources/installed_package_inventory.json')
aliases={'drain3':'Drain3','langgraph':'LangGraph','neo4j':'Neo4j','faiss-cpu':'FAISS','chromadb':'Chroma','scikit-learn':'scikit-learn','pytest':'pytest','scipy':'SciPy','volatility3':'Volatility 3'}
for p in packages:
 if p['status']=='INSTALLED_METADATA_VERIFIED' and p['name'] in aliases:
  mark(aliases[p['name']],'EXISTS — VERIFIED','Project venv distribution metadata verified; not reinstalled. Neo4j entry verifies Python driver only, not server. Full runtime compatibility not tested.',path='06_Existing_Project_Resources/installed_package_inventory.json',version=p['version'])
for repo in repo_manifest:
 if repo.get('note','').startswith('Original pinned'):
  match={'Velocidex/velociraptor':'Velociraptor','OISF/suricata':'Suricata','networkx/networkx':'NetworkX','SigmaHQ/sigma':'Sigma rules','giampaolo/psutil':'psutil'}.get(repo['repository'])
  if match:mark(match,'DOWNLOADED — VERIFIED','Exact-commit original source ZIP CRC/hash checked; no install or execution.',path=str(Path(repo['path']).relative_to(ROOT)),version=repo['commit'])
mark('Zeek','DEFERRED','Official repo verified; source archive exceeded 32 MiB automatic limit and was not saved. No install attempted.')
mark('Atomic Red Team','DEFERRED','Exact source commit resolved; archive exceeded 32 MiB automatic limit and was not saved. No lab execution.')
for name in ['MITRE CALDERA','CAPE Sandbox','YARA-X','MLflow','DVC']:
 mark(name,'PENDING — CONDITIONAL','Optional P2 feature/experiment-volume need not established; official source metadata/page checked. No installation or execution.',priority='P2')
for name in ['Wireshark / TShark',"Eric Zimmerman's"]:
 mark(name,'PARTIALLY DOWNLOADED','Official distribution/reference page preserved. Native installer/binary version not acquired or installed; source/binary choice remains pending.')
for name in ['pandas','statsmodels']:
 mark(name,'PENDING','Not installed in inspected project venv; official project page preserved. Installation is not authorized and is not required for these acquisition deliverables.')

# The process and named-existing-resource portions receive specific inventory dispositions.
for r in rows:
 if r['category'].startswith('0.') and r['acquisition_status']=='PENDING':
  r['acquisition_status']='AUDITED'
  r['local_storage_path']=str(ROOT/'00_Master_Inventory/existing_resource_inventory.csv')
  r['notes']+='; Audited parent resources plus source/fixture supplement. Exact named original absent unless identified in inventory; related Markdown/PDF is not silently equivalent.'
 if r['category'].startswith('Instructions') or r['category']=='':
  r['acquisition_status']='RECORDED';r['notes']+='; Operational rule enforced; no resource-download completion implied.'
 if r['category'].startswith('3.') and r['acquisition_status']=='PENDING' and not r['official_source']:
  r['notes']+='; Topic-level literature search remains pending: select by implemented research question, not title similarity.'
 if r['category'].startswith('6.'):
  r['acquisition_status']='TEMPLATE CREATED';r['notes']+='; No factual ground truth, reviewer judgments or experiment results fabricated.'
 if r['category'].startswith('8.'):
  r['acquisition_status']='CREATED — VERIFICATION PENDING';r['notes']+='; Final deliverable saved and checked by campaign verifier after export.'

for i,r in enumerate(rows,1):
 r['checklist_id']=f'CL-{i:03}'
 if r['local_storage_path']:
  linked=next((f for f in files if f['local_path']==r['local_storage_path']),None)
  if linked:
   r['download_url']=linked['source_url'];r['expected_size_bytes']=linked['expected_size_bytes']
   r['licence_access_restrictions']=linked['licence']
   r['notes']+='; Size/hash identify the linked local file; multipart/repository totals are in manifests.'
 for commitfile in (REPORT/'source_metadata').glob('*_commit.json'):
  c=load(commitfile)
  if c.get('sha') and c['sha'] in r['version']:
   r['release_date']=c['commit']['committer']['date']+' (source commit date, not release date)'
csvout(ROOT/'00_Master_Inventory/checklist_status.csv',list(rows[0]),rows)
original=list(csv.DictReader((ROOT/'00_Master_Inventory/initial_inventory.csv').open(encoding='utf-8-sig')))
supplement=list(csv.DictReader((ROOT/'06_Existing_Project_Resources/source_fixture_inventory.csv').open(encoding='utf-8-sig')))
existing=[{**r,'inventory_scope':'primary resource audit'} for r in original]
seen_paths={r['local_storage_path'] for r in existing}
for r in supplement:
 if r['local_storage_path'] not in seen_paths:existing.append({**r,'inventory_scope':'source/fixture/config supplement'})
existing_fields=list(dict.fromkeys(k for r in existing for k in r))
csvout(ROOT/'00_Master_Inventory/existing_resource_inventory.csv',existing_fields,existing)

# Empty evaluator templates and experiment scaffolds deliberately contain no results.
templates={
 'case_ground_truth.csv':['case_id','event_id','verified_event','outcome','identity','timestamp','evidence_id','source_reference','reviewer_id','review_status'],
 'critical_evidence.csv':['case_id','evidence_id','critical_label','supporting_rationale','source_reference','reviewer_id'],
 'ground_truth_relationships.csv':['case_id','source_entity_id','relationship_type','target_entity_id','source_reference','reviewer_id'],
 'known_temporal_order.csv':['case_id','earlier_event_id','later_event_id','order_certainty','source_reference','reviewer_id'],
 'reviewer_scores.csv':['blind_run_id','claim_id','reviewer_id','claim_support','citation_validity','evidence_reference','original_judgment','adjudicated_judgment'],
 'baseline_results.csv':['blind_run_id','case_id','system_alias','repeat','metric','value','unit','failure_reason'],
 'ablation_results.csv':['blind_run_id','case_id','ablation_id','metric','value','unit','failure_reason'],
 'latency_resource_log.csv':['blind_run_id','started_at','compute_seconds','human_wait_seconds','input_tokens','output_tokens','peak_ram_bytes','peak_vram_bytes','failure','timeout'],
}
for name,fields in templates.items():
 folder=ROOT/'07_Evaluation_Artifacts/evaluator_only/templates' if name in ['case_ground_truth.csv','critical_evidence.csv','ground_truth_relationships.csv','known_temporal_order.csv','reviewer_scores.csv'] else ROOT/'07_Evaluation_Artifacts/templates'
 csvout(folder/name,fields,[])
write(ROOT/'07_Evaluation_Artifacts/templates/experiment_config.yaml','status: unconfigured\nsource_commit: b9b2012edaed8da5062113ddc9982e3c33b27983\ndataset_subset: null\nmodel_identity: null\nmodel_digest: null\nretrieval_settings: null\nrun_parameters: null\nreviewer_blinding: required\nnisthacking_dependent_experiments: pending_dataset_acquisition_and_verification\n')
write(ROOT/'07_Evaluation_Artifacts/templates/statistical_analysis.ipynb',json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':[{'cell_type':'markdown','metadata':{},'source':['# Case-level analysis template\n','No results exist. Freeze the experiment protocol before computing estimates. Analyse at case level; retain failures and timeouts. Report uncertainty and independent reviewer agreement. Do not treat empty labels as negative labels.']} ]},indent=2))
write(ROOT/'07_Evaluation_Artifacts/templates/reproducibility_manifest.json',json.dumps({'status':'template_no_experiments','source_commit':'b9b2012edaed8da5062113ddc9982e3c33b27983','dataset_hashes':[],'environment_metadata':'../../06_Existing_Project_Resources/installed_package_inventory.json','run_identifiers':[],'models':[],'pending_experiments':['NIST Hacking dependent experiments: dataset deferred, not cancelled']},indent=2))

bibliography=[]
for p in (ROOT/'03_Research_Papers').glob('*/metadata.html'):
 h=p.read_text(encoding='utf-8');meta=lambda k:[html.unescape(x) for x in re.findall(r'<meta name="'+k+r'" content="([^"]+)"',h)]
 local=list(p.parent.glob('*.pdf'));licenses=re.findall(r'href="([^"]+)"[^>]*>\s*view license',h)
 bibliography.append({'title':'; '.join(meta('citation_title')),'authors':'; '.join(meta('citation_author')),'date':'; '.join(meta('citation_date')),'version':local[0].stem if local else '', 'doi':'','official_source':next((e['url'] for e in events if e['path']==str(p)),''),'download_url':next((e['url'] for e in events if local and Path(e['path']).name==local[0].name),''),'local_path':str(local[0]) if local else '', 'sha256':digest(local[0]) if local else '', 'licence':'; '.join(licenses) or 'See original arXiv licence link; no redistribution inferred','status':'DOWNLOADED — VERIFIED' if local else 'METADATA ONLY'})
dfirmeta=ROOT/'03_Research_Papers/DFIR-Metric/arxiv_metadata.html'
h=dfirmeta.read_text(encoding='utf-8')
bibliography.append({'title':'DFIR-Metric: A Benchmark Dataset for Evaluating Large Language Models in Digital Forensics and Incident Response','authors':'; '.join(re.findall(r'<meta name="citation_author" content="([^"]+)"',h)),'date':'2025-05-26','version':'2505.19973v1','doi':'10.48550/arXiv.2505.19973','official_source':'https://arxiv.org/abs/2505.19973','download_url':'https://arxiv.org/pdf/2505.19973v1','local_path':str(ROOT/'03_Research_Papers/DFIR-Metric/2505.19973v1.pdf'),'sha256':digest(ROOT/'03_Research_Papers/DFIR-Metric/2505.19973v1.pdf'),'licence':'See preserved arXiv licence link','status':'DOWNLOADED — VERIFIED'})
for folder,filename,doi in [('Drain2017','ICWS17-author-copy.pdf','10.1109/ICWS.2017.13'),('Hmimou','ACCESS.2025.3602681.pdf','10.1109/ACCESS.2025.3602681'),('CFA-Bench','', '10.1109/EuroSPW67616.2025.00031'),('MADIK','', '10.1007/978-3-540-88875-8_10')]:
 metadata=ROOT/f'03_Research_Papers/{folder}'
 source=metadata/('candidate_crossref_metadata.json' if folder=='MADIK' else 'crossref_metadata.json')
 d=load(source)['message'];p=metadata/filename if filename else None
 bibliography.append({'title':'; '.join(d.get('title',[])),'authors':'; '.join(' '.join([x.get('given',''),x.get('family','')]).strip() for x in d.get('author',[])),'date':str(d.get('published',d.get('issued',{})).get('date-parts','')),'version':'author copy' if folder=='Drain2017' else 'version of record' if folder=='Hmimou' else 'candidate' if folder=='MADIK' else 'metadata only','doi':doi,'official_source':'https://doi.org/'+doi,'download_url':next((e['url'] for e in events if p and relocation_by_path.get(e['path'],e['path'])==str(p)),''),'local_path':str(p) if p else '', 'sha256':digest(p) if p else '', 'licence':'; '.join(x['URL'] for x in d.get('license',[])) or 'Publisher copyright; public author availability does not imply redistribution permission','status':'NEEDS CONFIRMATION' if folder=='MADIK' else 'DOWNLOADED — VERIFIED' if p else 'MANUSCRIPT PUBLIC; LOCAL DOWNLOAD BLOCKED'})
csvout(ROOT/'08_Checksums_And_Manifests/research_paper_bibliography.csv',list(bibliography[0]),bibliography)
csvout(ROOT/'03_Research_Papers/research_paper_bibliography.csv',list(bibliography[0]),bibliography)
csvout(ROOT/'08_Checksums_And_Manifests/repository_manifest.csv',list(dict.fromkeys(k for r in repo_manifest for k in r)),repo_manifest)
csvout(ROOT/'08_Checksums_And_Manifests/acquired_file_manifest.csv',list(files[0]),files)
checks=[{'local_path':r['local_storage_path'],'actual_size_bytes':r['file_size_bytes'],'sha256':r['sha256'],'verification_status':r.get('verification_status','SOURCE_FIXTURE_HASH_VERIFIED'),'source_url':'existing project; see inventory','version':'existing snapshot','checked_at':NOW} for r in existing]
checks += [{'local_path':f['local_path'],'actual_size_bytes':f['actual_size_bytes'],'sha256':f['sha256'],'verification_status':f['verification_status'],'source_url':f['source_url'],'version':f['version'],'checked_at':NOW} for f in files]
checks += [{'local_path':x['agent_evidence_path'],'actual_size_bytes':Path(x['agent_evidence_path']).stat().st_size,'sha256':x['sha256'],'verification_status':'BYTE_IDENTICAL_EVIDENCE_COPY','source_url':'CFA-Bench pinned raw evidence; mapping evaluator-only','version':'da8a92fa16d6d6f30e702299c8e368cb6461d5f7','checked_at':NOW} for x in maps]
csvout(ROOT/'08_Checksums_And_Manifests/resource_checksums.csv',list(checks[0]),checks)
datasets=[r for r in rows if r['category'].startswith(('1.','2.','7.'))]
csvout(ROOT/'08_Checksums_And_Manifests/dataset_manifest.csv',list(rows[0]),datasets)
pending=[r for r in rows if not any(x in r['acquisition_status'] for x in ['VERIFIED','AUDITED','RECORDED','TEMPLATE CREATED','CREATED'])]
restricted=[r for r in rows if 'RESTRICTED' in r['acquisition_status']]
csvout(ROOT/'00_Master_Inventory/missing_resources_report.csv',list(rows[0]),pending)
csvout(ROOT/'00_Master_Inventory/restricted_resources_report.csv',list(rows[0]),restricted)
csvout(REPORT/'missing_resources_report.csv',list(rows[0]),pending)
csvout(REPORT/'restricted_resources_report.csv',list(rows[0]),restricted)

summary={'checked_at':NOW,'checklist_rows':len(rows),'status_counts':dict(collections.Counter(r['acquisition_status'] for r in rows)),
 'acquired_files':len(files),'acquired_bytes':sum(f['actual_size_bytes'] for f in files),'verified_pdf_count':len(pdfs),'research_papers_acquired':sum(x['status']=='DOWNLOADED — VERIFIED' for x in bibliography),'pinned_clones':len(clones),'reference_archives':sum(x.get('files_present')=='archive' for x in repo_manifest),'existing_unique_files':len(existing),'existing_primary_hashed':2458,'existing_hash_deferred':31,'cfa_cases':len({Path(x['agent_evidence_path']).parent.name for x in maps}),'cfa_evidence_files':len(maps),'disk_free_bytes':shutil.disk_usage(ROOT).free,'dfir_counts':counts,'pilot':[r for r in rows if r['category'].startswith('7.')], 'remaining':len(pending)}
write(REPORT/'campaign_input.json',json.dumps({'summary':summary,'checklist':rows,'files':files,'existing':existing,'papers':bibliography},indent=2))
write(REPORT/'campaign_summary.json',json.dumps(summary,indent=2))
write(REPORT/'acquisition_log.md','# Acquisition log - 11 November 2026\n\nAuthoritative scope: CHECKLIST.md, including user-supplied bibliography corrections. Original checklist and preliminary audit outputs preserved.\n\nAll network attempts, HTTP headers, source URLs, byte counts and SHA-256 values are in download_events.jsonl. Exact clone commits, sparse paths and original archive commits are in their receipts and repository_manifest.csv. No installation, experiment or reference-code execution occurred.\n\nNIST Hacking Case remains DEFERRED, P0. User deferred large evidence downloads; no large evidence request remains awaiting a default approval. The OpTC small-file quota HTML and zero-byte IEEE responses are rejected, not evidence/papers. CFA-Bench paper has an openly visible author manuscript but validated direct download failed; no actual local PDF is claimed. MADIK is a candidate pending relevance confirmation.\n\nIntegrity checks: HTTP lengths when supplied; local SHA-256; strict PDF structure/EOF; ZIP CRC; JSON parse; git clean status/connectivity; STIX git blob identity; OCSF version.json; observed benchmark question counts. Scientific label correctness and runtime compatibility remain untested.\n\nSource archives for Zeek/Atomic Red Team exceeded 32 MiB bounds and were not saved. Optional software/standards or reviewer inputs remain explicitly pending/restricted. See master tracker for every checklist row and remaining action.\n')
write(ROOT/'README.md','# Specula research acquisition workspace\n\nAuthoritative scope: CHECKLIST.md. See 00_Master_Inventory/master_acquisition_tracker.xlsx and 09_Acquisition_Reports/acquisition_summary.pdf for actual acquired, existing, deferred, restricted and pending resources. Initial audit artifacts and checklist are retained under 09_Acquisition_Reports/preliminary_audit and CHECKLIST.original.20261111.md.\n\nNIST Hacking Case: DEFERRED, P0 retained. Experiments requiring it remain pending. Large evidence downloads are deferred by user instruction. No installs or Specula implementation changes were made.\n\nOnly 02_Benchmarks/CFA_Bench/agent_evidence is prepared as a candidate agent evidence root. Raw CFA byte copies have opaque filenames; tasks, labels, results and original name mapping are evaluator-only. Do not give agents the master inventory, source repos, original public benchmark paths or evaluator directory as evidence. Windows ACL restricts evaluator storage to DELL, SYSTEM and the acquisition sandbox account; same-principal agents still need separate identities or enforced read roots. Do not begin blinded experiments until access separation is verified.\n\nRun verification as the evaluator account: `..\\venv\\Scripts\\python.exe 09_Acquisition_Reports\\verify_campaign.py`. Native software compatibility, scientific truth/independence, publisher checksum authenticity where absent, and unseen external project files are outside the completed checks.\n')
print(json.dumps({k:v for k,v in summary.items() if k!='pilot'},indent=2))
