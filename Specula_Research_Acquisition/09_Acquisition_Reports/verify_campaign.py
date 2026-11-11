"""Executable acquisition oracle; never runs downloaded reference implementations."""
import csv,datetime as dt,hashlib,json,re,struct,subprocess,zipfile
from pathlib import Path
from xml.etree import ElementTree as ET
from pypdf import PdfReader
from fetch_official import ROOT

def read_csv(name):
 with (ROOT/name).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def git(path,*args):
 return subprocess.check_output(['git','-c','safe.directory='+str(path),'-C',str(path),*args],text=True).strip()

required=['00_Master_Inventory/master_acquisition_tracker.xlsx','00_Master_Inventory/existing_resource_inventory.csv','00_Master_Inventory/missing_resources_report.csv','00_Master_Inventory/restricted_resources_report.csv','08_Checksums_And_Manifests/dataset_manifest.csv','08_Checksums_And_Manifests/repository_manifest.csv','08_Checksums_And_Manifests/research_paper_bibliography.csv','08_Checksums_And_Manifests/resource_checksums.csv','09_Acquisition_Reports/acquisition_summary.pdf','09_Acquisition_Reports/acquisition_log.md']
for name in required:assert (ROOT/name).is_file() and (ROOT/name).stat().st_size>0,name
checks=read_csv('08_Checksums_And_Manifests/resource_checksums.csv');verified=0;deferred=0;seen={}
for row in checks:
 path=Path(row['local_path']);assert path.is_file(),path
 if not row['sha256']:
  assert 'mutable' in row['verification_status'],row
  deferred+=1;continue
 if str(path) in seen:
  assert row['sha256']==seen[str(path)];continue
 assert path.stat().st_size==int(row['actual_size_bytes']),path
 actual=sha(path);assert actual==row['sha256'],path
 seen[str(path)]=actual;verified+=1
assert deferred==31
for r in read_csv('07_Evaluation_Artifacts/evaluator_only/CFA_evidence_mapping.csv'):
 assert sha(Path(r['original_path']))==sha(Path(r['agent_evidence_path']))==r['sha256']
 assert not re.search(r'CVE-|success|fail',Path(r['agent_evidence_path']).name,re.I)
evidence=list((ROOT/'02_Benchmarks/CFA_Bench/agent_evidence').rglob('*'))
assert len([p for p in evidence if p.is_file()])==59
assert all(p.suffix.lower() in ['.pcap','.log','.pcapng'] for p in evidence if p.is_file())
pcap_files=0;pcap_packets=0
for p in evidence:
 if not p.is_file() or p.suffix.lower()!='.pcap':continue
 content=p.read_bytes();assert len(content)>=24,p
 magic=content[:4]
 assert magic in [b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d'],(p,magic)
 endian='<' if magic in [b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'] else '>'
 snaplen=struct.unpack_from(endian+'I',content,16)[0];position=24
 while position<len(content):
  assert position+16<=len(content),p
  _,_,captured,original=struct.unpack_from(endian+'IIII',content,position)
  assert captured<=snaplen and captured<=original,p
  position+=16+captured;assert position<=len(content),p;pcap_packets+=1
 assert position==len(content);pcap_files+=1
assert not list((ROOT/'01_Forensic_Datasets/NIST_Hacking_Case').glob('SCHARDT.00?'))
assert not list((ROOT/'01_Forensic_Datasets/OpTC/network_subset').glob('*.gz'))
clones=[json.loads(x) for x in (ROOT/'09_Acquisition_Reports/clone_receipts.jsonl').read_text().splitlines()]
for r in clones:
 path=Path(r['path']);assert git(path,'rev-parse','HEAD')==r['commit'];assert not git(path,'status','--porcelain');git(path,'fsck','--connectivity-only')
ledger=read_csv('00_Master_Inventory/checklist_status.csv')
assert len(ledger)==len(re.findall(r'^\s*- \[ \]',(ROOT/'CHECKLIST.md').read_text(encoding='utf-8-sig'),re.M))==136
current_names=[re.sub(r'^\s*- \[ \]\s*','',line).replace('**','').replace('`','') for line in (ROOT/'CHECKLIST.md').read_text(encoding='utf-8-sig').splitlines() if re.match(r'\s*- \[ \]',line)]
assert current_names==[r['resource_name'] for r in ledger]
assert len({r['checklist_id'] for r in ledger})==136
assert all(r['acquisition_status'] and r['notes'] for r in ledger)
pilot=[r for r in ledger if r['category'].startswith('7.')]
assert len(pilot)==10
assert pilot[0]['acquisition_status']=='DEFERRED'
assert pilot[2]['acquisition_status']=='UNAVAILABLE'
assert pilot[3]['acquisition_status']=='PARTIALLY DOWNLOADED'
assert sum('VERIFIED' in r['acquisition_status'] for r in pilot)==7
assert next(r for r in ledger if r['resource_name']=='MADIK original paper')['acquisition_status']=='NEEDS CONFIRMATION'
papers=read_csv('08_Checksums_And_Manifests/research_paper_bibliography.csv')
assert sum(r['status']=='DOWNLOADED — VERIFIED' for r in papers)==9
assert not next(r for r in papers if r['doi']=='10.1109/EuroSPW67616.2025.00031')['local_path']
assert all(not r['local_path'] or Path(r['local_path']).is_file() for r in papers)
for f in (ROOT/'07_Evaluation_Artifacts/evaluator_only/templates').glob('*.csv'):
 with f.open(encoding='utf-8-sig') as stream:assert len(list(csv.reader(stream)))==1
for f in (ROOT/'07_Evaluation_Artifacts/templates').glob('*.csv'):
 with f.open(encoding='utf-8-sig') as stream:assert len(list(csv.reader(stream)))==1
nb=json.loads((ROOT/'07_Evaluation_Artifacts/templates/statistical_analysis.ipynb').read_text());assert nb['nbformat']==4
assert all(c['cell_type']=='markdown' for c in nb['cells'])
namespace={'m':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
with zipfile.ZipFile(ROOT/required[0]) as archive:
 assert archive.testzip() is None
 book=ET.fromstring(archive.read('xl/workbook.xml'))
 assert [e.attrib['name'] for e in book.findall('m:sheets/m:sheet',namespace)]==['Overview','Checklist','Acquired','Existing audit']
 overview=ET.fromstring(archive.read('xl/worksheets/sheet1.xml'))
 values={c.attrib['r']:c.findtext('m:v',default='',namespaces=namespace) for c in overview.findall('.//m:c',namespace)}
 data=json.loads((ROOT/'09_Acquisition_Reports/campaign_input.json').read_text(encoding='utf-8'))
 expected=[len(ledger),len(data['files']),sum(f['actual_size_bytes'] for f in data['files'])]
 for cell,want in zip(['B4','B5','B6'],expected):assert float(values[cell])==want,(cell,values[cell],want)
 for number,count in [(2,len(ledger)),(3,len(data['files'])),(4,len(data['existing']))]:
  sheet=ET.fromstring(archive.read(f'xl/worksheets/sheet{number}.xml'))
  assert len(sheet.findall('m:sheetData/m:row',namespace))==count+1
 for number in range(1,5):
  sheet=ET.fromstring(archive.read(f'xl/worksheets/sheet{number}.xml'))
  assert not [c for c in sheet.findall('.//m:c',namespace) if c.attrib.get('t')=='e']
for name in ['09_Acquisition_Reports/acquisition_summary.pdf','07_Evaluation_Artifacts/reviewer_instructions.pdf']:
 pdf=PdfReader(ROOT/name,strict=True);assert 1<=len(pdf.pages)<=5
 assert b'%%EOF' in (ROOT/name).read_bytes()[-2048:]
text='\n'.join(p.extract_text() for p in PdfReader(ROOT/'09_Acquisition_Reports/acquisition_summary.pdf').pages)
text=' '.join(text.split())
assert 'DEFERRED / P0' in text and 'GenDFIR v4' in text and 'not completed or cancelled' in text
assert git(ROOT.parent,'rev-parse','HEAD')=='b9b2012edaed8da5062113ddc9982e3c33b27983'
assert not git(ROOT.parent,'diff','--name-only','HEAD','--','src','scripts','tests','docs','requirements.txt','DECISIONS.md','PROGRESS.md')
receipt={'checked_at':dt.datetime.now(dt.timezone.utc).isoformat(),'result':'PASS','scope':'Acquisition integrity/coverage only; unresolved resources remain explicitly pending/deferred/restricted',
 'unique_files_hash_rechecked':verified,'mutable_hashes_deferred':deferred,'checklist_rows':len(ledger),'checklist_sha256':sha(ROOT/'CHECKLIST.md'),'pilot_verified_scopes':7,'pilot_partial':1,'pilot_deferred':1,'pilot_unavailable':1,'verified_research_papers':9,'pinned_clones_checked':len(clones),'cfa_evidence_files_checked':59,'pcap_files_structure_checked':pcap_files,'pcap_packet_records_checked':pcap_packets,'workbook_summary_cache_reconciled':True,'original_implementation_unchanged':True}
target=ROOT/'09_Acquisition_Reports/final_verification_receipt.json'
if target.exists():
 old=json.loads(target.read_text());assert old['result']=='PASS'
else:
 with target.open('x',encoding='utf-8') as f:json.dump(receipt,f,indent=2)
print(json.dumps(receipt,indent=2))
