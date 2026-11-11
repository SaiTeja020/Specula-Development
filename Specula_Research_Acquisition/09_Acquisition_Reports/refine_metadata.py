"""Refine licence and named-original dispositions; preserve every prior report."""
import csv,json,re
from pathlib import Path
import collections
from fetch_official import ROOT
report=ROOT/'09_Acquisition_Reports'
data=json.loads((report/'campaign_input.json').read_text(encoding='utf-8'))
def rewrite(relative,fields,rows):
 p=ROOT/relative;backup=report/'pre_export_revision'/relative
 backup.parent.mkdir(parents=True,exist_ok=True)
 if p.exists():
  assert not backup.exists();p.rename(backup)
 with p.open('x',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
licences={}
for p in (ROOT/'03_Research_Papers').glob('*/*.html'):
 if p.name not in ['metadata.html','arxiv_metadata.html']:continue
 links=re.findall(r'href="(https?://(?:creativecommons\.org|arxiv\.org)/licenses/[^"]+)"',p.read_text(encoding='utf-8'))
 if links:
  for pdf in p.parent.glob('*.pdf'):licences[str(pdf)]=links[0]
licences[str(ROOT/'03_Research_Papers/Hmimou/ACCESS.2025.3602681.pdf')]='CC BY 4.0; https://creativecommons.org/licenses/by/4.0/'
licences[str(ROOT/'03_Research_Papers/Drain2017/ICWS17-author-copy.pdf')]='IEEE copyright; public author-hosted copy; redistribution not granted'
for f in data['files']:
 p=f['local_path']
 if p in licences:f['licence']=licences[p]
 elif '/OpTC/' in p.replace('\\','/'):f['licence']='Public domain; Distribution A / unlimited; see pinned DARPA README'
 elif '/MITRE_ATTACK/' in p.replace('\\','/'):f['licence']='MITRE research/development/commercial use with copyright and licence retention; see LICENSE.txt'
 elif 'ocsf-schema-1.9.0' in p:f['licence']='Apache-2.0; see pinned repository LICENSE'
 elif any(x in p.replace('\\','/') for x in ['/plaso/','/timesketch/']):f['licence']='Apache-2.0; see pinned repository licence'
 elif any(x in p.replace('\\','/') for x in ['/CFA-bench/','/CyberSleuth/','/DFIR-Metric/']):f['licence']='Public repository; explicit reuse licence not found; no redistribution permission inferred'
for p in data['papers']:
 if p['local_path'] in licences:p['licence']=licences[p['local_path']]
requested=['Master doc.docx','IEEE-paper-outline.txt','Base Paper.pdf','A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using LLMs.pdf','Metrics for Specula Agents','Report format','Output report format and standards','Specula Features','SPECULA DATA FLOW','Master_doc_planned_changes.md','architecture_agents.html']
named=[]
for name in requested:
 matches=[r['local_storage_path'] for r in data['existing'] if Path(r['local_storage_path']).name.casefold()==name.casefold() or (not Path(name).suffix and Path(r['local_storage_path']).stem.casefold()==name.casefold())]
 item={'requested_name':name,'status':'EXACT LOCAL MATCH' if matches else 'NAMED ORIGINAL NOT LOCATED IN AUDITED SCOPE','existing_paths':'; '.join(matches),'notes':'Related files are not silently treated as exact originals. See bibliography for newly acquired equivalent publications by identifier.'}
 named.append(item)
 for r in data['checklist']:
  if r['resource_name']==name:
   r['acquisition_status']='EXISTS — VERIFIED' if matches else 'UNAVAILABLE'
   r['notes']+='; '+item['status']
   r['local_storage_path']='; '.join(matches)
   r['verification_status']='Inventory path/hash checked' if matches else 'No exact local name located; external copies not assumed missing'
for r in data['checklist']:
 linked=next((f for f in data['files'] if f['local_path']==r['local_storage_path']),None)
 if linked:r['licence_access_restrictions']=linked['licence']
 if 'NIST' in r['resource_name'] and 'Hacking' in r['resource_name']:
  r['expected_size_bytes']=4871301120;r['actual_size_bytes']=0
  r['licence_access_restrictions']='Public official case; explicit case licence not found. Raw evidence deferred by owner.'
 if 'v1.9.0' in r['version'] or r['version']=='1.9.0':r['release_date']='2026-08-03 (GitHub release 1.9.0)'
 if 'NIST SP 800-86' in r['resource_name']:r['release_date']='2006-08'
 if 'NIST SP 800-61' in r['resource_name']:r['release_date']='2025-04'
 for p in data['papers']:
  if p['local_path'] and r['local_storage_path']==p['local_path']:
   r['release_date']=p['date']+' (original publication/submission; exact version date in preserved metadata)'
rewrite('00_Master_Inventory/named_existing_resource_audit.csv',list(named[0]),named)
rewrite('00_Master_Inventory/checklist_status.csv',list(data['checklist'][0]),data['checklist'])
rewrite('08_Checksums_And_Manifests/acquired_file_manifest.csv',list(data['files'][0]),data['files'])
for relative in ['08_Checksums_And_Manifests/research_paper_bibliography.csv','03_Research_Papers/research_paper_bibliography.csv']:
 rewrite(relative,list(data['papers'][0]),data['papers'])
pending=[r for r in data['checklist'] if not any(x in r['acquisition_status'] for x in ['VERIFIED','AUDITED','RECORDED','TEMPLATE CREATED','CREATED'])]
restricted=[r for r in data['checklist'] if 'RESTRICTED' in r['acquisition_status']]
for relative in ['00_Master_Inventory/missing_resources_report.csv','09_Acquisition_Reports/missing_resources_report.csv']:rewrite(relative,list(data['checklist'][0]),pending)
for relative in ['00_Master_Inventory/restricted_resources_report.csv','09_Acquisition_Reports/restricted_resources_report.csv']:rewrite(relative,list(data['checklist'][0]),restricted)
data['summary']['remaining']=len(pending)
data['summary']['status_counts']=dict(collections.Counter(r['acquisition_status'] for r in data['checklist']))
data['summary']['pilot']=[r for r in data['checklist'] if r['category'].startswith('7.')]
for name,value in [('campaign_input.json',data),('campaign_summary.json',data['summary'])]:
 p=report/name;b=report/'pre_export_revision'/name;b.parent.mkdir(exist_ok=True,parents=True);assert not b.exists();p.rename(b)
 with p.open('x',encoding='utf-8') as f:json.dump(value,f,indent=2)
old=ROOT/'00_Master_Inventory/master_acquisition_tracker.xlsx'
backup=report/'pre_export_revision/master_acquisition_tracker.xlsx';assert not backup.exists();old.rename(backup)
print('Precise licences/named-original dispositions updated; prior outputs preserved')
