import collections,csv,datetime as dt,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];REPORT=ROOT/'09_Acquisition_Reports';RUN=Path(json.loads((REPORT/'remediation_current.json').read_text())['run_directory'])
data=json.loads((REPORT/'campaign_input.json').read_text(encoding='utf-8'));lookup={r['checklist_id']:r for r in data['checklist']}
changes=json.loads((RUN/'metadata_corrections.json').read_text(encoding='utf-8'));added=[]
def change(identity,field,value,authority):
 r=lookup[identity]
 if r.get(field,'')==value:return
 record={'checklist_id':identity,'resource':r['resource_name'],'field':field,'original_value':r.get(field,''),'corrected_value':value,'authoritative_source':authority,'checked_utc':dt.datetime.now(dt.timezone.utc).isoformat()}
 changes.append(record);added.append(record);r[field]=value
source='00_Master_Inventory/named_existing_resource_audit.csv and primary bibliography: exact named original absent; separate DOI/arXiv-equivalent acquired copy retained'
for identity in ['CL-019','CL-020']:
 for field,value in {'acquisition_status':'UNAVAILABLE','resource_kind':'named_original_lookup','artifact_state':'EXACT_NAMED_ORIGINAL_NOT_LOCATED','local_storage_path':'','sha256':'','actual_size_bytes':'','version':'UNRESOLVED for the requested named original','checksum_reference':'No bytes asserted for missing named original; see separate acquired paper record and bibliography','verification_status':'Exact requested local filename not located; acquired bibliographic equivalent is a separate artifact','metadata_authority':source}.items():change(identity,field,value,source)
 change(identity,'notes',lookup[identity]['notes']+'; Reconciled named-original lookup: no acquired-copy hash/size is attributed to the absent original. The separately acquired equivalent paper remains verified in the bibliography.',source)
change('CL-015','acquisition_status','AUDITED — XLSX EXISTS; ORIGINAL STIX NOT LOCATED','Original inventory and offline workbooks are XLSX; separately acquired versioned STIX is recorded under CL-042/CL-122')
change('CL-015','resource_kind','audit_step','Checklist asks to check the prior offline copy; a workbook is not STIX JSON')
change('CL-015','artifact_state','EXISTING_XLSX_REFERENCE_NOT_STIX','known_attacks/enterprise-attack-v19.2.xlsx ZIP/XML format')
p=Path(lookup['CL-027']['local_storage_path'])
change('CL-027','sha256',hashlib.sha256(p.read_bytes()).hexdigest(),'Fresh hash of exact existing architecture_agents.html, already covered by resource_checksums.csv')
change('CL-027','actual_size_bytes',str(p.stat().st_size),'Filesystem byte size of exact existing path')
change('CL-027','checksum_reference','08_Checksums_And_Manifests/resource_checksums.csv#'+str(p),'Existing independent per-file integrity ledger')
fields=list(data['checklist'][0])
def csvwrite(path,values,columns):
 with path.open('w',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=columns);w.writeheader();w.writerows(values)
csvwrite(ROOT/'00_Master_Inventory/checklist_status.csv',data['checklist'],fields)
pending=[r for r in data['checklist'] if r['acquisition_status'].startswith(('PENDING','DEFERRED','UNAVAILABLE','RESTRICTED','PARTIALLY','NEEDS','METADATA ONLY')) or r.get('artifact_state')=='REFERENCE_ONLY_NO_TOOL_BINARY']
for relative in ['00_Master_Inventory/missing_resources_report.csv','09_Acquisition_Reports/missing_resources_report.csv']:csvwrite(ROOT/relative,pending,fields)
data['summary'].update(remaining=len(pending),status_counts=dict(collections.Counter(r['acquisition_status'] for r in data['checklist'])))
for p,value in [(REPORT/'campaign_input.json',data),(REPORT/'campaign_summary.json',data['summary']),(RUN/'metadata_corrections.json',changes)]:
 with p.open('w',encoding='utf-8') as f:json.dump(value,f,indent=2)
csvwrite(RUN/'metadata_corrections.csv',changes,list(changes[0]))
with (REPORT/'metadata_reconciliation_report.md').open('a',encoding='utf-8') as f:
 f.write('\n## Additional contradictions detected by final verification\n\nCL-019 and CL-020 distinguish missing named originals from separately acquired bibliographic equivalents. The latter remain present and verified; no paper was deleted or redownloaded. CL-015 now states that the prior offline copy is XLSX, not STIX. CL-027 now links its existing integrity proof directly. These changes increase unresolved named-original dispositions to '+str(len(pending))+' without changing the nine acquired-paper count.\n\n| ID | Field | Before | After | Authority |\n| --- | --- | --- | --- | --- |\n')
 for r in added:f.write('| '+' | '.join(str(r[k]).replace('|','/').replace('\n',' ') for k in ['checklist_id','field','original_value','corrected_value','authoritative_source'])+' |\n')
for p in [REPORT/'post_remediation_verification.md',RUN/'post_remediation_receipt.json']:
 q=RUN/'intermediate'/('first_failed_'+p.name);q.parent.mkdir(exist_ok=True)
 assert p.resolve().is_relative_to(ROOT) and q.resolve().is_relative_to(ROOT) and not q.exists();p.rename(q)
print(json.dumps({'additional_field_corrections':len(added),'field_ledger_entries':len(changes),'unresolved_rows':len(pending),'acquired_papers_unchanged':9}))
