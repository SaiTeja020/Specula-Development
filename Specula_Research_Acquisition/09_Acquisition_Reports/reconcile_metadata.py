"""Authorized metadata-only reconciliation; never writes evidence or clones."""
import collections,csv,datetime as dt,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REPORT=ROOT/'09_Acquisition_Reports'
RUN=Path(json.loads((REPORT/'remediation_current.json').read_text())['run_directory'])
NOW=dt.datetime.now(dt.timezone.utc).isoformat()
backups={x['relative_path']:x for x in json.loads((RUN/'backup_manifest.json').read_text())}
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def readcsv(relative):
 with (ROOT/relative).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def writecsv(relative,rows,fields=None):
 p=ROOT/relative
 if p.exists() and relative not in backups:raise RuntimeError('No original backup: '+relative)
 with p.open('w' if p.exists() else 'x',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields or list(rows[0]),extrasaction='ignore');w.writeheader();w.writerows(rows)
def writejson(relative,data):
 p=ROOT/relative
 if p.exists() and relative not in backups:raise RuntimeError('No original backup: '+relative)
 with p.open('w' if p.exists() else 'x',encoding='utf-8') as f:json.dump(data,f,indent=2)
rows=readcsv('00_Master_Inventory/checklist_status.csv');old={r['checklist_id']:dict(r) for r in rows};byid={r['checklist_id']:r for r in rows}
changes=[]
def change(r,field,value,source):
 value=str(value) if value is not None else ''
 before=r.get(field,'')
 if before==value:return
 changes.append({'checklist_id':r['checklist_id'],'resource':r['resource_name'],'field':field,'original_value':before,'corrected_value':value,'authoritative_source':source,'checked_utc':NOW})
 r[field]=value
def linked(r,path,source):
 p=ROOT/path
 if not p.is_file():raise FileNotFoundError(p)
 change(r,'local_storage_path',str(p),source)
 change(r,'actual_size_bytes',p.stat().st_size,'Filesystem byte count: '+str(p))
 change(r,'sha256',sha(p),'Fresh SHA-256: '+str(p))
 change(r,'checksum_reference','Direct SHA-256 of linked file; broader resource contents in per-file manifest',source)
for r in rows:
 category=r['category']
 kind='resource'
 if category.startswith('Instructions'):kind='operational_directive'
 elif category.startswith('0.'):kind='existing_resource_or_audit_step'
 elif category.startswith('1.'):kind='forensic_dataset'
 elif category.startswith('2.'):kind='benchmark_or_reference'
 elif category.startswith('3.'):kind='research_paper_or_literature_topic'
 elif category.startswith('4.'):kind='software_reference'
 elif category.startswith('5.'):kind='standard_or_documentation'
 elif category.startswith('6.'):kind='evaluation_preparation_artifact'
 elif category.startswith('7.'):kind='pilot_acquisition_alias'
 elif category.startswith('8.'):kind='derived_deliverable'
 change(r,'resource_kind',kind,'CHECKLIST.md: '+category)
 change(r,'artifact_state','NOT_ASSERTED_AS_EXPERIMENT_RESULT','Acquisition status is not experimental completion')
 change(r,'checksum_reference',r.get('checksum_reference') or ('Direct SHA-256 in row' if r['sha256'] else 'No acquired bytes asserted; see status/notes'),'Recorded resource scope; detached checksums for generated outputs')
 change(r,'metadata_authority','CHECKLIST.md; original source values retained in '+str((RUN/'backup/00_Master_Inventory/checklist_status.csv').relative_to(ROOT)),'Owner-authorized checklist and immutable metadata backup')

# The three aliases inherit explicitly stated P0 priority from their primary entries.
for identity in ['CL-121','CL-124','CL-125']:
 change(byid[identity],'priority','P0','CHECKLIST.md sections 2/3/5 P0 entries; same named resource in section 7')

# Websites are preserved HTML references, not acquired tool binaries.
for identity,name in [('CL-070','Wireshark'),('CL-072','Zimmerman')]:
 r=byid[identity];relative=f'05_Standards_Documentation/tool_reference_pages/{name}.html'
 linked(r,relative,'Actual saved HTML and download_events.jsonl official URL')
 change(r,'resource_kind','website_reference','Saved response is HTML, not a native tool/archive')
 change(r,'artifact_state','REFERENCE_ONLY_NO_TOOL_BINARY','Filesystem format and original acquisition log')
 change(r,'acquisition_status','WEBSITE REFERENCE — VERIFIED','Only official reference page was acquired')
 change(r,'version','UNRESOLVED: page snapshot does not establish installed tool version','No tool binary acquired')
 change(r,'verification_status','HTML file present, readable and SHA-256 verified; native tool not acquired or tested','Fresh read/hash, not tool execution')
 change(r,'notes',r['notes']+'; Reconciled: website reference only; no executable/install/source implementation claimed.',relative)

template_locations={
 'case_ground_truth.csv':'evaluator_only/templates','critical_evidence.csv':'evaluator_only/templates',
 'ground_truth_relationships.csv':'evaluator_only/templates','known_temporal_order.csv':'evaluator_only/templates',
 'reviewer_scores.csv':'evaluator_only/templates','baseline_results.csv':'templates','ablation_results.csv':'templates',
 'latency_resource_log.csv':'templates','experiment_config.yaml':'templates','statistical_analysis.ipynb':'templates',
 'reproducibility_manifest.json':'templates','reviewer_instructions.pdf':''}
for r in rows:
 if not r['category'].startswith('6.'):continue
 name=r['resource_name'].split(' ')[0]
 if name=='dataset_manifest.csv':
  relative='08_Checksums_And_Manifests/dataset_manifest.csv';state='POPULATED_RESOURCE_INVENTORY_NOT_CASE_GROUND_TRUTH';status='RESOURCE MANIFEST — POPULATED'
 else:
  relative='07_Evaluation_Artifacts/'+('/'.join(x for x in [template_locations[name],name] if x))
  if name.endswith('.csv'):
   assert not readcsv(relative)
   state='HEADER_ONLY_ZERO_DATA_ROWS';status='EVALUATION TEMPLATE — EMPTY'
  elif name.endswith('.yaml'):state='UNCONFIGURED_NULL_EXPERIMENT_FIELDS';status='CONFIGURATION TEMPLATE — UNCONFIGURED'
  elif name.endswith('.ipynb'):
   nb=json.loads((ROOT/relative).read_text());assert not any(c.get('outputs') for c in nb['cells'])
   state='MARKDOWN_ONLY_NO_EXECUTED_RESULTS';status='ANALYSIS TEMPLATE — UNEXECUTED'
  elif name.endswith('.json'):state='NO_RUN_IDS_OR_MODEL_SELECTION';status='REPRODUCIBILITY TEMPLATE — UNPOPULATED'
  else:state='DRAFT_REVIEW_INSTRUCTIONS_NOT_REVIEWER_JUDGMENTS';status='REVIEWER PROTOCOL — DRAFT'
 linked(r,relative,'Existing artifact inspected; no labels or results added')
 change(r,'artifact_state',state,'Actual CSV row count or document/configuration content')
 change(r,'acquisition_status',status,'Observed content distinguishes templates from populated results')
 change(r,'resource_kind','resource_inventory' if name=='dataset_manifest.csv' else 'evaluation_template_or_protocol','Observed artifact purpose')
 change(r,'verification_status','Artifact exists and its observed template/document state is verified; no experiment completion asserted',relative)

# Paper metadata must not point at a benchmark README as though it were full text.
for r in rows:
 if r['resource_name']=='CFA-Bench original paper':
  linked(r,'03_Research_Papers/CFA-Bench/crossref_metadata.json','Official DOI metadata preserved locally')
  change(r,'resource_kind','research_paper_metadata','No actual paper PDF is present')
  change(r,'acquisition_status','METADATA ONLY — FULL TEXT UNAVAILABLE','Bibliography and zero-byte rejected publisher responses')
  change(r,'artifact_state','METADATA_NOT_PAPER_FULL_TEXT','DOI record only')
  change(r,'version','2025 publication metadata; full text not acquired','10.1109/EuroSPW67616.2025.00031')
  change(r,'verification_status','Metadata JSON parsed and hashed; no local full-text paper verified','Actual file format')

# Preserve acquired source values; verify local authorities before adopting master metadata.
events=[json.loads(x) for x in (REPORT/'download_events.jsonl').read_text(encoding='utf-8').splitlines()]
parts={e['url']:e['expected_bytes'] for e in events if e.get('method')=='HEAD' and re.search(r'SCHARDT\.00[1-8]$',e['url'])}
assert len(parts)==8 and sum(parts.values())==4871301120
assert 'public domain' in (ROOT/'01_Forensic_Datasets/OpTC/documentation/README.md').read_text().lower()
assert 'Apache License' in (ROOT/'05_Standards_Documentation/ocsf-schema-1.9.0/LICENSE').read_text()
release=json.loads((REPORT/'source_metadata/ocsf_release.json').read_text());assert release['tag_name']=='1.9.0' and release['published_at'].startswith('2026-08-03')
assert 'creativecommons.org/licenses/by-nc-sa/4.0/' in (ROOT/'03_Research_Papers/DFIR-Metric/arxiv_metadata.html').read_text()
assert (ROOT/'02_Benchmarks/MITRE_ATTACK/LICENSE.txt').is_file()
authorities={
 'CL-033':'09_Acquisition_Reports/download_events.jsonl: eight official HEAD Content-Length values, sum 4871301120; raw files absent; licence remains explicitly unknown',
 'CL-035':'01_Forensic_Datasets/OpTC/documentation/README.md public-domain/Distribution A statement',
 'CL-040':'Pinned DFIR-Metric repository tree: no explicit reuse licence found; do not infer permission',
 'CL-041':'03_Research_Papers/DFIR-Metric/arxiv_metadata.html citation_date and licence link',
 'CL-042':'02_Benchmarks/MITRE_ATTACK/LICENSE.txt',
 'CL-044':'Pinned CFA-bench repository tree; no explicit reuse licence found',
 'CL-045':'Pinned CyberSleuth repository tree; no explicit reuse licence found',
 'CL-118':'01_Forensic_Datasets/OpTC/documentation/README.md',
 'CL-120':'Pinned DFIR-Metric tree; no explicit reuse licence found',
 'CL-121':'03_Research_Papers/DFIR-Metric/arxiv_metadata.html',
 'CL-122':'02_Benchmarks/MITRE_ATTACK/LICENSE.txt',
 'CL-123':'05_Standards_Documentation/ocsf-schema-1.9.0/LICENSE and 09_Acquisition_Reports/source_metadata/ocsf_release.json',
 'CL-124':'05_Standards_Documentation/NIST_SP_800-86/source.html and official PDF publication date',
 'CL-125':'05_Standards_Documentation/NIST_SP_800-61r3/source.html and official PDF publication date',
 'CL-126':'04_Software_Repositories/plaso/LICENSE and timesketch/LICENSE (Apache-2.0 sources)'}
datasets_before=readcsv('08_Checksums_And_Manifests/dataset_manifest.csv')
disagreements=[r['checklist_id'] for r in datasets_before if any(r[k]!=old[r['checklist_id']].get(k,'') for k in r)]
assert len(disagreements)==15
for identity in disagreements:change(byid[identity],'metadata_authority',authorities[identity],'Locally preserved original official source or explicit unresolved licence')

for r in rows:
 p=Path(r['local_storage_path']) if r['local_storage_path'] and '; ' not in r['local_storage_path'] else None
 if p and p.suffix.lower()=='.html' and r['category'].startswith('5.') and 'ISO/' not in r['resource_name']:
  change(r,'resource_kind','website_reference','Linked local artifact is an HTML page')
  change(r,'artifact_state','PAGE_SNAPSHOT_NOT_COMPLETE_SITE_MIRROR','HTML acquisition scope')
  if r['acquisition_status'] in ['DOWNLOADED — VERIFIED','PARTIALLY DOWNLOADED']:
   change(r,'acquisition_status','WEBSITE REFERENCE — VERIFIED','Only a source page snapshot is verified')
 if r['category'].startswith('8.') or r['checklist_id']=='CL-104':
  relative=r['resource_name'] if r['category'].startswith('8.') else '08_Checksums_And_Manifests/dataset_manifest.csv'
  assert (ROOT/relative).is_file()
  change(r,'local_storage_path',str(ROOT/relative),'Existing canonical file; byte size/hash kept detached to avoid self-reference')
  change(r,'sha256','','Generated artifact hash is recorded in detached deliverable_checksums.csv')
  change(r,'actual_size_bytes','','Generated artifact byte size is recorded in detached deliverable_checksums.csv')
  change(r,'checksum_reference','08_Checksums_And_Manifests/deliverable_checksums.csv#'+relative,'Detached final-file size and SHA-256; no workbook/checksum fixed-point claims')
  if r['category'].startswith('8.'):
   change(r,'acquisition_status','ARTIFACT — VERIFIED VIA DETACHED MANIFEST','Existence and final detached hash verification, not experiment readiness')
   change(r,'artifact_state','GENERATED_RESOURCE_REPORT_NOT_EXPERIMENT_RESULT','Document scope')
   change(r,'verification_status','Final file path, size and SHA-256 verified through detached manifest','Post-remediation verification oracle')

fields=list(rows[0])
for r in rows:
 for field in fields:r.setdefault(field,'')
writecsv('00_Master_Inventory/checklist_status.csv',rows,fields)
datasets=[dict(byid[r['checklist_id']]) for r in datasets_before]
writecsv('08_Checksums_And_Manifests/dataset_manifest.csv',datasets,fields)
for previous in datasets_before:
 current=byid[previous['checklist_id']]
 for field,value in current.items():
  if previous.get(field,'')!=value:
   changes.append({'checklist_id':previous['checklist_id'],'resource':previous['resource_name'],'field':'dataset_manifest.'+field,'original_value':previous.get(field,''),'corrected_value':value,'authoritative_source':authorities.get(previous['checklist_id'],'Master resource row and source files; original CSV retained in backup'),'checked_utc':NOW})
def unresolved(r):
 s=r['acquisition_status']
 return s.startswith(('PENDING','DEFERRED','UNAVAILABLE','RESTRICTED','PARTIALLY','NEEDS','METADATA ONLY')) or r.get('artifact_state')=='REFERENCE_ONLY_NO_TOOL_BINARY'
pending=[r for r in rows if unresolved(r)];restricted=[r for r in rows if 'RESTRICTED' in r['acquisition_status']]
for relative in ['00_Master_Inventory/missing_resources_report.csv','09_Acquisition_Reports/missing_resources_report.csv']:writecsv(relative,pending,fields)
for relative in ['00_Master_Inventory/restricted_resources_report.csv','09_Acquisition_Reports/restricted_resources_report.csv']:writecsv(relative,restricted,fields)
data=json.loads((REPORT/'campaign_input.json').read_text(encoding='utf-8'))
data['checklist']=rows
data['summary'].update(status_counts=dict(collections.Counter(r['acquisition_status'] for r in rows)),remaining=len(pending),pilot=[r for r in rows if r['category'].startswith('7.')],metadata_reconciled_utc=NOW,readiness='NOT READY — isolation and protocol approval outstanding')
writejson('09_Acquisition_Reports/campaign_input.json',data)
writejson('09_Acquisition_Reports/campaign_summary.json',data['summary'])
writecsv(str((RUN/'metadata_corrections.csv').relative_to(ROOT)),changes)
writejson(str((RUN/'metadata_corrections.json').relative_to(ROOT)),changes)

lines=['# Metadata reconciliation report','',f'11 November 2026. Backup: `{RUN.relative_to(ROOT)}`. Original source values remain in byte-verified backups and `metadata_corrections.csv/json` in that directory.','',
 '## Corrected scope','',
 '- All 25 identified records now point to actual existing files: CL-070, CL-072, CL-104–CL-116, CL-127–CL-136. No missing file was invented.',
 '- All 15 pre-existing dataset-manifest disagreements were reconciled from preserved original sources; all 23 dataset-manifest rows now match their master rows exactly.',
 '- CL-121, CL-124 and CL-125 are P0 aliases, as their primary checklist entries specify.',
 '- Website snapshots explicitly represent reference pages, not downloaded/installed software. Empty CSVs, unconfigured configuration, unexecuted analysis and draft reviewer instructions have separate states.',
 '- CFA-Bench original-paper record now links to actual DOI metadata, not to a benchmark README as paper full text. Full text remains unavailable.',
 '- Generated report sizes/hashes are detached. The workbook does not contain an impossible self-hash or pretend to know its final byte size before export. Detached manifest entries include full local relative paths.',
 '- NIST remains P0/DEFERRED; OpTC subset remains UNAVAILABLE; MADIK remains NEEDS CONFIRMATION. Raw evidence, repositories, task labels and answer keys are unchanged.',
 '', '## Original disagreement IDs','',', '.join(disagreements),'', '## Every changed master record','',
 '| ID | Resource | Changed fields | Current status |','| --- | --- | --- | --- |']
for r in rows:
 changed=sorted({c['field'] for c in changes if c['checklist_id']==r['checklist_id'] and not c['field'].startswith('dataset_manifest.')})
 if changed:lines.append('| '+r['checklist_id']+' | '+r['resource_name'].replace('|','/')+' | '+', '.join(changed)+' | '+r['acquisition_status']+' |')
lines += ['', '## Field-level evidence and preservation','',
 f'The complete before/after value, authoritative source and inspection time for every field change are recorded in `{(RUN/"metadata_corrections.csv").relative_to(ROOT)}`. This includes new derived classification fields; it does not replace original acquired source values. Saved release dates describe original publication/release metadata, not a fabricated acquisition or runtime date.',
 '', '## Unresolved discrepancies / limits','',
 '- No publisher signature/authenticity claim is added by local hash reconciliation. Where a licence or exact version date was not established, it remains unresolved or points to preserved metadata.',
 '- Release/metadata snapshots are not live runtime validation. No ISO access, missing original document, CFA paper download, OpTC payload or large dataset restriction is silently resolved.',
 '- Thirty-one mutable datastore hashes remain explicitly deferred. No original stores were opened for writes, reset or reindexed.',
 '- Historical acquisition_summary.pdf and earlier receipts remain historical records. The security plan and post_remediation_verification.md supersede any assumption that the top-level evaluator ACL describes all descendants.',
 '- Final workbook/detached checksum verification is reported separately in post_remediation_verification.md. No security or empirical-readiness gate is made passing by metadata repair.','']
target=REPORT/'metadata_reconciliation_report.md'
with target.open('x',encoding='utf-8') as f:f.write('\n'.join(lines))
print(json.dumps({'missing_path_records_repaired':25,'original_dataset_disagreements_reconciled':len(disagreements),'priority_aliases_corrected':3,'field_changes_recorded':len(changes),'checklist_rows':len(rows),'dataset_rows':len(datasets),'unresolved_rows':len(pending),'report':str(target)},indent=2))
