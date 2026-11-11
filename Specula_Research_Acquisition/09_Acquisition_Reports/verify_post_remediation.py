"""Post-remediation integrity/metadata oracle. No deployment or experiment execution."""
import collections,csv,datetime as dt,hashlib,json,os,re,struct,subprocess,zipfile
from pathlib import Path
from xml.etree import ElementTree as E
ROOT=Path(__file__).resolve().parents[1];REPORT=ROOT/'09_Acquisition_Reports'
RUN=Path(json.loads((REPORT/'remediation_current.json').read_text())['run_directory'])
ENV=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1')
errors=[];counts={}
def check(condition,message):
 if not condition:errors.append(message)
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def rows(relative):
 with (ROOT/relative).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def git(p,*args):
 result=subprocess.run(['git','--no-optional-locks','-c','safe.directory='+str(p),'-c','core.fsmonitor=false','-C',str(p),*args],env=ENV,text=True,capture_output=True)
 check(result.returncode==0,'git '+str(args)+': '+result.stderr)
 return result.stdout.strip()

# Backups and resource bytes are independent of the repaired tracker classifications.
backups=json.loads((RUN/'backup_manifest.json').read_text())
for r in backups:check(sha(ROOT/r['backup'])==r['sha256'],'Backup hash mismatch: '+r['relative_path'])
counts['backups_verified']=len(backups)
seen=set();deferred=0
for r in rows('08_Checksums_And_Manifests/resource_checksums.csv'):
 p=Path(r['local_path'])
 if str(p) in seen:continue
 seen.add(str(p));check(p.is_file(),'Missing resource: '+str(p))
 if not p.is_file():continue
 if not r['sha256']:
  check('mutable' in r['verification_status'],'Unexplained missing SHA: '+str(p));deferred+=1;continue
 check(p.stat().st_size==int(r['actual_size_bytes']) and sha(p)==r['sha256'],'Resource hash/size mismatch: '+str(p))
counts['immutable_resource_hashes_verified']=len(seen)-deferred;counts['mutable_datastore_hashes_deferred']=deferred
protected=json.loads((RUN/'immutable_evaluator_snapshot.json').read_text())
actual={str(p) for p in (ROOT/'07_Evaluation_Artifacts/evaluator_only').rglob('*') if p.is_file() and not p.is_symlink()}
check(actual=={r['path'] for r in protected},'Evaluator file membership changed')
for r in protected:
 p=Path(r['path']);check(p.is_file() and p.stat().st_size==r['bytes'] and sha(p)==r['sha256'],'Evaluator bytes changed: '+r['path'])
counts['evaluator_files_preserved']=len(protected)
before=json.loads((RUN/'evaluator_acl_before.json').read_text(encoding='utf-8-sig'))
after=json.loads((RUN/'evaluator_acl_after.json').read_text(encoding='utf-8-sig'))
check({r['Path']:r['Sddl'] for r in before}=={r['Path']:r['Sddl'] for r in after},'Evaluator ACL/owner SDDL changed')
counts['acl_descriptors_unchanged']=len(before)

ledger=rows('00_Master_Inventory/checklist_status.csv');master={r['checklist_id']:r for r in ledger}
source=(ROOT/'CHECKLIST.md').read_text(encoding='utf-8-sig')
names=[re.sub(r'^\s*- \[ \]\s*','',line).replace('**','').replace('`','') for line in source.splitlines() if re.match(r'\s*- \[ \]',line)]
check(len(ledger)==136 and len(master)==136,'136 unique dispositions required')
check(names==[r['resource_name'] for r in ledger],'Checklist scope/order changed')
for identity in ['CL-070','CL-072',*[f'CL-{i:03}' for i in range(104,117)],*[f'CL-{i:03}' for i in range(127,137)]]:
 r=master[identity];check(bool(r['local_storage_path']) and Path(r['local_storage_path']).is_file(),'Missing repaired path: '+identity)
for identity in ['CL-121','CL-124','CL-125']:check(master[identity]['priority']=='P0','Incorrect P0 alias '+identity)
for r in ledger:
 check(bool(r['resource_kind']) and bool(r['metadata_authority']) and bool(r['acquisition_status']),'Untraceable disposition '+r['checklist_id'])
 if r['sha256']:
  check(bool(re.fullmatch('[0-9a-f]{64}',r['sha256'])),'Invalid direct SHA field '+r['checklist_id'])
  if '; ' not in r['local_storage_path']:
   p=Path(r['local_storage_path']);check(p.is_file() and sha(p)==r['sha256'],'Master direct file hash mismatch '+r['checklist_id'])
 if r['category'].startswith('8.'):
  check(r['checksum_reference'].startswith('08_Checksums_And_Manifests/deliverable_checksums.csv#'),'Missing detached checksum reference '+r['checklist_id'])
  check(not r['sha256'] and not r['actual_size_bytes'],'Self-referential generated checksum/size '+r['checklist_id'])
datasets=rows('08_Checksums_And_Manifests/dataset_manifest.csv')
check(len(datasets)==23,'Dataset row membership changed')
for r in datasets:check(r==master[r['checklist_id']],'Dataset/master mismatch '+r['checklist_id'])
counts.update(checklist_dispositions=len(ledger),repaired_local_paths=25,reconciled_dataset_rows=len(datasets),dataset_disagreements=0,priority_aliases_corrected=3)
for identity in ['CL-070','CL-072']:
 r=master[identity];check(r['resource_kind']=='website_reference' and r['artifact_state']=='REFERENCE_ONLY_NO_TOOL_BINARY','Website/tool conflation '+identity)
for r in ledger:
 if r['artifact_state']=='HEADER_ONLY_ZERO_DATA_ROWS':
  with Path(r['local_storage_path']).open(encoding='utf-8-sig') as f:check(len(list(csv.DictReader(f)))==0,'Fabricated/populated template '+r['checklist_id'])
check(master['CL-033']['priority']=='P0' and master['CL-033']['acquisition_status']=='DEFERRED','NIST deferral changed')
check(not list((ROOT/'01_Forensic_Datasets/NIST_Hacking_Case').glob('SCHARDT.00?')),'Raw NIST images unexpectedly present')
check(master['CL-119']['acquisition_status']=='UNAVAILABLE','OpTC subset status changed')
check(not list((ROOT/'01_Forensic_Datasets/OpTC').rglob('*.gz')),'Unexpected OpTC dataset payload')
check(next(r for r in ledger if r['resource_name']=='MADIK original paper')['acquisition_status']=='NEEDS CONFIRMATION','MADIK confirmation invented')
check(next(r for r in ledger if r['resource_name']=='CFA-Bench original paper')['resource_kind']=='research_paper_metadata','CFA paper conflation')
mapping=rows('07_Evaluation_Artifacts/evaluator_only/CFA_evidence_mapping.csv');packets=0;pcaps=0;logs=0
for r in mapping:
 p=Path(r['agent_evidence_path']);check(sha(p)==sha(Path(r['original_path']))==r['sha256'],'Evidence copy mismatch '+str(p))
 check(not p.is_symlink() and p.stat().st_nlink==1,'Evidence link requires review '+str(p))
 if p.suffix=='.pcap':
  pcaps+=1;data=p.read_bytes();magic=data[:4];check(magic==b'\xd4\xc3\xb2\xa1','Unexpected PCAP format '+str(p));position=24;snap=struct.unpack_from('<I',data,16)[0]
  while position<len(data):
   if position+16>len(data):errors.append('Truncated PCAP header '+str(p));break
   _,_,captured,original=struct.unpack_from('<IIII',data,position);position+=16
   if captured>original or captured>snap or position+captured>len(data):errors.append('Truncated/invalid PCAP record '+str(p));break
   packets+=1;position+=captured
 elif p.suffix=='.log':logs+=1;p.read_text(encoding='utf-8')
check((pcaps,logs,packets)==(20,39,23152),'CFA counts differ')
counts.update(cfa_pcaps=pcaps,cfa_logs=logs,pcap_packets=packets)
for line in (REPORT/'clone_receipts.jsonl').read_text().splitlines():
 r=json.loads(line);p=Path(r['path']);check(git(p,'rev-parse','HEAD')==r['commit'],'Clone commit changed '+r['repository']);check(not git(p,'status','--porcelain'),'Clone modified '+r['repository']);git(p,'fsck','--connectivity-only')
check(git(ROOT.parent,'rev-parse','HEAD')=='b9b2012edaed8da5062113ddc9982e3c33b27983','Parent source commit changed')
check(not git(ROOT.parent,'diff','--name-only','HEAD'),'Parent tracked implementation changed')

data=json.loads((REPORT/'campaign_input.json').read_text(encoding='utf-8'));check(data['checklist']==ledger,'Workbook input/master CSV differs')
ns={'m':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
with zipfile.ZipFile(ROOT/'00_Master_Inventory/master_acquisition_tracker.xlsx') as z:
 check(z.testzip() is None,'Workbook ZIP CRC failed')
 strings=[''.join(si.itertext()) for si in E.fromstring(z.read('xl/sharedStrings.xml')).findall('m:si',ns)] if 'xl/sharedStrings.xml' in z.namelist() else []
 def sheet(i):
  result=[]
  for row in E.fromstring(z.read(f'xl/worksheets/sheet{i}.xml')).findall('m:sheetData/m:row',ns):
   values={}
   for c in row.findall('m:c',ns):
    value=c.findtext('m:v',default='',namespaces=ns);kind=c.attrib.get('t');key=re.sub(r'\d','',c.attrib['r'])
    if kind=='s':value=strings[int(value)]
    elif kind=='inlineStr':value=''.join(c.find('m:is',ns).itertext())
    if kind=='e':errors.append('Workbook cell error '+c.attrib['r'])
    values[key]=value
   result.append(values)
  return result
 overview=sheet(1);sheets=[sheet(i) for i in range(2,5)]
 check([len(s)-1 for s in sheets]==[136,2258,2810],'Workbook row counts differ')
 for n,want in [(4,136),(5,2258),(6,286557286),(25,sum(r['resource_kind']=='website_reference' for r in ledger))]:check(float(overview[n-1]['B'])==want,'Workbook cached total differs B'+str(n))
 header=sheets[0][0]
 for actual,want in zip(sheets[0][1:],ledger):
  for column,label in header.items():
   key=label.replace(' ','_');a=actual.get(column,'');b=want.get(key,'')
   if key=='date_checked':continue
   if key in ['actual_size_bytes','expected_size_bytes'] and a and b:equal=float(a)==float(b)
   else:equal=a==b
   check(equal,'Workbook/master field mismatch '+want['checklist_id']+'/'+key)
receipt=json.loads((RUN/'workbook_recalculation_receipt.json').read_text());check(receipt['source_perturbation_and_restoration']=='PASS','Recalculation probe absent')
check(receipt['workbook_sha256']==sha(ROOT/'00_Master_Inventory/master_acquisition_tracker.xlsx'),'Recalculation receipt workbook differs')
draft=json.loads((ROOT/'07_Evaluation_Artifacts/templates/experiment_config.proposed.json').read_text())
check(draft['status']=='DRAFT_REQUIRES_OWNER_APPROVAL_NOT_FROZEN' and not draft['proposed_not_approved']['approved'],'Protocol accidentally frozen')
check(draft['result_artifacts']==[] and draft['proposed_not_approved']['model_seed'] is None,'Invented experiment/model seed')
check(draft['proposed_not_approved']['global_token_budget'] is None,'Unverified global token budget populated')
for required in ['security_isolation_plan.md','metadata_reconciliation_report.md','experiment_protocol_draft.md']:check((REPORT/required).is_file(),'Missing report '+required)

stamp=dt.datetime.now(dt.timezone.utc).isoformat()
gates=[('Resource integrity for acquired scope','FAIL' if errors else 'PASS','5096 resource hashes; 31 mutable hashes remain explicitly deferred'),('Updated tracker and metadata','FAIL' if errors else 'PASS','136 dispositions;25 paths;23 dataset rows agree;3 priority aliases;detached checksums'),('Original evidence, labels, clones and parent source preservation','FAIL' if errors else 'PASS','296 evaluator files and 411 ACL descriptors compared; parent commit unchanged'),('Existing host evaluator separation','FAIL','DELL/sandbox access and broader descendant grants remain; no security change authorized'),('Actual proposed runtime positive/negative access tests','BLOCKED','No approved evaluation runtime or identity deployed; no runtime access proof claimed'),('Experiment configuration complete and frozen','BLOCKED','Draft only; global budgets, runtime pins, completion boundary and approvals unresolved'),('Independent truth for every selected empirical case','BLOCKED','20 CFA candidates have published tasks but independent review/richer truth not established'),('Safe functional smoke execution','BLOCKED','Isolation preflight and approval required; model service not running; zero new runs')]
counts['errors']=errors
body=['# Post-remediation verification','',f'11 November 2026. Verified UTC: {stamp}. No security changes, inference, ingestion or experiment runs were performed.','',
 '| Gate | Status | Evidence / reason |','| --- | --- | --- |']
body+=['| '+' | '.join(g)+' |' for g in gates]
body+=['','## Executed non-experiment checks','', '```json',json.dumps(counts,indent=2),'```','',
 'All metadata backups are verified against their original hashes. Resource hashes and original evaluator-file membership/bytes were rechecked independently of status labels. Workbook caches and every non-date checklist field were compared to CSV; summary input perturbation/restoration passed. Evidence link/packet checks are acquisition checks, not a complete leakage or runtime access test.',
 '', '## Readiness assessment','',
 '| Category | Decision | Scope |','| --- | --- | --- |',
 f'| A. Resource acquisition | NOT READY for full planned corpus; acquired subset integrity/metadata PASS | {data["summary"]["remaining"]} unresolved dispositions remain. Deferred NIST and unavailable OpTC have not become usable evidence. Missing named originals are separate from the nine acquired bibliographic equivalents; website references do not fulfil native-tool scope. |',
 '| B. Safe functional smoke test | NOT READY / BLOCKED | Review/approve isolated runtime, verify permitted evidence and denied evaluator access as the actual identity, then authorize a bounded synthetic smoke. No services started or tests launched. |',
 '| C. Controlled empirical evaluation | NOT READY / BLOCKED | Independent ground truth/reviewers, matched baselines, full protocol/runtime pins/budgets and explicit freeze approval are still required. |',
 '', '## Approvals still needed','',
 '1. Isolation topology, dedicated identity/VM, reviewed image/model/service pins and any staged permission/mount changes. No ACL, account, credential, mount or running service was changed.',
 '2. A bounded real-runtime access preflight and, only after passing it, a separate inert synthetic functional smoke. No automatic HITL approval.',
 '3. Dataset eligibility, independent reviewers/truth, matched baselines, global budgets/seed policy/completion boundary and a frozen protocol. Full experiments are not authorized by this metadata repair.',
 '', '## Provenance and unresolved discrepancies','',
 f'Backups, field-level source values and preservation snapshots: `{RUN.relative_to(ROOT)}`. Current detached hashes: `08_Checksums_And_Manifests/deliverable_checksums.csv`. Source metadata corrections are in metadata_reconciliation_report.md and the detailed ledger. Prior acquisition_summary.pdf/receipts are retained as historical snapshots; current security/experiment gates above govern readiness.',
 '', 'The detached manifest is generated after this report to avoid self-hash cycles, then all its listed files are reread and checked. Its own hash and the terminal result are recorded in the separate post_remediation_receipt.json. No assertion of Specula functional correctness follows from these acquisition/metadata checks.','']
post=REPORT/'post_remediation_verification.md'
if post.exists():raise RuntimeError('Report exists; preserve predecessor before rerunning authoring')
post.write_text('\n'.join(body),encoding='utf-8')

# Final detached checksums: no entry for this manifest itself or the terminal receipt.
output_set={r['relative_path'] for r in rows('08_Checksums_And_Manifests/deliverable_checksums.csv')}
output_set.update(['00_Master_Inventory/checklist_status.csv','README.md','09_Acquisition_Reports/security_isolation_plan.md','09_Acquisition_Reports/metadata_reconciliation_report.md','09_Acquisition_Reports/experiment_protocol_draft.md','09_Acquisition_Reports/post_remediation_verification.md','07_Evaluation_Artifacts/templates/experiment_config.proposed.json',str((RUN/'metadata_corrections.csv').relative_to(ROOT)).replace('\\','/'),str((RUN/'metadata_corrections.json').relative_to(ROOT)).replace('\\','/'),str((RUN/'protocol_observations.json').relative_to(ROOT)).replace('\\','/')])
for r in ledger:
 if r['category'].startswith('6.') and r['local_storage_path']:output_set.add(str(Path(r['local_storage_path']).relative_to(ROOT)).replace('\\','/'))
detached=[]
for relative in sorted(output_set):
 p=ROOT/relative;check(p.is_file(),'Missing detached output '+relative)
 if p.is_file():detached.append({'relative_path':relative,'file_size_bytes':p.stat().st_size,'sha256':sha(p)})
with (ROOT/'08_Checksums_And_Manifests/deliverable_checksums.csv').open('w',encoding='utf-8-sig',newline='') as f:
 w=csv.DictWriter(f,fieldnames=['relative_path','file_size_bytes','sha256']);w.writeheader();w.writerows(detached)
for r in rows('08_Checksums_And_Manifests/deliverable_checksums.csv'):
 p=ROOT/r['relative_path'];check(sha(p)==r['sha256'] and p.stat().st_size==int(r['file_size_bytes']),'Detached checksum mismatch '+r['relative_path'])
for r in ledger:
 if r['category'].startswith('8.') or r['checklist_id']=='CL-104':
  relative=str(Path(r['local_storage_path']).relative_to(ROOT)).replace('\\','/')
  check(any(x['relative_path']==relative for x in detached),'Unresolved detached reference '+r['checklist_id'])
result={'checked_utc':stamp,'non_experiment_integrity_and_metadata':'FAIL' if errors else 'PASS','actual_runtime_isolation':'BLOCKED_PENDING_APPROVAL','controlled_experiments':'NOT_READY','new_experiments':0,'counts':counts,'detached_manifest_entries':len(detached),'detached_manifest_sha256':sha(ROOT/'08_Checksums_And_Manifests/deliverable_checksums.csv'),'gates':gates}
with (RUN/'post_remediation_receipt.json').open('x',encoding='utf-8') as f:json.dump(result,f,indent=2)
print(json.dumps(result,indent=2))
if errors:raise SystemExit(1)
