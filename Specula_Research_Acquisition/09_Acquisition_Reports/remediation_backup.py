"""Back up only mutable acquisition metadata and fingerprint immutable resources."""
import csv,datetime as dt,hashlib,json,shutil,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
STAMP=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
RUN=ROOT/'09_Acquisition_Reports'/('remediation_'+STAMP)
RUN.mkdir()
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
targets=['PROGRESS.md','README.md','CHECKLIST.md','00_Master_Inventory/master_acquisition_tracker.xlsx','00_Master_Inventory/checklist_status.csv','00_Master_Inventory/missing_resources_report.csv','00_Master_Inventory/restricted_resources_report.csv','08_Checksums_And_Manifests/dataset_manifest.csv','08_Checksums_And_Manifests/repository_manifest.csv','08_Checksums_And_Manifests/research_paper_bibliography.csv','08_Checksums_And_Manifests/resource_checksums.csv','08_Checksums_And_Manifests/deliverable_checksums.csv','09_Acquisition_Reports/campaign_input.json','09_Acquisition_Reports/campaign_summary.json','09_Acquisition_Reports/missing_resources_report.csv','09_Acquisition_Reports/restricted_resources_report.csv','09_Acquisition_Reports/acquisition_summary.pdf','09_Acquisition_Reports/acquisition_log.md','09_Acquisition_Reports/build_campaign_tracker.mjs']
backups=[]
for relative in targets:
 p=ROOT/relative
 if not p.is_file():continue
 q=RUN/'backup'/relative;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q)
 assert sha(p)==sha(q)
 backups.append({'relative_path':relative,'backup':str(q.relative_to(ROOT)),'sha256':sha(p),'bytes':p.stat().st_size})
with (RUN/'backup_manifest.json').open('x',encoding='utf-8') as f:json.dump(backups,f,indent=2)
with (ROOT/'08_Checksums_And_Manifests/resource_checksums.csv').open(encoding='utf-8-sig') as f:resources=list(csv.DictReader(f))
bad=[];seen=set();checked=0;deferred=0
for row in resources:
 p=Path(row['local_path'])
 if str(p) in seen:continue
 seen.add(str(p))
 if not row['sha256']:deferred+=1;continue
 if not p.is_file() or sha(p)!=row['sha256'] or p.stat().st_size!=int(row['actual_size_bytes']):bad.append(str(p))
 else:checked+=1
protected=[]
for p in sorted((ROOT/'07_Evaluation_Artifacts/evaluator_only').rglob('*')):
 if p.is_file() and not p.is_symlink():protected.append({'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)})
for name,value in [('immutable_evaluator_snapshot.json',protected),('resource_baseline.json',{'checked':checked,'deferred':deferred,'errors':bad})]:
 with (RUN/name).open('x',encoding='utf-8') as f:json.dump(value,f,indent=2)
with (ROOT/'09_Acquisition_Reports/remediation_current.json').open('x',encoding='utf-8') as f:json.dump({'run_directory':str(RUN),'started_utc':STAMP},f,indent=2)
print(json.dumps({'run_directory':str(RUN),'backups_verified':len(backups),'immutable_resource_hashes_verified':checked,'mutable_deferred':deferred,'resource_errors':bad,'protected_files_fingerprinted':len(protected)},indent=2))
if bad:raise SystemExit(1)
