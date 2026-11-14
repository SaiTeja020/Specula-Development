import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Workbook,SpreadsheetFile} from '@oai/artifact-tool';
const here=path.dirname(fileURLToPath(import.meta.url)),root=path.dirname(here);
const run=JSON.parse(await fs.readFile(path.join(here,'remediation_current.json'),'utf8')).run_directory;
const backups=JSON.parse(await fs.readFile(path.join(run,'backup_manifest.json'),'utf8'));
const target=path.join(root,'00_Master_Inventory/master_acquisition_tracker.xlsx');
const previous=backups.find(x=>x.relative_path==='00_Master_Inventory/master_acquisition_tracker.xlsx');
const currentHash=crypto.createHash('sha256').update(await fs.readFile(target)).digest('hex');
if(currentHash!==previous.sha256){
 const intermediate=path.join(run,'intermediate');await fs.mkdir(intermediate,{recursive:true});
 const saved=path.join(intermediate,'master_acquisition_tracker.'+currentHash+'.xlsx');
 try{await fs.copyFile(target,saved,fs.constants.COPYFILE_EXCL);}catch(e){if(e.code!=='EEXIST')throw e;}
}
const data=JSON.parse(await fs.readFile(path.join(here,'campaign_input.json'),'utf8'));
const wb=Workbook.create(),overview=wb.worksheets.add('Overview');
function col(i){let result='';for(i++;i;i=Math.floor((i-1)/26))result=String.fromCharCode(65+(i-1)%26)+result;return result;}
function grid(name,rows,fields,widths){
 const sheet=wb.worksheets.add(name),end=rows.length+1,last=col(fields.length-1);
 sheet.getRange(`A1:${last}${end}`).values=[fields.map(k=>k.replaceAll('_',' ')),...rows.map(r=>fields.map(k=>r[k]==null||r[k]===''?null:r[k]==='unassigned: checklist unavailable'?'Historical audit snapshot; see Checklist priority':typeof r[k]==='object'?JSON.stringify(r[k]):r[k]))];
 sheet.getRange(`A1:${last}${end}`).format={font:{name:'Arial',size:10,color:'#17354B'},wrapText:true,verticalAlignment:'top',columnWidth:32,rowHeight:90};
 for(const [letter,width]of Object.entries(widths))sheet.getRange(`${letter}1:${letter}${end}`).format.columnWidth=width;
 fields.forEach((key,i)=>{
  if(['date_checked','acquired_at','audit_date','acquisition_date'].includes(key))sheet.getRange(`${col(i)}2:${col(i)}${end}`).setNumberFormat('yyyy-mm-dd hh:mm:ss');
  if(['expected_size_bytes','actual_size_bytes','file_size_bytes'].includes(key))sheet.getRange(`${col(i)}2:${col(i)}${end}`).setNumberFormat('#,##0');
 });
 sheet.tables.add(`A1:${last}${end}`,true,name.replaceAll(' ',''));
 sheet.getRange(`A1:${last}1`).format={fill:'#17354B',font:{name:'Arial',size:10,bold:true,color:'#FFFFFF'},wrapText:true,rowHeight:38};
 sheet.freezePanes.freezeRows(1);sheet.showGridLines=false;return sheet;
}
const fields=Object.keys(data.checklist[0]),check=grid('Checklist',data.checklist,fields,{A:80,B:55,C:18,D:85,E:90,F:65,G:62,H:22,I:22,J:52,K:115,L:75,M:100,N:105,O:35,P:180,Q:16,R:44,S:65,T:115,U:140});
const acquired=grid('Acquired',data.files,Object.keys(data.files[0]),{A:100,B:130,C:55,D:22,E:22,F:130,G:75,H:48,I:35,J:110,K:105});
grid('Existing audit',data.existing,[...new Set(data.existing.flatMap(r=>Object.keys(r)))],{A:100,H:130,I:75,K:110,L:100});
const n=data.files.length,c=data.checklist.length,s=data.summary;
const rows=[['SPECULA / POST-AUDIT REMEDIATION','11 November 2026 | Approval drafts; no experiments'],
 ['Overall decision','NOT READY: isolation changes and actual-runtime access tests await approval; protocol is not frozen'],
 ['Scope','Metadata reconciled after verified backups. Original evidence, labels, source clones and parent implementation remain unchanged.'],
 ['Checklist dispositions',null],['File ledger entries',null],['Ledger bytes (includes rejected responses)',null],
 ['Acquired research papers',s.research_papers_acquired],['Pinned source clones',s.pinned_clones],['Pinned source ZIP archives',s.reference_archives],
 ['Existing unique inventoried files',s.existing_unique_files],['Mutable datastore hashes deferred',s.existing_hash_deferred],
 ['CFA candidate evidence',`${s.cfa_cases} cases; ${s.cfa_evidence_files} files; independent truth not established`],
 ['NIST Hacking Case','P0 / DEFERRED. Raw images absent; dependent experiments pending.'],
 ['OpTC event subset','UNAVAILABLE. Quota HTML is a rejected response; documentation and ground truth are separate resources.'],
 ['DFIR-Metric release','713 MCQ / 150 CTF / 510 search questions; published README counts differ. Matched evaluation runner remains unresolved.'],
 ['CFA-Bench paper','DOI metadata only; no local full-text PDF. The benchmark README is not the paper.'],
 ['Evaluator isolation','FAIL for same-account host separation; proposed runtime access tests BLOCKED. Root ACL does not describe all child grants.'],
 ['Protocol','DRAFT / NOT FROZEN. Cached model manifests observed; live model service unavailable. No labels, scores or measurements invented.'],
 ['Unresolved acquisition dispositions',s.remaining],
 ['Report checksum policy','Generated file sizes and SHA-256 are in deliverable_checksums.csv. Blank self-hash cells are deliberate detached references, not missing evidence.'],
 ['Previously missing local paths repaired',25],['Dataset rows reconciled',23],['Dataset/master disagreements remaining',0],['P0 pilot aliases corrected',3],
 ['Website-reference dispositions',null],['Approval required','Review security_isolation_plan.md and experiment_protocol_draft.md before security changes or any evaluation run.']];
overview.getRange('A1:B26').values=rows;
overview.getRange('A1:B26').format={font:{name:'Arial',size:11,color:'#17354B'},wrapText:true,verticalAlignment:'top',rowHeight:42};
overview.getRange('A1:A26').format.columnWidth=44;overview.getRange('B1:B26').format.columnWidth=112;
overview.getRange('A1:B1').format={fill:'#17354B',font:{name:'Arial',size:13,bold:true,color:'#FFFFFF'},wrapText:true,rowHeight:46};
overview.getRange('A2:B3').format.fill='#FFF0CC';overview.getRange('A12:B20').format.rowHeight=65;overview.getRange('A26:B26').format.rowHeight=65;
overview.getRange('B4').formulas=[[`=COUNTA(Checklist!A2:A${c+1})`]];
overview.getRange('B5').formulas=[[`=COUNTA(Acquired!A2:A${n+1})`]];
overview.getRange('B6').formulas=[[`=SUM(Acquired!E2:E${n+1})`]];
const kindColumn=col(fields.indexOf('resource_kind'));
overview.getRange('B25').formulas=[[`=COUNTIF(Checklist!${kindColumn}2:${kindColumn}${c+1},"website_reference")`]];
overview.getRange('B4:B11').setNumberFormat('#,##0');overview.getRange('B19').setNumberFormat('0');overview.showGridLines=false;overview.freezePanes.freezeRows(3);
for(let i=0;i<c;i++)if(/DEFERRED|UNAVAILABLE|RESTRICTED|CONFIRMATION|EMPTY|UNCONFIGURED|DRAFT|UNPOPULATED/.test(data.checklist[i].acquisition_status))check.getRange(`J${i+2}`).format.fill='#FFF0CC';
wb.recalculate();
const expected=[c,n,s.acquired_bytes],actual=overview.getRange('B4:B6').values.map(r=>r[0]);
if(JSON.stringify(actual)!==JSON.stringify(expected))throw Error('Counts fail reconciliation');
// Meaningful recomputation check: perturb a source byte count in memory, restore before export.
const originalBytes=acquired.getRange('E2').values[0][0];acquired.getRange('E2').values=[[originalBytes+1]];wb.recalculate();
if(overview.getRange('B6').values[0][0]!==s.acquired_bytes+1)throw Error('Byte summary does not recalculate');
acquired.getRange('E2').values=[[originalBytes]];
const expectedSites=data.checklist.filter(r=>r.resource_kind==='website_reference').length;
const siteIndex=data.checklist.findIndex(r=>r.resource_kind==='website_reference'),siteCell=`${kindColumn}${siteIndex+2}`;
check.getRange(siteCell).values=[['temporary_recalculation_probe']];wb.recalculate();
if(overview.getRange('B25').values[0][0]!==expectedSites-1)throw Error('Reference summary does not recalculate');
check.getRange(siteCell).values=[['website_reference']];wb.recalculate();
if(overview.getRange('B6').values[0][0]!==s.acquired_bytes || overview.getRange('B25').values[0][0]!==expectedSites)throw Error('Restoration failed');
await(await SpreadsheetFile.exportXlsx(wb)).save(target);
for(const [sheetName,range,label]of [['Overview','A1:B13','overview-top'],['Overview','A14:B26','overview-gates'],['Checklist','I70:K74','website-rows'],['Checklist','R104:U108','artifact-states'],['Acquired','D1:I4','acquired'],['Existing audit','A1:C4','existing']]){
 const preview=await wb.render({sheetName,range,scale:0.9,format:'png'});
 await fs.writeFile(path.join(here,'previews','remediation-'+label+'.png'),new Uint8Array(await preview.arrayBuffer()));
}
const receiptFile=path.join(run,'workbook_recalculation_receipt.json');
try{await fs.copyFile(receiptFile,path.join(run,'intermediate','workbook_recalculation_receipt.'+currentHash+'.json'),fs.constants.COPYFILE_EXCL);}catch(e){if(!['ENOENT','EEXIST'].includes(e.code))throw e;}
await fs.writeFile(receiptFile,JSON.stringify({checklist_rows:c,file_ledger_entries:n,ledger_bytes:s.acquired_bytes,website_reference_count:expectedSites,workbook_sha256:crypto.createHash('sha256').update(await fs.readFile(target)).digest('hex'),source_perturbation_and_restoration:'PASS',model_or_experiment_execution:false},null,2));
console.log(JSON.stringify({target,rows:c,websiteReferences:expectedSites,recalculation:'PASS'}));
