import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Workbook,SpreadsheetFile} from '@oai/artifact-tool';
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.dirname(here);
const data=JSON.parse(await fs.readFile(path.join(here,'campaign_input.json'),'utf8'));
const wb=Workbook.create();
const overview=wb.worksheets.add('Overview');
function column(i){let s='';for(i++;i;i=Math.floor((i-1)/26))s=String.fromCharCode(65+(i-1)%26)+s;return s;}
function grid(name,rows,fields,widths={}){
 const sheet=wb.worksheets.add(name),last=column(fields.length-1),end=rows.length+1;
 sheet.getRange(`A1:${last}${end}`).values=[fields.map(x=>x.replaceAll('_',' ')),...rows.map(r=>fields.map(k=>r[k]==null||r[k]===''?null:r[k]==='unassigned: checklist unavailable'?'Not individually prioritized; see Checklist':typeof r[k]==='object'?JSON.stringify(r[k]):r[k]))];
 const all=sheet.getRange(`A1:${last}${end}`);
 all.format={font:{name:'Arial',size:10,color:'#17354B'},wrapText:true,verticalAlignment:'top',columnWidth:30,rowHeight:84};
 for(const [c,w] of Object.entries(widths))sheet.getRange(`${c}1:${c}${end}`).format.columnWidth=w;
 fields.forEach((key,i)=>{
  if(['date_checked','acquired_at','audit_date','acquisition_date'].includes(key))sheet.getRange(`${column(i)}2:${column(i)}${end}`).setNumberFormat('yyyy-mm-dd hh:mm:ss');
  if(['expected_size_bytes','actual_size_bytes','file_size_bytes'].includes(key))sheet.getRange(`${column(i)}2:${column(i)}${end}`).setNumberFormat('#,##0');
 });
 sheet.tables.add(`A1:${last}${end}`,true,name.replaceAll(' ',''));
 sheet.getRange(`A1:${last}1`).format={fill:'#17354B',font:{name:'Arial',size:10,bold:true,color:'#FFFFFF'},wrapText:true,rowHeight:38};
 sheet.freezePanes.freezeRows(1);sheet.showGridLines=false;
 return sheet;
}
const check=grid('Checklist',data.checklist,Object.keys(data.checklist[0]),{A:82,B:55,C:18,D:85,E:100,F:70,G:60,H:22,I:22,J:34,K:115,L:75,M:100,N:100,O:35,P:180,Q:16});
const acquired=grid('Acquired',data.files,Object.keys(data.files[0]),{A:100,B:130,C:55,D:22,E:22,F:130,G:75,H:48,I:35,J:110,K:105});
const existingFields=[...new Set(data.existing.flatMap(r=>Object.keys(r)))];
grid('Existing audit',data.existing,existingFields,{A:100,H:130,I:75,K:110,L:100});
for(let i=0;i<data.checklist.length;i++){
 const status=data.checklist[i].acquisition_status;
 if(/DEFERRED|RESTRICTED|UNAVAILABLE|CONFIRMATION/.test(status))check.getRange(`J${i+2}`).format.fill='#FFF0CC';
}
const s=data.summary,n=data.files.length,c=data.checklist.length;
const rows=[['SPECULA / ACQUISITION','11 November 2026 | Asia/Calcutta'],
 ['Status','Feasible acquisitions verified; remaining items explicitly deferred, restricted or pending'],
 ['Authoritative scope','CHECKLIST.md, including owner-supplied bibliography corrections; original checklist and preliminary reports preserved'],
 ['Checklist rows tracked',null],['File ledger entries',null],['Ledger bytes (includes responses)',null],
 ['Research papers acquired',s.research_papers_acquired],['Pinned repository clones',s.pinned_clones],['Pinned source ZIP archives',s.reference_archives],
 ['Existing unique files inventoried',s.existing_unique_files],['Mutable datastore hashes deferred',s.existing_hash_deferred],
 ['CFA-Bench evidence cases / files',`${s.cfa_cases} cases / ${s.cfa_evidence_files} files`],
 ['NIST Hacking Case','DEFERRED / P0 retained. Raw evidence 4.54 GiB not downloaded. Dependent experiments pending.'],
 ['OpTC small subset','UNAVAILABLE: small network-file request returned quota HTML; endpoint archive 1.86 GB deferred. Documentation and ground truth verified.'],
 ['DFIR-Metric caveat','713 MCQs / 150 CTF / 510 search questions in actual files; README says 700 / 150 / 500. Standalone evaluation runner absent from pinned release.'],
 ['CFA-Bench paper','DOI and publicly accessible university author manuscript verified via web; local download failed. No actual paper PDF is claimed.'],
 ['Ground-truth boundary','Labels/results/original repositories are evaluator-only. Candidate CFA evidence copies have opaque filenames and byte-identical content. Enforce a separate agent identity/read root before experiments.'],
 ['Code / environment','No packages installed, reference code executed, experiments run or Specula implementation files changed. Source-only sparse clones omit stated directories.'],
 ['Remaining actions','Resolve restricted/inaccessible sources and MADIK relevance; select optional P2 resources where needed. Large evidence remains deferred under owner instruction.'],
 ['Audit and provenance','Per-file URLs/hashes/commits are in Acquired and CSV manifests. Four rejected responses are explicitly flagged and excluded from resource-completion claims. Local hashes do not establish scientific truth.']];
overview.getRange('A1:B20').values=rows;
overview.getRange('A1:B20').format={font:{name:'Arial',size:11,color:'#17354B'},wrapText:true,verticalAlignment:'top',rowHeight:42};
overview.getRange('A1:A20').format.columnWidth=42;
overview.getRange('B1:B20').format.columnWidth=112;
overview.getRange('A1:B1').format={fill:'#17354B',font:{name:'Arial',size:14,bold:true,color:'#FFFFFF'},wrapText:true,rowHeight:44};
overview.getRange('A2:B3').format.fill='#E7F0F5';
overview.getRange('A13:B20').format.rowHeight=64;
overview.getRange('A17:B17').format.rowHeight=80;
overview.getRange('B4').formulas=[[`=COUNTA(Checklist!A2:A${c+1})`]];
overview.getRange('B5').formulas=[[`=COUNTA(Acquired!A2:A${n+1})`]];
overview.getRange('B6').formulas=[[`=SUM(Acquired!E2:E${n+1})`]];
overview.getRange('B4:B11').setNumberFormat('#,##0');
overview.showGridLines=false;overview.freezePanes.freezeRows(3);
wb.recalculate();
const observed=overview.getRange('B4:B6').values.map(r=>r[0]);
if(JSON.stringify(observed)!==JSON.stringify([c,n,s.acquired_bytes]))throw new Error('Reconciliation failed: '+JSON.stringify(observed));
console.log((await wb.inspect({kind:'match',searchTerm:'#REF!|#DIV/0!|#VALUE!|#NAME\\?|#NUM!|#N/A',options:{useRegex:true,maxResults:10},maxChars:500})).ndjson);
const target=path.join(root,'00_Master_Inventory/master_acquisition_tracker.xlsx');
try{await fs.access(target);throw new Error('Refusing overwrite');}catch(e){if(e.code!=='ENOENT')throw e;}
await(await SpreadsheetFile.exportXlsx(wb)).save(target);
for(const [sheetName,range,label] of [['Overview','A1:B20','campaign-overview'],['Checklist','A1:C5','campaign-checklist'],['Checklist','H1:J5','campaign-status'],['Acquired','D1:I5','campaign-acquired'],['Existing audit','A1:C5','campaign-existing']]){
 const preview=await wb.render({sheetName,range,scale:1,format:'png'});
 await fs.writeFile(path.join(here,'previews',label+'.png'),new Uint8Array(await preview.arrayBuffer()));
}
console.log(JSON.stringify({target,checklistRows:c,acquiredFiles:n,summaryReconciled:true}));
