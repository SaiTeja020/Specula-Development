import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Workbook, SpreadsheetFile } from '@oai/artifact-tool';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const data = JSON.parse(await fs.readFile(path.join(here, 'workbook_input.json'), 'utf8'));
const output = path.join(root, '00_Master_Inventory', 'master_acquisition_tracker.xlsx');
try { await fs.access(output); throw new Error('Refusing to overwrite tracker'); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
const wb = Workbook.create();
const overview = wb.worksheets.add('Overview');
const inventory = wb.worksheets.add('Inventory');
const fields = Object.keys(data.records[0]);
const labels = ['Resource name','Priority','Official source','Download URL','Version',
  'File size (bytes)','Acquisition status','Local storage path','SHA-256 checksum',
  'Licence / access restrictions','Verification status','Notes','Release date',
  'Dependencies','Acquisition date','Audit date','Access scope'];
const n = data.records.length;
inventory.getRange(`A1:Q${n+1}`).values = [labels, ...data.records.map(r => fields.map(k => r[k] === '' ? null : r[k]))];
inventory.getRange(`A1:Q${n+1}`).format.font = {name:'Arial',size:10,color:'#17354B'};
inventory.getRange(`A1:Q${n+1}`).format.wrapText = true;
inventory.getRange(`A1:Q${n+1}`).format.verticalAlignment = 'top';
inventory.getRange(`A1:Q${n+1}`).format.rowHeight = 72;
inventory.getRange(`A1:Q${n+1}`).format.columnWidth = 28;
for (const [column,width] of Object.entries({A:76,B:30,C:35,D:35,E:40,F:20,G:26,H:100,I:75,J:70,K:90,L:65,M:20,N:22,O:30,P:36,Q:60})) {
  inventory.getRange(`${column}1:${column}${n+1}`).format.columnWidth = width;
}
inventory.getRange(`F2:F${n+1}`).setNumberFormat('#,##0');
inventory.tables.add(`A1:Q${n+1}`,true,'ResourceInventory');
inventory.getRange('A1:Q1').format = {fill:'#17354B',font:{name:'Arial',size:10,bold:true,color:'#FFFFFF'},wrapText:true,rowHeight:38};
inventory.freezePanes.freezeRows(1);
inventory.showGridLines = false;
const s = data.summary;
const rows = [
 ['SPECULA / ACQUISITION AUDIT','11 November 2026 | Asia/Calcutta'],
 ['Status','PRELIMINARY - exact checklist unavailable'],
 ['Required action','Provide the named checklist, including first ten acquisitions and P0/P1/P2.'],
 ['Existing files inventoried',null],
 ['Files with local SHA-256',null],
 ['Inventory size (bytes)',null],
 ['Hash deferred / unavailable',s.hash_deferred_or_failed],
 ['Exact duplicate groups',s.duplicate_groups],
 ['Evaluator-only indexed artifacts',s.evaluator_artifacts],
 ['New external acquisitions',0],
 ['Free storage at audit (GiB)',Math.round(s.disk_free_bytes/2**30*10)/10],
 ['Scope','Parent docs, data, output, known_attacks, quarantine and selected root documents. See README for exclusions.'],
 ['Existing resources','Referenced in place; originals preserved. Historical backups are not automatically outdated.'],
 ['Integrity limitation','Local hashes identify observed bytes; publisher authenticity, completeness and official version currency remain unverified.'],
 ['Evaluator boundary','Answer keys and evaluation outputs indexed separately in 07_Evaluation_Artifacts/evaluator_only; no labels copied into dataset or benchmark folders. Directory separation is not OS access control.'],
 ['Unknown fields','Priorities, official sources, release dates, licences and dependencies require the checklist and official-source verification.'],
 ['Empty manifests','Header-only bibliography and restricted-resource report mean not assessed; they do not establish that no such resources are required.'],
 ['Next sequence','Map exact checklist to inventory; verify sources; acquire first ten in document order; continue remaining P0/P1/P2. Ask approval before large, paid or restricted requests.'],
 ['Audit timestamp',s.audit_date],
];
overview.getRange('A1:B19').values = rows;
overview.getRange('A1:B19').format = {font:{name:'Arial',size:11,color:'#17354B'},wrapText:true,verticalAlignment:'top',rowHeight:42};
overview.getRange('A1:A19').format.columnWidth = 38;
overview.getRange('B1:B19').format.columnWidth = 105;
overview.getRange('A1:B1').format = {fill:'#17354B',font:{name:'Arial',size:14,bold:true,color:'#FFFFFF'},wrapText:true,rowHeight:44};
overview.getRange('A2:B3').format.fill = '#FFF0CC';
overview.getRange('A4:A11').format.font.bold = true;
overview.getRange('B4').formulas = [[`=COUNTA(Inventory!A2:A${n+1})`]];
overview.getRange('B5').formulas = [[`=COUNTA(Inventory!I2:I${n+1})`]];
overview.getRange('B6').formulas = [[`=SUM(Inventory!F2:F${n+1})`]];
overview.getRange('B4:B10').setNumberFormat('#,##0');
overview.getRange('B11').setNumberFormat('0.0');
overview.getRange('A12:B18').format.rowHeight = 57;
overview.getRange('A15:B15').format.rowHeight = 72;
overview.freezePanes.freezeRows(3);
overview.showGridLines = false;
wb.recalculate();
const observed = overview.getRange('B4:B6').values.map(r=>r[0]);
if (observed[0] !== n || observed[1] !== s.hashed_files || observed[2] !== s.total_inventory_bytes) throw new Error('Summary reconciliation failed: '+JSON.stringify(observed));
console.log((await wb.inspect({kind:'match',searchTerm:'#REF!|#DIV/0!|#VALUE!|#NAME\\?|#NUM!|#N/A',options:{useRegex:true,maxResults:10},maxChars:1000})).ndjson);
await (await SpreadsheetFile.exportXlsx(wb)).save(output);
for (const [sheetName,range,name] of [['Overview','A1:B19','tracker-overview'],['Inventory','A1:C6','tracker-inventory-left'],['Inventory','H1:K4','tracker-inventory-verification'],['Inventory','L1:Q4','tracker-inventory-metadata']]) {
  const preview = await wb.render({sheetName,range,scale:1,format:'png'});
  await fs.writeFile(path.join(here,'previews',`${name}.png`),new Uint8Array(await preview.arrayBuffer()));
}
console.log(JSON.stringify({output,rows:n,summaryReconciled:true}));
