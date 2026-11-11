"""Read-only parent audit. New outputs use exclusive creation; never install tools."""
import argparse
import collections
import csv
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parent
NOW = dt.datetime.now(dt.timezone(dt.timedelta(hours=5, minutes=30))).isoformat()
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_csv(path, fields, rows):
    with path.open('x', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def text(path, content):
    with path.open('x', encoding='utf-8') as stream:
        stream.write(content)


def git(*args):
    return subprocess.check_output(['git', '-C', str(PROJECT), *args], text=True).strip()


def category(relative):
    name = relative.lower()
    if any(term in name for term in ['answer-key', 'answer_key', 'ground_truth', 'ground-truth']):
        return 'Evaluator-only labels / answer keys'
    if name.startswith('known_attacks/'):
        return 'Existing reference corpus'
    if name.startswith('data/repo-cleanup-backup/'):
        return 'Historical backup (currency unverified)'
    if name.startswith('output/evaluation') or name.startswith('data/evaluation'):
        return 'Evaluation artifact (not independent benchmark)'
    if name.startswith('data/verification/'):
        return 'Verification receipt'
    if 'extracted_logs/' in name or name.endswith(('.zip', '.pcap', '.evtx', '.ndjson', '.jsonl')):
        return 'Candidate evidence / derived data (provenance unverified)'
    if name.endswith(('.sqlite3', '.db', '.pickle', '.bin')) or 'chroma' in name or 'checkpoints/' in name:
        return 'Mutable datastore / derived index'
    if name.endswith('.pdf'):
        return 'Project PDF (not verified scholarly paper)'
    return 'Project documentation / artifact'


def audit():
    paths = []
    for folder in ['docs', 'known_attacks', 'output', 'data', 'quarantine']:
        directory = PROJECT / folder
        if directory.is_dir():
            paths.extend(p for p in directory.rglob('*') if p.is_file() and not p.is_symlink())
    paths.extend(p for p in PROJECT.iterdir() if p.is_file() and
                 (p.suffix.lower() in {'.docx', '.pdf', '.zip', '.ndjson'} or
                  p.name in {'README.md', 'requirements.txt', 'DECISIONS.md', 'AGENTS.md', 'PROGRESS.md'}))
    paths = sorted(set(paths))
    records, problems, hashed_bytes = [], [], 0
    for path in paths:
        relative = path.relative_to(PROJECT).as_posix()
        kind = category(relative)
        stat = path.stat()
        digest = ''
        check = 'not_hashed: mutable datastore' if kind.startswith('Mutable') else ''
        if not check and stat.st_size > MAX_FILE:
            check = 'not_hashed: exceeds 64 MiB audit read limit'
        if not check and hashed_bytes + stat.st_size > MAX_TOTAL:
            check = 'not_hashed: exceeds 512 MiB total audit read limit'
        if not check:
            try:
                digest = sha(path)
                hashed_bytes += stat.st_size
                after = path.stat()
                check = 'local SHA-256 recorded; publisher integrity unverified'
                if (stat.st_size, stat.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    digest, check = '', 'changed_during_read: hash discarded'
                elif path.suffix.lower() in {'.zip', '.xlsx', '.docx'}:
                    with zipfile.ZipFile(path) as archive:
                        expanded = sum(i.file_size for i in archive.infolist())
                        if expanded <= MAX_FILE:
                            bad = archive.testzip()
                            if bad:
                                check = 'CORRUPT: ZIP CRC failure'
                            else:
                                check = 'ZIP CRC passed; local SHA-256 recorded; origin unverified'
                        else:
                            check += '; archive CRC deferred: expanded size >64 MiB'
            except Exception as exc:
                check = 'read_error: ' + type(exc).__name__ + ': ' + str(exc)
        if not digest or check.startswith(('CORRUPT', 'read_error')):
            problems.append({'resource_name': relative, 'status': check, 'reason': 'Existing resource audit limitation', 'action': 'Verify separately before use'})
        version = 'v19.2 (filename only; official currency unverified)' if 'v19.2' in path.name else 'unknown'
        records.append({
            'resource_name': relative, 'priority': 'unassigned: checklist unavailable',
            'official_source': 'unknown: existing local resource', 'download_url': '',
            'version': version, 'file_size_bytes': stat.st_size,
            'acquisition_status': 'existing_in_place', 'local_storage_path': str(path),
            'sha256': digest, 'licence_access_restrictions': 'unknown; local availability is not redistribution permission',
            'verification_status': check, 'notes': kind,
            'release_date': 'unknown', 'dependencies': 'not assessed',
            'acquisition_date': 'unknown (predates audit)', 'audit_date': NOW,
            'access_scope': 'evaluator_only' if kind.startswith('Evaluator') or 'Evaluation artifact' in kind else 'unassigned; do not ingest automatically',
        })
    fields = list(records[0]) if records else []
    write_csv(ROOT/'00_Master_Inventory'/'initial_inventory.csv', fields, records)
    checks = [{'local_storage_path': r['local_storage_path'], 'file_size_bytes': r['file_size_bytes'],
               'sha256': r['sha256'], 'hash_date': NOW, 'verification_status': r['verification_status']} for r in records]
    write_csv(ROOT/'08_Checksums_And_Manifests'/'resource_checksums.csv', list(checks[0]), checks)
    grouped = collections.defaultdict(list)
    for r in records:
        if r['sha256'] and r['file_size_bytes']:
            grouped[r['sha256']].append(r)
    duplicates = []
    for digest, group in grouped.items():
        if len(group) > 1:
            duplicates.extend({'sha256': digest, 'group_size': len(group), 'file_size_bytes': r['file_size_bytes'],
                               'local_storage_path': r['local_storage_path'], 'action': 'preserved; no deletion'} for r in group)
    write_csv(ROOT/'00_Master_Inventory'/'duplicate_resources.csv', ['sha256','group_size','file_size_bytes','local_storage_path','action'], duplicates)
    write_csv(ROOT/'09_Acquisition_Reports'/'verification_exceptions.csv', ['resource_name','status','reason','action'], problems)
    datasets = [r for r in records if 'Candidate evidence' in r['notes'] or 'Evaluator-only' in r['notes']]
    dataset_rows = [{**r, 'dataset_status': 'local candidate; checklist membership and independent ground truth unverified'} for r in datasets]
    write_csv(ROOT/'08_Checksums_And_Manifests'/'dataset_manifest.csv', fields+['dataset_status'], dataset_rows)
    keys = [r for r in records if r['access_scope'] == 'evaluator_only']
    write_csv(ROOT/'07_Evaluation_Artifacts'/'evaluator_only'/'existing_evaluator_artifacts.csv', fields, keys)
    repository = [{'resource_name':'Existing Specula implementation', 'priority':'unassigned: checklist unavailable',
                   'official_source':'not verified (remote URLs not exported)', 'download_url':'',
                   'local_storage_path':str(PROJECT), 'commit':git('rev-parse','HEAD'),
                   'branch':git('branch','--show-current'), 'status':'existing working tree; not cloned or executed',
                   'licence':'not assessed', 'audit_date':NOW}]
    write_csv(ROOT/'08_Checksums_And_Manifests'/'repository_manifest.csv', list(repository[0]), repository)
    write_csv(ROOT/'03_Research_Papers'/'research_paper_bibliography.csv',
              ['title','authors','year','doi','official_source','download_url','local_storage_path','sha256','licence','status'], [])
    missing = [{'resource_name':'Specula - Complete Download and Resource Checklist',
                'status':'source_document_unavailable', 'reason':'No attachment visible; no matching project filename or attachment title text found',
                'action':'User must supply local path, attach document, or paste checklist including first ten and priorities'}]
    write_csv(ROOT/'09_Acquisition_Reports'/'missing_resources_report.csv', list(missing[0]), missing)
    write_csv(ROOT/'09_Acquisition_Reports'/'restricted_resources_report.csv',
              ['resource_name','official_source','restriction','status','required_action'], [])
    disk = shutil.disk_usage(ROOT)
    summary = {'audit_date':NOW, 'project_root':str(PROJECT), 'workspace_root':str(ROOT),
               'existing_files':len(records), 'total_inventory_bytes':sum(r['file_size_bytes'] for r in records),
               'hashed_files':sum(bool(r['sha256']) for r in records), 'hashed_bytes':hashed_bytes,
               'hash_deferred_or_failed':sum(not bool(r['sha256']) for r in records),
               'duplicate_groups':sum(len(g)>1 for g in grouped.values()), 'duplicate_files':len(duplicates),
               'evaluator_artifacts':len(keys), 'verification_exceptions':len(problems),
               'new_external_acquisitions':0, 'disk_free_bytes':disk.free, 'disk_total_bytes':disk.total,
               'checklist_status':'unavailable; first ten and P0/P1/P2 unknown',
               'categories':dict(collections.Counter(r['notes'] for r in records))}
    text(ROOT/'00_Master_Inventory'/'audit_summary.json', json.dumps(summary, indent=2))
    text(ROOT/'09_Acquisition_Reports'/'workbook_input.json', json.dumps({'summary':summary,'records':records}, indent=2))
    text(ROOT/'06_Existing_Project_Resources'/'README.md',
         '# Existing project resources\n\nOriginals remain in the parent project. See ../00_Master_Inventory/initial_inventory.csv for exact paths, hashes and limitations. No original files were moved or overwritten. Historical backup paths are not automatically obsolete. Official version currency, licensing and provenance remain unverified.\n')
    text(ROOT/'07_Evaluation_Artifacts'/'README.md',
         '# Evaluation boundary\n\nAnswer keys and evaluation-derived artifacts are indexed only under evaluator_only/. No keys or labels are copied into 01_Forensic_Datasets or 02_Benchmarks. Existing parent files remain untouched. This directory separation is organizational, not an OS permission or sandbox guarantee. Configure agent read roots explicitly before ingestion. Independent label quality and evaluator blinding remain unverified.\n')
    text(ROOT/'README.md',
         '# Specula research acquisition workspace\n\nPRELIMINARY LOCAL AUDIT ONLY. The exact checklist is unavailable; no external resource acquisitions are claimed. Unknown checklist items are not treated as absent.\n\nSee 00_Master_Inventory/master_acquisition_tracker.xlsx and 09_Acquisition_Reports/acquisition_summary.pdf. CSVs live in 08_Checksums_And_Manifests, 03_Research_Papers and 09_Acquisition_Reports. Header-only bibliography and restricted-resource CSVs mean not assessed, not none required.\n\nExisting resources are referenced in place. Inventory excludes source trees, virtual environments, node_modules, hidden/credential directories, caches and pytest scratch trees. Large-file hashes and mutable datastore hashes are deferred and recorded explicitly. ZIP CRC checks are bounded to 64 MiB expanded size. Local hashes show observed bytes, not authenticity, scientific suitability or publisher completeness. No source code, services, datasets or dependency environment were changed.\n\nNext: supply the exact checklist; map existing items; verify official versions, licences, dependencies and sizes; acquire first ten in document order, then remaining P0/P1/P2. Obtain approval before large, paid or restricted requests. Preserve raw bytes and original docs; pin repository commits. Keep answer keys outside agent evidence read roots.\n\nVerification: run `..\\venv\\Scripts\\python.exe 09_Acquisition_Reports\\audit_resources.py --verify`. Audit generation refuses existing output names. Preserve this snapshot and use a new dated workspace for a fresh audit.\n')
    print(json.dumps(summary, indent=2))


def pdf():
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    s = json.loads((ROOT/'00_Master_Inventory'/'audit_summary.json').read_text())
    target = ROOT/'09_Acquisition_Reports'/'acquisition_summary.pdf'
    if target.exists():
        raise FileExistsError(target)
    styles = getSampleStyleSheet()
    story = [Paragraph('SPECULA | Resource acquisition audit', styles['Title']),
             Paragraph('Preliminary local inventory - 11 November 2026 (Asia/Calcutta)', styles['Normal']), Spacer(1,16),
             Paragraph('Status: checklist required', styles['Heading2']),
             Paragraph('The named Complete Download and Resource Checklist was not available. The first ten acquisitions and P0/P1/P2 assignments cannot be determined. No external downloads, clones, source checks or access requests are claimed. This report documents feasible local work only.', styles['BodyText'])]
    rows = [['Local audit measure','Observed value'],
            ['Existing files inventoried',str(s['existing_files'])],
            ['Stable files with local SHA-256',str(s['hashed_files'])],
            ['Hash deferred or unavailable',str(s['hash_deferred_or_failed'])],
            ['Exact duplicate groups / files',f"{s['duplicate_groups']} / {s['duplicate_files']}"],
            ['Evaluator-only indexed artifacts',str(s['evaluator_artifacts'])],
            ['New external acquisitions','0'],['Free storage at audit',f"{s['disk_free_bytes']/2**30:.1f} GiB"]]
    table = Table(rows,colWidths=[3.7*inch,2.2*inch],hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#17354B')),
                              ('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
                              ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#F0F5F8'),colors.white]),
                              ('FONTSIZE',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),9)]))
    story += [Spacer(1,14),table,Spacer(1,12)]
    for title,body in [
        ('Existing resources','The parent project is available. The inventory includes ATT&CK v19.2 workbooks (version from filenames only), local evidence and derived data, project documents, verification receipts, pilot evaluation outputs and answer keys. Project PDFs have not been identified as scholarly papers. Existing materials are referenced in place; no originals were moved or overwritten.'),
        ('Integrity and provenance limits','Recorded SHA-256 values identify observed local bytes. They have not been matched to publisher checksums. ZIP-based files receive CRC checks only when expanded size is at most 64 MiB. Mutable datastores and files exceeding the audit read budget remain explicitly unverified. Duplicate reports identify equal nonempty bytes; no duplicates were deleted. Backup locations do not prove outdated content. Official versions, release dates, licences, dependencies and download completeness remain unassessed.'),
        ('Ground truth separation','Evaluator keys and evaluation-derived artifacts are indexed under 07_Evaluation_Artifacts/evaluator_only. No labels were copied to the dataset or benchmark directories. Existing parent locations remain unchanged. This is organizational separation, not access control; agent evidence roots must exclude evaluator material. The local pilot is not an independently validated empirical benchmark.'),
        ('Deliverables and interpretation','The master tracker and initial inventory record existing local files. Dataset and repository manifests record local candidates and the exact existing repository commit. The scholarly bibliography and restricted-resource report contain headers only because their checklist-driven scope is unknown. The missing-resource report records the missing checklist, not speculative missing datasets. Resource checksums and verification exceptions record per-file limitations.'),
        ('Next action','Supply the exact checklist document or local path. Then map existing assets to each required item, check original official sources, record version/release/licence/dependencies/size, acquire the first ten in document order and continue through remaining priorities. Assess storage and request approval before large downloads, paid resources or restricted-access requests. No tools were installed or implementation files changed.'),
    ]:
        story += [Paragraph(title,styles['Heading2']), Paragraph(body,styles['BodyText'])]
    def footer(canvas,doc):
        canvas.setFont('Helvetica',8)
        canvas.setFillColor(colors.HexColor('#526778'))
        canvas.drawString(42,28,'SPECULA | Preliminary audit | No research results or acquisition completion claimed')
        canvas.drawRightString(570,28,str(doc.page))
    SimpleDocTemplate(str(target),pagesize=(612,792),rightMargin=42,leftMargin=42,topMargin=40,bottomMargin=45).build(story,onFirstPage=footer,onLaterPages=footer)
    print(target)


def verify():
    inventory = list(csv.DictReader((ROOT/'00_Master_Inventory'/'initial_inventory.csv').open(encoding='utf-8-sig')))
    verified = 0
    for row in inventory:
        path = Path(row['local_storage_path'])
        assert path.is_file(), path
        if row['sha256']:
            assert path.stat().st_size == int(row['file_size_bytes']), path
            assert sha(path) == row['sha256'], path
            verified += 1
    expected = ['00_Master_Inventory/master_acquisition_tracker.xlsx',
                '08_Checksums_And_Manifests/dataset_manifest.csv',
                '08_Checksums_And_Manifests/repository_manifest.csv',
                '03_Research_Papers/research_paper_bibliography.csv',
                '08_Checksums_And_Manifests/resource_checksums.csv',
                '09_Acquisition_Reports/restricted_resources_report.csv',
                '09_Acquisition_Reports/missing_resources_report.csv',
                '09_Acquisition_Reports/acquisition_summary.pdf']
    for name in expected:
        assert (ROOT/name).stat().st_size > 0, name
    with zipfile.ZipFile(ROOT/expected[0]) as z:
        assert z.testzip() is None
        namespace = {'m':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        book = ET.fromstring(z.read('xl/workbook.xml'))
        assert [e.attrib['name'] for e in book.findall('m:sheets/m:sheet', namespace)] == ['Overview','Inventory']
        sheet = ET.fromstring(z.read('xl/worksheets/sheet2.xml'))
        assert len(sheet.findall('m:sheetData/m:row', namespace)) >= len(inventory)+1
    from pypdf import PdfReader
    document = PdfReader(ROOT/expected[-1])
    assert 1 <= len(document.pages) <= 4
    assert 'checklist required' in document.pages[0].extract_text().lower()
    for folder in ['01_Forensic_Datasets','02_Benchmarks']:
        assert not list((ROOT/folder).rglob('*')), 'Unexpected evidence/labels copied'
    assert git('rev-parse','HEAD') == 'b9b2012edaed8da5062113ddc9982e3c33b27983'
    receipt = {'verified_at':dt.datetime.now(dt.timezone.utc).isoformat(), 'original_hashes_rechecked':verified,
               'inventory_rows':len(inventory), 'required_deliverables':len(expected), 'pdf_pages':len(document.pages),
               'result':'PASS for local audit only; checklist acquisition remains blocked'}
    path = ROOT/'09_Acquisition_Reports'/'verification_receipt.json'
    if path.exists():
        assert json.loads(path.read_text())['result'] == receipt['result']
    else:
        text(path,json.dumps(receipt,indent=2))
    print(json.dumps(receipt,indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--pdf',action='store_true')
    parser.add_argument('--verify',action='store_true')
    args = parser.parse_args()
    if args.verify:
        verify()
    elif args.pdf:
        pdf()
    else:
        audit()
