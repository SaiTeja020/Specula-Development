import json
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
from fetch_official import ROOT

data=json.loads((ROOT/'09_Acquisition_Reports/campaign_input.json').read_text(encoding='utf-8'))
s=data['summary'];styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='SmallBody',parent=styles['BodyText'],fontSize=9,leading=12,spaceAfter=6))
styles['BodyText'].leading=14
def para(text,style='BodyText'):return Paragraph(escape(text),styles[style])
def header(canvas,doc):
 canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#526778'))
 canvas.drawString(42,28,'SPECULA | 11 November 2026 | Research acquisition, not experimental results')
 canvas.drawRightString(570,28,str(doc.page))
def document(path,story):
 assert not path.exists(),path
 SimpleDocTemplate(str(path),pagesize=(612,792),leftMargin=42,rightMargin=42,topMargin=38,bottomMargin=44).build(story,onFirstPage=header,onLaterPages=header)
def table(rows,widths):
 t=Table([[para(str(c),'SmallBody') for c in r] for r in rows],colWidths=widths,hAlign='LEFT',repeatRows=1)
 t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#E7F0F5')),('VALIGN',(0,0),(-1,-1),'TOP'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#F4F7F9'),colors.white]),('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),4)]))
 return t

rejected=sum(f['verification_status'] in ['EMPTY_RESPONSE_NOT_RESOURCE','HTML_QUOTA_RESPONSE_NOT_EVIDENCE'] for f in data['files'])
story=[para('SPECULA | Acquisition summary','Title'),para('11 November 2026 | Asia/Calcutta','Normal'),Spacer(1,10),
 para('Verified acquisitions with explicit remaining gates','Heading2'),
 para(f"The authoritative checklist has {s['checklist_rows']} tracked checkbox rows, including process and deliverable entries. Acquired resources include {s['research_papers_acquired']} research papers, {s['pinned_clones']} pinned repository clones, {s['reference_archives']} pinned source ZIP archives, ATT&CK v19.2 STIX and official documentation. The file ledger records {s['acquired_files']-rejected:,} acquired source/document files plus {rejected} preserved rejected responses ({s['acquired_bytes']/2**20:.1f} MiB total), including repository worktrees. This is not a claim that every checklist resource is complete."),Spacer(1,8)]
pilot=[['First-ten pilot item','Status','Verified scope / remaining limit'],
 ['1. NIST Hacking Case','DEFERRED / P0','Scenario, acquisition log and public answers acquired. Raw image 4.54 GiB deferred by owner; dependent experiments pending.'],
 ['2. OpTC documentation','VERIFIED','README, eCAR, errata and red-team ground-truth PDF pinned to 5b108604f11f...; keys stored separately.'],
 ['3. OpTC small events','UNAVAILABLE','Small public network request returned quota HTML. Endpoint host-group archive inspected is 1.86 GB and deferred.'],
 ['4. DFIR-Metric release','PARTIAL','Three JSON datasets and generator notebooks acquired. Standalone evaluation runner absent at the pinned commit.'],
 ['5. DFIR-Metric paper','VERIFIED','Actual arXiv 2505.19973v1 PDF downloaded, parsed and hashed.'],
 ['6. ATT&CK STIX','VERIFIED','v19.2, 53,835,637 bytes, 26,086 objects; official Git blob hash matched. Existing XLSX exports preserved.'],
 ['7. OCSF schema','VERIFIED','v1.9.0 source clone; version.json, exact commit and licence preserved. No installation.'],
 ['8. NIST SP 800-86','VERIFIED','Official final PDF and publication source page present.'],
 ['9. NIST SP 800-61r3','VERIFIED','Official April 2025 Revision 3 PDF and source page present.'],
 ['10. Plaso / Timesketch','VERIFIED SCOPE','Both exact-commit sparse source/docs clones. Large test corpora omitted and recorded; neither installed.']]
story += [table(pilot,[125,88,315]),PageBreak(),para('Existing resources, integrity and limitations','Heading1')]
for title,body in [
 ('Existing-resource audit',f"Inventoried {s['existing_unique_files']:,} unique project files, including 322 source/fixture/config entries added to the primary inventory. Primary audit recorded 2,458 hashes and deferred 31 mutable datastore/index hashes. It identified 93 exact nonempty duplicate groups (654 member files); nothing was deleted. Named requested originals have a separate exact-name audit. Related Markdown/PDF files are not silently treated as the requested originals. Existing external or unseen files are not assumed absent."),
 ('Source and format verification','HTTP byte counts were reconciled where the source supplied Content-Length. Local SHA-256 values were recorded; repository commits and clean worktrees were checked with git connectivity verification. All acquired ZIP archives passed CRC checks; JSON parsed and PDFs passed strict structural/page/EOF checks. The original GenDFIR v4 PDF produces a non-zero-index xref warning in the PDF parser; its source bytes are preserved and the parser opens all pages. No publisher checksum is invented when one is not available.'),
 ('Benchmark discrepancies','The actual DFIR-Metric release has 713 MCQ, 150 CTF and 510 forensic-search questions. Its README advertises 700/150/500. Exact source commit and actual counts are recorded; these are not independent label-quality validations. CFA-Bench supplies 20 cases; 59 raw PCAP/log files were copied with opaque filenames and byte-identical content. Original labels/results/name mappings remain in evaluator storage.'),
 ('Bibliographic corrections','The corrected 2017 Drain paper (DOI 10.1109/ICWS.2017.13) and the separate 2018 DAG paper are acquired. CyberSleuth 2508.20643v2 is acquired with an author-linked sparse source clone. CFA-Bench DOI metadata and official benchmark are acquired; the publicly listed university author manuscript could be read through web tooling but validated direct downloads failed. No local CFA-Bench paper is claimed. MADIK DOI 10.1007/978-3-540-88875-8_10 remains a candidate needing relevance confirmation.'),
 ('Access and size gates','Large evidence downloads remain deferred at the owner\'s request. NIST Hacking remains a P0 planned dataset, not completed or cancelled. NIST Data Leakage, CERT corpus releases, M57 images and large CyberSleuth/OpTC evidence are deferred. M57 instructor keys are encrypted/restricted; no access request or decryption was attempted. ISO source requests returned 403; UNB direct requests failed TLS validation; CERT small-file URLs returned 403. Zeek and Atomic Red Team source archives exceeded the 32 MiB automatic bound and were not saved. These failures are logged; no access checks were bypassed.'),
]:
 story += [para(title,'Heading2'),para(body,'SmallBody')]
story += [PageBreak(),para('Evaluation boundary and reproducibility','Heading1')]
for title,body in [
 ('Evaluator-only access','The evaluator directory has protected Windows ACL inheritance and grants DELL, SYSTEM and the acquisition sandbox account. This restricts other accounts but cannot isolate an evaluated agent sharing those identities. Enforce a distinct agent identity or evidence read-root policy before blinded evaluation. Give the system only the prepared CFA agent_evidence tree, after content-level leakage review; never expose inventories, original label-bearing filenames, tasks, results, original benchmark repos or mapping files. No existing parent answer keys were moved or repermissioned.'),
 ('Templates, not research results','Empty templates exist for verified events, critical evidence, relationships, temporal order, original reviewer judgments, baseline/ablation measurements and resource logs. Reviewer instructions describe blinding and evidence-linked judgments. Experiment configuration, notebook and reproducibility manifest contain no invented labels, scores, model settings or runs. NIST-dependent experiments remain pending dataset acquisition and verification.'),
 ('Deliverables','The master workbook contains Overview, Checklist, Acquired and Existing audit tabs. CSV manifests cover existing resources, exact-name checks, datasets, repositories, bibliography, acquired files, checksums, missing/pending and restricted resources. Acquisition receipts preserve official URLs, timestamps, HTTP headers, exact commits, sparse paths and source-archive versions. Preliminary report versions and the original checklist are retained.'),
 ('Verification command','Run ..\\venv\\Scripts\\python.exe 09_Acquisition_Reports\\verify_campaign.py from the acquisition workspace as an authorized evaluator. It rechecks original and acquired hashes, original-to-evidence byte identity, repository status/commits, workbook counts/formula caches, manifest coverage, report structures and the unchanged parent source commit. Final PDF and workbook previews are inspected separately. Hashes establish observed bytes, not semantic truth or scientific suitability.'),
 ('Next actions','Resolve the recorded access/source blockers without bypassing restrictions. Establish whether the MADIK candidate belongs to the original proposal. Select optional P2 resources according to a defined evaluation need and install tools only under separate approval. Obtain independent forensic labels and blinded reviewers; freeze models, budgets and protocol before experiments. Resume large evidence acquisition only under a new owner instruction.'),
]:
 story += [para(title,'Heading2'),para(body)]
document(ROOT/'09_Acquisition_Reports/acquisition_summary.pdf',story)

review=[para('SPECULA | Blinded reviewer instructions','Title'),para('Unpopulated protocol template - 11 November 2026','Normal'),Spacer(1,12)]
for title,body in [
 ('Before review','An evaluation coordinator must validate the evidence/labels, freeze the case subset and record corpus hashes before review. Assign randomized run aliases that conceal the producing system, ablation condition and model. Keep the alias key, original labels, answer keys and benchmark filenames evaluator-only. Reviewers must not receive other reviewers\' judgments before submitting their own.'),
 ('Unit of judgment','Review every atomic factual claim separately. Link each judgment to case-local evidence and an evidence identifier. Record claim support as supported, partially supported, unsupported or unverifiable. Use unverifiable when evidence or annotation is insufficient; do not convert missing data to a negative label. A syntactically valid citation does not prove claim support.'),
 ('Additional judgments','Assess citation validity separately from semantic support. Use verified outcomes and timestamp uncertainty; chronological order alone is not causation. Record critical-evidence and relationship judgments only where independent sources support them. Fixture/synthetic provenance does not prove benignness, maliciousness or successful execution.'),
 ('Independence and adjudication','Use at least two independent forensic-literate reviewers for scored claim-support judgments. Preserve each original judgment and evidence reference before discussion. Store any adjudicated judgment in a separate field, with rationale, without replacing originals. Record blinding breaks, conflicts, missing evidence and ambiguous cases. Calculate reviewer agreement only after collecting independent ratings.'),
 ('Reporting','Do not fill templates with guessed truth or scores. Freeze metric denominators and case-level uncertainty analysis before comparing systems. Retain failed runs and timeouts. Separate compute time from analyst wait. NIST Hacking Case dependent runs remain pending while the image is deferred. This template does not certify independent annotation or completed experiments.'),
]:review += [para(title,'Heading2'),para(body)]
if not (ROOT/'07_Evaluation_Artifacts/reviewer_instructions.pdf').exists():
 document(ROOT/'07_Evaluation_Artifacts/reviewer_instructions.pdf',review)
print('Created acquisition summary and reviewer protocol PDFs')
