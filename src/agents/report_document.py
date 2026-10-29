"""Audience-specific report content and ReportLab PDF layout from saved evidence.

Input strings are evidence data, never markup or instructions. No model is called.
"""
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from io import BytesIO
import json
import math
import re

from .grounded_report import _prepared, _utc
from .case_analysis import current_findings, current_traces, decode_record

TEMPLATE = 'specula-examination-v2'


def text(value):
    if value is None or value == '':
        return 'Not recorded'
    if isinstance(value, (dict, list)):
        return 'Structured data retained in case record'
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(value))


def timestamp(event):
    return _utc(event.get('time', event.get('event_time', event.get('timestamp'))))


def observation(event):
    """Display only recorded, whitelisted fields, without nested source dumps."""
    details = []
    for key, label in [('host_name', 'Host'), ('canonical_host_id', 'Host ID'),
                       ('process_name', 'Process'), ('parent_process_name', 'Parent'),
                       ('command_line', 'Command'), ('file_path', 'File'),
                       ('source_user_name', 'User'), ('api_operation', 'Operation'),
                       ('source_event_id', 'Source event'), ('source_outcome', 'Outcome'),
                       ('bytes_out', 'Outbound bytes'), ('bytes_in', 'Inbound bytes')]:
        if event.get(key) is not None and event.get(key) != '':
            details.append((label, text(event[key])))
    for name, label in [('src_endpoint', 'Source'), ('dst_endpoint', 'Destination')]:
        endpoint = event.get(name)
        if not isinstance(endpoint, dict) and isinstance(event.get(name + '_json'), str):
            try:
                endpoint = json.loads(event[name + '_json'])
            except ValueError:
                pass
        if isinstance(endpoint, dict):
            address = endpoint.get('ip') or endpoint.get('hostname')
            if address:
                details.append((label, str(address) + (f":{endpoint['port']}" if endpoint.get('port') else '')))
    return details


def finding_summary(finding):
    """Keep the recorded interpretation, removing embedded diagnostic payloads."""
    summary = text(finding.get('summary'))
    summary = re.sub(r';?\s*source context=.*$', '', summary, flags=re.IGNORECASE)
    summary = re.sub(r'\b\w+=None;?\s*', '', summary)
    if finding.get('finding_type') == 'cloud_principal_activity' and '[{' in summary:
        summary = summary.split('[{', 1)[0].rstrip(': ') + '. ' + (
            f"{len(finding.get('dfkg_refs') or [])} linked records; individual operations and outcomes require review in the cited exhibits.")
    return summary


def report_content(state, kind):
    if kind not in {'court', 'technical'}:
        raise ValueError('Unknown report type')
    events, meta = _prepared(state)
    events = sorted((decode_record(e) for e in events), key=lambda e: (timestamp(e) or '9999', e.get('uid', e.get('event_uid', ''))))
    provenance = state.get('ingestion_provenance') or {}
    declared = provenance.get('declared_metadata') or {}
    flags = set(meta['degraded_flags'])
    if not state.get('execution_manifest'):
        flags.add('historical_execution_version_not_recorded')
    if any(t.get('agent_role') == 'log_analysis' and t.get('model_used') == 'hybrid_rules_and_llm'
           for t in current_traces(state)):
        flags.add('historical_log_analysis_adapter_may_have_discarded_source_fields')
    for field, flag in [('clock_skew_unverified', 'source_clock_skew_unverified'),
                        ('security_scan_degraded', 'security_screening_degraded')]:
        if any(e.get(field) for e in events):
            flags.add(flag)
    processing = provenance.get('processing') or {}
    if provenance.get('source') == 'uploaded_zip' and (
        processing.get('selected_records_without_normalized_events', 0) or
        processing.get('selected_records', 0) < sum(f.get('records', 0) for f in provenance.get('files') or [])
    ):
        flags.add('uploaded_record_coverage_limited')
    meta['degraded_flags'] = sorted(flags)
    if flags:
        meta['status'] = 'incomplete'
    ids = {e.get('uid') or e.get('event_uid'): f'E-{i:04d}' for i, e in enumerate(events, 1)}
    allowed_roles = {'log_analysis', 'network_forensics', 'identity', 'cloud_container',
                     'memory_forensics', 'insider_threat', 'malware_stylometry', 'network_specialist'}
    detections, seen = [], set()
    excluded = 0
    for finding in current_findings(state):
        if finding.get('agent_role') not in allowed_roles:
            continue
        refs = finding.get('dfkg_refs') or []
        if finding.get('source') != 'validated_case_rule' or not refs or not set(refs) <= ids.keys():
            excluded += 1
            continue
        key = (finding.get('finding_type') or finding.get('pattern') or finding.get('summary'), tuple(sorted(refs)))
        if key in seen:
            continue
        seen.add(key)
        detections.append(finding)
    sections = []

    def add(title, paragraphs=(), headers=(), rows=(), widths=None, detail=False):
        sections.append({'title': title, 'paragraphs': list(paragraphs),
                         'headers': headers, 'rows': list(rows), 'widths': widths, 'detail': detail})

    def cites(refs):
        return ', '.join(ids[r] for r in refs if r in ids)

    generated = datetime.now(timezone.utc).isoformat(timespec='seconds')
    title = 'Digital Forensic Examination Report' if kind == 'court' else 'Technical Incident Analysis Report'
    subtitle = 'COURT DRAFT | UNSIGNED' if kind == 'court' else 'INCIDENT RESPONSE | ANALYST REVIEW'
    control = [('Case identifier', state.get('case_id')), ('Report generated (UTC)', generated),
               ('Evidence assessment', meta['status'].capitalize())]
    # Do not fill a report with absent fields, or import expected attack stories as conclusions.
    for label, key in [('Matter', 'case_title'), ('Examiner (declared)', 'examiner_name'),
                       ('Organization (declared)', 'organization'), ('Authority (declared)', 'authority')]:
        if declared.get(key):
            control.append((label, declared[key]))
    summary = [f'The saved case contains {len(events)} verified case-linked records and '
               f'{len(detections)} distinct evidence-cited automated observations. '
               'These observations require examiner validation; they are not confirmed incidents.']
    if declared.get('synthetic') is True:
        summary.insert(0, 'TEST DATA: The submitted metadata identifies this collection as a synthetic validation fixture. '
                       'It does not document an independently verified real-world incident.')
    if excluded:
        summary.append(f'{excluded} uncited or non-rule analytical finding(s) were excluded from the evidentiary observations.')
    valid_times = [timestamp(e) for e in events if timestamp(e)]
    if valid_times:
        summary.append(f'Recorded event times span {valid_times[0]} to {valid_times[-1]}. '
                       'These are source-recorded times, not independently verified activity times.')

    if kind == 'court':
        add('Examination summary', summary)
        add('Scope and authority', [
            'Examination is limited to the preserved records linked to this case. '
            'No conclusion is made about activity outside the supplied evidence.',
            'Examination authority and examiner qualifications must be supplied and verified before submission.'
            if not declared.get('authority') else 'The authority listed above is uploader-declared and has not been independently verified.',
        ])
        receipt = [('Collection source', provenance.get('source')),
                   ('Receipt time (UTC)', provenance.get('received_at')),
                   ('Original archive SHA-256', provenance.get('archive_sha256')),
                   ('Archive size (bytes)', provenance.get('archive_bytes')),
                   ('Recorded custody', provenance.get('custody_status'))]
        add('Evidence received and integrity', [
            'Receipt hashes identify the submitted bytes. They do not independently establish acquisition authenticity '
            'or custody before receipt. The inventory below identifies original submitted files.'
        ], ['Receipt item', 'Recorded value'], receipt, [0.29, 0.71])
        add('Original evidence inventory', (), ['File / records', 'SHA-256 at receipt'], [
            (f"{f.get('path', 'Unnamed file')} ({f.get('records', 'unknown')} records; {f.get('bytes', 'unknown')} bytes)", f.get('sha256'))
            for f in provenance.get('files') or []], [0.42, 0.58])
        add('Examination method', [
            'The system reads saved case-linked records, normalizes supported source fields, and applies recorded '
            'detection rules. This report maps each observation to numbered exhibits. '
            'Model-generated narratives and expected test scenarios are excluded from evidentiary conclusions.',
            'Exhibit hashes identify derived normalized records; original-file hashes are listed separately.'
        ])
        add('Evidence-cited observations', [
            'The following are automated interpretations of supplied records. '
            'A rule match or source-reported alert does not by itself establish malicious intent, successful execution or actor identity.'
        ])
        for i, finding in enumerate(detections, 1):
            add(f'Observation {i}', [finding_summary(finding), f"Exhibits: {cites(finding['dfkg_refs'])}"], detail=True)
        if not detections:
            add('Observation result', ['No supported rule-based detection is available. This does not establish that the examined systems are uncompromised.'])
        # Court readers get a compact source chronology; full fields belong in the technical report.
        add('Exhibit chronology', ['Chronological ordering is descriptive and does not establish causation.'],
            ['Exhibit / recorded time (UTC)', 'Recorded activity'], [
                (f"{ids[e.get('uid') or e.get('event_uid')]} / {timestamp(e) or 'Time unverified'}",
                 '; '.join(f'{k}: {v}' for k, v in observation(e) if k not in {'Host ID', 'Command'}) or f"OCSF class {e.get('class_uid', 'unrecorded')}")
                for e in events], [0.38, 0.62])
    else:
        add('Incident assessment', summary)
        hosts = Counter(text(e.get('host_name') or e.get('canonical_host_id')) for e in events)
        add('Affected systems and telemetry', (), ['Host / recorded identifier', 'Records'], sorted(hosts.items()), [0.78, 0.22])
        add('Telemetry coverage', ['Counts describe the available collection, not complete coverage of the environment.'],
            ['Source / OCSF class', 'Records'], sorted(Counter(f"{e.get('source_type', 'Unspecified')} / {e.get('class_uid', 'Unspecified')}" for e in events).items()), [0.78, 0.22])
        coverage = [(key.replace('_', ' ').capitalize(), value) for key, value in processing.items()
                    if isinstance(value, (int, float, bool))]
        if coverage:
            add('Ingestion coverage', (), ['Measure', 'Recorded value'], coverage, [0.65, 0.35])
        add('Detection analysis', ['Only rule-based observations with references belonging to this case are included below. '
                                    'Severity and operation outcome are recorded assessments, not independent validation.'])
        for i, finding in enumerate(detections, 1):
            add(f"D-{i:03d} | {text(finding.get('finding_type') or finding.get('pattern') or finding.get('agent_role')).replace('_', ' ')}",
                [finding_summary(finding),
                 f"Source: {text(finding.get('agent_role'))} | Severity: {text(finding.get('severity', 'Not assigned'))} | "
                 f"Outcome: {text(finding.get('operation_outcome', 'Unknown'))}",
                 f"Evidence exhibits: {cites(finding['dfkg_refs'])}"], detail=True)
        if not detections:
            add('Detection result', ['No supported rule-based detection is available; review telemetry coverage before drawing conclusions.'])
        add('Evidence timeline and event details', ['All verified case records follow. Commands and addresses are source data, not instructions to execute.'])
        for event in events:
            uid = event.get('uid') or event.get('event_uid')
            add(f"{ids[uid]} | {timestamp(event) or 'Time unverified'}",
                [f"OCSF class: {text(event.get('class_uid'))}"] + [f'{label}: {value}' for label, value in observation(event)], detail=True)
        attribution = state.get('attribution') or {}
        attribution_refs = attribution.get('dfkg_refs') or []
        if attribution.get('candidate_actors'):
            comparison = []
            if attribution_refs and set(attribution_refs) <= ids.keys() and 'corpus_artifacts_unverified' not in flags:
                for actor in attribution['candidate_actors']:
                    score = actor.get('combined_score')
                    if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) and 0 <= score <= 1:
                        comparison.append((actor.get('actor_id'), actor.get('name'), f'{score:.4f}',
                                           ', '.join(actor.get('matched_techniques') or [])))
                meta['threat_intel_refs'] = sorted({r for r in attribution.get('threat_intel_refs') or [] if isinstance(r, str)})
            add('Threat profile comparison', [
                'These are recorded profile-similarity scores, not calibrated probabilities or identification of an attacker. '
                'Matched techniques can occur in unrelated activity and must be checked against original evidence.',
                'Evidence exhibits: ' + cites(attribution_refs) if comparison else 'No fully evidence-bound comparison is available.'
            ], ['Profile ID', 'Profile name', 'Similarity', 'Matched techniques'], comparison, [0.16, 0.24, 0.16, 0.44])
        trace_rows = []
        for trace in current_traces(state):
            if trace.get('agent_role') in {'report_generation', 'timeline_artifact_generation'}:
                continue
            coverage = trace.get('review_coverage') or trace.get('examination_coverage') or {}
            trace_rows.append((trace.get('agent_role'), trace.get('model_used'),
                               'Incomplete' if coverage.get('complete') is False or coverage.get('unavailable', 0) else 'See saved execution record'))
        add('Execution and reproducibility', [
            'This table identifies recorded tools and models. Generated reasoning is retained in the case record and is not reproduced as source evidence.',
            f'Report template: {TEMPLATE}. Historical investigation versions are separate from the current rendering environment.'
        ], ['Role', 'Recorded tool / model', 'Coverage'], trace_rows, [0.26, 0.41, 0.33])
        manifest = state.get('execution_manifest') or {}
        if manifest.get('packages'):
            add('Recorded investigation software', (), ['Package', 'Version'], sorted(manifest['packages'].items()), [0.65, 0.35])
        if manifest:
            add('Execution manifest reference', [
                'The full recorded software manifest and source fingerprints are retained with the saved case. '
                'This SHA-256 identifies its canonical JSON representation, not original evidence bytes.',
                sha256(json.dumps(manifest, sort_keys=True, default=str).encode()).hexdigest(),
            ])
        followup = state.get('evidence_requests') or []
        if followup:
            add('Open evidence requests', ['Requests remain unresolved until acquisition and reanalysis are documented.'],
                ['Request', 'Recorded status'], [(r.get('question') or r.get('reason') or r.get('artifact_type') or 'See saved acquisition request', r.get('status', 'Unresolved'))
                for r in followup if isinstance(r, dict)], [0.75, 0.25])
        add('Analyst follow-up', [
            'Validate the cited observations against original artifacts and confirm collection scope, source clocks and operation outcomes.',
            'Acquire missing telemetry listed in the limitations before deciding whether further containment or remediation is justified. '
            'Record any action taken separately; this report does not assert that remediation occurred.'
        ])

    for run in state.get('sandbox_runs') or []:
        add('Isolated laboratory dynamic examination', [
            'This is a separate guest experiment. Its timestamps and behavior do not establish execution on the investigated host.'
        ], ['Receipt field', 'Value'], [(key.replace('_', ' ').capitalize(), run.get(key))
            for key in ('status', 'report_sha256', 'sample_sha256') if run.get(key) is not None], [0.3, 0.7])
    explanations = {
        'security_screening_degraded': 'Security screening of one or more source records was incomplete.',
        'source_clock_skew_unverified': 'One or more source clocks were not independently verified.',
        'event_time_unavailable': 'Some records have no valid timezone-aware event time and are listed after dated records.',
        'historical_execution_version_not_recorded': 'The saved evidence supplied to this renderer does not record the investigation software version.',
        'additional_evidence_requested': 'Additional evidence has been requested; the current conclusions remain coverage-limited.',
        'agent_review_incomplete': 'Automated review is incomplete; unresolved interpretations require analyst review.',
        'uploaded_record_coverage_limited': 'The selected normalized records do not cover every uploaded source record.',
        'historical_log_analysis_adapter_may_have_discarded_source_fields': 'The historical log-analysis adapter may have omitted source fields needed for detection; absence of a match is unreliable.',
        'no_verified_case_evidence': 'No verified case-linked records are available.',
    }
    limitations = [explanations.get(flag, flag.replace('_', ' ').capitalize() + '.') for flag in sorted(flags)]
    limitations.append('Source alerts and inferred associations are not independent proof of actor identity, intent or causation. '
                       'Missing evidence is not a negative finding.')
    add('Limitations', limitations)
    add('Evidence reference register', ['Exhibit IDs are local to this document. SHA-256 values below identify normalized record JSON, not original source files.'],
        ['Exhibit / source UID', 'Normalized record SHA-256'], [
            (f"{ids[e.get('uid') or e.get('event_uid')]} / {e.get('uid') or e.get('event_uid')}",
             sha256(json.dumps(e, sort_keys=True, default=str).encode()).hexdigest()) for e in events], [0.52, 0.48])
    if kind == 'court':
        add('Examiner declaration and review', [
            'UNSIGNED DRAFT. NOT CERTIFIED for submission. No expert opinion, qualification, signature or admissibility decision is generated by this system.',
            'Examiner: ____________________    Qualifications: ____________________',
            'Signature / date: ____________________',
            'Independent reviewer / date: ____________________',
        ])
    return {'title': title, 'subtitle': subtitle, 'control': control, 'sections': sections}, {
        **meta, 'kind': kind, 'template': TEMPLATE, 'document_generated_at': generated,
        'submission_readiness': 'review_required' if kind == 'court' else 'not_applicable',
        'observation_count': len(detections), 'excluded_analysis_count': excluded,
    }


def render_html(state, kind):
    """Compact checkpoint companion; browser downloads use render_pdf instead."""
    content, meta = report_content(state, kind)
    def safe(value):
        return escape(text(value))
    def table(headers, rows):
        return '<table><thead><tr>' + ''.join(f'<th>{safe(h)}</th>' for h in headers) + '</tr></thead><tbody>' + ''.join(
            '<tr>' + ''.join(f'<td>{safe(cell)}</td>' for cell in row) + '</tr>' for row in rows) + '</tbody></table>'
    body = table(['Document control', 'Value'], content['control'])
    number = 0
    for section in content['sections']:
        if not section['detail']:
            number += 1
        level = 'h3' if section['detail'] else 'h2'
        label = section['title'] if section['detail'] else f"{number}. {section['title']}"
        body += f"<{level}>{safe(label)}</{level}>" + ''.join(f'<p>{safe(p)}</p>' for p in section['paragraphs'])
        if section['headers']:
            body += table(section['headers'], section['rows'])
    document = '<!doctype html><html lang="en"><meta charset="utf-8"><title>' + safe(content['title']) + '</title><body><h1>' + safe(content['title']) + '</h1><p>' + safe(content['subtitle']) + '</p>' + body + '<footer>End of report</footer></body></html>'
    return document, {**meta, 'document_sha256': sha256(document.encode()).hexdigest()}


def render_pdf(state, kind):
    from pathlib import Path
    import reportlab
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle, KeepTogether

    content, meta = report_content(state, kind)
    font_dir = Path(reportlab.__file__).parent / 'fonts'
    for name, filename in [('Specula', 'Vera.ttf'), ('Specula-Bold', 'VeraBd.ttf')]:
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(font_dir / filename)))
    pdfmetrics.registerFontFamily('Specula', normal='Specula', bold='Specula-Bold')
    navy = colors.HexColor('#19324b')
    body = ParagraphStyle('Body', fontName='Specula', fontSize=9, leading=14, textColor=colors.HexColor('#263445'),
                          spaceAfter=8, splitLongWords=True, alignment=TA_LEFT)
    cell = ParagraphStyle('Cell', parent=body, fontSize=8, leading=11.5, spaceAfter=0)
    heading = ParagraphStyle('Heading', parent=body, fontName='Specula-Bold', fontSize=12, leading=16,
                             textColor=navy, spaceBefore=15, spaceAfter=8, keepWithNext=True)
    subheading = ParagraphStyle('Subheading', parent=heading, fontSize=9.5, leading=14, spaceBefore=9, spaceAfter=4)
    detail_body = ParagraphStyle('Detail', parent=body, spaceAfter=3)
    title_style = ParagraphStyle('Title', parent=heading, fontSize=24, leading=30, spaceBefore=12, spaceAfter=12)
    small = ParagraphStyle('Small', parent=body, fontSize=8, leading=12)
    story = []
    def paragraph(value, style=body):
        return Paragraph(escape(text(value)).replace('\n', '<br/>'), style)
    def table(headers, rows, widths):
        data = [[paragraph(h, cell) for h in headers]]
        data += [[paragraph(value, cell) for value in row] for row in rows]
        if not rows:
            story.append(paragraph('No entries recorded.'))
            return
        width = A4[0] - 100
        flow = LongTable(data, colWidths=[width * x for x in widths], repeatRows=1,
                         hAlign='LEFT', splitByRow=1, splitInRow=1)
        flow.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e6edf3')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f7f9')]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LINEBELOW', (0, 0), (-1, 0), 0.6, navy),
            ('LINEBELOW', (0, 1), (-1, -1), 0.3, colors.HexColor('#d9e1e8')),
            ('LEFTPADDING', (0, 0), (-1, -1), 8), ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 7), ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ]))
        story.append(flow)
        story.append(Spacer(1, 8))
    story.extend([paragraph('SPECULA  /  DIGITAL FORENSICS', small), paragraph(content['title'], title_style),
                  paragraph(content['subtitle'], heading)])
    table(['Document control', 'Value'], content['control'], [0.3, 0.7])
    number = 0
    for section in content['sections']:
        if not section['detail']:
            number += 1
        label = section['title'] if section['detail'] else f"{number:02d}  {section['title']}"
        block = [paragraph(label, subheading if section['detail'] else heading)]
        block.extend(paragraph(p, detail_body if section['detail'] else body) for p in section['paragraphs'])
        if section['detail']:
            story.append(KeepTogether(block))
        else:
            story.extend(block)
        if section['headers']:
            count = len(section['headers'])
            table(section['headers'], section['rows'], section['widths'] or [1 / count] * count)
    story.append(paragraph('End of report', small))
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=58, bottomMargin=55,
                            title=content['title'], author='Specula', pageCompression=1)
    def frame(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor('#c6d2dd'))
        canvas.line(50, 40, A4[0] - 50, 40)
        canvas.setFillColor(navy)
        canvas.setFont('Specula', 7)
        canvas.drawString(50, A4[1] - 31, 'SPECULA | ' + ('COURT DRAFT' if kind == 'court' else 'TECHNICAL ANALYSIS'))
        canvas.drawString(50, 27, 'Case ' + text(state.get('case_id')))
        canvas.drawRightString(A4[0] - 50, 27, f'Page {document.page}')
        canvas.restoreState()
    doc.build(story, onFirstPage=frame, onLaterPages=frame)
    document = buffer.getvalue()
    return document, {**meta, 'document_sha256': sha256(document).hexdigest()}
