"""Formal printable examination artifacts grounded in saved case evidence."""
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import html
import json
from pathlib import Path
import platform
from importlib.metadata import PackageNotFoundError, version

from .grounded_report import _prepared, _utc


def runtime_manifest():
    fingerprints = {}
    for relative in ("src/agents/examination_reports.py", "src/agents/grounded_report.py",
                     "src/ingestion/run_pipeline.py", "src/agents/log_analysis_factory.py",
                     "src/agents/log_analysis/detection_rules.py"):
        path = Path(__file__).resolve().parents[2] / relative
        if path.is_file():
            fingerprints[relative] = sha256(path.read_bytes()).hexdigest()
    packages = {}
    for name in ("langgraph", "neo4j", "pydantic", "fastapi"):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = "not installed"
    return {"python": platform.python_version(), "packages": packages, "source_sha256": fingerprints}


def _text(value):
    return html.escape(str(value if value is not None else "Not recorded"), quote=True)


def _json(value):
    return '<pre>' + _text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str)) + '</pre>'


def _table(headers, rows):
    return '<table><thead><tr>' + ''.join('<th>' + _text(h) + '</th>' for h in headers) + \
        '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + _text(v) + '</td>' for v in row) + '</tr>'
                                      for row in rows) + '</tbody></table>'


def render_examination_report(state: dict, kind: str) -> tuple[str, dict]:
    if kind not in {"court", "technical"}:
        raise ValueError("Unknown report type")
    events, meta = _prepared(state)
    flags = set(meta["degraded_flags"])
    if not state.get("execution_manifest"):
        flags.add("historical_execution_version_not_recorded")
    if any(e.get("clock_skew_unverified") for e in events):
        flags.add("source_clock_skew_unverified")
    if any(e.get("security_scan_degraded") for e in events):
        flags.add("security_screening_degraded")
    if any(t.get("agent_role") == "log_analysis" and t.get("model_used") == "hybrid_rules_and_llm"
           for t in state.get("agent_traces") or []):
        flags.add("historical_log_analysis_adapter_may_have_discarded_source_fields")
    meta["degraded_flags"] = sorted(flags)
    if flags:
        meta["status"] = "incomplete"
    events.sort(key=lambda e: (_utc(e.get("time")) or "9999", str(e.get("uid"))))
    provenance = state.get("ingestion_provenance") or {}
    processing = provenance.get("processing") or {}
    if provenance.get("source") == "uploaded_zip" and (
            processing.get("selected_records_without_normalized_events", 0) or
            processing.get("selected_records", 0) < sum(f.get("records", 0) for f in provenance.get("files") or [])):
        meta["degraded_flags"] = sorted(set(meta["degraded_flags"]) | {"uploaded_record_coverage_limited"})
        meta["status"] = "incomplete"
    declared = provenance.get("declared_metadata") or {}
    now = datetime.now(timezone.utc).isoformat()
    verified_uids = set(meta["dfkg_refs"])
    supported = [f for f in state.get("findings") or []
                 if f.get("agent_role") in {"log_analysis", "network_forensics"} and
                 f.get("dfkg_refs") and set(f["dfkg_refs"]) <= verified_uids]
    input_digest = sha256(json.dumps({"case_id": state.get("case_id"), "events": events,
        "provenance": provenance}, sort_keys=True, default=str).encode()).hexdigest()
    title = "Digital Forensic Examination Report" if kind == "court" else "Technical Incident Examination Report"
    subtitle = "COURT SUBMISSION DRAFT — EXAMINER REVIEW REQUIRED" if kind == "court" else "CYBER DEFENSE / INCIDENT RESPONSE"
    sections = []

    def section(title, content):
        sections.append('<section><h2>' + _text(f'{len(sections) + 1}. {title}') + '</h2>' + content + '</section>')

    section("Mandate, scope and document control", _table(["Field", "Recorded value"], [
        ("Case identifier", state.get("case_id")), ("Declared matter/title", declared.get("case_title")),
        ("Declared examiner", declared.get("examiner_name")), ("Declared organization", declared.get("organization")),
        ("Declared examination authority", declared.get("authority")),
        ("Investigation start (UTC)", state.get("report_generated_at")), ("Document generated (UTC)", now),
        ("Evidence completeness", meta["status"]), ("Normalized snapshot SHA-256", input_digest),
    ]) + '<p>Scope is limited to the preserved records linked to this case. Supplied metadata is declarative. '
          'No conclusion about activity outside this collection window or unsupported log types is made.</p>')
    section("Executive examination result", f'<p>{len(events)} normalized evidence records and '
            f'{len(supported)} evidence-cited detection findings were available. '
            'An absence of supported detections does not establish that a device is uncompromised.</p>' +
            _table(["Measure", "Value"], [("Case state", state.get("case_status")),
            ("Acceptance status", state.get("acceptance_status")),
            ("Earliest recorded event", _utc(events[0].get("time")) if events else None),
            ("Latest recorded event", _utc(events[-1].get("time")) if events else None),
            ("Executed agent steps", len(state.get("agent_traces") or []))]))
    section("Evidence receipt, integrity and custody", _table(["Item", "Recorded value"], [
        ("Collection source", provenance.get("source", "Historical local collection; receipt metadata unavailable")),
        ("Original archive SHA-256", provenance.get("archive_sha256")),
        ("Archive byte length", provenance.get("archive_bytes")),
        ("Receipt time (UTC)", provenance.get("received_at")),
        ("Custody scope", provenance.get("custody_status", "Prior custody and acquisition not documented")),
    ]) + _table(["Original file", "Bytes", "SHA-256", "Record count"], [
        (f.get("path"), f.get("bytes"), f.get("sha256"), f.get("records")) for f in provenance.get("files") or []
    ]) + '<p>Original archive/file hashes identify bytes at receipt. Normalized record hashes identify derived data. '
          'They do not prove authenticity at acquisition, independent custody verification or legal admissibility. '
          'Hash verification on every subsequent transfer remains a reviewer responsibility.</p>' +
          '<h3>Uploader-declared acquisition and custody</h3>' + _json(declared))
    current_manifest = runtime_manifest()
    section("Methods and reproducibility", '<ol><li>Preserve submitted bytes and inventory original files.</li>'
            '<li>Apply security screening and supported source normalization to OCSF records with deterministic UIDs.</li>'
            '<li>Read case-linked evidence; apply deterministic triage and supported detection rules.</li>'
            '<li>Record model-assisted synthesis and debate as analysis requiring verification.</li>'
            '<li>Render factual exhibits from saved structured records and retain incompleteness flags.</li></ol>' +
            _table(["Runtime", "Version"], [("Python", platform.python_version()), ("Report template", "specula-examination-v1")]) +
            '<h3>Source files measured at investigation start</h3>' + _json(state.get("execution_manifest")) +
            '<h3>Current report-rendering environment</h3>' + _json(current_manifest) +
            '<p>Current source fingerprints do not prove which source version executed a historical investigation.</p>' +
            '<p>Timestamp conversion does not independently verify source clocks. Local evidence hashing and '
            'storage do not establish Hyperledger Fabric anchoring. Model outputs are not admitted as measured evidence.</p>')
    if kind == "court":
        section("Rule 702 and Daubert review record", '<p>Submission readiness: <strong>NOT CERTIFIED — HUMAN REVIEW REQUIRED</strong>. '
                'This automated draft is not an expert qualification, attestation or judicial admissibility finding.</p>' +
                _table(["Review factor", "Current evidence / gap"], [
                    ("Qualified expert and helpfulness (Rule 702)", "Examiner qualifications, relevance and opinion scope require documented expert review."),
                    ("Sufficient facts and reliable application (Rule 702)", "Case exhibits and limitations are listed; sufficiency and reliable application require review."),
                    ("Testability and validation", "Reproducible component fingerprints included; case-specific independent validation evidence not attached."),
                    ("Peer review / publication", "No independent peer-review evidence for this complete system recorded."),
                    ("Known or potential error rate", "No validated system sensitivity, specificity, false-positive or false-negative rate recorded."),
                    ("Operational standards", "OCSF mapping and deterministic IDs used; laboratory accreditation and SOP compliance not established."),
                    ("General acceptance", "Not established by use of SHA-256, OCSF or an LLM alone."),
                    ("Custody and authenticity", "Receipt hashes are documented when available; earlier acquisition/custody declarations require verification."),
                ]) + '<p>Authorities: <a href="https://www.uscourts.gov/sites/default/files/document/federal-rules-of-evidence.pdf">'
                'Federal Rules of Evidence, Rule 702 (December 1, 2025)</a>; Daubert v. Merrell Dow Pharmaceuticals, '
                '509 U.S. 579 (1993). Applicable jurisdiction and evidentiary procedure must be confirmed by counsel.</p>')
    section("Recorded automated detection results", '<p>Automated screening results require examiner validation. '
            'Citations establish record membership, not independent correctness of an inference.</p>' +
            (''.join('<article><h3>' + _text(f.get("agent_role")) + '</h3><p>' +
            (_text(f.get("summary")) if kind == "technical" else _text({
                "finding_type": f.get("finding_type"), "severity_id": f.get("severity_id"), "attacks": f.get("attacks")})) +
            '</p><p>Evidence references: ' + _text(', '.join(f["dfkg_refs"])) + '</p></article>'
            for f in supported) or '<p>No supported detection finding is available. This is a coverage-limited result.</p>')
            )
    section("Event chronology and exhibit index", '<p>Exhibit hashes below identify normalized JSON, not original source-file bytes.</p>' +
        _table(["Exhibit / UID", "Time (UTC)", "OCSF class", "Recorded observation", "Normalized JSON SHA-256"], [
        (f"E-{i + 1:05d} / {e.get('uid')}", _utc(e.get("time")), e.get("class_uid"),
         e.get("process_name") or e.get("host_name") or e.get("finding_info") or "Normalized event",
         sha256(json.dumps(e, sort_keys=True, default=str).encode()).hexdigest())
        for i, e in enumerate(events)]))
    if kind == "technical":
        section("Telemetry coverage and ingestion diagnostics", _json({"class_counts": dict(Counter(str(e.get("class_uid")) for e in events)),
                "selection": provenance.get("selection"), "processing": provenance.get("processing"),
                "triage": (state.get("evidence_collection") or {}).get("triage"),
                "guardrails": {k: state.get(k) for k in ("guardrail_tier1_result", "guardrail_tier2_result", "guardrail_tier3_result", "hitl_decision")}}))
        section("Agent execution, synthesis and hypotheses", '<p>Model-generated hypotheses and attack-path prose are unverified unless '
                'supported by independently checked evidence. No structured exploit path is certified by prose.</p>' +
                _json({"agent_traces": state.get("agent_traces") or [],
                       "findings": [f for f in state.get("findings") or [] if f.get("agent_role") not in {"report_generation", "timeline_artifact_generation"}],
                       "attribution": state.get("attribution"), "timeline": state.get("timeline")}))
        section("Normalized evidence appendix", _json(events))
        section("Cyber-team follow-up", '<ol><li>Review cited raw artifacts and confirm source clock/custody assumptions.</li>'
                '<li>Validate detections against additional endpoint/network telemetry and document counter-evidence.</li>'
                '<li>Confirm indicators and scope before containment or remediation.</li>'
                '<li>Re-run with missing telemetry and retain the input hashes, selections and software fingerprints.</li></ol>')
    section("Limitations and alternative explanations", _json(meta["degraded_flags"]) +
            '<p>Unsupported records, source selection, excluded ports and missing telemetry can reduce coverage. '
            'Model inference, attribution similarity and event ordering do not establish actor identity, intent or causality. '
            'Collection integrity and error rates require independent validation.</p>')
    section("Examiner and independent reviewer approval", '<p>Examiner name / qualifications: ______________________________</p>'
            '<p>Scope and methods reviewed: ______________________________</p>'
            '<p>Examiner signature / date: ______________________________</p>'
            '<p>Independent reviewer signature / date: ______________________________</p>'
            '<p>Approval status: UNSIGNED. No signature or certification is generated by this system.</p>')
    style = """@page{size:A4;margin:22mm 18mm}*{box-sizing:border-box}body{font:11pt/1.55 Georgia,serif;color:#182230;background:#eef1f5;margin:0}main{background:white;max-width:210mm;margin:24px auto;padding:22mm 18mm;box-shadow:0 2px 20px #ccd}header{border-bottom:3px solid #203550;padding-bottom:18px}.brand{font:700 10pt Arial;letter-spacing:3px;color:#203550}h1{font-size:26pt;line-height:1.2}h2{font-size:15pt;border-bottom:1px solid #aab;padding-bottom:6px;margin-top:28px;break-after:avoid}h3{font-size:12pt;break-after:avoid}.status{font:700 10pt Arial;color:#70441c}table{border-collapse:collapse;width:100%;font:9pt/1.45 Arial;margin:12px 0;table-layout:fixed}td,th{border:1px solid #aab;padding:7px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#e9eef4}thead{display:table-header-group}tr{break-inside:avoid}pre{font:8pt/1.5 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f9;padding:10px}footer{margin-top:32px;border-top:1px solid #aab;font:9pt Arial;padding-top:12px}@media print{body{background:white}main{margin:0;padding:0;max-width:none;box-shadow:none}a{color:inherit;text-decoration:none}header{break-inside:avoid}}"""
    document = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + _text(title) + '</title><style>' + style + '</style></head><body><main><header><div class="brand">SPECULA • DIGITAL FORENSIC EXAMINATION</div><h1>' + title + '</h1><p class="status">' + subtitle + '</p><p>Case ' + _text(state.get("case_id")) + '</p></header>' + ''.join(sections) + '<footer>Specula examination template v1 • Case ' + _text(state.get("case_id")) + ' • End of report</footer></main></body></html>'
    return document, {**meta, "kind": kind, "document_generated_at": now,
                      "document_sha256": sha256(document.encode()).hexdigest(),
                      "submission_readiness": "review_required" if kind == "court" else "not_applicable"}
