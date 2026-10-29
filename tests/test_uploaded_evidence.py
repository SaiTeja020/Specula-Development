"""Archive trust boundaries and report evidentiary separation."""
from hashlib import sha256
from io import BytesIO
import json
import stat
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from fastapi.testclient import TestClient
import pytest

from src.ingestion.upload_archive import validate_archive
from src.agents.examination_reports import render_examination_report


def archive(files):
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as zip_file:
        for name, payload in files:
            zip_file.writestr(name, payload)
    return buffer.getvalue()


def test_original_archive_and_file_hashes():
    payload = b'{"Id":4688}\n{"Id":4624}\n'
    data = archive([("windows/security.jsonl", payload), ("manifest.json", b'{"examiner_name":"Declared"}')])
    receipt = validate_archive(data)
    assert receipt["archive_sha256"] == sha256(data).hexdigest()
    assert receipt["files"][0]["sha256"] == sha256(payload).hexdigest()
    assert receipt["files"][0]["records"] == 2
    assert receipt["files"][0]["source_type"] == "evtx"


@pytest.mark.parametrize("name", ["../windows/a.json", "/windows/a.json", "C:/a.json",
    "windows/../a.json", "windows\\a.json", "windows/a.exe", "wrapper/windows/a.json"])
def test_unsafe_or_unsupported_archive_entries_rejected(name):
    entry = ZipInfo(name)
    entry.filename = name  # Preserve raw ZIP separators even on Windows.
    with pytest.raises(ValueError):
        validate_archive(archive([(entry, b'{}')]))


def test_symlink_duplicate_and_bomb_rejected():
    link = ZipInfo("windows/link.json")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    for data in (archive([(link, b'{}')]),
                 archive([("windows/A.json", b'{}'), ("windows/a.json", b'{}')]),
                 archive([("windows/a.json", b' ' * (2 * 1024 * 1024))])):
        with pytest.raises(ValueError):
            validate_archive(data)


def test_invalid_record_json_rejected():
    for payload in (b'[1,2]', b'{oops', b'[]'):
        with pytest.raises(ValueError):
            validate_archive(archive([("windows/a.json", payload)]))


def test_raw_upload_preserves_receipt_before_scheduled_ingestion(monkeypatch, tmp_path):
    from scripts import local_boot_api as controller
    monkeypatch.setattr(controller, "ROOT", tmp_path)
    monkeypatch.setattr(controller, "_case_job", None)
    monkeypatch.setattr(controller, "_job", None)

    async def execute(job, *args):
        job["phase"] = "complete"
    monkeypatch.setattr(controller, "_execute_case", execute)
    data = archive([("windows/a.json", b'{"Id":4688}')])
    with TestClient(controller.app, client=("127.0.0.1", 1234)) as client:
        response = client.post("/api/local/investigations/upload", content=data,
            headers={"Origin": "http://localhost:5173", "X-Specula-Local-Boot": "1", "Content-Type": "application/zip"})
    assert response.status_code == 202
    directory = tmp_path / "data" / "uploads" / response.json()["case_id"]
    assert (directory / "evidence.zip").read_bytes() == data
    assert json.loads((directory / "receipt.json").read_text())["archive_sha256"] == sha256(data).hexdigest()


def test_dual_reports_escape_inputs_and_do_not_certify_admissibility():
    state = {"case_id": "LOCAL-test", "case_status": "closed", "report_generated_at": "2026-10-12T10:00:00+00:00",
             "evidence_collection": {"case_id": "LOCAL-test", "status": "complete", "records": [
                 {"uid": "e1", "time": "2026-10-12T09:00:00+00:00", "class_uid": 1007, "process_name": '<script>alert(1)</script>'}]},
             "findings": [{"agent_role": "dag", "summary": "UNVERIFIED-MODEL-CLAIM", "dfkg_refs": []}]}
    court, metadata = render_examination_report(state, "court")
    technical, technical_meta = render_examination_report(state, "technical")
    assert '<script>' not in court and '&lt;script&gt;' in court
    assert "UNVERIFIED-MODEL-CLAIM" not in court
    assert "UNVERIFIED-MODEL-CLAIM" not in technical
    assert 'Detection analysis' in technical and 'Examiner declaration' not in technical
    assert 'Examiner declaration' in court and 'Execution and reproducibility' not in court
    assert "NOT CERTIFIED" in court and "UNSIGNED" in court
    assert metadata["submission_readiness"] == "review_required"
    assert metadata["document_sha256"] == sha256(court.encode()).hexdigest()
    assert technical_meta["document_sha256"] != metadata["document_sha256"]


def test_case_log_adapter_preserves_fields_needed_by_detection_rules():
    from src.agents.log_analysis_factory import CaseLogRecord
    from src.agents.log_analysis.detection_rules import _rule_unusual_parent, load_signatures
    event = CaseLogRecord(trace_id="t", uid="e", activity_id=1, category_uid=1, class_uid=1007,
        severity_id=2, time="2026-10-12T09:00:00+00:00", raw_source_timestamp="2026-10-12T09:00:00Z",
        process_name="powershell.exe", parent_process_name="winword.exe", command_line="powershell.exe -enc test")
    assert event.command_line == "powershell.exe -enc test"
    assert _rule_unusual_parent(event, load_signatures()) is not None
    event.parent_process_name = r"C:\Program Files\Office\WINWORD.EXE"
    event.process_name = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert _rule_unusual_parent(event, load_signatures()) is not None


def test_windows_export_normalizer_retains_sysmon_process_identity():
    from src.ingestion.normalization.evtx_normalizer import normalize_evtx_process_creation
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    from src.schemas.entity_resolver import CanonicalEntityResolver
    event = normalize_evtx_process_creation({"Id": 1, "ProviderName": "Microsoft-Windows-Sysmon",
        "MachineName": "fixture", "TimeCreated": "2026-10-12T09:00:00+00:00",
        "EventData": {"Image": r"C:\Windows\powershell.exe", "ParentImage": r"C:\Office\winword.exe",
                      "ProcessId": "123", "ParentProcessId": "45"}},
        TimeNormalizer(dc_anchor_skew_ms=0), CanonicalEntityResolver(), "fixture-trace")
    assert event.process_name == r"C:\Windows\powershell.exe"
    assert event.parent_process_name == r"C:\Office\winword.exe"
    assert event.process_pid == 123 and event.parent_process_pid == 45


def test_uploaded_sources_dates_and_provenance_reach_shared_ingestion(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from scripts.local_case_pipeline import ingest_uploaded_case
    from src.ingestion import run_pipeline
    from src.ingestion.preservation.quickwit_client import QuickwitClient
    from src.graph.neo4j_client import Neo4jClient
    calls, writes = [], []
    payload = archive([
        ("windows/a.json", json.dumps([{"Id": 4688, "TimeCreated": "2026-10-12T09:00:00+00:00"},
                                      {"Id": 4688, "TimeCreated": "2026-10-12T11:00:00+00:00"}])),
        ("edr/a.json", json.dumps({"TimeCreated": "2026-10-12T09:10:00+00:00"})),
    ])
    receipt = validate_archive(payload)
    path = tmp_path / "evidence.zip"
    path.write_bytes(payload)

    class Graph:
        def execute(self, query, params):
            writes.append((query, params))
            return []
        def close(self):
            pass

    def normalize(raw, *args, **kwargs):
        calls.append((raw, kwargs))
        event = SimpleNamespace(uid=kwargs["source_type"], model_dump=lambda mode: {
            "uid": kwargs["source_type"], "case_id": kwargs["case_id"], "time": raw["TimeCreated"]})
        return [(SimpleNamespace(valid=True, event=event), "merge", [])]

    monkeypatch.setattr(run_pipeline, "run_pipeline_on_event", normalize)
    monkeypatch.setattr("src.ingestion.preservation.quickwit_client.QuickwitClient",
                        lambda: SimpleNamespace(ensure_index=lambda: None))
    monkeypatch.setattr("src.graph.neo4j_client.Neo4jClient", Graph)
    monkeypatch.setattr("src.graph.process_lineage.persist_lineage",lambda *a:{"resolved":0})
    monkeypatch.setattr("src.ingestion.indexing.case_evidence.CaseEvidenceIndex",lambda:SimpleNamespace(index=lambda *a:{"status":"verified"}))
    monkeypatch.setattr("src.agents.case_analytics.write_case_analytics",lambda *a:{"status":"verified"})
    monkeypatch.setattr("src.ingestion.broker.case_stream.publish_normalized_case",lambda *a:{"status":"verified"})
    result = ingest_uploaded_case("LOCAL-fixture", path, receipt, "2026-10-12T08:00:00+00:00",
                                 "2026-10-12T10:00:00+00:00", 1, [443])
    assert result["accepted"] == 2
    assert [kwargs["source_type"] for _, kwargs in calls] == ["evtx", "edr"]
    assert all(kwargs["exclude_ports"] == {443} for _, kwargs in calls)
    recorded = json.loads(writes[-1][1]["provenance"])
    assert recorded["archive_sha256"] == sha256(payload).hexdigest()
    assert recorded["processing"]["selected_records"] == 2
