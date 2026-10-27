from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from src.ingestion.export_aliases import adapt_export, record_timestamp

STAMP = "2026-10-13T09:00:00Z"


def test_native_windows_computer_is_a_source_host():
    raw = {"System": {"EventID": 1102, "Computer": "APP-03", "TimeCreated": {"SystemTime": STAMP},
                      "Provider": {"Name": "Microsoft-Windows-Security-Auditing"}}}
    assert adapt_export(raw, "evtx", "windows/Security.json")["host_name"] == "APP-03"


def test_gcp_flat_aliases_preserve_original_and_native_fields():
    raw = {"timestamp": STAMP, "resource": "projects/test/key", "method": "CreateKey",
           "project_id": "test", "principal_email": "examiner@example.test", "caller_ip": "192.0.2.1"}
    before = deepcopy(raw)
    mapped = adapt_export(raw, "gcp_audit")
    assert raw == before
    assert mapped["resource"]["labels"]["project_id"] == "test"
    assert mapped["protoPayload"]["methodName"] == "CreateKey"
    raw["protoPayload"] = {"methodName": "NativeMethod"}
    assert adapt_export(raw, "gcp_audit")["protoPayload"]["methodName"] == "NativeMethod"


@pytest.mark.parametrize("raw", [{}, {"timestamp": "2026-10-13"}, {"timestamp": "invalid"}])
def test_missing_or_ambiguous_time_is_not_inferred(raw):
    with pytest.raises(ValueError, match="timestamp|Timestamp"):
        adapt_export(raw, "malware")


def test_ueba_normal_observation_is_not_promoted_to_anomaly():
    result = adapt_export({"timestamp": STAMP, "event": "login", "baseline_status": "normal"}, "ueba")
    assert result["verdict"] == "normal" and result["severity_id"] == 1
    assert result["confidence"] == "Unspecified"


def test_mft_memory_and_vulnerability_aliases():
    mft = adapt_export({"standard_information_modified": STAMP, "path": r"C:\evidence\file.txt",
                        "standard_information_created": STAMP}, "mft")
    assert mft["FileName"] == "file.txt" and mft["Created0x10"] == STAMP
    assert record_timestamp(mft, "mft") == STAMP
    memory = adapt_export({"timestamp": STAMP, "process": "example.exe", "pid": 42}, "memory")
    assert memory["ImageFileName"] == "example.exe" and memory["PID"] == 42
    assert adapt_export({"scan_time": STAMP, "cvss": 7.5}, "vuln_scan")["cvss_score"] == 7.5


def test_pipeline_preserves_original_before_mapping_and_filters_flat_ports(monkeypatch):
    from src.ingestion import run_pipeline
    from src.ingestion.normalization import evtx_normalizer
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.schemas.entity_resolver import CanonicalEntityResolver
    from src.ingestion.normalization.time_normalizer import TimeNormalizer

    monkeypatch.setattr(run_pipeline, "run_security_gate", lambda *args: SimpleNamespace(injection_blocked=False))
    monkeypatch.setattr(evtx_normalizer, "detect_prompt_injection", lambda *args: (False, True))
    preserved = []
    quickwit = SimpleNamespace(commit_raw_evidence=lambda **values: preserved.append(values))
    raw = {"timestamp": STAMP, "event_id": 1, "host": "fixture", "image": "powershell.exe",
           "parent_image": "explorer.exe", "command_line": "powershell.exe -File test.ps1"}
    before = deepcopy(raw)
    result = run_pipeline.run_pipeline_on_event(raw, VCTAtomicChain(), CanonicalEntityResolver(),
        TimeNormalizer(None), qw_client=quickwit, source_type="evtx", exported_log_path="windows/Sysmon.jsonl")
    assert json.loads(preserved[0]["raw_bytes"]) == before and raw == before
    assert result[0][0].valid and result[0][0].event.process_name == "powershell.exe"
    network = {"timestamp": STAMP, "event_type": "network_connection", "destination_ip": "192.0.2.2",
               "destination_port": 443, "bytes_sent": 8192}
    mapped_network = run_pipeline.run_pipeline_on_event(network, VCTAtomicChain(), CanonicalEntityResolver(),
        TimeNormalizer(None), source_type="edr", exported_log_path="edr/events.jsonl")
    assert mapped_network[0][0].event.bytes_out == 8192
    assert run_pipeline.run_pipeline_on_event(network, VCTAtomicChain(), CanonicalEntityResolver(),
        TimeNormalizer(None), source_type="edr", exported_log_path="edr/events.jsonl", exclude_ports={443}) == []
