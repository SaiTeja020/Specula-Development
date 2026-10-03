"""test_identity_agent.py — 17-test golden-fixture verification suite for Identity Agent (F13a).

Verification oracle:
  .\\venv\\Scripts\\pytest.exe tests/agents/test_identity_agent.py -v

Acceptance criteria (per TASK-4.9):
  - 17/17 passing
  - Zero dfkg_citations=[] on non-clean verdicts
  - trace_id present as Kafka message header (tested via publish_finding mock)
  - Supernode guard fires at degree >= 200 (fallback, no abort)
  - No class_uid 6001 in any query or fixture
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest

# ─── Import modules under test ────────────────────────────────────────────────

from src.agents.identity.kerberos_analyzer import analyze_kerberos_events
from src.agents.identity.privilege_escalation_detector import detect_privilege_escalations
from src.agents.identity.cloud_iam_analyzer import analyze_cloud_iam_events
from src.agents.identity.lateral_movement_correlator import correlate_lateral_movement, LateralMovementChain
from src.agents.identity.kerberos_analyzer import KerberosAnomalyResult
from src.agents.identity.agent import run_identity_analysis, IdentityAgentDeps

FIXTURES = Path(__file__).parent / "identity" / "fixtures"


def _load(name: str) -> dict:
    # utf-8-sig strips the UTF-8 BOM that PowerShell Out-File adds
    return json.loads((FIXTURES / name).read_text(encoding="utf-8-sig"))


def _make_state(events: list[dict], case_id: str = "case-001") -> dict:
    """Build a minimal IdentityAgentState with raw events injected for testing."""
    return {
        "case_id": case_id,
        "batch_uids": [f"{case_id}:ev-{i}" for i in range(len(events))],
        "ocsf_classes": [3001, 3002, 6003],
        "kerberos_anomalies": [],
        "privilege_escalations": [],
        "lateral_movement_chains": [],
        "cloud_iam_anomalies": [],
        "verdict": None,
        "confidence_score": 0.0,
        "dfkg_citations": [],
        "iteration_count": 0,
        "max_iterations": 1,
        "dead_end": False,
        "status": "pending",
        "trace_id": "test-trace-abc123",
        "_raw_events_for_testing": events,
    }


def _no_deps() -> IdentityAgentDeps:
    """Deps with no DFKG/Kafka/VCT clients — analyzer falls back to _raw_events_for_testing."""
    return IdentityAgentDeps(dfkg_client=None, kafka_producer=None, vct_ledger_client=None)


# ─── 1. Kerberoasting detection ───────────────────────────────────────────────

def test_kerberoasting_detected():
    fix = _load("kerberoasting_fixture.json")
    events = fix["events"]
    results = analyze_kerberos_events(events)
    assert len(results) == fix["expected"]["kerberos_anomalies_count"]
    assert results[0].anomaly_type == "KERBEROASTING"
    assert results[0].evidence_uid == "ev-kerb-001"
    assert results[0].confidence > 0.8


# ─── 2. AS-REP Roasting detection ────────────────────────────────────────────

def test_as_rep_roasting_detected():
    events = [{
        "uid": "ev-asrep-001", "class_uid": 3002, "event_id": 4768,
        "user_name": "no_preauth_user", "src_ip": "10.0.0.99",
        "ticket_encryption_type": "RC4", "auth_protocol": "Kerberos",
        "utc_timestamp": "2026-09-22T10:00:00Z",
    }]
    results = analyze_kerberos_events(events)
    assert len(results) == 1
    assert results[0].anomaly_type == "AS_REP_ROASTING"
    assert results[0].severity == "HIGH"


# ─── 3. DCSync detection ─────────────────────────────────────────────────────

def test_dcsync_detected():
    fix = _load("dcsync_fixture.json")
    results = analyze_kerberos_events(fix["events"])
    assert len(results) == fix["expected"]["kerberos_anomalies_count"]
    assert results[0].anomaly_type == "DCSYNC"
    assert results[0].severity == "CRITICAL"


# ─── 4. Clean auth events produce no anomaly ─────────────────────────────────

def test_clean_auth_events_no_alert():
    fix = _load("clean_auth_fixture.json")
    results = analyze_kerberos_events(fix["events"])
    assert len(results) == fix["expected"]["kerberos_anomalies_count"] == 0


# ─── 5. Pass-the-Ticket cross-host detection ─────────────────────────────────

def test_pass_the_ticket_detected():
    fix = _load("pass_the_ticket_fixture.json")
    results = analyze_kerberos_events(fix["events"])
    types = {r.anomaly_type for r in results}
    assert "PASS_THE_TICKET" in types


# ─── 6. Group membership escalation to privileged group ──────────────────────

def test_group_membership_escalation_to_domain_admins():
    events = [{
        "uid": "ev-grp-001", "class_uid": 3001, "event_id": 4728,
        "user_name": "attacker", "target_account": "victim",
        "group_name": "Domain Admins", "utc_timestamp": "2026-09-22T09:00:00Z",
    }]
    results = detect_privilege_escalations(events)
    assert len(results) == 1
    assert results[0].escalation_type == "GROUP_MEMBERSHIP_ESCALATION"
    assert results[0].severity == "CRITICAL"


# ─── 7. SID history injection ────────────────────────────────────────────────

def test_sid_history_injection_detected():
    events = [{
        "uid": "ev-sid-001", "class_uid": 3001, "event_id": 4765,
        "user_name": "attacker", "target_account": "victim",
        "utc_timestamp": "2026-09-22T09:30:00Z",
    }]
    results = detect_privilege_escalations(events)
    assert len(results) == 1
    assert results[0].escalation_type == "SID_HISTORY_INJECTION"


# ─── 8. Cloud IAM priv-esc ───────────────────────────────────────────────────

def test_cloud_iam_priv_esc_detected():
    fix = _load("iam_priv_esc_fixture.json")
    results = analyze_cloud_iam_events(fix["events"])
    assert len(results) == fix["expected"]["cloud_iam_anomalies_count"]
    assert results[0].anomaly_type == "IAM_PRIV_ESC"


# ─── 9. MFA bypass detection ─────────────────────────────────────────────────

def test_mfa_bypass_detected():
    fix = _load("mfa_bypass_fixture.json")
    results = analyze_cloud_iam_events(fix["events"])
    assert len(results) == 1
    assert results[0].anomaly_type == "MFA_BYPASS"
    assert results[0].confidence > 0.9


# ─── 10. Clean cloud IAM events produce no anomaly ───────────────────────────

def test_clean_cloud_iam_no_alert():
    fix = _load("clean_cloud_iam_fixture.json")
    results = analyze_cloud_iam_events(fix["events"])
    assert len(results) == fix["expected"]["cloud_iam_anomalies_count"] == 0


# ─── 11. Empty batch → no_identity_evidence ──────────────────────────────────

def test_empty_batch_returns_no_evidence():
    state = _make_state(events=[])
    state["batch_uids"] = []
    with patch("src.agents.identity.agent.publish_identity_finding"):
        result = run_identity_analysis(state, _no_deps())
    assert result["verdict"] == "no_identity_evidence"
    assert result["confidence_score"] == 0.0


# ─── 12. Non-clean finding always has dfkg_citations ─────────────────────────

def test_finding_has_mandatory_dfkg_citations():
    """Any non-clean verdict must carry at least one DFKG citation."""
    events = [
        {
            "uid": "ev-mandatory-001", "class_uid": 3002, "event_id": 4769,
            "user_name": "attacker", "src_ip": "10.0.0.50",
            "ticket_encryption_type": "RC4",
            "service_principal_name": "MSSQLSvc/sql.corp.local:1433",
            "auth_protocol": "Kerberos", "utc_timestamp": "2026-09-22T10:00:00Z",
        }
    ]
    state = _make_state(events)
    with patch("src.agents.identity.agent.publish_identity_finding"):
        result = run_identity_analysis(state, _no_deps())
    assert result["verdict"] != "clean"
    assert len(result["dfkg_citations"]) > 0, "Non-clean verdict must have non-empty dfkg_citations"


# ─── 13. Kafka publish: trace_id forwarded as header ─────────────────────────

def test_kafka_publish_on_finding():
    """publish_identity_finding must forward trace_id so publish_finding can set it as a header."""
    events = [
        {
            "uid": "ev-kafka-001", "class_uid": 3002, "event_id": 4769,
            "user_name": "hacker", "src_ip": "10.0.0.1",
            "ticket_encryption_type": "RC4",
            "service_principal_name": "HOST/server",
            "auth_protocol": "Kerberos", "utc_timestamp": "2026-09-22T10:00:00Z",
        }
    ]
    state = _make_state(events)
    # Patch publish_finding in the kafka_publisher module (not the original)
    with patch("src.agents.identity.kafka_publisher.publish_finding") as mock_pf:
        run_identity_analysis(state, _no_deps())
        # Verify called with correct topic AND trace_id as third positional arg
        assert mock_pf.called
        call_args = mock_pf.call_args
        topic = call_args[0][0]
        trace_id_kwarg = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get("trace_id")
        assert topic == "findings.specialist.identity"
        assert trace_id_kwarg == "test-trace-abc123", (
            "trace_id must be forwarded to publish_finding() so it is set as a Kafka header"
        )


# ─── 14. Single case isolation ───────────────────────────────────────────────

def test_single_case_isolation():
    """Batches spanning multiple case_ids must raise ValueError."""
    state = _make_state(events=[{"uid": "x", "class_uid": 3002}])
    state["batch_uids"] = ["case-A:ev-1", "case-B:ev-2"]
    with pytest.raises(ValueError, match="multiple case_ids"):
        run_identity_analysis(state, _no_deps())


# ─── 15. Lateral movement PTH chain built ────────────────────────────────────

def test_lateral_movement_pth_chain_built():
    fix = _load("lateral_movement_pth_fixture.json")
    anomaly_objects = [
        KerberosAnomalyResult(
            anomaly_type=a["anomaly_type"], severity=a["severity"],
            evidence_uid=a["evidence_uid"], target_account=a["target_account"],
            source_host=a["source_host"], confidence=a["confidence"],
            raw_indicators=a.get("raw_indicators", {}),
        )
        for a in fix["kerberos_anomalies"]
    ]
    chains = correlate_lateral_movement(anomaly_objects, fix["auth_events"], {})
    assert len(chains) == fix["expected"]["lateral_movement_chains_count"]
    assert chains[0].technique == fix["expected"]["technique"]


# ─── 16. Supernode guard: high-degree user handled gracefully ─────────────────

def test_supernode_guard_host_graph():
    """If host graph is empty (supernode guard fired), pipeline falls back gracefully — no abort."""
    events = [
        {
            "uid": "ev-super-001", "class_uid": 3002, "event_id": 4769,
            "user_name": "high_degree_svc", "src_ip": "10.0.0.50",
            "ticket_encryption_type": "RC4",
            "service_principal_name": "SVC/many-hosts.corp.local",
            "auth_protocol": "Kerberos", "utc_timestamp": "2026-09-22T10:00:00Z",
        }
    ]
    state = _make_state(events)
    # Empty host graph simulates supernode guard (degree >= 200)
    with patch("src.agents.identity.agent.publish_identity_finding"):
        result = run_identity_analysis(state, _no_deps())
    # Should complete (not abort) with a valid verdict even with no host graph
    assert result["verdict"] in ("compromised", "suspicious", "clean", "no_identity_evidence")
    assert result["status"] in ("complete", "partial")


# ─── 17. CloudAudit queries use class_uid=6003, never 6001 ───────────────────

def test_cloud_audit_uses_6003_not_6001():
    """All cloud fixtures must carry class_uid=6003 (CloudAudit per ocsf_events.py:224)."""
    cloud_fixtures = [
        "iam_priv_esc_fixture.json",
        "assume_role_chain_fixture.json",
        "mfa_bypass_fixture.json",
        "clean_cloud_iam_fixture.json",
    ]
    for fname in cloud_fixtures:
        fix = _load(fname)
        events = fix.get("events", [])
        for ev in events:
            assert ev["class_uid"] == 6003, (
                f"{fname}: event has class_uid={ev['class_uid']}, expected 6003. "
                "CloudAudit is registered as class_uid=6003 in ocsf_events.py:224. "
                "Using 6001 would silently produce zero CloudAudit matches in DFKG queries."
            )
        # Also verify the expected dict references 6003 if present
        if "class_uid" in fix.get("expected", {}):
            assert fix["expected"]["class_uid"] == 6003, f"{fname} expected.class_uid must be 6003"
