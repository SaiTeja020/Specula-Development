"""AD_Kerberos_Analysis_Skill — callable wrapper for manifest-enforced invocation.

Wraps kerberos_analyzer + privilege_escalation_detector into a single callable
that can be invoked by the skill router after manifest validation.
"""
from __future__ import annotations

from src.agents.identity.kerberos_analyzer import analyze_kerberos_events, KerberosAnomalyResult
from src.agents.identity.privilege_escalation_detector import detect_privilege_escalations, PrivEscResult


def run(
    auth_events: list[dict],
    audit_events: list[dict],
) -> dict:
    """Execute AD/Kerberos analysis skill.

    Args:
        auth_events: OCSF class_uid=3002 (Authentication) event dicts.
        audit_events: OCSF class_uid=3001 (AuditActivity) event dicts.

    Returns:
        dict with keys: kerberos_anomalies, privilege_escalations
    """
    kerberos = analyze_kerberos_events(auth_events + audit_events)
    priv_esc = detect_privilege_escalations(audit_events + auth_events)
    return {
        "kerberos_anomalies": [_k(r) for r in kerberos],
        "privilege_escalations": [_p(r) for r in priv_esc],
    }


def _k(r: KerberosAnomalyResult) -> dict:
    return {
        "anomaly_type": r.anomaly_type, "severity": r.severity,
        "evidence_uid": r.evidence_uid, "target_account": r.target_account,
        "source_host": r.source_host, "confidence": r.confidence,
    }


def _p(r: PrivEscResult) -> dict:
    return {
        "escalation_type": r.escalation_type, "severity": r.severity,
        "evidence_uid": r.evidence_uid, "actor_account": r.actor_account,
        "target_account": r.target_account, "group_name": r.group_name,
        "confidence": r.confidence,
    }
