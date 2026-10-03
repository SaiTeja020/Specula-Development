"""kafka_publisher.py — Identity Agent Kafka finding publisher.

Wraps the shared kafka_utils.publish_finding() so that trace_id propagates as
a Kafka MESSAGE HEADER (for distributed tracing) as well as a payload field
(for DFKG node properties). Does NOT create a bespoke producer — reuses the
singleton managed in kafka_utils to avoid duplicate connection overhead.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from src.agents.kafka_utils import publish_finding, ROLE_TOPIC_MAP

log = logging.getLogger(__name__)

_IDENTITY_TOPIC = ROLE_TOPIC_MAP["identity"]  # "findings.specialist.identity"


def publish_identity_finding(state: dict, deps: Any = None) -> None:
    """Serialize an IdentityAgentState into a finding dict and publish to Kafka.

    The trace_id is forwarded to publish_finding() which places it in the Kafka
    message *header* (kafka_utils.py:86) for OpenTelemetry distributed tracing,
    AND includes it in the payload for DFKG node properties.

    Rule enforced: any non-clean verdict with empty dfkg_citations is logged as
    an error (invalid finding) before publishing — the finding is still published
    so it reaches the Supervisor as a partial result.
    """
    verdict = state.get("verdict")
    dfkg_citations = state.get("dfkg_citations") or []

    # Validate Daubert citation requirement
    if verdict not in (None, "clean", "no_identity_evidence") and not dfkg_citations:
        log.error(
            "[Identity] INVALID FINDING: verdict=%s but dfkg_citations=[] — "
            "Daubert chain-of-custody requires at least one DFKG node UID citation.",
            verdict,
        )

    finding = {
        "agent_role": "identity",
        "case_id": state.get("case_id", "unknown"),
        "trace_id": state.get("trace_id", ""),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "confidence_score": state.get("confidence_score", 0.0),
        "status": state.get("status", "complete"),
        "dfkg_citations": dfkg_citations,
        "kerberos_anomalies": state.get("kerberos_anomalies") or [],
        "privilege_escalations": state.get("privilege_escalations") or [],
        "lateral_movement_chains": state.get("lateral_movement_chains") or [],
        "cloud_iam_anomalies": state.get("cloud_iam_anomalies") or [],
        "summary": _build_summary(state),
        "kafka_offset": None,
    }

    # publish_finding places trace_id as a Kafka header (kafka_utils.py:86)
    publish_finding(_IDENTITY_TOPIC, finding, state.get("trace_id"))
    log.debug("[Identity] Published finding to %s (verdict=%s)", _IDENTITY_TOPIC, verdict)


def _build_summary(state: dict) -> str:
    """Build a human-readable summary string for the Supervisor's findings list."""
    parts = []
    kerb = state.get("kerberos_anomalies") or []
    priv = state.get("privilege_escalations") or []
    lm = state.get("lateral_movement_chains") or []
    cloud = state.get("cloud_iam_anomalies") or []
    if kerb:
        types = {a.get("anomaly_type", "?") for a in kerb}
        parts.append(f"Kerberos:{','.join(sorted(types))}({len(kerb)})")
    if priv:
        types = {a.get("escalation_type", "?") for a in priv}
        parts.append(f"PrivEsc:{','.join(sorted(types))}({len(priv)})")
    if lm:
        parts.append(f"LM-chains({len(lm)})")
    if cloud:
        types = {a.get("anomaly_type", "?") for a in cloud}
        parts.append(f"CloudIAM:{','.join(sorted(types))}({len(cloud)})")
    if not parts:
        return f"Identity analysis complete: {state.get('verdict', 'unknown')}"
    return "; ".join(parts)
