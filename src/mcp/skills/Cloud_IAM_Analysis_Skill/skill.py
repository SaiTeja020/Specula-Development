"""Cloud_IAM_Analysis_Skill — callable wrapper."""
from __future__ import annotations
from src.agents.identity.cloud_iam_analyzer import analyze_cloud_iam_events, CloudIAMAnomalyResult


def run(cloud_events: list[dict]) -> dict:
    results = analyze_cloud_iam_events(cloud_events)
    return {
        "cloud_iam_anomalies": [
            {
                "anomaly_type": r.anomaly_type, "severity": r.severity,
                "evidence_uid": r.evidence_uid, "user_identity": r.user_identity,
                "source_ip": r.source_ip, "api_operation": r.api_operation,
                "confidence": r.confidence, "cloud_provider": r.cloud_provider,
            }
            for r in results
        ]
    }
