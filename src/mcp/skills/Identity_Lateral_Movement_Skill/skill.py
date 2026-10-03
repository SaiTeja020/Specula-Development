"""Identity_Lateral_Movement_Skill — callable wrapper."""
from __future__ import annotations
from src.agents.identity.lateral_movement_correlator import correlate_lateral_movement, LateralMovementChain
from src.agents.identity.kerberos_analyzer import KerberosAnomalyResult


def run(
    kerberos_anomalies: list[dict],
    auth_events: list[dict],
    dfkg_host_graph: dict,
) -> dict:
    # Re-hydrate dicts into dataclass instances for the correlator
    anomaly_objects = [
        KerberosAnomalyResult(
            anomaly_type=a["anomaly_type"], severity=a["severity"],
            evidence_uid=a["evidence_uid"], target_account=a["target_account"],
            source_host=a["source_host"], confidence=a["confidence"],
            raw_indicators=a.get("raw_indicators", {}),
        )
        for a in kerberos_anomalies
    ]
    chains = correlate_lateral_movement(anomaly_objects, auth_events, dfkg_host_graph)
    return {
        "lateral_movement_chains": [
            {
                "chain_id": c.chain_id, "technique": c.technique,
                "hop_sequence": c.hop_sequence, "account_uid": c.account_uid,
                "time_window_start": c.time_window_start,
                "time_window_end": c.time_window_end,
                "dfkg_edge_uids": c.dfkg_edge_uids, "confidence": c.confidence,
            }
            for c in chains
        ]
    }
