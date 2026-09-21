import json
import hashlib
from typing import Dict, Any, List
from src.agents.network_forensics.state import NetworkForensicsState

FINDING_TOPIC = "findings.network_forensics"

def build_ocsf_2004_finding(anomaly: Dict[str, Any], state: NetworkForensicsState) -> Dict[str, Any]:
    """
    Wraps a detected anomaly into an OCSF Class 2004 (DetectionFinding) payload.
    """
    return {
        "class_name": "Detection Finding",
        "class_uid": 2004,
        "category_name": "Findings",
        "category_uid": 2,
        
        # Standard extensions/context for Specula
        "trace_id": state["case_id"], # Link to case trace
        "agent_role": "network_forensics",
        "finding": {
            "title": anomaly.get("type", "Network Anomaly"),
            "desc": anomaly.get("description", ""),
            "severity_id": anomaly.get("severity_id", 1),
            "types": [anomaly.get("technique", "Unknown")]
        },
        "dfkg_refs": anomaly.get("dfkg_refs", []),
        "timestamp": 0 # Usually populated by ingestion, but added here for schema compliance
    }

def publish_finding(state: NetworkForensicsState, producer, deps=None) -> None:
    """
    Publishes anomalies to FINDING_TOPIC as OCSF 2004 payloads, partitioned by hash(canonical_host_id).
    """
    if not state["batch_uids"]:
        raise ValueError("Cannot publish empty batch")

    first_uid = state["batch_uids"][0]
    
    canonical_host_id = None
    if deps is not None:
        event = deps.fetch_event(first_uid)
        canonical_host_id = getattr(event, "canonical_host_id", None)
        
    if canonical_host_id is None:
        raise ValueError(f"Cannot partition finding: Event {first_uid} lacks canonical_host_id.")
        
    # Derive partition key from hash(canonical_host_id)
    partition_key = str(hashlib.sha256(canonical_host_id.encode('utf-8')).hexdigest())

    for anomaly in state["anomalies_detected"]:
        finding_payload = build_ocsf_2004_finding(anomaly, state)
        
        producer.produce(
            topic=FINDING_TOPIC,
            key=partition_key.encode('utf-8'),
            value=json.dumps(finding_payload).encode('utf-8')
        )
