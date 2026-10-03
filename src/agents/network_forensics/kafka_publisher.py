"""Publish evidence-grounded OCSF 2004 network findings to Kafka."""

from datetime import datetime, timezone
import json
from typing import Any

from src.agents.network_forensics.state import NetworkForensicsState
from src.schemas.ocsf_events import DetectionFindingEvent
from src.schemas.uid_generator import generate_deterministic_uid

FINDING_TOPIC = "findings.network_forensics"


def build_ocsf_2004_finding(
    anomaly: dict[str, Any], state: NetworkForensicsState, canonical_host_id: str,
) -> dict[str, Any]:
    refs = list(dict.fromkeys(uid for uid in anomaly.get("dfkg_refs", []) if uid))
    if not refs:
        raise ValueError("Network finding requires evidence UIDs")
    now = datetime.now(timezone.utc)
    uid = generate_deterministic_uid("network_finding", {
        "case_id": state["case_id"], "type": anomaly["type"], "dfkg_refs": refs,
    })
    event = DetectionFindingEvent(
        case_id=state["case_id"], trace_id=state["trace_id"], uid=uid,
        activity_id=1, severity_id=anomaly["severity_id"],
        time=now, raw_source_timestamp=now.isoformat(),
        canonical_host_id=canonical_host_id,
        finding_info=anomaly["description"], attacks=[anomaly["technique"]],
    )
    payload = event.model_dump(mode="json")
    payload.update({
        "agent_role": "network_forensics", "summary": anomaly["description"],
        "timestamp": now.isoformat(), "dfkg_refs": refs,
        "finding_type": anomaly["type"],
        "bytes_out": anomaly.get("bytes_out", 0),
        "destination_ip": anomaly.get("destination_ip"),
    })
    return payload


def publish_finding(state: NetworkForensicsState, producer: Any, deps: Any) -> None:
    if not state["batch_uids"]:
        raise ValueError("Cannot publish empty batch")
    first = deps.fetch_event(state["batch_uids"][0])
    canonical_host_id = (first.get("canonical_host_id") if isinstance(first, dict)
                         else getattr(first, "canonical_host_id", None))
    if not canonical_host_id:
        raise ValueError("Cannot partition finding without canonical_host_id")
    key = f"host:{canonical_host_id}".encode("utf-8")
    for anomaly in state["anomalies_detected"]:
        payload = build_ocsf_2004_finding(anomaly, state, canonical_host_id)
        producer.produce(topic=FINDING_TOPIC, key=key,
                         value=json.dumps(payload, sort_keys=True).encode("utf-8"))
