"""
Specula Cloud Topology Normalizer — Phase 3.

Maps cloud asset inventory and topology API JSON to DeviceInventoryInfoEvent (class 5001).
Reference: ocsf_phase2_phase3_implementation_plan_FINAL.md §2.8
"""

from typing import Any, Dict, List

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.ocsf_base import OCSFBaseEvent
from src.schemas.ocsf_phase3_events import DeviceInventoryInfoEvent
from src.schemas.uid_generator import generate_deterministic_uid


def normalize(raw_payload: Dict[str, Any], trace_id: str, case_id: str) -> List[OCSFBaseEvent]:
    """
    Normalize cloud asset topology JSON to DeviceInventoryInfoEvent (class 5001).
    Always sets clock_skew_offset_ms = 0 and clock_skew_unverified = True.
    """
    time_normalizer = TimeNormalizer()
    raw_timestamp = str(raw_payload.get("timestamp") or raw_payload.get("discovered_at") or "1970-01-01T00:00:00Z")
    utc_time, _, _ = time_normalizer.normalize(raw_timestamp)

    # Cloud topology API has no on-prem DC anchor by definition
    skew_ms = 0
    unverified = True

    uid = generate_deterministic_uid("cloud_topology", raw_payload)

    events: List[OCSFBaseEvent] = [
        DeviceInventoryInfoEvent(
            case_id=case_id,
            trace_id=trace_id,
            activity_id=1,  # Inventory Logged
            severity_id=int(raw_payload.get("severity_id", 1)),
            time=utc_time,
            raw_source_timestamp=raw_timestamp,
            clock_skew_offset_ms=skew_ms,
            clock_skew_unverified=unverified,
            uid=uid,
            device_id=raw_payload.get("resource_id") or raw_payload.get("device_id") or "RES-UNKNOWN",
            device_name=raw_payload.get("resource_name") or raw_payload.get("device_name"),
            device_type=raw_payload.get("resource_type") or raw_payload.get("device_type"),
            ip_addresses=raw_payload.get("ip_addresses") if isinstance(raw_payload.get("ip_addresses"), list) else None,
            region=raw_payload.get("region"),
            account_id=raw_payload.get("account_id"),
            metadata=raw_payload.get("metadata"),
            canonical_host_id=raw_payload.get("canonical_host_id"),
        )
    ]

    return events
