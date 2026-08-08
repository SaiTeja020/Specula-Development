"""
Specula Container Logs Normalizer — Phase 2.

Maps Docker / K8s JSON logs to system activity events enriched with container metadata.
Reference: ocsf_phase2_phase3_implementation_plan_FINAL.md §2.5
"""

from typing import Any, Dict, List

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.ocsf_base import OCSFBaseEvent
from src.schemas.ocsf_phase2_events import (
    FileActivityEvent,
    NetworkActivityEvent,
    ProcessActivityEvent,
)
from src.schemas.uid_generator import generate_deterministic_uid


def normalize(raw_payload: Dict[str, Any], trace_id: str, case_id: str) -> List[OCSFBaseEvent]:
    """
    Normalize Docker/K8s logs to System Activity OCSF events enriched with a container profile object.
    """
    time_normalizer = TimeNormalizer()
    raw_timestamp = str(raw_payload.get("timestamp") or raw_payload.get("time") or "1970-01-01T00:00:00Z")
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)

    if raw_payload.get("is_managed_k8s", True):
        skew_ms = 0
        unverified = True

    uid = generate_deterministic_uid("container", raw_payload)
    
    container_object = {
        "container_id": raw_payload.get("container_id"),
        "image_name": raw_payload.get("image_name") or raw_payload.get("image"),
        "namespace": raw_payload.get("namespace") or raw_payload.get("k8s_namespace"),
        "pod_name": raw_payload.get("pod_name") or raw_payload.get("k8s_pod"),
    }

    log_type = str(raw_payload.get("log_type") or raw_payload.get("category") or "process").lower()
    events: List[OCSFBaseEvent] = []

    if "file" in log_type:
        events.append(
            FileActivityEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1,
                severity_id=int(raw_payload.get("severity_id", 1)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                uid=uid,
                file_name=raw_payload.get("file_name"),
                file_path=raw_payload.get("file_path"),
                container=container_object,
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )
    elif "net" in log_type or "network" in log_type:
        events.append(
            NetworkActivityEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1,
                severity_id=int(raw_payload.get("severity_id", 1)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                uid=uid,
                src_ip=raw_payload.get("src_ip"),
                dst_ip=raw_payload.get("dst_ip"),
                src_port=raw_payload.get("src_port"),
                dst_port=raw_payload.get("dst_port"),
                protocol=raw_payload.get("protocol"),
                container=container_object,
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )
    else:
        # Default: Process / Execution inside container
        events.append(
            ProcessActivityEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1,
                severity_id=int(raw_payload.get("severity_id", 1)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                uid=uid,
                process_name=raw_payload.get("process_name") or raw_payload.get("cmd") or "entrypoint",
                process_pid=int(raw_payload.get("process_pid", 1)),
                command_line=raw_payload.get("command_line") or raw_payload.get("log"),
                container=container_object,
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )

    return events
