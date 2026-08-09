"""
Specula EDR Logs Normalizer — Phase 2.

Maps EDR telemetry (Process, File, Network, Auth, Alerts) to OCSF events.
Reference: ocsf_phase2_phase3_implementation_plan_FINAL.md §2.1
"""

from typing import Any, Dict, List

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.security_gate.sanitizer import sanitize_text
from src.schemas.ocsf_base import OCSFBaseEvent
from src.schemas.ocsf_phase2_events import (
    AuthenticationEvent,
    DetectionFindingEvent,
    FileActivityEvent,
    NetworkActivityEvent,
    ProcessActivityEvent,
)
from src.schemas.uid_generator import generate_deterministic_uid


def normalize(raw_payload: Dict[str, Any], trace_id: str, case_id: str) -> List[OCSFBaseEvent]:
    """
    Normalize raw EDR JSON payload into concrete OCSF Phase 2 events.
    """
    events: List[OCSFBaseEvent] = []
    time_normalizer = TimeNormalizer()
    
    raw_timestamp = str(raw_payload.get("timestamp") or raw_payload.get("event_time") or "1970-01-01T00:00:00Z")
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    # Check if cloud-only EDR agent override is present
    if raw_payload.get("is_cloud_only", False):
        skew_ms = 0
        unverified = True

    event_type = str(raw_payload.get("event_type", "")).lower()
    
    # Generate deterministic UID for EDR event
    uid_attrs = {
        "event_type": event_type,
        "timestamp": raw_timestamp,
        "host": raw_payload.get("host_name"),
        "raw_payload": raw_payload,
    }
    uid = generate_deterministic_uid("edr", uid_attrs)

    # 1. Branch by main sub-event type
    if event_type in ("process_create", "process_terminate", "process_exec"):
        sanitized_cmd, _ = sanitize_text(raw_payload.get("command_line", ""))
        events.append(
            ProcessActivityEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1 if "create" in event_type or "exec" in event_type else 2,
                severity_id=int(raw_payload.get("severity_id", 1)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                uid=uid,
                process_name=raw_payload.get("process_name", "unknown"),
                process_pid=int(raw_payload.get("process_pid", 0)),
                parent_process_name=raw_payload.get("parent_process_name"),
                parent_process_pid=raw_payload.get("parent_process_pid"),
                command_line=sanitized_cmd,
                file_path=raw_payload.get("file_path"),
                user_name=raw_payload.get("user_name"),
                host_name=raw_payload.get("host_name"),
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )
    elif event_type in ("file_write", "file_delete", "file_modify"):
        events.append(
            FileActivityEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1 if "write" in event_type else (2 if "delete" in event_type else 3),
                severity_id=int(raw_payload.get("severity_id", 1)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                uid=uid,
                file_name=raw_payload.get("file_name"),
                file_path=raw_payload.get("file_path"),
                file_hash_sha256=raw_payload.get("file_hash_sha256"),
                user_name=raw_payload.get("user_name"),
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )
    elif event_type in ("network_connection", "net_conn"):
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
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )
    elif event_type in ("logon", "logoff"):
        events.append(
            AuthenticationEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1 if event_type == "logon" else 2,
                severity_id=int(raw_payload.get("severity_id", 1)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                uid=uid,
                user_name=raw_payload.get("user_name", "unknown"),
                auth_protocol=raw_payload.get("auth_protocol"),
                src_ip=raw_payload.get("src_ip"),
                status=raw_payload.get("status", "Success"),
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )

    # 2. Check if detection / alert is present or if event_type itself is alert/detection
    if event_type in ("alert", "detection") or "alert_title" in raw_payload:
        alert_uid = generate_deterministic_uid("edr", {"alert": raw_payload, "parent_uid": uid})
        events.append(
            DetectionFindingEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1,
                severity_id=int(raw_payload.get("severity_id", 4)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                uid=alert_uid,
                finding_title=raw_payload.get("alert_title") or raw_payload.get("title") or "EDR Alert",
                analytic_name=raw_payload.get("rule_name"),
                confidence=str(raw_payload.get("confidence", "High")),
                canonical_host_id=raw_payload.get("canonical_host_id"),
                details=raw_payload.get("details"),
            )
        )

    return events
