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
from src.schemas.entity_resolver import CanonicalEntityResolver
from src.schemas.uid_generator import generate_deterministic_uid


def normalize(raw_payload: Dict[str, Any], trace_id: str, case_id: str, entity_resolver: CanonicalEntityResolver) -> List[OCSFBaseEvent]:
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
    
    # Try to resolve IP to host
    host_name_raw = raw_payload.get("host_name") or "LOCAL_HOST"
    ip = raw_payload.get("src_ip")
    try:
        # Prioritize IP resolution via DHCP mapping if present
        canonical_host_id = entity_resolver.resolve_any(ip=ip, hostname=host_name_raw, event_timestamp=utc_time)
        if not canonical_host_id:
            canonical_host_id = f"host-{host_name_raw}"
    except Exception:
        canonical_host_id = f"host-{host_name_raw}"
    
    # Generate deterministic UID for EDR event
    uid_attrs = {
        "event_type": event_type,
        "timestamp": raw_timestamp,
        "host": canonical_host_id,
        "raw_payload": raw_payload,
    }
    uid = generate_deterministic_uid("edr", uid_attrs)

    # 1. Branch by main sub-event type
    if event_type in ("process_create", "process_terminate", "process_exec"):
        sanitized_cmd, _ = sanitize_text(raw_payload.get("command_line", ""))
        
        proc_pid = int(raw_payload.get("process_pid", 0))
        proc_name = raw_payload.get("process_name", "unknown")
        
        parent_proc_pid = int(raw_payload.get("parent_process_pid") or 0)
        parent_proc_name = raw_payload.get("parent_process_name")
        
        proc_uid = generate_deterministic_uid("process", {
            "process_name": proc_name,
            "pid": proc_pid,
            "host_id": canonical_host_id
        })
        
        parent_proc_uid = generate_deterministic_uid("process", {
            "process_name": parent_proc_name or "unknown",
            "pid": parent_proc_pid,
            "host_id": canonical_host_id
        })
        
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
                uid=proc_uid,
                process_name=proc_name,
                process_pid=proc_pid,
                parent_process_name=parent_proc_name,
                parent_process_pid=parent_proc_pid,
                parent_process_uid=parent_proc_uid,
                command_line=sanitized_cmd if sanitized_cmd else None,
                file_path=raw_payload.get("file_path") if raw_payload.get("file_path") else None,
                user_name=raw_payload.get("user_name") if raw_payload.get("user_name") else None,
                host_name=host_name_raw,
                canonical_host_id=canonical_host_id,
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
                canonical_host_id=canonical_host_id,
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
                canonical_host_id=canonical_host_id,
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
                canonical_host_id=canonical_host_id,
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
                canonical_host_id=canonical_host_id,
                details=raw_payload.get("details"),
            )
        )

    return events
