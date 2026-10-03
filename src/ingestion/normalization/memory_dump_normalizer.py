"""
Specula Memory Dump Normalizer — Phase 2.

Maps Volatility JSON plugin outputs to OCSF events.
Reference: ocsf_phase2_phase3_implementation_plan_FINAL.md §2.4
"""

from typing import Any, Dict, List, Optional

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.ocsf_base import OCSFBaseEvent
from src.schemas.ocsf_phase2_events import (
    DetectionFindingEvent,
    NetworkActivityEvent,
    ProcessActivityEvent,
)
from src.schemas.uid_generator import generate_deterministic_uid


def _first_timestamp(payload: Dict[str, Any], keys: tuple[str, ...]) -> Optional[str]:
    """Return the first non-empty timestamp string in *keys*."""
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def normalize(raw_payload: Dict[str, Any], trace_id: str, case_id: str) -> List[OCSFBaseEvent]:
    """
    Normalize Volatility JSON plugin output into ProcessActivityEvent, NetworkActivityEvent, or DetectionFindingEvent.
    """
    time_normalizer = TimeNormalizer()

    # OCSF's canonical `time` and `raw_source_timestamp` always represent
    # the artifact time used for timeline ordering.  Acquisition time is
    # supplementary provenance, not a competing timestamp convention.
    artifact_raw_timestamp = _first_timestamp(
        raw_payload,
        ("artifact_timestamp", "process_create_time", "CreateTime", "timestamp"),
    )
    raw_capture_timestamp = _first_timestamp(
        raw_payload,
        ("capture_time", "acquisition_time", "image_capture_time"),
    )
    artifact_time_unverified = artifact_raw_timestamp is None
    raw_timestamp = artifact_raw_timestamp or raw_capture_timestamp or "1970-01-01T00:00:00Z"
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    capture_time = None
    if raw_capture_timestamp:
        capture_time, _, _ = time_normalizer.normalize(raw_capture_timestamp)

    if raw_payload.get("has_dc_anchor") is False:
        skew_ms = 0
        unverified = True

    plugin_name = str(raw_payload.get("plugin") or raw_payload.get("artifact_type") or "").lower()
    uid = generate_deterministic_uid("memory_dump", raw_payload)

    events: List[OCSFBaseEvent] = []

    if "pslist" in plugin_name or "pstree" in plugin_name:
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
                capture_time=capture_time,
                raw_capture_timestamp=raw_capture_timestamp,
                artifact_time_unverified=artifact_time_unverified,
                uid=uid,
                process_name=raw_payload.get("ImageFileName") or raw_payload.get("process_name", "unknown"),
                process_pid=int(raw_payload.get("PID") or raw_payload.get("process_pid", 0)),
                parent_process_pid=raw_payload.get("PPID") or raw_payload.get("parent_process_pid"),
                command_line=raw_payload.get("CommandLine"),
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )
    elif "netscan" in plugin_name or "netstat" in plugin_name:
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
                capture_time=capture_time,
                raw_capture_timestamp=raw_capture_timestamp,
                artifact_time_unverified=artifact_time_unverified,
                uid=uid,
                src_ip=raw_payload.get("ForeignAddr") or raw_payload.get("src_ip"),
                dst_ip=raw_payload.get("LocalAddr") or raw_payload.get("dst_ip"),
                src_port=raw_payload.get("ForeignPort") or raw_payload.get("src_port"),
                dst_port=raw_payload.get("LocalPort") or raw_payload.get("dst_port"),
                protocol=raw_payload.get("Proto") or raw_payload.get("protocol"),
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )
    elif "malfind" in plugin_name or "hollowfind" in plugin_name or "injected" in plugin_name:
        events.append(
            DetectionFindingEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1,
                severity_id=int(raw_payload.get("severity_id", 5)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                capture_time=capture_time,
                raw_capture_timestamp=raw_capture_timestamp,
                artifact_time_unverified=artifact_time_unverified,
                uid=uid,
                finding_title=f"Memory Injection Finding: {plugin_name}",
                analytic_name=f"Volatility {plugin_name}",
                confidence="High",
                raw_verdict="Injected Memory Region Detected",
                canonical_host_id=raw_payload.get("canonical_host_id"),
                details=raw_payload,
            )
        )
    else:
        # Generic process detection fallback for memory dump artifacts
        events.append(
            ProcessActivityEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1,
                severity_id=1,
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                capture_time=capture_time,
                raw_capture_timestamp=raw_capture_timestamp,
                artifact_time_unverified=artifact_time_unverified,
                uid=uid,
                process_name=raw_payload.get("process_name", "unknown"),
                process_pid=int(raw_payload.get("process_pid", 0)),
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )

    return events
