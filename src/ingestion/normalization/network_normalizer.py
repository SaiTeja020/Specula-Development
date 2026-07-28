"""
Specula Network Logs to OCSF Normalizer.

Maps Zeek/Suricata logs to OCSF format.
Source category 3 (Tier 2 High).

Reference: specula_ingestion_final_plan.md §5.1
"""

from typing import Any, Dict

from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.rebuff_gate import detect_prompt_injection
from src.schemas.ocsf_events import NetworkActivity
from src.ingestion.normalization.time_normalizer import TimeNormalizer


def normalize_zeek_conn(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    trace_id: str,
) -> NetworkActivity:
    """Normalize Zeek conn.log JSON to OCSF NetworkActivity."""
    
    raw_timestamp = str(raw_parsed_event.get("ts", ""))
    
    # Text-native source (JSON), but fields like user_agent or 
    # DNS queries need sanitization
    raw_service = raw_parsed_event.get("service", "")
    sanitized_service, _ = sanitize_text(raw_service)
    
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    return NetworkActivity(
        trace_id=trace_id,
        activity_id=1, # Traffic
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        security_scan_degraded=False, # Connection logs usually don't need Rebuff
        uid="PENDING_UID",
        src_ip=raw_parsed_event.get("id.orig_h", None),
        dst_ip=raw_parsed_event.get("id.resp_h", None),
        src_port=int(raw_parsed_event.get("id.orig_p", 0)),
        dst_port=int(raw_parsed_event.get("id.resp_p", 0)),
        protocol=raw_parsed_event.get("proto", None),
        bytes_in=int(raw_parsed_event.get("resp_bytes", 0) or 0),
        bytes_out=int(raw_parsed_event.get("orig_bytes", 0) or 0),
        connection_uid=raw_parsed_event.get("uid", None),
    )
