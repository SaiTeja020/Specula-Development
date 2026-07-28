"""
Specula AD & Authentication Logs to OCSF Normalizer.

Maps AD LDAP/Kerberos logs to OCSF format.
Source category 4 (Tier 1 Critical).

Reference: specula_ingestion_final_plan.md §5.1
"""

from typing import Any, Dict

from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.rebuff_gate import detect_prompt_injection
from src.schemas.ocsf_events import Authentication
from src.ingestion.normalization.time_normalizer import TimeNormalizer


def normalize_ad_auth(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    trace_id: str,
) -> Authentication:
    """Normalize AD Auth (e.g. EVTX 4624) to OCSF Authentication."""
    
    # Binary ordering applies to EVTX sources
    
    raw_timestamp = raw_parsed_event.get("System", {}).get("TimeCreated", {}).get("SystemTime", "")
    event_data = raw_parsed_event.get("EventData", {})
    
    raw_user = event_data.get("TargetUserName", "")
    sanitized_user, _ = sanitize_text(raw_user)
    
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    return Authentication(
        trace_id=trace_id,
        activity_id=1, # Logon
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        security_scan_degraded=False,
        uid="PENDING_UID",
        user_name=sanitized_user,
        auth_protocol=event_data.get("AuthenticationPackageName", None),
        logon_type=int(event_data.get("LogonType", 0) or 0),
        src_ip=event_data.get("IpAddress", None),
        status="Success", # Assumed for 4624
    )
