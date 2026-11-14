import re
from typing import Dict, Any, Optional
from datetime import datetime
from src.schemas.ocsf_phase2_events import AuthenticationEvent
from src.schemas.uid_generator import generate_deterministic_uid
from src.schemas.entity_resolver import CanonicalEntityResolver
from src.ingestion.security_gate.sanitizer import sanitize_text

def normalize_ad_auth_event(
    raw_event: Dict[str, Any],
    sanitized_msg: str,
    utc_time: datetime,
    skew_offset: int,
    skew_unverified: bool,
    is_degraded: bool,
    trace_id: str,
    resolver: CanonicalEntityResolver
) -> AuthenticationEvent:
    event_id = str(raw_event.get("Id", 0))
    time_str = raw_event.get("TimeCreated", "") or raw_event.get("LastRecordChange", "") or raw_event.get("eventTime", "")

    # Extract user and IP from sanitized msg
    user_match = re.search(r'Account Name:\s*([^\s]+)', sanitized_msg)
    user_name = user_match.group(1) if user_match else "UNKNOWN_USER"
    
    ip_match = re.search(r'Source Network Address:\s*([^\s]+)', sanitized_msg)
    src_ip = ip_match.group(1) if ip_match and ip_match.group(1) != "-" else "UNKNOWN_IP"
    
    # Extract Logon Type
    logon_type_match = re.search(r'Logon Type:\s*(\d+)', sanitized_msg)
    logon_type = int(logon_type_match.group(1)) if logon_type_match else 0
    
    # Authentication result mapping
    activity_id = 1 # Logon
    failure_reason = None
    if event_id == "4625":
        activity_id = 2 # Failed Logon
        failure_reason = "Logon Failure"
    
    # Resolve host dynamically using the event's UTC timestamp to anchor dynamic DHCP assignments
    host_uid = resolver.resolve_any(ip=src_ip, event_timestamp=utc_time)
    
    entity_uid = generate_deterministic_uid("auth", {
        "event_id": event_id,
        "user_name": user_name,
        "timestamp": utc_time.isoformat()
    })

    return AuthenticationEvent(
        trace_id=trace_id,
        case_id="UNASSIGNED_CONTINUOUS",
        activity_id=activity_id,
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=str(time_str),
        clock_skew_offset_ms=skew_offset,
        clock_skew_unverified=skew_unverified,
        security_scan_degraded=is_degraded,
        uid=entity_uid,
        user_name=user_name,
        src_ip=src_ip,
        auth_protocol="Kerberos" if event_id in ["4768", "4769"] else "NTLM",
        logon_type=logon_type,
        failure_reason=failure_reason,
        canonical_host_id=host_uid
    )
