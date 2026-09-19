import os
import re
from typing import Dict, Any, Optional
from datetime import datetime
from src.schemas.ocsf_events import ProcessActivity
from src.schemas.uid_generator import generate_deterministic_uid
from src.schemas.entity_resolver import CanonicalEntityResolver
from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.normalization.time_normalizer import TimeNormalizer

def normalize_evtx_process_creation(
    raw_event: Dict[str, Any],
    sanitized_msg: str,
    utc_time: datetime,
    skew_offset: int,
    skew_unverified: bool,
    is_degraded: bool,
    trace_id: str,
    resolver: CanonicalEntityResolver
) -> ProcessActivity:
    provider = raw_event.get("ProviderName", raw_event.get("FileName", raw_event.get("eventSource", "Windows")))
    event_id = raw_event.get("Id", 0)
    time_str = raw_event.get("TimeCreated", "") or raw_event.get("LastRecordChange", "") or raw_event.get("eventTime", "")

    # Regex extraction for PID
    pid_match = re.search(r'(?:New Process ID|ProcessId|Process Id):\s*(0x[0-9a-fA-F]+|\d+)', sanitized_msg, re.IGNORECASE)
    extracted_pid = 0
    if pid_match:
        val = pid_match.group(1)
        extracted_pid = int(val, 16) if val.lower().startswith('0x') else int(val)
        
    # Regex extraction for PPID
    ppid_match = re.search(r'(?:Creator Process ID|ParentProcessId|Parent Process Id):\s*(0x[0-9a-fA-F]+|\d+)', sanitized_msg, re.IGNORECASE)
    extracted_ppid = 0
    parent_uid = None
    
    # Resolve host dynamically
    computer_name = raw_event.get("MachineName", raw_event.get("Computer", ""))
    host_uid = resolver.resolve_any(hostname=computer_name) if computer_name else None
    
    if ppid_match:
        val = ppid_match.group(1)
        extracted_ppid = int(val, 16) if val.lower().startswith('0x') else int(val)
        if extracted_ppid > 0:
            parent_uid = generate_deterministic_uid("process", {"pid": extracted_ppid, "host": host_uid})

    # Regex extraction for Image and CommandLine
    image_match = re.search(r'(?:Image|New Process Name):\s*([^\r\n]+)', sanitized_msg, re.IGNORECASE)
    extracted_image = image_match.group(1).strip() if image_match else provider
    process_name = os.path.basename(extracted_image) if image_match else sanitize_text(str(provider))[0]
    
    cmd_match = re.search(r'CommandLine:\s*([^\r\n]+)', sanitized_msg, re.IGNORECASE)
    extracted_cmd = cmd_match.group(1).strip() if cmd_match else sanitized_msg.strip()

    entity_uid = generate_deterministic_uid("process", {
        "event_id": event_id,
        "provider": provider,
        "timestamp": utc_time.isoformat()
    })

    return ProcessActivity(
        trace_id=trace_id,
        case_id="UNASSIGNED_CONTINUOUS",
        activity_id=1,
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=str(time_str),
        clock_skew_offset_ms=skew_offset,
        clock_skew_unverified=skew_unverified,
        security_scan_degraded=is_degraded,
        uid=entity_uid,
        process_name=process_name,
        process_pid=extracted_pid,
        parent_process_pid=extracted_ppid,
        parent_process_uid=parent_uid,
        command_line=extracted_cmd,
        host_name=computer_name or "UNKNOWN_HOST",
        canonical_host_id=host_uid
    )
