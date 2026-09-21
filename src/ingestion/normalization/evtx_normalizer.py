"""
Specula EVTX to OCSF Normalizer.

Maps Windows EVTX (System Logs) to OCSF format.
Source category 1 (Tier 1 Critical).

Reference: specula_ingestion_final_plan.md §4.3 (Binary ordering) & §5.1
"""

from typing import Any, Dict
from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.rebuff_gate import detect_prompt_injection
from src.schemas.ocsf_events import (
    ProcessActivity, Authentication, UserIdentity, 
    NetworkEndpoint, NetworkActivity, FileActivity, GenericEvent,
    DetectionFindingEvent, AuditActivity
)
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.entity_resolver import CanonicalEntityResolver
from src.schemas.uid_generator import generate_deterministic_uid

def normalize_evtx_process_creation(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    entity_resolver: CanonicalEntityResolver,
    trace_id: str,
) -> ProcessActivity:
    """
    Normalize an EVTX process creation event to OCSF ProcessActivity.
    """
    system_block = raw_parsed_event.get("System", {})
    event_data = raw_parsed_event.get("EventData", {})
    
    raw_timestamp = system_block.get("TimeCreated", {}).get("SystemTime", "")
    if not raw_timestamp:
        raw_timestamp = raw_parsed_event.get("TimeCreated", "")
        if isinstance(raw_timestamp, str) and "/Date(" in raw_timestamp:
            from datetime import datetime, timezone
            ms = int(raw_timestamp.split("(")[1].split(")")[0])
            raw_timestamp = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
    
    event_id = system_block.get("EventID", raw_parsed_event.get("Id", 0))
    
    raw_cmdline = event_data.get("CommandLine") or raw_parsed_event.get("Message") or event_data.get("ScriptBlockText") or ""
    raw_process_name = event_data.get("NewProcessName") or raw_parsed_event.get("ProviderName") or event_data.get("Path") or ""
    raw_parent_process_name = event_data.get("ParentProcessName") or ""
    
    # For PowerShell 4104, force process name to "powershell.exe" if not found
    if event_id in [4104, 4103] and not raw_process_name:
        raw_process_name = "powershell.exe"
    
    sanitized_cmdline, has_homoglyphs = sanitize_text(raw_cmdline)
    is_injection, is_degraded = detect_prompt_injection(sanitized_cmdline or "")
    
    sanitized_proc_name, _ = sanitize_text(raw_process_name)
    sanitized_parent_proc_name, _ = sanitize_text(raw_parent_process_name)
    
    if not sanitized_proc_name or sanitized_proc_name.strip() == "":
        raise ValueError("Process name cannot be empty")
    
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    # Resolve host
    # For EVTX, typically we have Computer name in System block
    computer_name = system_block.get("Computer") or raw_parsed_event.get("MachineName") or "LOCAL_HOST"
    # Try to resolve IP if it exists, otherwise resolve by hostname (assuming some static mapping exists)
    try:
        canonical_host_id = entity_resolver.resolve_any(hostname=computer_name, event_timestamp=utc_time)
        if not canonical_host_id:
            canonical_host_id = f"host-{computer_name}"
    except Exception:
        canonical_host_id = f"host-{computer_name}"

    def _parse_pid(val: Any) -> int:
        if not val:
            return 0
        if isinstance(val, int):
            return val
        val_str = str(val).strip()
        if val_str.startswith("0x") or val_str.startswith("0X"):
            try:
                return int(val_str, 16)
            except ValueError:
                return 0
        try:
            return int(val_str)
        except ValueError:
            return 0

    pid = _parse_pid(event_data.get("NewProcessId", 0))
    ppid = _parse_pid(event_data.get("ProcessId", 0))

    uid = generate_deterministic_uid("process", {
        "event_id": event_id,
        "process_name": sanitized_proc_name,
        "timestamp": utc_time.isoformat(),
        "pid": pid,
        "host_id": canonical_host_id
    })

    if not sanitized_parent_proc_name and ppid == 0:
        parent_uid = None
    else:
        parent_uid = generate_deterministic_uid("process", {
            "process_name": sanitized_parent_proc_name,
            "pid": ppid,
            "host_id": canonical_host_id
        })
    
    return ProcessActivity(
        trace_id=trace_id,
        activity_id=1, 
        severity_id=1, 
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        security_scan_degraded=is_degraded,
        uid=uid,
        process_name=sanitized_proc_name,
        process_pid=pid,
        command_line=sanitized_cmdline,
        parent_process_name=sanitized_parent_proc_name,
        parent_process_pid=ppid,
        parent_process_uid=parent_uid,
        host_name=computer_name,
        canonical_host_id=canonical_host_id
    )

def normalize_evtx_auth(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    entity_resolver: CanonicalEntityResolver,
    trace_id: str,
) -> Authentication:
    """Normalize EVTX Auth (e.g. 4624, 4625, 4768) to OCSF Authentication."""
    system_block = raw_parsed_event.get("System", {})
    event_data = raw_parsed_event.get("EventData", {})
    
    raw_timestamp = system_block.get("TimeCreated", {}).get("SystemTime", "")
    if not raw_timestamp:
        raw_timestamp = raw_parsed_event.get("TimeCreated", "")
        if isinstance(raw_timestamp, str) and "/Date(" in raw_timestamp:
            from datetime import datetime, timezone
            ms = int(raw_timestamp.split("(")[1].split(")")[0])
            raw_timestamp = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
    
    event_id = system_block.get("EventID", raw_parsed_event.get("Id", 0))
    if isinstance(event_id, str):
        try:
            event_id = int(event_id)
        except ValueError:
            event_id = 0
            
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    raw_user = event_data.get("TargetUserName", event_data.get("TargetUser", ""))
    sanitized_user, _ = sanitize_text(raw_user)
    
    computer_name = system_block.get("Computer") or raw_parsed_event.get("MachineName") or "LOCAL_HOST"
    
    domain = event_data.get("TargetDomainName")
    sid = event_data.get("TargetUserSid")
    user_identity = UserIdentity(name=sanitized_user, domain=domain, sid=sid)
    
    src_ip = event_data.get("IpAddress")
    src_port = event_data.get("IpPort")
    try:
        src_port = int(src_port) if src_port else None
    except ValueError:
        src_port = None
        
    src_endpoint = None
    if src_ip and src_ip not in ("-", ""):
        canonical_src_host = entity_resolver.resolve_any(ip=src_ip, event_timestamp=utc_time)
        src_endpoint = NetworkEndpoint(ip_address=src_ip, port=src_port, canonical_host_uid=canonical_src_host)
        
    try:
        canonical_dst_host = entity_resolver.resolve_any(hostname=computer_name, event_timestamp=utc_time) or f"host-{computer_name}"
    except Exception:
        canonical_dst_host = f"host-{computer_name}"
        
    dst_endpoint = NetworkEndpoint(canonical_host_uid=canonical_dst_host)
    
    logon_type = event_data.get("LogonType")
    try:
        logon_type = int(logon_type) if logon_type else None
    except ValueError:
        logon_type = None

    ticket_options = event_data.get("TicketOptions")
    
    uid = generate_deterministic_uid("auth", {
        "event_id": event_id,
        "user": sanitized_user,
        "timestamp": utc_time.isoformat(),
        "host_id": canonical_dst_host
    })
    
    # 1: Logon, 2: Logoff, 3: TGT Request
    activity_id = 1
    if event_id in (4768, 4769, 4771, 4776, 4648):
        activity_id = 3
    elif event_id == 4634:
        activity_id = 2
        
    return Authentication(
        trace_id=trace_id,
        activity_id=activity_id,
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        uid=uid,
        user=user_identity,
        src_endpoint=src_endpoint,
        dst_endpoint=dst_endpoint,
        auth_protocol=event_data.get("AuthenticationPackageName"),
        logon_type=logon_type,
        ticket_options=ticket_options
    )

def normalize_evtx_network(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    entity_resolver: CanonicalEntityResolver,
    trace_id: str,
) -> NetworkActivity:
    """Normalize EVTX Network (5156, Sysmon 3, Sysmon 22) to OCSF NetworkActivity."""
    system_block = raw_parsed_event.get("System", {})
    event_data = raw_parsed_event.get("EventData", {})
    
    raw_timestamp = system_block.get("TimeCreated", {}).get("SystemTime", "")
    if not raw_timestamp:
        raw_timestamp = raw_parsed_event.get("TimeCreated", "")
        if isinstance(raw_timestamp, str) and "/Date(" in raw_timestamp:
            from datetime import datetime, timezone
            ms = int(raw_timestamp.split("(")[1].split(")")[0])
            raw_timestamp = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
            
    event_id = system_block.get("EventID", raw_parsed_event.get("Id", 0))
    if isinstance(event_id, str):
        try:
            event_id = int(event_id)
        except ValueError:
            event_id = 0
            
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    computer_name = system_block.get("Computer") or raw_parsed_event.get("MachineName") or "LOCAL_HOST"
    try:
        canonical_dst_host = entity_resolver.resolve_any(hostname=computer_name, event_timestamp=utc_time) or f"host-{computer_name}"
    except Exception:
        canonical_dst_host = f"host-{computer_name}"
        
    src_ip = event_data.get("SourceAddress", event_data.get("SourceIp", ""))
    dst_ip = event_data.get("DestAddress", event_data.get("DestinationIp", ""))
    
    if (not src_ip or src_ip.strip() in ("", "-")) and (not dst_ip or dst_ip.strip() in ("", "-")):
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        
    src_port = event_data.get("SourcePort")
    dst_port = event_data.get("DestPort", event_data.get("DestinationPort"))
    protocol = event_data.get("Protocol", "")
    dns_query = event_data.get("QueryName", "")
    
    try:
        src_port = int(src_port) if src_port else None
    except ValueError:
        src_port = None
    try:
        dst_port = int(dst_port) if dst_port else None
    except ValueError:
        dst_port = None

    canonical_src_host = entity_resolver.resolve_any(ip=src_ip, event_timestamp=utc_time) if src_ip else None
    canonical_dst_ip_host = entity_resolver.resolve_any(ip=dst_ip, event_timestamp=utc_time) if dst_ip else None
    
    src_endpoint = NetworkEndpoint(ip_address=src_ip, port=src_port, canonical_host_uid=canonical_src_host)
    dst_endpoint = NetworkEndpoint(ip_address=dst_ip, port=dst_port, canonical_host_uid=canonical_dst_ip_host)
    
    activity_id = 1
    if event_id == 22:
        activity_id = 3 # DNS Query
        
    uid = generate_deterministic_uid("network", {
        "event_id": event_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "timestamp": utc_time.isoformat(),
        "host_id": canonical_dst_host
    })

    return NetworkActivity(
        trace_id=trace_id,
        activity_id=activity_id,
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        uid=uid,
        src_endpoint=src_endpoint,
        dst_endpoint=dst_endpoint,
        protocol=str(protocol) if protocol else None,
        dns_query=dns_query if dns_query else None
    )

def normalize_evtx_file_access(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    entity_resolver: CanonicalEntityResolver,
    trace_id: str,
) -> FileActivity:
    """Normalize EVTX File Access (4663, Sysmon 11, Sysmon 2)."""
    system_block = raw_parsed_event.get("System", {})
    event_data = raw_parsed_event.get("EventData", {})
    
    raw_timestamp = system_block.get("TimeCreated", {}).get("SystemTime", "")
    if not raw_timestamp:
        raw_timestamp = raw_parsed_event.get("TimeCreated", "")
        if isinstance(raw_timestamp, str) and "/Date(" in raw_timestamp:
            from datetime import datetime, timezone
            ms = int(raw_timestamp.split("(")[1].split(")")[0])
            raw_timestamp = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
            
    event_id = system_block.get("EventID", raw_parsed_event.get("Id", 0))
    if isinstance(event_id, str):
        try:
            event_id = int(event_id)
        except ValueError:
            event_id = 0
            
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    computer_name = system_block.get("Computer") or raw_parsed_event.get("MachineName") or "LOCAL_HOST"
    try:
        canonical_host_id = entity_resolver.resolve_any(hostname=computer_name, event_timestamp=utc_time) or f"host-{computer_name}"
    except Exception:
        canonical_host_id = f"host-{computer_name}"
        
    file_path = event_data.get("ObjectName", event_data.get("TargetFilename", ""))
    sanitized_path, is_homoglyph = sanitize_text(file_path)
    
    if not sanitized_path or sanitized_path.strip() == "":
        raise ValueError("File path cannot be empty")
        
    file_name = sanitized_path.split("\\")[-1] if sanitized_path else ""
    
    uid = generate_deterministic_uid("file", {
        "event_id": event_id,
        "file_path": sanitized_path,
        "timestamp": utc_time.isoformat(),
        "host_id": canonical_host_id
    })
    
    si_created = None
    fn_created = None
    
    if event_id == 2: # Sysmon File Creation Time Changed
        raw_create_time = event_data.get("CreationUtcTime")
        raw_prev_time = event_data.get("PreviousCreationUtcTime")
        if raw_create_time:
            si_created, _, _ = time_normalizer.normalize(raw_create_time)
        if raw_prev_time:
            fn_created, _, _ = time_normalizer.normalize(raw_prev_time)

    return FileActivity(
        trace_id=trace_id,
        activity_id=1,
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        uid=uid,
        file_name=file_name,
        file_path=sanitized_path,
        si_created=si_created,
        fn_created=fn_created,
        canonical_host_id=canonical_host_id
    )

def normalize_evtx_defense_evasion(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    entity_resolver: CanonicalEntityResolver,
    trace_id: str,
) -> AuditActivity:
    """Normalize EVTX Defense Evasion (1102, 104 - Audit Log Cleared)."""
    system_block = raw_parsed_event.get("System", {})
    event_data = raw_parsed_event.get("EventData", {})
    
    raw_timestamp = system_block.get("TimeCreated", {}).get("SystemTime", "")
    if not raw_timestamp:
        raw_timestamp = raw_parsed_event.get("TimeCreated", "")
        if isinstance(raw_timestamp, str) and "/Date(" in raw_timestamp:
            from datetime import datetime, timezone
            ms = int(raw_timestamp.split("(")[1].split(")")[0])
            raw_timestamp = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
            
    event_id = system_block.get("EventID", raw_parsed_event.get("Id", 0))
    if isinstance(event_id, str):
        try:
            event_id = int(event_id)
        except ValueError:
            event_id = 0

    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    computer_name = system_block.get("Computer") or raw_parsed_event.get("MachineName") or "LOCAL_HOST"
    try:
        canonical_host_id = entity_resolver.resolve_any(hostname=computer_name, event_timestamp=utc_time) or f"host-{computer_name}"
    except Exception:
        canonical_host_id = f"host-{computer_name}"
        
    uid = generate_deterministic_uid("audit", {
        "event_id": event_id,
        "name": "Audit Log Cleared",
        "timestamp": utc_time.isoformat(),
        "host_id": canonical_host_id
    })
    
    return AuditActivity(
        trace_id=trace_id,
        activity_id=99,
        severity_id=5,  # High severity anomaly
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        uid=uid,
        message="Audit Log Cleared",
        canonical_host_id=canonical_host_id
    )

def normalize_evtx_detection_finding(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    entity_resolver: CanonicalEntityResolver,
    trace_id: str,
) -> DetectionFindingEvent:
    """Normalize EVTX Defender and AppLocker events to DetectionFindingEvent."""
    system_block = raw_parsed_event.get("System", {})
    event_data = raw_parsed_event.get("EventData", {})
    
    raw_timestamp = system_block.get("TimeCreated", {}).get("SystemTime", "")
    if not raw_timestamp:
        raw_timestamp = raw_parsed_event.get("TimeCreated", "")
        if isinstance(raw_timestamp, str) and "/Date(" in raw_timestamp:
            from datetime import datetime, timezone
            ms = int(raw_timestamp.split("(")[1].split(")")[0])
            raw_timestamp = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
            
    event_id = system_block.get("EventID", raw_parsed_event.get("Id", 0))
    if isinstance(event_id, str):
        try:
            event_id = int(event_id)
        except ValueError:
            event_id = 0

    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    computer_name = system_block.get("Computer") or raw_parsed_event.get("MachineName") or "LOCAL_HOST"
    try:
        canonical_host_id = entity_resolver.resolve_any(hostname=computer_name, event_timestamp=utc_time) or f"host-{computer_name}"
    except Exception:
        canonical_host_id = f"host-{computer_name}"
        
    # Extract finding logic
    finding_info = "Unknown Detection"
    severity_id = 3 # Medium default
    
    if event_id in [1116, 1150, 1151, 5007]:
        finding_info = event_data.get("Threat Name", event_data.get("Path", "Windows Defender Detection"))
        severity = event_data.get("Severity ID", "")
        if str(severity) in ("4", "5", "High", "Critical"):
            severity_id = 5
        elif str(severity) in ("1", "Low"):
            severity_id = 2
    elif event_id in [8003, 8004]:
        file_path = event_data.get("FilePath", "")
        finding_info = f"AppLocker Blocked Execution: {file_path}"
        severity_id = 4 # High
        
    uid = generate_deterministic_uid("finding", {
        "event_id": event_id,
        "finding": finding_info,
        "timestamp": utc_time.isoformat(),
        "host_id": canonical_host_id
    })
    
    return DetectionFindingEvent(
        trace_id=trace_id,
        activity_id=1,
        severity_id=severity_id,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        uid=uid,
        finding_info=finding_info,
        attacks=None, # Will be enriched downstream
        canonical_host_id=canonical_host_id
    )
