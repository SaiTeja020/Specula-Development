"""
Specula EVTX to OCSF Normalizer.

Maps Windows EVTX (System Logs) to OCSF format.
Source category 1 (Tier 1 Critical).

Reference: specula_ingestion_final_plan.md §4.3 (Binary ordering) & §5.1
"""

from typing import Any, Dict

from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.rebuff_gate import detect_prompt_injection
from src.schemas.ocsf_events import ProcessActivity
from src.ingestion.normalization.time_normalizer import TimeNormalizer

# Mapping subset for ProcessActivity (4688, Sysmon 1)
# Note: Actual EVTX parsing logic (e.g. EvtxECmd or python-evtx) is assumed
# to have run prior to this function, providing a parsed dict.


def normalize_evtx_process_creation(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    trace_id: str,
) -> ProcessActivity:
    """
    Normalize an EVTX process creation event to OCSF ProcessActivity.
    
    Adheres strictly to the Binary Source ordering (v6 §4.3):
    1. Binary Structural Parse (done upstream of this).
    2. Text-Field Sanitize (done here per-field).
    3. OCSF Normalization.
    """
    
    # --- 1. Extract raw fields ---
    # Support both nested python-evtx XML-JSON and flat PowerShell Get-WinEvent formats
    system_block = raw_parsed_event.get("System", {})
    event_data = raw_parsed_event.get("EventData", {})
    
    raw_timestamp = system_block.get("TimeCreated", {}).get("SystemTime", "")
    if not raw_timestamp:
        raw_timestamp = raw_parsed_event.get("TimeCreated", "")
        # Handle PowerShell JSON /Date(...) format
        if isinstance(raw_timestamp, str) and "/Date(" in raw_timestamp:
            from datetime import datetime, timezone
            ms = int(raw_timestamp.split("(")[1].split(")")[0])
            raw_timestamp = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
    
    event_id = system_block.get("EventID", raw_parsed_event.get("Id", 0))
    
    # 4688 mapping / fallback to flat Message
    raw_cmdline = event_data.get("CommandLine") or raw_parsed_event.get("Message") or ""
    raw_process_name = event_data.get("NewProcessName") or raw_parsed_event.get("ProviderName") or ""
    raw_parent_process_name = event_data.get("ParentProcessName") or ""
    
    # --- 2. Security Gate per-field sanitization ---
    # Apply NFKC/zero-width stripping and prompt-injection detection to string fields
    sanitized_cmdline, has_homoglyphs = sanitize_text(raw_cmdline)
    is_injection, is_degraded = detect_prompt_injection(sanitized_cmdline or "")
    
    sanitized_proc_name, _ = sanitize_text(raw_process_name)
    sanitized_parent_proc_name, _ = sanitize_text(raw_parent_process_name)
    
    # --- 3. Time Normalization ---
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    # --- 4. UID Generation (deferred to central pipeline, set dummy here for Pydantic) ---
    # The actual deterministic UID uses canonical_host_id which is resolved later
    
    # --- 5. OCSF Construction ---
    return ProcessActivity(
        trace_id=trace_id,
        activity_id=1, # Create
        severity_id=1, # Informational
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        security_scan_degraded=is_degraded,
        uid="PENDING_UID", # Replaced during final schema validation pipeline
        process_name=sanitized_proc_name,
        process_pid=int(event_data.get("NewProcessId", 0) or 0),
        command_line=sanitized_cmdline,
        parent_process_name=sanitized_parent_proc_name,
        # Other fields would be populated from event_data
    )
