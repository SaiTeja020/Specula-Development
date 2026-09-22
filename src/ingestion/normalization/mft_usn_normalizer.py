"""
Specula NTFS Artifacts to OCSF Normalizer.

Maps $MFT and $USNjrnl records to OCSF format.
Source category 2 (Tier 1 Critical).

Reference: specula_ingestion_final_plan.md §4.3 (Binary ordering) & §5.1

WARNING: Includes $MFT/$USNjrnl-specific fields required for F17 
timestomping detection.
"""

from typing import Any, Dict

from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.rebuff_gate import detect_prompt_injection
from src.schemas.ocsf_events import FileActivity
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.uid_generator import generate_deterministic_uid

# Note: Actual NTFS parsing logic (e.g. MFTECmd) is assumed
# to have run prior to this function, providing a parsed dict.


def normalize_mft_record(
    raw_parsed_record: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    trace_id: str,
) -> FileActivity:
    """
    Normalize an MFT record to OCSF FileActivity.
    
    Adheres strictly to the Binary Source ordering (v6 §4.3):
    1. Binary Structural Parse (done upstream of this).
    2. Text-Field Sanitize (done here per-field).
    3. OCSF Normalization.
    """
    
    # --- 1. Extract raw fields ---
    # Example fields based on standard MFT parsers
    raw_timestamp = raw_parsed_record.get("LastRecordChange", "")
    raw_file_name = raw_parsed_record.get("FileName", "")
    raw_file_path = raw_parsed_record.get("ParentPath", "")
    
    # Critical fields for timestomping detection
    raw_si_created = raw_parsed_record.get("Created0x10", None)
    raw_fn_created = raw_parsed_record.get("Created0x30", None)
    
    # --- 2. Security Gate per-field sanitization ---
    sanitized_file_name, _ = sanitize_text(raw_file_name)
    sanitized_file_path, _ = sanitize_text(raw_file_path)
    
    if (not sanitized_file_name or sanitized_file_name.strip() == "") and (not sanitized_file_path or sanitized_file_path.strip() == ""):
        raise ValueError("File name and path cannot both be empty")
    
    # Rebuff scan on file path (can contain injection payloads)
    is_injection, is_degraded = detect_prompt_injection(sanitized_file_path)
    
    # --- 3. Time Normalization ---
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    # Parse the timestomping fields into UTC
    si_dt = None
    if raw_si_created:
        si_dt, _, _ = time_normalizer.normalize(raw_si_created)
    
    fn_dt = None
    if raw_fn_created:
        fn_dt, _, _ = time_normalizer.normalize(raw_fn_created)
        
    raw_reason = raw_parsed_record.get("UsnReasonCode", None)
    if isinstance(raw_reason, str):
        try:
            raw_reason = int(raw_reason)
        except ValueError:
            raw_reason = None

    # --- 4. OCSF Construction ---
    return FileActivity(
        trace_id=trace_id,
        activity_id=1, # Create/Update
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        security_scan_degraded=is_degraded,
        uid=generate_deterministic_uid("file", {
            "file_name": sanitized_file_name,
            "file_path": sanitized_file_path,
            "timestamp": utc_time.isoformat()
        }),
        file_name=sanitized_file_name,
        file_path=sanitized_file_path,
        # NTFS Timestomping required fields
        si_created=si_dt,
        fn_created=fn_dt,
        usn_reason_code=raw_reason,
        timestamp_precision_bitmask=raw_parsed_record.get("TimestampPrecision", None),
    )
