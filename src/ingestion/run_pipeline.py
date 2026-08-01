"""
Specula Pipeline Runner.

Extracts local Windows System/Security event logs (via PowerShell Get-WinEvent)
and passes them end-to-end through the Specula ingestion pipeline:
1. Preservation (SHA-256 + VCT chain + Quickwit commit stub)
2. Security Gate (Sanitization + Rebuff injection scan)
3. OCSF Normalization (Dual timestamp baseline + EVTX mapping)
4. Validation & Canonical Entity Resolution
5. DFKG Knowledge Graph Cypher query generation

Reference: specula_ingestion_final_plan.md
"""

import json
import logging
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath("."))

from src.schemas.entity_resolver import CanonicalEntityResolver
from src.schemas.uid_generator import generate_deterministic_uid
from src.ingestion.preservation.sha256_hasher import compute_sha256_bytes
from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.rebuff_gate import detect_prompt_injection
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.normalization.evtx_normalizer import normalize_evtx_process_creation
from src.ingestion.validation.validator import validate_event
from src.schemas.ocsf_events import ProcessActivity
from src.graph.cypher_builder import CypherBuilder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SpeculaPipeline")


def extract_windows_events(log_name: str, max_events: int = 50) -> list[dict]:
    """
    Extract Windows Event Logs for a given log channel using PowerShell Get-WinEvent.
    Returns parsed JSON dictionaries.
    """
    ps_command = (
        f"Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} -ErrorAction SilentlyContinue | "
        "Select-Object Id, TimeCreated, ProviderName, Message | "
        "ConvertTo-Json -Compress"
    )
    
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True,
            text=True,
            check=False
        )
        if not res.stdout.strip():
            return []
        data = json.loads(res.stdout)
        if isinstance(data, dict):
            return [data]
        return data
    except Exception as e:
        logger.debug(f"Log channel {log_name} not available or empty: {e}")
        return []


def run_pipeline_on_event(raw_event: dict, vct_chain: VCTAtomicChain, resolver: CanonicalEntityResolver, time_normalizer: TimeNormalizer):
    """Pass a single raw extracted log through the pipeline stages."""
    trace_id = f"trace-{uuid.uuid4().hex[:12]}"
    
    # 1. Preservation & Integrity
    raw_bytes = json.dumps(raw_event).encode("utf-8")
    sha256_digest = compute_sha256_bytes(raw_bytes)
    vct_hash = vct_chain.register_hash(sha256_digest, trace_id, "TEMP_UID")
    
    # 2. Security Gate
    message_text = raw_event.get("Message", "") or raw_event.get("FileName", "") or raw_event.get("eventName", "") or ""
    sanitized_msg, has_homoglyphs = sanitize_text(message_text)
    is_injection, is_degraded = detect_prompt_injection(sanitized_msg)

    # 3. OCSF Normalization
    time_str = raw_event.get("TimeCreated", "") or raw_event.get("LastRecordChange", "") or raw_event.get("eventTime", "")
    if time_str and "/Date(" in str(time_str):
        ms = int(time_str.split("(")[1].split(")")[0])
        time_str = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
    elif not time_str:
        time_str = datetime.now(timezone.utc).isoformat()
        
    utc_time, skew_offset, skew_unverified = time_normalizer.normalize(str(time_str))
    
    # Generate deterministic entity UID
    provider = raw_event.get("ProviderName", raw_event.get("FileName", raw_event.get("eventSource", "Windows")))
    event_id = raw_event.get("Id", 0)
    
    entity_uid = generate_deterministic_uid("process", {
        "event_id": event_id,
        "provider": provider,
        "timestamp": utc_time.isoformat()
    })
    
    # Construct OCSF ProcessActivity event
    ocsf_evt = ProcessActivity(
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
        process_name=sanitize_text(str(provider))[0],
        process_pid=int(event_id) if isinstance(event_id, int) else 0,
        command_line=sanitized_msg[:200],
        host_name="LOCAL_HOST",
        canonical_host_id="uuid-local-host"
    )
    
    # 4. Schema Validation
    validated_evt = validate_event(ocsf_evt.model_dump(mode="json"), ProcessActivity)
    
    # 5. DFKG Knowledge Graph Cypher Builder
    event_dict = ocsf_evt.model_dump(mode="json") if hasattr(ocsf_evt, "model_dump") else ocsf_evt
    cypher_query, cypher_params = CypherBuilder.build_process_creation(event_dict)
    
    return validated_evt, cypher_query


def main():
    logger.info("Extracting logs across all available system channels and categories...")
    
    # 1. Available Windows Event Log Channels
    channels = [
        "System",
        "Security",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-Sysmon/Operational"
    ]
    
    all_extracted_events = {}
    total_count = 0
    
    for channel in channels:
        events = extract_windows_events(channel, max_events=20)
        if events:
            all_extracted_events[channel] = events
            total_count += len(events)
            logger.info(f"Extracted {len(events)} events from channel: {channel}")
        else:
            logger.info(f"Channel {channel}: No events found or insufficient permissions.")

    # 2. Add sample records for non-EVTX categories (MFT, Network, AD Auth, CloudTrail)
    sample_mft = {
        "LastRecordChange": "2026-07-28T12:00:00Z",
        "FileName": "ntds.dit",
        "ParentPath": "C:\\Windows\\NTDS",
        "Created0x10": "2026-07-28T12:00:00Z",
        "Created0x30": "2026-07-28T10:00:00Z", # Timestomped mismatch sample
        "UsnReasonCode": 2,
        "TimestampPrecision": 7
    }
    all_extracted_events["NTFS_MFT_Sample"] = [sample_mft]
    total_count += 1

    sample_cloud = {
        "eventTime": "2026-07-28T12:05:00Z",
        "eventName": "RunInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.45",
        "userAgent": "aws-cli/2.15.0",
        "recipientAccountId": "123456789012"
    }
    all_extracted_events["CloudTrail_Sample"] = [sample_cloud]
    total_count += 1

    # Save all raw extracted log collections to disk
    out_dir = os.path.abspath("data/extracted_logs")
    os.makedirs(out_dir, exist_ok=True)
    
    raw_path = os.path.join(out_dir, "raw_system_events.json")
    with open(raw_path, "w") as f:
        json.dump(all_extracted_events, f, indent=2)
    logger.info(f"Saved {total_count} total raw events across all categories to: {raw_path}")

    # 3. Process all extracted channels through pipeline
    vct_chain = VCTAtomicChain()
    resolver = CanonicalEntityResolver()
    time_normalizer = TimeNormalizer(dc_anchor_skew_ms=0)

    ocsf_outputs = []

    for channel_name, log_list in all_extracted_events.items():
        logger.info(f"--- Processing Category: {channel_name} ({len(log_list)} records) ---")
        for event in log_list:
            validated_evt, _ = run_pipeline_on_event(event, vct_chain, resolver, time_normalizer)
            evt_obj = getattr(validated_evt, "event", validated_evt)
            evt_dict = evt_obj.model_dump(mode="json") if hasattr(evt_obj, "model_dump") else (evt_obj.__dict__ if hasattr(evt_obj, "__dict__") else evt_obj)
            ocsf_outputs.append(evt_dict)

    # Save processed OCSF events to disk
    ocsf_path = os.path.abspath(os.path.join(out_dir, "ocsf_system_events.json"))
    with open(ocsf_path, "w") as f:
        json.dump(ocsf_outputs, f, indent=2)
    logger.info(f"Saved {len(ocsf_outputs)} validated OCSF events to: {ocsf_path}")

    print("\n==========================================================================")
    print("SPECULA LOG INGESTION COMPLETE")
    print("==========================================================================")
    print(f"RAW telemetry logs stored at: {os.path.abspath(raw_path)}")
    print(f"VALIDATED OCSF logs stored at: {ocsf_path}")
    print("==========================================================================")


if __name__ == "__main__":
    main()
