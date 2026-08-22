"""
Specula Pipeline Runner.

Extracts local Windows System/Security event logs (via PowerShell Get-WinEvent)
and passes them end-to-end through the Specula ingestion pipeline:
1. Preservation  (SHA-256 + VCT chain + Quickwit append-only commit)
2. Security Gate (Sanitization + Rebuff injection scan)
3. OCSF Normalization (Dual timestamp baseline + EVTX mapping)
4. Validation & Canonical Entity Resolution
5. DFKG Knowledge Graph write (Neo4j MERGE via parameterized Cypher)

Reference: specula_ingestion_final_plan.md
"""

import argparse
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
from src.ingestion.preservation.quickwit_client import QuickwitClient, QuickwitClientError
from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.pipeline import run_security_gate
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.normalization.evtx_normalizer import normalize_evtx_process_creation
from src.ingestion.normalization.mft_usn_normalizer import normalize_mft_record
from src.ingestion.normalization.cloud_normalizer import normalize_cloudtrail
from src.ingestion.validation.validator import validate_event
from src.schemas.ocsf_events import ProcessActivity, FileActivity, CloudAudit
from src.graph.cypher_builder import CypherBuilder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SpeculaPipeline")

# ---------------------------------------------------------------------------
# Quickwit feature flag.
# Set SPECULA_QUICKWIT_ENABLED=true in your environment when the docker-compose
# stack is running. When false, preservation is logged as a warning and skipped
# so local dev without Docker still works.
# ---------------------------------------------------------------------------
QUICKWIT_ENABLED: bool = os.environ.get("SPECULA_QUICKWIT_ENABLED", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Neo4j feature flag.
# Set SPECULA_NEO4J_ENABLED=true when the docker-compose stack is running.
# When false, Cypher is built but not executed (logged as a warning).
# Neo4j write failure is NON-FATAL — unlike Quickwit, graph nodes can be
# replayed from raw evidence. Losing preservation is permanent; graph is not.
# ---------------------------------------------------------------------------
NEO4J_ENABLED: bool = os.environ.get("SPECULA_NEO4J_ENABLED", "false").lower() == "true"

# Maps channel/category names to OCSF-style source_type labels
_SOURCE_TYPE_MAP: dict[str, str] = {
    "System": "evtx",
    "Security": "evtx",
    "Application": "evtx",
    "Microsoft-Windows-PowerShell/Operational": "evtx",
    "Microsoft-Windows-Windows Defender/Operational": "evtx",
    "Microsoft-Windows-TaskScheduler/Operational": "evtx",
    "Microsoft-Windows-Sysmon/Operational": "evtx",
    "NTFS_MFT": "mft",
    "CloudTrail": "cloudtrail",
    "Containers": "container",
    "Network_PCAP": "network",
    "EDR_Telemetry": "edr",
    "Email_Gateway": "email",
    "Malware_Sandbox": "malware",
    "Memory_Dump": "memory_dump",
    "Cloud_Topology": "cloud_topology",
    "UEBA_Browser": "ueba_browser",
    "Vulnerability_Scan": "vuln_scan",
    "AD_Auth": "ad_auth",
}


def extract_windows_events(log_name: str, max_events: int = 50, start_time: str = None, end_time: str = None) -> list[dict]:
    """
    Extract Windows Event Logs for a given log channel using PowerShell Get-WinEvent.
    Returns parsed JSON dictionaries.
    """
    time_filter = ""
    if start_time and end_time:
        time_filter = f" -FilterHashTable @{{LogName='{log_name}'; StartTime='{start_time}'; EndTime='{end_time}'}} "
    elif start_time:
        time_filter = f" -FilterHashTable @{{LogName='{log_name}'; StartTime='{start_time}'}} "
    elif end_time:
        time_filter = f" -FilterHashTable @{{LogName='{log_name}'; EndTime='{end_time}'}} "
    
    if time_filter:
        ps_command = (
            f"Get-WinEvent {time_filter} -ErrorAction SilentlyContinue | "
            f"Select-Object -First {max_events} Id, TimeCreated, ProviderName, Message | "
            "ConvertTo-Json -Compress"
        )
    else:
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


def run_pipeline_on_event(
    raw_event: dict,
    vct_chain: VCTAtomicChain,
    resolver: CanonicalEntityResolver,
    time_normalizer: TimeNormalizer,
    qw_client: "QuickwitClient | None" = None,
    source_type: str = "evtx",
    neo4j_client=None,
):
    """Pass a single raw extracted log through the pipeline stages."""
    trace_id = f"trace-{uuid.uuid4().hex[:12]}"
    
    # 1. Preservation & Integrity
    # Raw bytes are captured BEFORE any sanitization or parsing — chain of custody requires this.
    raw_bytes = json.dumps(raw_event).encode("utf-8")
    sha256_digest = compute_sha256_bytes(raw_bytes)
    vct_hash = vct_chain.register_hash(sha256_digest, trace_id, "TEMP_UID")
    
    # 1b. Quickwit append-only commit (fatal if enabled and Quickwit is down)
    if qw_client is not None:
        # sha256_digest is the content-addressable uid for raw evidence in Quickwit
        qw_client.commit_raw_evidence(
            uid=sha256_digest,
            trace_id=trace_id,
            sha256_digest=sha256_digest,
            raw_bytes=raw_bytes,
            source_type=source_type,
        )
        logger.debug(f"Quickwit preservation committed: trace_id={trace_id} sha256={sha256_digest[:12]}...")

    # 2. Security Gate (sanitize + injection scan per Stage 2 §3 Step 2)
    message_text = raw_event.get("Message", "") or raw_event.get("FileName", "") or raw_event.get("eventName", "") or ""
    raw_msg_bytes = message_text.encode("utf-8")
    gate_result = run_security_gate("text", raw_msg_bytes)

    if gate_result.injection_blocked:
        logger.warning(f"Event blocked by Security Gate — injection detected (trace={trace_id})")
        return None, None, None

    sanitized_msg = gate_result.sanitized_fields[0] if gate_result.sanitized_fields else ""
    has_homoglyphs = False  # Homoglyph flag is on the SanitizerResult, not needed here
    is_injection = gate_result.injection_blocked
    is_degraded = False

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
    
    # 3. Dynamic Normalizer Routing
    schema_class = None
    try:
        import importlib
        
        # Map source_type to module and function name
        # If the specific normalizer is unavailable, it will trigger the except block
        module_name = f"src.ingestion.normalization.{source_type}_normalizer"
        if source_type == "mft":
            module_name = "src.ingestion.normalization.mft_usn_normalizer"
            func_name = "normalize_mft_record"
        elif source_type == "cloudtrail":
            module_name = "src.ingestion.normalization.cloud_normalizer"
            func_name = "normalize_cloudtrail"
        elif source_type == "evtx":
            func_name = "normalize_evtx_process_creation"
        else:
            func_name = f"normalize_{source_type}"

        # Try to retrieve the normalizer module
        module = importlib.import_module(module_name)
        normalizer_func = getattr(module, func_name)
        
        # CloudTrail has special time normalizer
        if source_type == "cloudtrail":
            time_normalizer_cloud = TimeNormalizer(dc_anchor_skew_ms=None)
            ocsf_evt = normalizer_func(raw_event, time_normalizer_cloud, trace_id)
            schema_class = CloudAudit
        else:
            ocsf_evt = normalizer_func(raw_event, time_normalizer, trace_id)
            if source_type == "mft":
                schema_class = FileActivity
            elif source_type == "evtx":
                schema_class = ProcessActivity
            else:
                # If we have other specific schemas, we'd assign them here
                # For now, if we loaded the module, assume it returns its specific type
                schema_class = type(ocsf_evt)
                
        # Assign real uid
        evt_dict = ocsf_evt.model_dump() if hasattr(ocsf_evt, "model_dump") else ocsf_evt.__dict__
        evt_dict["uid"] = entity_uid
        if source_type == "evtx":
            evt_dict["canonical_host_id"] = "uuid-local-host"
        ocsf_evt = schema_class(**evt_dict)

    except (ImportError, AttributeError, Exception) as e:
        logger.debug(f"Normalizer retrieval failed for {source_type} ({e}). Falling back to heuristic.")
        from src.ingestion.normalization.heuristic_normalizer import normalize_heuristic
        from src.schemas.ocsf_events import GenericEvent
        ocsf_evt = normalize_heuristic(raw_event, time_normalizer, trace_id)
        schema_class = GenericEvent
        evt_dict = ocsf_evt.model_dump()
        evt_dict["uid"] = entity_uid
        ocsf_evt = GenericEvent(**evt_dict)
    
    # 4. Schema Validation
    validated_evt = validate_event(ocsf_evt.model_dump(mode="json") if hasattr(ocsf_evt, "model_dump") else ocsf_evt, schema_class)
    
    # 5. DFKG Knowledge Graph — build Cypher and execute against Neo4j
    event_dict = ocsf_evt.model_dump(mode="json") if hasattr(ocsf_evt, "model_dump") else ocsf_evt
    
    # Simple dynamic dispatch to CypherBuilder
    if schema_class == ProcessActivity:
        cypher_query, cypher_params = CypherBuilder.build_process_creation(event_dict)
    elif hasattr(CypherBuilder, "build_file_activity") and schema_class == FileActivity:
        cypher_query, cypher_params = CypherBuilder.build_file_activity(event_dict)
    elif hasattr(CypherBuilder, "build_cloud_audit") and schema_class == CloudAudit:
        cypher_query, cypher_params = CypherBuilder.build_cloud_audit(event_dict)
    else:
        cypher_query, cypher_params = CypherBuilder.build_node_merge("Event", uid=entity_uid, props=event_dict)

    neo4j_result = None
    if neo4j_client is not None:
        try:
            neo4j_result = neo4j_client.execute(cypher_query, cypher_params)
            logger.debug(f"Neo4j MERGE executed: trace_id={trace_id}")
        except Exception as e:
            # Non-fatal: log and continue. Graph can be replayed from Quickwit.
            logger.warning(f"Neo4j write failed (non-fatal): {e} | trace_id={trace_id}")

    return validated_evt, cypher_query, neo4j_result


def main():
    parser = argparse.ArgumentParser(description="Specula Pipeline Runner")
    parser.add_argument("--start", type=str, help="Start timestamp (ISO-8601)", default=None)
    parser.add_argument("--end", type=str, help="End timestamp (ISO-8601)", default=None)
    args = parser.parse_args()

    mode_str = "LIVE" if not args.start and not args.end else "HISTORICAL"
    logger.info(f"Starting pipeline in {mode_str} mode. Extracting logs across all available system channels...")
    
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
        events = extract_windows_events(channel, max_events=50, start_time=args.start, end_time=args.end)
        if events:
            all_extracted_events[channel] = events
            total_count += len(events)
            logger.info(f"Extracted {len(events)} events from channel: {channel}")
        else:
            logger.info(f"Channel {channel}: No events found or insufficient permissions.")

    # 2. Extract logs from remaining categories, with heuristic fallback if retrieval is not possible
    
    # NTFS MFT extraction
    logger.info("Triggering UAC prompt to extract real MFT/USN journal records...")
    mft_out_file = os.path.abspath("data/extracted_logs/temp_mft.json")
    script_path = os.path.abspath("src/ingestion/extractors/usn_extractor.ps1")
    
    ps_cmd = f"Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"{script_path}\" -OutputPath \"{mft_out_file}\"'"
    
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], check=True)
        if os.path.exists(mft_out_file):
            with open(mft_out_file, "r", encoding="utf-8-sig") as f:
                content = f.read()
                if content.strip():
                    mft_events = json.loads(content)
                    if isinstance(mft_events, dict):
                        mft_events = [mft_events]
                    all_extracted_events["NTFS_MFT"] = mft_events
                    total_count += len(mft_events)
                    logger.info(f"Extracted {len(mft_events)} real events from USN Journal.")
            os.remove(mft_out_file)
        else:
            raise FileNotFoundError("MFT output file not generated")
    except Exception as e:
        logger.warning(f"MFT extraction failed ({e}). Adding heuristic fallback sample.")
        all_extracted_events["NTFS_MFT"] = [{
            "LastRecordChange": "2026-08-21T12:00:00Z",
            "FileName": "sample_mft_heuristic.exe"
        }]
        total_count += 1

    # Container logs extraction
    try:
        logger.info("Attempting to retrieve active container logs from Docker...")
        container_events = []
        active_containers = ["specula-neo4j", "specula-quickwit", "specula-kafka", "specula-redis"]
        
        for c_name in active_containers:
            try:
                res = subprocess.run(["docker", "logs", "--tail", "5", c_name], capture_output=True, text=True, check=True)
                # Combine stdout and stderr since some containers log to stderr
                output = res.stdout.strip() + "\n" + res.stderr.strip()
                for line in output.split("\n"):
                    if line.strip():
                        # Wrap raw text logs into a dict so the normalizer can parse them
                        container_events.append({
                            "eventTime": datetime.now(timezone.utc).isoformat(),
                            "eventName": "DockerLogEntry",
                            "image": c_name,
                            "Message": line.strip()
                        })
            except Exception:
                continue
                
        if container_events:
            all_extracted_events["Containers"] = container_events
            total_count += len(container_events)
            logger.info(f"Extracted {len(container_events)} real logs from active Docker containers.")
        else:
            raise Exception("No container logs could be extracted from active infrastructure.")
    except Exception as e:
        logger.warning(f"Container log retrieval failed ({e}). Adding heuristic fallback sample.")
        all_extracted_events["Containers"] = [{
            "eventTime": "2026-08-21T12:05:00Z",
            "eventName": "ContainerExec",
            "image": "nginx:latest",
            "heuristic_fallback": True
        }]
        total_count += 1

    # Generate heuristic fallbacks for the remaining categories that don't have explicit scripts
    heuristic_fallbacks = {
        "CloudTrail": {"eventTime": "2026-07-28T12:05:00Z", "eventName": "RunInstances", "eventSource": "ec2.amazonaws.com"},
        "Network_PCAP": {"timestamp": "2026-08-21T12:10:00Z", "type": "packet", "src_ip": "10.0.0.5"},
        "EDR_Telemetry": {"date": "2026-08-21T12:15:00Z", "Action": "ProcessInject", "ProviderName": "CrowdStrike"},
        "Email_Gateway": {"time": "2026-08-21T12:20:00Z", "subject": "Invoice", "sender": "bad@evil.com"},
        "Malware_Sandbox": {"log_time": "2026-08-21T12:25:00Z", "event_type": "file_drop", "hash": "abcd"},
        "Memory_Dump": {"eventTime": "2026-08-21T12:30:00Z", "eventName": "Volatility_Malfind"},
        "Cloud_Topology": {"eventTime": "2026-08-21T12:35:00Z", "eventName": "VPC_Configuration"},
        "UEBA_Browser": {"TimeCreated": "2026-08-21T12:40:00Z", "eventName": "Login_Anomaly"},
        "Vulnerability_Scan": {"eventTime": "2026-08-21T12:45:00Z", "eventName": "Nessus_Scan"},
        "AD_Auth": {"TimeCreated": "2026-08-21T12:50:00Z", "ProviderName": "Microsoft-Windows-Security-Auditing", "Id": 4624}
    }
    
    for category, sample in heuristic_fallbacks.items():
        if category not in all_extracted_events:
            logger.info(f"Adding heuristic fallback sample for {category}")
            sample["heuristic_fallback"] = True
            all_extracted_events[category] = [sample]
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

    # Quickwit: ensure index exists (idempotent) and create client once
    qw_client = None
    if QUICKWIT_ENABLED:
        qw_client = QuickwitClient()
        try:
            qw_client.ensure_index()
            logger.info("Quickwit index verified/created. Preservation is ACTIVE.")
        except QuickwitClientError as e:
            logger.error(f"Quickwit startup failed — cannot guarantee chain of custody: {e}")
            raise
    else:
        logger.warning(
            "SPECULA_QUICKWIT_ENABLED is not set. "
            "Quickwit preservation is DISABLED. "
            "Do not use this mode for production or evidentiary runs."
        )

    # Neo4j: apply schema constraints and create client once
    neo4j_client = None
    if NEO4J_ENABLED:
        try:
            from src.graph.neo4j_client import Neo4jClient, Neo4jClientError
            neo4j_client = Neo4jClient()
            schema_path = os.path.abspath("src/graph/schema_constraints.cypher")
            if os.path.exists(schema_path):
                neo4j_client.apply_schema(schema_path)
            logger.info("Neo4j connected and schema applied. Graph writes are ACTIVE.")
        except Exception as e:
            logger.error(f"Neo4j startup failed — graph writes disabled: {e}")
            neo4j_client = None  # Non-fatal: degrade to no-graph mode
    else:
        logger.warning(
            "SPECULA_NEO4J_ENABLED is not set. "
            "Neo4j graph writes are DISABLED. "
            "Events are normalized and validated but not written to the DFKG."
        )

    neo4j_write_count = 0
    ocsf_outputs = []

    for channel_name, log_list in all_extracted_events.items():
        source_type = _SOURCE_TYPE_MAP.get(channel_name, "evtx")
        logger.info(f"--- Processing Category: {channel_name} (source_type={source_type}, {len(log_list)} records) ---")
        for event in log_list:
            validated_evt, _, neo4j_result = run_pipeline_on_event(
                event, vct_chain, resolver, time_normalizer,
                qw_client=qw_client,
                source_type=source_type,
                neo4j_client=neo4j_client,
            )
            if validated_evt is None:
                logger.info("Event blocked by Security Gate — skipping.")
                continue
            if neo4j_result is not None:
                neo4j_write_count += 1
            evt_obj = getattr(validated_evt, "event", validated_evt)
            evt_dict = evt_obj.model_dump(mode="json") if hasattr(evt_obj, "model_dump") else (evt_obj.__dict__ if hasattr(evt_obj, "__dict__") else evt_obj)
            ocsf_outputs.append(evt_dict)

    # Close Neo4j driver cleanly
    if neo4j_client is not None:
        neo4j_client.close()

    # Save processed OCSF events to disk
    ocsf_path = os.path.abspath(os.path.join(out_dir, "ocsf_system_events.json"))
    with open(ocsf_path, "w") as f:
        json.dump(ocsf_outputs, f, indent=2)
    logger.info(f"Saved {len(ocsf_outputs)} validated OCSF events to: {ocsf_path}")

    print("\n==========================================================================")
    print("SPECULA LOG INGESTION COMPLETE")
    print("==========================================================================")
    print(f"RAW telemetry logs stored at:    {os.path.abspath(raw_path)}")
    print(f"VALIDATED OCSF logs stored at:   {ocsf_path}")
    print(f"Neo4j graph nodes written:       {neo4j_write_count} / {len(ocsf_outputs)}")
    print("==========================================================================")


if __name__ == "__main__":
    main()
