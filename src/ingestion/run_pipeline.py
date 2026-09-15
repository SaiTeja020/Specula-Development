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
from src.ingestion.normalization.evtx_normalizer import (
    normalize_evtx_process_creation, normalize_evtx_auth,
    normalize_evtx_network, normalize_evtx_file_access,
    normalize_evtx_defense_evasion, normalize_evtx_detection_finding
)
from src.ingestion.normalization.mft_usn_normalizer import normalize_mft_record
from src.ingestion.normalization.cloud_normalizer import normalize_cloudtrail
from src.ingestion.validation.validator import validate_event
from src.schemas.ocsf_events import ProcessActivity, GenericEvent, FileActivity, CloudAudit
from src.ingestion.normalization.edr_normalizer import normalize as normalize_edr
from src.ingestion.normalization.malware_normalizer import normalize as normalize_malware
from src.ingestion.normalization.memory_dump_normalizer import normalize as normalize_memory
from src.ingestion.normalization.ueba_browser_normalizer import normalize as normalize_ueba
from src.ingestion.normalization.vuln_scan_normalizer import normalize as normalize_vuln
from src.graph.cypher_builder import CypherBuilder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SpeculaPipeline")

# Silence noisy third-party loggers
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("neo4j").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

_warned_evtx_ids = set()

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
    "NTFS_MFT_Sample": "mft",
    "CloudTrail_Sample": "cloudtrail",
    "EDR_Telemetry": "edr",
    "Malware_Sandbox": "malware",
    "Memory_Dump": "memory",
    "UEBA_Browser": "ueba",
    "Vulnerability_Scan": "vuln_scan"
}


def extract_windows_events(log_name: str, start_time: str = None, end_time: str = None, max_events: int = 50) -> list[dict]:
    """
    Extract Windows Event Logs for a given log channel using PowerShell Get-WinEvent.
    Returns parsed JSON dictionaries.
    """
    if start_time and end_time:
        ps_command = (
            f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; StartTime='{start_time}'; EndTime='{end_time}'}} -MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            "Select-Object Id, TimeCreated, ProviderName, Message | "
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
    qw_client: QuickwitClient = None,
    source_type: str = "evtx",
    neo4j_client = None,
    exclude_ports: set[int] = None,
) -> list:
    trace_id = raw_event.get("trace_id", str(uuid.uuid4()))
    raw_event["trace_id"] = trace_id
    
    if qw_client is not None:
        raw_event["vct_merkle_root"] = vct_chain.current_chain_hash
        sha256_hash = compute_sha256_bytes(json.dumps(raw_event, sort_keys=True).encode("utf-8"))
        raw_event["sha256_hash"] = sha256_hash
        vct_chain.register(sha256_digest=sha256_hash, trace_id=trace_id)
        
        try:
            uid = raw_event.get("uid", generate_deterministic_uid("raw_event", raw_event))
            raw_bytes = json.dumps(raw_event, sort_keys=True).encode("utf-8")
            qw_client.commit_raw_evidence(
                uid=uid,
                trace_id=trace_id,
                sha256_digest=sha256_hash,
                raw_bytes=raw_bytes,
                source_type=source_type
            )
            qw_result = True
        except QuickwitClientError as e:
            logger.error(f"Preservation failure for trace {trace_id}: {e}")
            qw_result = None
    else:
        qw_result = None

    raw_msg_bytes = json.dumps(raw_event, sort_keys=True).encode("utf-8")
    gate_result = run_security_gate("text", raw_msg_bytes)
    if gate_result.injection_blocked:
        logger.warning(f"Event blocked by Security Gate — injection detected (trace={trace_id})")
        return []

    time_str = raw_event.get("TimeCreated", "") or raw_event.get("LastRecordChange", "") or raw_event.get("eventTime", "")
    if time_str and "/Date(" in str(time_str):
        ms = int(time_str.split("(")[1].split(")")[0])
        time_str = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
    elif not time_str:
        time_str = datetime.now(timezone.utc).isoformat()
        
    utc_time, skew_offset, skew_unverified = time_normalizer.normalize(str(time_str))
    
    ocsf_evts = []
    
    if source_type == "evtx":
        event_id = raw_event.get("Id", raw_event.get("System", {}).get("EventID", 0))
        if isinstance(event_id, str):
            try:
                event_id = int(event_id)
            except ValueError:
                event_id = 0
                
        provider = raw_event.get("ProviderName") or raw_event.get("System", {}).get("Provider", {}).get("Name", "")
        is_security = "Security-Auditing" in provider
        is_sysmon = "Sysmon" in provider
        
        ocsf_evt = None
        if event_id in [4688, 1, 7045] or (event_id in [4100, 4103, 4104] and "PowerShell" in provider):
            ocsf_evt = normalize_evtx_process_creation(raw_event, time_normalizer, resolver, trace_id)
        elif (event_id in [1002, 1116, 1150, 1151, 5007] and "Defender" in provider) or (event_id in [8003, 8004] and "AppLocker" in provider):
            ocsf_evt = normalize_evtx_detection_finding(raw_event, time_normalizer, resolver, trace_id)
        elif event_id in [104, 1102]:
            ocsf_evt = normalize_evtx_defense_evasion(raw_event, time_normalizer, resolver, trace_id)
        elif event_id in (4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4771, 4776) and is_security:
            ocsf_evt = normalize_evtx_auth(raw_event, time_normalizer, resolver, trace_id)
        elif event_id == 5156 and is_security:
            ocsf_evt = normalize_evtx_network(raw_event, time_normalizer, resolver, trace_id)
        elif event_id in (3, 22) and is_sysmon:
            ocsf_evt = normalize_evtx_network(raw_event, time_normalizer, resolver, trace_id)
        elif event_id == 4663 and is_security:
            ocsf_evt = normalize_evtx_file_access(raw_event, time_normalizer, resolver, trace_id)
        elif event_id in (11, 2) and is_sysmon:
            ocsf_evt = normalize_evtx_file_access(raw_event, time_normalizer, resolver, trace_id)
        elif event_id in [4698, 106, 140]:
            ocsf_evt = normalize_evtx_process_creation(raw_event, time_normalizer, resolver, trace_id)
        elif event_id in [1000, 1001, 1002] and "Application" in provider:
            ocsf_evt = normalize_evtx_detection_finding(raw_event, time_normalizer, resolver, trace_id)
        else:
            if event_id not in _warned_evtx_ids:
                logger.warning(f"EVTX event dropped (unsupported EventID {event_id} from {provider})")
                _warned_evtx_ids.add(event_id)
        
        if ocsf_evt:
            ocsf_evt.case_id = "UNASSIGNED_CONTINUOUS"
            ocsf_evts.append(ocsf_evt)
            
    elif source_type == "mft":
        ocsf_evt = normalize_mft_record(raw_event, time_normalizer, trace_id)
        ocsf_evt.case_id = "UNASSIGNED_CONTINUOUS"
        if not ocsf_evt.canonical_host_id:
            ocsf_evt.canonical_host_id = resolver.resolve_any(hostname="LOCAL_HOST") or "host-LOCAL_HOST"
        ocsf_evts.append(ocsf_evt)
    elif source_type == "cloudtrail":
        ocsf_evt = normalize_cloudtrail(raw_event, time_normalizer, trace_id)
        ocsf_evt.case_id = "UNASSIGNED_CONTINUOUS"
        if not ocsf_evt.canonical_host_id:
            ocsf_evt.canonical_host_id = resolver.resolve_any(cloud_device_id=ocsf_evt.cloud_account_id)
        ocsf_evts.append(ocsf_evt)
    elif source_type == "edr":
        ocsf_evts.extend(normalize_edr(raw_event, trace_id, "UNASSIGNED_CONTINUOUS", resolver))
    elif source_type == "malware":
        ocsf_evts.extend(normalize_malware(raw_event, trace_id, "UNASSIGNED_CONTINUOUS"))
    elif source_type == "memory":
        ocsf_evts.extend(normalize_memory(raw_event, trace_id, "UNASSIGNED_CONTINUOUS"))
    elif source_type == "ueba":
        ocsf_evts.extend(normalize_ueba(raw_event, trace_id, "UNASSIGNED_CONTINUOUS"))
    elif source_type == "vuln_scan":
        ocsf_evts.extend(normalize_vuln(raw_event, trace_id, "UNASSIGNED_CONTINUOUS"))
    else:
        logger.warning(f"Event dropped (unsupported source type {source_type})")
    
    results = []
    for ocsf_evt in ocsf_evts:
        if exclude_ports:
            # Check if this event has endpoints with excluded ports
            dst_port = getattr(getattr(ocsf_evt, "dst_endpoint", None), "port", None)
            src_port = getattr(getattr(ocsf_evt, "src_endpoint", None), "port", None)
            if (dst_port in exclude_ports) or (src_port in exclude_ports):
                continue

        validated_evt = validate_event(ocsf_evt.model_dump(mode="json") if hasattr(ocsf_evt, 'model_dump') else ocsf_evt, type(ocsf_evt))
        event_dict = ocsf_evt.model_dump(mode="json") if hasattr(ocsf_evt, "model_dump") else ocsf_evt
        cypher_query, cypher_params = CypherBuilder.dispatch_event(event_dict)

        neo4j_result = None
        if neo4j_client is not None and cypher_query:
            try:
                neo4j_result = neo4j_client.execute(cypher_query, cypher_params)
                logger.debug(f"Neo4j MERGE executed: trace_id={trace_id}")
            except Exception as e:
                logger.warning(f"Neo4j write failed (non-fatal): {e} | trace_id={trace_id}")

        results.append((validated_evt, cypher_query, neo4j_result))

    return results

import argparse

def main():
    parser = argparse.ArgumentParser(description="Run the Specula ingestion pipeline.")
    parser.add_argument("--start-time", dest="start_time", type=str, default=None, help="Start date and time (e.g., '2026-08-25T00:00:00')")
    parser.add_argument("--end-time", dest="end_time", type=str, default=None, help="End date and time (e.g., '2026-08-25T12:00:00'). Defaults to current date and time if start_time is provided.")
    parser.add_argument("--max-events", dest="max_events", type=int, default=2000, help="Max events to extract per channel.")
    parser.add_argument("--exclude-ports", dest="exclude_ports", type=str, default="80,443,53", help="Comma-separated list of ports to exclude from network events (e.g., '80,443,53')")
    args = parser.parse_args()

    exclude_ports = {int(p.strip()) for p in args.exclude_ports.split(",") if p.strip().isdigit()} if args.exclude_ports else set()

    start_time = args.start_time
    end_time = args.end_time
    if start_time and not end_time:
        end_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    if start_time:
        logger.info(f"Extracting logs from {start_time} to {end_time}...")
    else:
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
        events = extract_windows_events(channel, start_time=start_time, end_time=end_time, max_events=args.max_events)
        if events:
            all_extracted_events[channel] = events
            total_count += len(events)
            logger.info(f"Extracted {len(events)} events from channel: {channel}")
        else:
            logger.info(f"Channel {channel}: No events found or insufficient permissions.")

    # 2. Add sample records for non-EVTX categories (MFT, Network, AD Auth, CloudTrail)
    # Extract real MFT/USN records using a UAC-prompted PowerShell script
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
                    all_extracted_events["NTFS_MFT_Sample"] = mft_events
                    total_count += len(mft_events)
                    logger.info(f"Extracted {len(mft_events)} real events from USN Journal.")
            # Clean up the temp file
            os.remove(mft_out_file)
        else:
            logger.warning("UAC prompt declined or extraction failed. Skipping MFT extraction.")
    except Exception as e:
        logger.error(f"Failed to execute USN extraction script: {e}")

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
            
            logger.info("Temporarily clearing Neo4j database...")
            neo4j_client.execute("MATCH (n) DETACH DELETE n", {})
            
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
            results = run_pipeline_on_event(
                event, vct_chain, resolver, time_normalizer,
                qw_client=qw_client,
                source_type=source_type,
                neo4j_client=neo4j_client,
                exclude_ports=exclude_ports,
            )
            if not results:
                logger.debug("Event blocked or dropped.")
                continue
            for validated_evt, _, neo4j_result in results:
                if validated_evt is None:
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

    # --- Entropy-Based Semantic Distillation ---
    try:
        from src.ingestion.distillation.distillation_layer import DistillationLayer
        logger.info("--- Starting Entropy-Based Semantic Distillation ---")
        distiller = DistillationLayer(entropy_threshold=0.3)
        distilled_batch = distiller.process_batch(ocsf_outputs)
        logger.info(f"Distillation reduced {len(ocsf_outputs)} events to {len(distilled_batch)} nodes.")

        # --- ChromaDB Vectorization ---
        from src.ingestion.indexing.vector_store import ChromaVectorStore, EmbeddingGenerator
        import uuid
        # Use the HttpClient to connect to the Docker container (default behavior when persist_dir is None)
        v_store = ChromaVectorStore(collection_name="specula_dfkg_embeddings")
        embedder = EmbeddingGenerator()
        
        for dist_evt in distilled_batch:
            text_repr = str(dist_evt.get("Message", dist_evt))
            vector = embedder.embed(text_repr)
            uid = dist_evt.get("uid", str(uuid.uuid4()))
            v_store.upsert(
                record_id=uid,
                text=text_repr,
                vector=vector,
                metadata={"case_id": dist_evt.get("case_id", "UNASSIGNED")}
            )
            
        logger.info(f"Vectorization active: Successfully embedded {len(distilled_batch)} compressed nodes into ChromaDB.")
    except Exception as e:
        logger.error(f"Semantic Distillation or Vectorization failed: {e}")

    print("\n==========================================================================")
    print("SPECULA LOG INGESTION COMPLETE")
    print("==========================================================================")
    print(f"RAW telemetry logs stored at:    {os.path.abspath(raw_path)}")
    print(f"VALIDATED OCSF logs stored at:   {ocsf_path}")
    print(f"Neo4j graph nodes written:       {neo4j_write_count} / {len(ocsf_outputs)}")
    print("==========================================================================")


if __name__ == "__main__":
    main()
