"""
Specula Pipeline Runner (Producer).

Extracts local Windows System/Security event logs (via PowerShell Get-WinEvent)
and passes them through extraction, preservation, security gate, and normalization.
Finally, publishes the OCSF validated events to Kafka.
"""

import json
import logging
import os
import subprocess
import sys
import uuid
import hashlib
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath("."))

from src.schemas.entity_resolver import CanonicalEntityResolver
from src.ingestion.preservation.sha256_hasher import compute_sha256_bytes
from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
from src.ingestion.preservation.quickwit_client import QuickwitClient, QuickwitClientError
from src.ingestion.security_gate.pipeline import run_security_gate
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.normalization.evtx_normalizer import normalize_evtx_process_creation
from src.ingestion.normalization.ad_auth_normalizer import normalize_ad_auth_event
from src.ingestion.validation.validator import validate_event
from src.schemas.ocsf_events import ProcessActivity
from src.schemas.ocsf_phase2_events import AuthenticationEvent
from src.ingestion.broker.kafka_producer import EventProducer
from src.ingestion.broker.active_cases_cache import ActiveCasesCache
from src.ingestion.validation.schema_registry_client import OCSF_BASE_JSON_SCHEMA

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SpeculaProducer")

QUICKWIT_ENABLED: bool = os.environ.get("SPECULA_QUICKWIT_ENABLED", "false").lower() == "true"

def extract_windows_events(log_name: str, start_time: str = None, end_time: str = None, max_events: int = 2000) -> list[dict]:
    if start_time and end_time:
        ps_command = (
            f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; StartTime=[datetime]::Parse('{start_time}'); EndTime=[datetime]::Parse('{end_time}')}} "
            f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            "Select-Object Id, TimeCreated, ProviderName, MachineName, Message | "
            "ConvertTo-Json -Compress"
        )
    else:
        ps_command = (
            f"Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            "Select-Object Id, TimeCreated, ProviderName, MachineName, Message | "
            "ConvertTo-Json -Compress"
        )
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_command], capture_output=True, text=True, check=False)
        if not res.stdout.strip():
            return []
        data = json.loads(res.stdout)
        if isinstance(data, dict):
            return [data]
        return data
    except Exception as e:
        logger.debug(f"Log channel {log_name} not available: {e}")
        return []

def run_pipeline_on_event(
    raw_event: dict,
    vct_chain: VCTAtomicChain,
    resolver: CanonicalEntityResolver,
    time_normalizer: TimeNormalizer,
    qw_client: "QuickwitClient | None" = None,
    source_type: str = "evtx"
):
    trace_id = f"trace-{uuid.uuid4().hex[:12]}"
    raw_bytes = json.dumps(raw_event).encode("utf-8")
    sha256_digest = compute_sha256_bytes(raw_bytes)
    vct_chain.register_hash(sha256_digest, trace_id, "TEMP_UID")
    
    if qw_client is not None:
        qw_client.commit_raw_evidence(
            uid=sha256_digest,
            trace_id=trace_id,
            sha256_digest=sha256_digest,
            raw_bytes=raw_bytes,
            source_type=source_type,
        )

    message_text = raw_event.get("Message", "") or ""
    raw_msg_bytes = message_text.encode("utf-8")
    gate_result = run_security_gate("text", raw_msg_bytes)

    if gate_result.injection_blocked:
        logger.warning(f"Event blocked by Security Gate — injection detected (trace={trace_id})")
        return None

    sanitized_msg = gate_result.sanitized_fields[0] if gate_result.sanitized_fields else ""
    is_injection = gate_result.injection_blocked
    is_degraded = False

    time_str = raw_event.get("TimeCreated", "")
    if time_str and "/Date(" in str(time_str):
        ms = int(time_str.split("(")[1].split(")")[0])
        time_str = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
    elif not time_str:
        time_str = datetime.now(timezone.utc).isoformat()
        
    utc_time, skew_offset, skew_unverified = time_normalizer.normalize(str(time_str))
    provider = raw_event.get("ProviderName", "")
    event_id = str(raw_event.get("Id", 0))

    event_type = None
    if provider == "Microsoft-Windows-Sysmon" and event_id == "1":
        event_type = "PROCESS"
    elif provider == "Microsoft-Windows-Security-Auditing":
        if event_id == "4688":
            event_type = "PROCESS"
        elif event_id in ["4624", "4625", "4768", "4769"]:
            event_type = "AUTH"

    ocsf_evt = None
    if event_type == "PROCESS":
        ocsf_evt = normalize_evtx_process_creation(
            raw_event, sanitized_msg, utc_time, skew_offset, skew_unverified, is_degraded, trace_id, resolver
        )
    elif event_type == "AUTH":
        ocsf_evt = normalize_ad_auth_event(
            raw_event, sanitized_msg, utc_time, skew_offset, skew_unverified, is_degraded, trace_id, resolver
        )
    
    if ocsf_evt:
        validate_event(ocsf_evt.model_dump(mode="json"), ocsf_evt.__class__)
        return ocsf_evt
    return None

def main():
    parser = argparse.ArgumentParser(description="Specula Pipeline Runner")
    parser.add_argument("--start-time", type=str, help="Start time (e.g., '2026-08-31 00:00:00')", default=None)
    parser.add_argument("--end-time", type=str, help="End time (e.g., '2026-08-31 23:59:59')", default=None)
    parser.add_argument("--max-events", type=int, help="Max events per channel", default=2000)
    args = parser.parse_args()

    logger.info("Extracting logs and running producer pipeline...")
    vct_chain = VCTAtomicChain()
    resolver = CanonicalEntityResolver()
    
    from src.schemas.entity_resolver import DHCPLease
    resolver.register_hostname("DESKTOP-N08P1L3", "uuid-local-host")
    resolver.register_dhcp_lease(DHCPLease(
        ip="10.0.0.99",
        canonical_host_uid="uuid-local-host",
        valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
        valid_to=datetime(2030, 1, 1, tzinfo=timezone.utc)
    ))
    time_normalizer = TimeNormalizer(dc_anchor_skew_ms=0)
    
    qw_client = QuickwitClient() if QUICKWIT_ENABLED else None
    
    cache = ActiveCasesCache()
    producer = EventProducer(
        schema_str=OCSF_BASE_JSON_SCHEMA,
        topic="logs.normalized.ocsf",
        active_cases_cache=cache
    )

    channels = ["System", "Security", "Microsoft-Windows-Sysmon/Operational"]
    for channel in channels:
        events = extract_windows_events(channel, start_time=args.start_time, end_time=args.end_time, max_events=args.max_events)
        for event in events:
            ocsf_evt = run_pipeline_on_event(event, vct_chain, resolver, time_normalizer, qw_client)
            if ocsf_evt:
                producer.produce_event(ocsf_evt)

    producer.flush()
    logger.info("Pipeline published events to Kafka topic: logs.normalized.ocsf")

if __name__ == "__main__":
    main()
