"""
Specula Cloud Audit to OCSF Normalizer.

Maps AWS CloudTrail / Azure Logs to OCSF format.
Source category 5 (Phase 1 scope).

Reference: specula_ingestion_final_plan.md §5.1
"""

import json
from typing import Any, Dict

from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.rebuff_gate import detect_prompt_injection
from src.schemas.ocsf_events import CloudAudit
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.uid_generator import generate_deterministic_uid


def normalize_cloudtrail(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    trace_id: str,
) -> CloudAudit:
    """
    Normalize CloudTrail JSON to OCSF CloudAudit.
    
    CloudTrail is text-native (JSON). The Security Gate should run
    on the full JSON payload before this point, but we still ensure
    structured text fields are clean.
    
    Crucially, CloudTrail typically has NO DC ANCHOR for time skew,
    so time_normalizer is expected to be initialized with None,
    resulting in clock_skew_unverified = True.
    """
    
    raw_timestamp = raw_parsed_event.get("eventTime", "")
    
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    # Fields that could contain injection payloads
    user_agent = raw_parsed_event.get("userAgent", "")
    sanitized_ua, _ = sanitize_text(user_agent)
    is_injection, is_degraded = detect_prompt_injection(sanitized_ua)
    
    identity = raw_parsed_event.get("userIdentity", {}).get("arn", "")
    sanitized_identity, _ = sanitize_text(identity)
    if not sanitized_identity or sanitized_identity.strip() == "":
        sanitized_identity = None
    
    return CloudAudit(
        trace_id=trace_id,
        activity_id=1, # API Call
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        # This should correctly be True because CloudTrail lacks a DC anchor
        clock_skew_unverified=unverified, 
        security_scan_degraded=is_degraded,
        uid=generate_deterministic_uid("cloud", {
            "event_name": raw_parsed_event.get("eventName"), 
            "timestamp": raw_parsed_event.get("eventTime")
        }),
        cloud_provider="AWS",
        cloud_region=raw_parsed_event.get("awsRegion", None),
        cloud_account_id=raw_parsed_event.get("recipientAccountId", None),
        api_operation=raw_parsed_event.get("eventName", None),
        api_service=raw_parsed_event.get("eventSource", None),
        source_ip=raw_parsed_event.get("sourceIPAddress", None),
        user_identity=sanitized_identity,
    )
