"""
Specula Cloud Audit to OCSF Normalizer.

Maps GCP Audit Logs to OCSF format.
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


def normalize_gcp_audit(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    trace_id: str,
) -> CloudAudit:
    """
    Normalize GCP Audit Logs JSON to OCSF CloudAudit.
    
    GCP Audit Logs are text-native (JSON). The Security Gate should run
    on the full JSON payload before this point, but we still ensure
    structured text fields are clean.
    
    Crucially, GCP Audit Logs typically have NO DC ANCHOR for time skew,
    so time_normalizer is expected to be initialized with None,
    resulting in clock_skew_unverified = True.
    """
    
    proto_payload = raw_parsed_event.get("protoPayload", {})
    resource_labels = raw_parsed_event.get("resource", {}).get("labels", {})
    req_metadata = proto_payload.get("requestMetadata", {})
    auth_info = proto_payload.get("authenticationInfo", {})

    raw_timestamp = raw_parsed_event.get("timestamp") or proto_payload.get("timestamp") or ""
    
    utc_time, skew_ms, unverified = time_normalizer.normalize(str(raw_timestamp))
    
    # Cloud sources have no DC anchor
    skew_ms = 0
    unverified = True

    # Fields that could contain injection payloads
    user_agent = req_metadata.get("callerSuppliedUserAgent", "")
    sanitized_ua, _ = sanitize_text(user_agent)
    is_injection, is_degraded = detect_prompt_injection(sanitized_ua)
    
    identity = auth_info.get("principalEmail", "")
    sanitized_identity, _ = sanitize_text(identity)
    if not sanitized_identity or sanitized_identity.strip() == "":
        sanitized_identity = None
    
    uid_attributes = {
        "project_id": resource_labels.get("project_id"),
        "method_name": proto_payload.get("methodName"),
        "timestamp": raw_timestamp,
        "principal": identity,
    }

    return CloudAudit(
        trace_id=trace_id,
        activity_id=1, # API Call
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified, 
        security_scan_degraded=is_degraded,
        uid=generate_deterministic_uid("cloud", uid_attributes),
        cloud_provider="GCP",
        cloud_region=resource_labels.get("location", "global"),
        cloud_account_id=resource_labels.get("project_id"),
        api_operation=proto_payload.get("methodName"),
        api_service=proto_payload.get("serviceName"),
        source_ip=req_metadata.get("callerIp"),
        user_identity=sanitized_identity,
    )
