"""
Specula Vulnerability Scan Normalizer — Phase 3.

Maps Nessus / Qualys vulnerability scan report findings to VulnerabilityFindingEvent (class 2002).
Reference: ocsf_phase2_phase3_implementation_plan_FINAL.md §2.6
"""

from typing import Any, Dict, List

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.ocsf_base import OCSFBaseEvent
from src.schemas.ocsf_phase3_events import VulnerabilityFindingEvent
from src.schemas.uid_generator import generate_deterministic_uid


def _map_severity(raw_sev: Any) -> int:
    """Map raw scanner severity string/int to OCSF severity_id (0-6)."""
    if isinstance(raw_sev, int):
        if 0 <= raw_sev <= 6:
            return raw_sev
    sev_str = str(raw_sev).lower()
    if "critical" in sev_str or "fatal" in sev_str:
        return 5
    if "high" in sev_str:
        return 4
    if "med" in sev_str or "medium" in sev_str:
        return 3
    if "low" in sev_str:
        return 2
    if "info" in sev_str or "informational" in sev_str:
        return 1
    return 0


def normalize(raw_payload: Dict[str, Any], trace_id: str, case_id: str) -> List[OCSFBaseEvent]:
    """
    Normalize vulnerability scanner report row into VulnerabilityFindingEvent (class 2002).
    """
    time_normalizer = TimeNormalizer()
    raw_timestamp = str(raw_payload.get("timestamp") or raw_payload.get("scan_time") or "1970-01-01T00:00:00Z")
    utc_time, _, _ = time_normalizer.normalize(raw_timestamp)

    # Vulnerability scanner timestamps have no DC anchor
    skew_ms = 0
    unverified = True

    uid = generate_deterministic_uid("vuln_scan", raw_payload)
    severity_id = _map_severity(raw_payload.get("severity") or raw_payload.get("vendor_severity"))

    events: List[OCSFBaseEvent] = [
        VulnerabilityFindingEvent(
            case_id=case_id,
            trace_id=trace_id,
            activity_id=1,  # Finding Logged
            severity_id=severity_id,
            time=utc_time,
            raw_source_timestamp=raw_timestamp,
            clock_skew_offset_ms=skew_ms,
            clock_skew_unverified=unverified,
            uid=uid,
            vulnerability_id=raw_payload.get("cve") or raw_payload.get("vulnerability_id") or "CVE-UNKNOWN",
            title=raw_payload.get("title") or raw_payload.get("plugin_name"),
            description=raw_payload.get("description"),
            cve_score=float(raw_payload.get("cvss_score") or raw_payload.get("cve_score") or 0.0),
            vendor_severity=str(raw_payload.get("severity")),
            host_name=raw_payload.get("host_name") or raw_payload.get("ip"),
            canonical_host_id=raw_payload.get("canonical_host_id"),
        )
    ]

    return events
