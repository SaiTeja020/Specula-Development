"""
Specula UEBA & Browser Artifacts Normalizer — Phase 3.

Maps browser activity to HTTPActivityEvent and behavioral anomaly flags to DetectionFindingEvent.
Reference: ocsf_phase2_phase3_implementation_plan_FINAL.md §2.7
"""

from typing import Any, Dict, List

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.ocsf_base import OCSFBaseEvent
from src.schemas.ocsf_phase2_events import DetectionFindingEvent
from src.schemas.ocsf_phase3_events import HTTPActivityEvent
from src.schemas.uid_generator import generate_deterministic_uid


def normalize(raw_payload: Dict[str, Any], trace_id: str, case_id: str) -> List[OCSFBaseEvent]:
    """
    Normalize browser history / access to HTTPActivityEvent (class 4002),
    or UEBA behavioral anomaly flags to DetectionFindingEvent (class 2004).
    Distinguishes pre-existing reports vs live agent output.
    """
    time_normalizer = TimeNormalizer()
    raw_timestamp = str(raw_payload.get("timestamp") or raw_payload.get("visit_time") or "1970-01-01T00:00:00Z")
    utc_time, _, _ = time_normalizer.normalize(raw_timestamp)

    skew_ms = 0
    unverified = True

    uid = generate_deterministic_uid("ueba_browser", raw_payload)
    artifact_type = str(raw_payload.get("artifact_type") or raw_payload.get("event_type") or "").lower()

    events: List[OCSFBaseEvent] = []

    if "ueba" in artifact_type or "anomaly" in artifact_type or "flag" in artifact_type:
        # UEBA Behavioral Anomaly Flag -> DetectionFindingEvent (class 2004)
        events.append(
            DetectionFindingEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1,
                severity_id=int(raw_payload.get("severity_id", 4)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                uid=uid,
                finding_title=raw_payload.get("anomaly_name") or raw_payload.get("title") or "UEBA Behavioral Anomaly Flag",
                analytic_name=raw_payload.get("rule_name") or "UEBA Engine",
                confidence=str(raw_payload.get("confidence", "High")),
                raw_verdict=raw_payload.get("verdict", "Anomalous Behavior Detected"),
                canonical_host_id=raw_payload.get("canonical_host_id"),
                details=raw_payload,
            )
        )
    else:
        # Browser History / Web Access -> HTTPActivityEvent (class 4002)
        events.append(
            HTTPActivityEvent(
                case_id=case_id,
                trace_id=trace_id,
                activity_id=1,
                severity_id=int(raw_payload.get("severity_id", 1)),
                time=utc_time,
                raw_source_timestamp=raw_timestamp,
                clock_skew_offset_ms=skew_ms,
                clock_skew_unverified=unverified,
                uid=uid,
                url=raw_payload.get("url") or "http://unknown.local",
                http_method=raw_payload.get("http_method") or "GET",
                user_agent=raw_payload.get("user_agent"),
                status_code=int(raw_payload.get("status_code", 200)),
                referrer=raw_payload.get("referrer"),
                canonical_host_id=raw_payload.get("canonical_host_id"),
            )
        )

    return events
