"""
Specula Email Logs Normalizer — Phase 2.

Maps SMTP / messaging gateway logs to EmailActivityEvent and optional DetectionFindingEvent.
Reference: ocsf_phase2_phase3_implementation_plan_FINAL.md §2.3
"""

from typing import Any, Dict, List

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.security_gate.sanitizer import sanitize_text
from src.schemas.ocsf_base import OCSFBaseEvent
from src.schemas.ocsf_phase2_events import DetectionFindingEvent, EmailActivityEvent
from src.schemas.uid_generator import generate_deterministic_uid


def normalize(raw_payload: Dict[str, Any], trace_id: str, case_id: str) -> List[OCSFBaseEvent]:
    """
    Normalize email gateway payload to EmailActivityEvent (class 4009).
    Emits DetectionFindingEvent alongside if a phishing/malware verdict is present.
    """
    time_normalizer = TimeNormalizer()
    raw_timestamp = str(raw_payload.get("timestamp") or raw_payload.get("date") or "1970-01-01T00:00:00Z")
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)

    # If cloud email gateway, set clock_skew_unverified = True
    if raw_payload.get("is_cloud_gateway", False):
        skew_ms = 0
        unverified = True

    uid = generate_deterministic_uid("email", raw_payload)
    sanitized_subject, _ = sanitize_text(raw_payload.get("subject", ""))

    events: List[OCSFBaseEvent] = [
        EmailActivityEvent(
            case_id=case_id,
            trace_id=trace_id,
            activity_id=1,  # Receive / Delivery
            severity_id=int(raw_payload.get("severity_id", 1)),
            time=utc_time,
            raw_source_timestamp=raw_timestamp,
            clock_skew_offset_ms=skew_ms,
            clock_skew_unverified=unverified,
            uid=uid,
            sender=raw_payload.get("sender"),
            recipients=raw_payload.get("recipients") if isinstance(raw_payload.get("recipients"), list) else [raw_payload.get("recipient")] if raw_payload.get("recipient") else None,
            subject=sanitized_subject if sanitized_subject else None,
            message_id=raw_payload.get("message_id"),
            attachments=raw_payload.get("attachments"),
            canonical_host_id=raw_payload.get("canonical_host_id"),
        )
    ]

    # If email gateway flagged a verdict (phish, spam, malicious), emit DetectionFindingEvent alongside
    verdict = raw_payload.get("verdict") or raw_payload.get("security_verdict")
    if verdict and str(verdict).lower() in ("phish", "phishing", "spam", "malicious"):
        finding_uid = generate_deterministic_uid("email", {"verdict": raw_payload, "email_uid": uid})
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
                uid=finding_uid,
                finding_title=f"Email Security Verdict: {verdict}",
                analytic_name="Email Gateway Security Inspection",
                confidence="High",
                raw_verdict=str(verdict),
                canonical_host_id=raw_payload.get("canonical_host_id"),
                details={"subject": sanitized_subject, "sender": raw_payload.get("sender")},
            )
        )

    return events
