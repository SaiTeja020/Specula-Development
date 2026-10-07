"""Extract ordered, cited ATT&CK techniques from a frozen timeline."""

from datetime import datetime, timezone
import re
from typing import Any

from .models import ObservedTTP

_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _timestamp(value: Any) -> datetime | None:
    try:
        result = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def extract_observed_ttps(timeline: dict, threat_intel: Any) -> tuple[list[ObservedTTP], list[str]]:
    flags = []
    if not timeline or not timeline.get("frozen"):
        return [], ["timeline_unavailable"]
    events = timeline.get("events") or []
    if not events:
        return [], ["timeline_has_no_cited_events"]
    observed = []
    for item in sorted(events, key=lambda event: _timestamp(event.get("time") or event.get("timestamp")) or datetime.max.replace(tzinfo=timezone.utc)):
        refs = sorted(set(item.get("dfkg_refs") or item.get("evidence_uids") or []))
        timestamp = _timestamp(item.get("time") or item.get("timestamp"))
        if not refs or timestamp is None:
            continue
        technique_ids = item.get("attacks") or item.get("technique_ids") or []
        records = []
        for technique_id in technique_ids:
            if _TECHNIQUE_ID.fullmatch(str(technique_id)):
                response = threat_intel.get_attack_technique(technique_id)
                if response.get("status") == "ok":
                    records.append(response["record"])
                else:
                    flags.append("unsupported_technique_id")
        if not technique_ids and item.get("summary"):
            response = threat_intel.query_attack_techniques(item["summary"], top_k=3)
            if response.get("status") == "ok":
                records = [record.get("metadata", {}) for record in response.get("results", [])
                           if record.get("score", 0) >= 0.65 and record.get("metadata", {}).get("record_type") == "attack_technique"][:1]
        for record in records:
            technique_id = record.get("record_id")
            if technique_id and _TECHNIQUE_ID.fullmatch(technique_id):
                observed.append(ObservedTTP(
                    technique_id=technique_id, time=timestamp, evidence_uids=refs,
                    threat_intel_refs=[f"{technique_id}:{record['source_hash']}"] if record.get("source_hash") else [technique_id],
                ))
    if not observed:
        flags.append("no_confirmed_ttps")
    return observed, sorted(set(flags))
