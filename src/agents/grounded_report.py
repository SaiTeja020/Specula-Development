"""Complete evidence-grounded artifacts, independent of model prose/token limits."""
from __future__ import annotations

import html
import json
import math
from datetime import datetime, timezone
from typing import Any


def _safe(value: Any) -> str:
    """Quote untrusted values without allowing Markdown/HTML structure."""
    text = html.escape(json.dumps(value, ensure_ascii=True, default=str), quote=True)
    for char in "\\`*_{}[]()#+!|":
        text = text.replace(char, "\\" + char)
    return text


def _utc(value: Any) -> str | None:
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not math.isfinite(value):
                return None
            parsed = datetime.fromtimestamp(value / 1000 if abs(value) > 1e11 else value, timezone.utc)
        elif isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return None
        else:
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _prepared(state: dict) -> tuple[list[dict], dict]:
    collection = state.get("evidence_collection") or {}
    flags = {flag for flag in collection.get("degraded_flags", []) if isinstance(flag, str)}
    records = collection.get("records") or []
    events = {}
    conflicts = set()
    for record in records:
        if not isinstance(record, dict):
            flags.add("invalid_evidence_record")
            continue
        uid = record.get("uid") or record.get("event_uid")
        if not isinstance(uid, str) or not uid.strip():
            flags.add("evidence_uid_missing")
            continue
        relation_membership_confirmed = (bool(state.get("case_id")) and
                                         collection.get("case_id") == state["case_id"])
        if record.get("case_id") and record["case_id"] != state.get("case_id") and not relation_membership_confirmed:
            flags.add("foreign_case_evidence_excluded")
            continue
        if uid in conflicts:
            continue
        if uid in events and record != events[uid]:
            flags.add("conflicting_evidence_uid")
            events.pop(uid)
            conflicts.add(uid)
            continue
        events[uid] = record
    if not events:
        flags.add("no_verified_case_evidence")
    complete = collection.get("status") == "complete" or collection.get("complete") is True
    if not complete:
        flags.add("evidence_collection_incomplete")
    for event in events.values():
        if _utc(event.get("time", event.get("event_time", event.get("timestamp")))) is None:
            flags.add("event_time_unavailable")
    generated = _utc(state.get("report_generated_at"))
    if generated is None:
        generated = datetime.now(timezone.utc).isoformat()
        if state.get("report_generated_at"):
            flags.add("invalid_report_generation_time")
    attr = state.get("attribution") or {}
    flags.update(flag for flag in attr.get("degraded_flags", []) if isinstance(flag, str))
    refs = sorted(events)
    claimed = attr.get("dfkg_refs") or []
    if any(ref not in events for ref in claimed):
        flags.add("unverified_attribution_references_excluded")
    metadata = {"generated_at": generated,
                "status": "complete" if complete and events and not flags else "incomplete",
                "dfkg_refs": refs, "threat_intel_refs": [], "degraded_flags": sorted(flags)}
    return list(events.values()), metadata


def _event_line(event: dict) -> str:
    event = dict(event)
    for endpoint in ("src_endpoint", "dst_endpoint"):
        if endpoint not in event and isinstance(event.get(endpoint + "_json"), str):
            try:
                parsed = json.loads(event[endpoint + "_json"])
                if isinstance(parsed, dict):
                    event[endpoint] = parsed
            except (ValueError, TypeError):
                pass
    uid = event.get("uid") or event.get("event_uid")
    timestamp = _utc(event.get("time", event.get("event_time", event.get("timestamp"))))
    facts = []
    for key in ("class_uid", "activity_id", "type_uid", "status_id", "severity_id",
                "src_endpoint", "dst_endpoint", "bytes", "bytes_in", "bytes_out",
                "traffic", "connection_info", "protocol_name"):
        if key in event:
            value = event[key]
            if isinstance(value, dict):
                value = {k: v for k, v in value.items() if k in {
                    "ip", "port", "hostname", "bytes", "bytes_in", "bytes_out",
                    "protocol_name", "protocol_num", "direction_id", "uid"}}
            facts.append(f"{key}={_safe(value)}")
    return f"- {timestamp or 'UNKNOWN TIME'}; " + "; ".join(facts) + f" [event:{_safe(uid)}]"


def render_report(state: dict) -> tuple[str, dict]:
    """Return full report text and structured citation/completeness metadata."""
    events, meta = _prepared(state)
    lines = ["# Specula evidence report", f"Case: {_safe(state.get('case_id', 'unknown'))}",
             f"Generated at (UTC): {meta['generated_at']}", f"Status: {meta['status'].upper()}",
             "", "## Original case evidence"]
    lines.extend(_event_line(event) for event in events)
    if not events:
        lines.append("No verified case evidence is available. Investigation conclusions are incomplete.")
    lines.extend(["", "## Collection triage"])
    triage = (state.get("evidence_collection") or {}).get("triage") or []
    rendered_triage = 0
    for item in triage:
        if not isinstance(item, dict):
            continue
        uid = item.get("uid") or item.get("event_uid")
        verdict = item.get("verdict")
        if uid in meta["dfkg_refs"] and verdict in {"KEEP", "ESCALATE", "DISCARD"}:
            lines.append(f"- Recorded triage: {verdict} [event:{_safe(uid)}]")
            rendered_triage += 1
    if not rendered_triage:
        lines.append("No per-event triage decisions are recorded.")
    attr = state.get("attribution") or {}
    valid_refs = sorted(set(attr.get("dfkg_refs") or []) & set(meta["dfkg_refs"]))
    lines.extend(["", "## Attribution comparison", "Profile similarity does not establish actor identity or intent."])
    corpus_verified = "corpus_artifacts_unverified" not in meta["degraded_flags"]
    if valid_refs and not set(attr.get("dfkg_refs") or []) - set(valid_refs) and corpus_verified:
        for actor in attr.get("candidate_actors") or []:
            score = actor.get("combined_score")
            if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) and 0 <= score <= 1:
                lines.append(f"- Profile {_safe(actor.get('actor_id'))}; similarity score={score}; " +
                             " ".join(f"[event:{_safe(uid)}]" for uid in valid_refs))
        meta["threat_intel_refs"] = sorted({ref for ref in attr.get("threat_intel_refs") or [] if isinstance(ref, str)})
    else:
        lines.append("No fully evidence-bound attribution comparison is available.")
    lines.extend(["", "## Limitations", "Automated model/debate prose is excluded from evidence facts.",
                  "Collection and attribution limitations: " + ", ".join(_safe(flag) for flag in meta["degraded_flags"]) if meta["degraded_flags"] else "No collection limitations recorded.",
                  "", "## Follow-up", "Review the cited original records and unresolved limitations before accepting conclusions.",
                  "", "END OF SPECULA REPORT"])
    return "\n".join(lines), meta


def render_timeline_artifact(state: dict) -> tuple[str, dict]:
    """Use original event timestamps, never a model's reconstructed dates."""
    events, meta = _prepared(state)
    events.sort(key=lambda event: (_utc(event.get("time", event.get("event_time", event.get("timestamp")))) or "9999", str(event.get("uid", event.get("event_uid")))))
    lines = ["# Specula evidence timeline", f"Generated at (UTC): {meta['generated_at']}",
             f"Status: {meta['status'].upper()}"]
    lines.extend(_event_line(event) for event in events)
    if not events:
        lines.append("No verified event timestamps are available; timeline is incomplete.")
    lines.append("END OF SPECULA TIMELINE")
    return "\n".join(lines), meta
