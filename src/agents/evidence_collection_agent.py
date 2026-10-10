"""Retrieve actual case events and triage deterministically, without model tool claims."""
from __future__ import annotations

from datetime import datetime, timezone
import time

from src.agents.kafka_utils import publish_finding
from src.agents.react_engine import Tool, ToolResult

CASE_EVENTS_QUERY = "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(e:Event) RETURN e ORDER BY e.uid"
LOW_SIGNAL_CLASS_UIDS = {3002}


class RelevanceCheckTool(Tool):
    """Keep evidence by default; escalate high severity, never discard."""
    name = "check_relevance"
    description = "Deterministic KEEP or ESCALATE classification of a real event."

    def run(self, event: dict) -> ToolResult:
        severity = event.get("severity_id", 0)
        if not isinstance(severity, (int, float)) or isinstance(severity, bool):
            return ToolResult(ok=False, observation="Invalid event severity_id.")
        if event.get("class_uid") in LOW_SIGNAL_CLASS_UIDS and (
            event.get("status") == "Success" and event.get("activity_id") in (1, 2)
        ):
            verdict, reason = "KEEP", "routine_auth_discard_gated"
        elif severity >= 4:
            verdict, reason = "ESCALATE", "high_severity"
        else:
            verdict, reason = "KEEP", "default_keep"
        return ToolResult(ok=True, observation=reason,
                          data={"verdict": verdict, "reason_code": reason})


def make_evidence_collection_node(redis_client, neo4j_driver):
    """Redis argument remains for factory compatibility; no LLM is invoked."""
    def evidence_collection_node(state: dict) -> dict:
        started = time.monotonic()
        case_id = state.get("case_id")
        records, triage, flags = [], [], []
        fetched_count = 0
        if not isinstance(case_id, str) or not case_id.strip():
            flags.append("missing_case_id")
        elif neo4j_driver is None:
            flags.append("graph_unavailable")
        else:
            try:
                with neo4j_driver.session() as session:
                    fetched = list(session.run(CASE_EVENTS_QUERY, {"case_id": case_id}))
                fetched_count = len(fetched)
                if not fetched:
                    flags.append("no_case_events")
                seen = set()
                relevance = RelevanceCheckTool()
                for row in fetched:
                    try:
                        event = dict(row["e"])
                        uid = event.get("uid")
                        if not isinstance(uid, str) or not uid.strip():
                            flags.append("malformed_event_uid")
                            continue
                        if uid in seen:
                            flags.append("duplicate_event_uid")
                            continue
                        seen.add(uid)
                        decision = relevance.run(event)
                        if not decision.ok:
                            flags.append("invalid_event_triage")
                            continue
                        records.append(event)
                        triage.append({"uid": uid, **decision.data})
                    except (KeyError, TypeError, ValueError):
                        flags.append("malformed_event")
            except Exception:
                flags.append("graph_query_failed")
        paired = sorted(zip(records, triage), key=lambda pair: pair[0]["uid"])
        records = [pair[0] for pair in paired]
        triage = [pair[1] for pair in paired]
        refs = [record["uid"] for record in records]
        flags = sorted(set(flags))
        complete = bool(records) and not flags and len(records) == fetched_count
        collection = {
            "case_id": case_id, "status": "complete" if complete else "incomplete",
            "complete": complete, "degraded": bool(flags), "degraded_flags": flags,
            "records": records, "triage": triage, "dfkg_refs": refs,
            "reference_uids": refs, "fetched_count": fetched_count,
            "triaged_count": len(triage), "loop_count": state.get("loop_count", 0),
        }
        escalated = sum(item["verdict"] == "ESCALATE" for item in triage)
        summary = (
            f"Case evidence collection {collection['status']}: "
            f"{len(triage)}/{fetched_count} fetched events triaged; "
            f"{escalated} escalated, {len(triage) - escalated} kept."
        )
        if flags:
            summary += " Limitations: " + ", ".join(flags) + "."
        finding = {
            "agent_role": "evidence_collection", "case_id": case_id,
            "summary": summary, "dfkg_refs": refs,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kafka_offset": None, "evidence_collection": collection,
        }
        # One publication attempt; this helper does not acknowledge delivery.
        publish_finding("findings.evidence_collection", finding, state.get("trace_id"))
        trace = {
            "agent_role": "evidence_collection", "thought": "Triage actual case events",
            "action": "case_scoped_retrieval_and_triage", "observation": summary,
            "model_used": "deterministic_rules", "terminal": complete,
            "termination_reason": "complete" if complete else "incomplete",
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
        }
        return {"evidence_collection": collection, "findings": [finding],
                "agent_traces": [trace]}
    return evidence_collection_node
