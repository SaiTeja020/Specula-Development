"""Project checkpointed agent execution into the case knowledge graph."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from hashlib import sha256


def _uid(kind: str, case_id: str, index: int = 0) -> str:
    return sha256(f"{kind}:{case_id}:{index}".encode("utf-8")).hexdigest()


def persist_case_execution(driver, case_id: str, traces: list[dict],
                           findings: list[dict], report: str | None = None,
                           report_metadata: dict | None = None,
                           start_index: int = 0) -> None:
    """Idempotently save observed outputs, model labels and bounded citations.

    The full checkpoint retains all structured findings and evidence refs. This
    projection gives Neo4j a navigable audit trail without storing private model
    reasoning or claiming a rule-based step invoked Qwen.
    """
    by_role = defaultdict(deque)
    for finding in findings:
        by_role[finding.get("agent_role")].append(finding)
    runs = []
    for index, trace in enumerate(traces, start=start_index):
        role = trace.get("agent_role", "unknown")
        finding = by_role[role].popleft() if by_role[role] else {}
        refs = trace.get("dfkg_refs") or finding.get("dfkg_refs") or []
        runs.append({
            "uid": _uid("agent-run", case_id, index),
            "case_id": case_id,
            "sequence": index,
            "agent_role": role,
            "model_used": trace.get("model_used") or "none",
            "action": trace.get("action") or "",
            "analysis": finding.get("summary") or trace.get("observation") or "",
            "observation": trace.get("observation") or "",
            "timestamp": trace.get("timestamp") or finding.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "latency_ms": float(trace.get("latency_ms") or 0),
            "evidence_refs": [str(ref) for ref in refs[:30]],
            "evidence_ref_count": len(refs),
        })
    if runs:
        driver.execute_query(
            "UNWIND $runs AS run "
            "MATCH (c:Case {uid: $case_id}) "
            "MERGE (a:AgentRun {uid: run.uid}) SET a += run "
            "MERGE (c)-[:HAS_AGENT_RUN]->(a)",
            runs=runs, case_id=case_id)
    if report:
        metadata = report_metadata or {}
        driver.execute_query(
            "MATCH (c:Case {uid: $case_id}) "
            "MERGE (r:Report {uid: $uid}) "
            "SET r.case_id = $case_id, r.content = $content, "
            "r.status = $status, r.generated_at = $generated_at "
            "MERGE (c)-[:HAS_REPORT]->(r)",
            case_id=case_id, uid=_uid("report", case_id), content=report,
            status=metadata.get("status") or "generated",
            generated_at=metadata.get("generated_at") or datetime.now(timezone.utc).isoformat())
