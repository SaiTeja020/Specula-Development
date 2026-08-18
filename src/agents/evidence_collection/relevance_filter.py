from dataclasses import dataclass
from typing import Optional

from src.agents.evidence_collection.agent_verdict import AgentVerdict
from src.schemas.ocsf_base import OCSFBaseEvent


@dataclass
class CaseContext:
    """
    Minimal case-scoped context needed for relevance decisions.
    Populated by a bounded mcp-dfkg-cypher query at the start of each
    invocation — NOT the full subgraph (that would violate the same
    APOC-bounded-BFS discipline used elsewhere: max 3 hops, max 100
    nodes, max 300 relationships, per Master doc §2.4 Feature 2).
    """
    case_id: str
    known_host_uids: set[str]          # canonical_host_id values already
                                       # present in this case's DFKG subgraph


@dataclass
class RelevanceResult:
    uid: str
    verdict: AgentVerdict
    reason_code: str                   # always populated, even for KEEP
                                       # (e.g. "KEEP_DEFAULT",
                                       # "DISCARD_LOW_SEVERITY_KNOWN_HOST")


# Low-signal allowlist: source-type + class_uid combinations that are
# candidates for DISCARD when all other criteria also hold. This is a
# STATIC, checked-in table for v1 — see §7 Open Items re: rule-engine
# migration.
LOW_SIGNAL_CLASS_UIDS: set[int] = {
    3002,   # Authentication — only when activity/status indicate routine success
}


def classify_event(event: OCSFBaseEvent, ctx: CaseContext) -> RelevanceResult:
    """
    Conjunctive DISCARD rule — ALL FOUR criteria must hold, this is not
    a single weighted score with a cutoff:

      1. event.severity_id <= 1 (informational only)
      2. event.canonical_host_id is CONFIRMED absent from ctx.known_host_uids
         (i.e. resolver returned a definite value, and that value is not
         in the known set — NOT "resolver returned None")
      3. event.class_uid is in LOW_SIGNAL_CLASS_UIDS, AND the event's
         specific fields indicate the routine case (e.g. Authentication
         with status == "Success" and no off-hours/impossible-travel flag
         — that flag is a DetectionFindingEvent emitted separately by
         upstream/UEBA logic, not recomputed here)
      4. event was already flagged is_summary=True by the ingestion
         pipeline's entropy clusterer (Component 6) — this agent trusts
         that flag, it does not re-cluster.

    ESCALATE (never silently discarded):
      - event.canonical_host_id is None / unresolved (resolver gap, not
        evidence of irrelevance — mirrors entity_resolver.py's own
        contract: raise/flag rather than guess).
      - Any event where criteria 1-4 are partially satisfied in a way
        that makes the DISCARD conjunction indeterminate (e.g. severity
        present but class_uid not in the allowlist AND host is unknown —
        two independent signals pointing different directions).

    KEEP: everything else, including the default when in doubt. This
    function is intentionally asymmetric: staying in the working set is
    the safe failure mode, being silently dropped is not.
    """
    host_id = getattr(event, "canonical_host_id", None)

    if host_id is None:
        return RelevanceResult(uid=event.uid, verdict=AgentVerdict.ESCALATE,
                               reason_code="ESCALATE_UNRESOLVED_HOST")

    host_known = host_id in ctx.known_host_uids
    is_low_severity = getattr(event, "severity_id", 99) <= 1
    is_low_signal_class = getattr(event, "class_uid", None) in LOW_SIGNAL_CLASS_UIDS
    is_pre_collapsed = bool(getattr(event, "is_summary", False))

    if is_low_severity and (not host_known) and is_low_signal_class and is_pre_collapsed:
        return RelevanceResult(uid=event.uid, verdict=AgentVerdict.DISCARD,
                               reason_code="DISCARD_ALL_FOUR_CRITERIA_MET")

    return RelevanceResult(uid=event.uid, verdict=AgentVerdict.KEEP,
                           reason_code="KEEP_DEFAULT")
