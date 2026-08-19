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
    Evidence relevance classifier. Returns KEEP or ESCALATE in v1.
    
    DISCARD is INTENTIONALLY DISABLED until Stage 4b (entropy distillation / Drain3
    clustering) ships. Criterion 4 (is_summary flag) is never true in Stage 2's output,
    making the full DISCARD conjunction unreachable. See Stage 2 plan §3, §6.
    
    Once Stage 4b adds is_summary=True to summaries, re-enable DISCARD by uncommenting
    the `_conjunctive_discard_path()` function below and restoring the code path.
    
    TICKET: [Link to Stage 4b tracking ticket for DISCARD re-enablement]
    """
    reason: str

    host_id = event.canonical_host_id if hasattr(event, "canonical_host_id") else None

    if host_id is None:
        return RelevanceResult(
            uid=event.uid,
            verdict=AgentVerdict.ESCALATE,
            reason_code="ESCALATE_UNRESOLVED_HOST"
        )

    # STAGE 4B TODO: Uncomment the DISCARD path once entropy distillation ships.
    # For now, v1 behavior is: everything with a resolved host is KEEP,
    # everything with unresolved host is ESCALATE.
    
    return RelevanceResult(
        uid=event.uid,
        verdict=AgentVerdict.KEEP,
        reason_code="KEEP_DEFAULT_V1_DISCARD_DISABLED_PENDING_STAGE_4B"
    )


def _conjunctive_discard_path(event: OCSFBaseEvent, ctx: CaseContext) -> RelevanceResult:
    """
    STAGE 4B: Uncomment this function and restore it to classify_event() once
    entropy distillation ships and is_summary flags are guaranteed present.
    
    Original four-criterion DISCARD logic (disabled in v1):
    
    1. event.severity_id <= 1 (informational only)
    2. event.canonical_host_id is CONFIRMED absent from ctx.known_host_uids
    3. event.class_uid is in LOW_SIGNAL_CLASS_UIDS, AND event-specific fields
       indicate the routine case (e.g., Authentication with status == "Success")
    4. event was flagged is_summary=True by entropy clustering
    
    ALL FOUR must hold for DISCARD; this is not a weighted score.
    """
    host_id = getattr(event, "canonical_host_id", None)
    host_known = host_id in ctx.known_host_uids
    is_low_severity = getattr(event, "severity_id", 99) <= 1
    is_low_signal_class = getattr(event, "class_uid", None) in LOW_SIGNAL_CLASS_UIDS
    is_pre_collapsed = bool(getattr(event, "is_summary", False))
    
    # Criterion 3 addition: for Authentication events, also check status/activity_id.
    is_routine_authentication = False
    if is_low_signal_class and getattr(event, "class_uid", None) == 3002:  # class_uid 3002 = Authentication
        # MUST BE SUCCESSFUL - failed auth is high-signal, never discard
        auth_status = getattr(event, "status", None)
        auth_activity_id = getattr(event, "activity_id", None)
        is_routine_authentication = (
            auth_status == "Success" or auth_activity_id == 1  # activity_id 1 = "Success"
        )
        is_low_signal_class = is_low_signal_class and is_routine_authentication

    if is_low_severity and (not host_known) and is_low_signal_class and is_pre_collapsed:
        return RelevanceResult(
            uid=event.uid,
            verdict=AgentVerdict.DISCARD,
            reason_code="DISCARD_ALL_FOUR_CRITERIA_MET"
        )

    return RelevanceResult(
        uid=event.uid,
        verdict=AgentVerdict.KEEP,
        reason_code="KEEP_DEFAULT"
    )
