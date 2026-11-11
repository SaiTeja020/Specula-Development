from typing import TypedDict, Literal


class EvidenceCollectionState(TypedDict):
    """
    LangGraph subgraph state for one Evidence Collection Agent invocation.
    Every field is single-writer — no field is written by more than one
    node in this subgraph, so no append-reducer is required (same
    invariant established for ChatbotTurnState).
    """
    case_id: str                       # REQUIRED. Never UNASSIGNED_CONTINUOUS
                                       # for this agent — see §5 Mistakes.
    trace_id: str                      # W3C trace-context id, propagated
                                       # from Supervisor dispatch.
    batch_uids: list[str]              # DFKG node uids under review this pass.
    kept_uids: list[str]
    discarded_uids: list[str]
    escalated_uids: list[str]          # ambiguous cases — never silently
                                       # dropped, always routed onward.
    discard_reason_codes: dict[str, str]   # uid -> reason code (enum value,
                                           # not free text).
    iteration_count: int               # loop-budget enforcement, per
                                       # runtime harness §9.5.
    max_iterations: int                # supplied by Supervisor at dispatch;
                                       # this agent does not hardcode it.
    dead_end: bool                     # observation only — this agent
                                       # NEVER decides dead-end itself,
                                       # only reports "found nothing new
                                       # to keep this pass."
    status: Literal["running", "complete", "escalated_to_supervisor"]
