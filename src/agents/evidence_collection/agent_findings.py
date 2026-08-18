from typing import Literal
from pydantic import BaseModel, Field


class EvidenceCollectionFinding(BaseModel):
    case_id: str
    trace_id: str
    agent_role: Literal["EvidenceCollection"] = "EvidenceCollection"
    kept_uids: list[str]
    discarded_uids: list[str]
    escalated_uids: list[str]
    discard_reason_codes: dict[str, str] = Field(
        ...,
        description=(
            "Per-UID reason code for EVERY uid in kept_uids, "
            "discarded_uids, AND escalated_uids — not discarded_uids "
            "only. Daubert admissibility (Master doc §9.6) requires "
            "showing why an agent examined a piece of evidence, not "
            "just what it concluded about the ones it dropped."
        ),
    )
    batch_size: int
    dead_end: bool
