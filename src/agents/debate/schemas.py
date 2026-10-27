"""ACH Debate schemas — Implementation Plan v3 §4.

§4.1 LangGraph routing state (scalars + SHA-256 UIDs only).
§4.2 Redis storage contract (durable payloads).
§4.3 DebateResult output contract for guardrails and report generation.
"""
from __future__ import annotations

import re
from typing import Dict, List, Literal, Optional, TypedDict

from pydantic import BaseModel, Field, field_validator

# 64-hex SHA-256 or entity UID pattern
HEX64_PATTERN = re.compile(r"^[a-fA-F0-9]{16,64}$")


class DebateGraphState(TypedDict):
    case_id: str
    trace_id: str
    debate_run_id: str                     # Deterministic per (case, trace, attempt); scopes Redis keys + blind seed
    round_index: int                       # Code-managed (1 to 3); incremented only by the judge node
    validation_attempts: int               # Code-managed per-agent turn syntax attempts (Max 3 per turn)
    entailment_attempts: int               # Code-managed judge claim entailment retry counter (defect 1)
    active_turn: Literal["PROPONENT", "CRITIC", "JUDGE"]
    proponent_payload_uid: str             # SHA-256 hash pointer to Redis
    critic_payload_uid: str                # SHA-256 hash pointer to Redis
    p_h1: Optional[float]                  # Previous judge round's P(H1); read back as prev_p_h1 (None in round 1)
    p_h2: Optional[float]                  # Code-managed derived probability
    degraded_capability_mode: bool         # True when any role used a fallback model -> forces HITL
    models_used: Dict[str, str]            # Map role -> model actually invoked
    start_time: float                      # Wall-clock timestamp for total session budget enforcement (M6)
    convergence_status: Literal[
        "PENDING", "CONVERGED_DOMINANT", "CONVERGED_STABLE",
        "DEADLOCK_TIE", "VALIDATION_EXHAUSTED", "TOOL_TIMEOUT",
        "INSUFFICIENT_EVIDENCE", "PAYLOAD_MISSING", "CASE_REOPENED",
        "JUDGE_OUTPUT_INVALID",
    ]
    debate_result: Optional[dict]          # Populated upon convergence per DebateResult schema


class CitedClaim(BaseModel):
    assertion: str
    cited_uids: List[str] = Field(min_length=1)  # Reject empty citations
    # Justification: stored explanation of how cited evidence entails the claim (stored, not scored in ACH matrix)
    justification: str = ""

    @field_validator("cited_uids")
    @classmethod
    def validate_uid_format(cls, uids: List[str]) -> List[str]:
        for u in uids:
            if not u or not isinstance(u, str):
                raise ValueError(f"Invalid empty or non-string UID: {u}")
        return uids


class ClaimEntailment(BaseModel):
    """M4: Per-claim entailment evaluated by the Judge from raw node content."""
    claim_index: int
    hypothesis_label: Literal["A", "B"]
    status: Literal["SUPPORTED", "UNSUPPORTED"]
    reason: str = ""


class AgentPayload(BaseModel):
    case_id: str
    round_index: int
    hypothesis: str
    claims: List[CitedClaim]
    retrieved_uids: List[str]  # Middleware-recorded provenance


class EvidenceEvaluation(BaseModel):
    evidence_uid: str
    relation_to_A: Literal["CONFIRMS", "CONTRADICTS", "NEUTRAL"]
    relation_to_B: Literal["CONFIRMS", "CONTRADICTS", "NEUTRAL"]


class DebateResult(BaseModel):
    """Downstream contract for Guardrails (Tier 1/2/3) and Report Generation (defect 5)."""
    winning_hypothesis: str
    winning_role: Literal["PROPONENT", "CRITIC", "TIE", "INSUFFICIENT"]
    status: str
    rules_version: str
    calibrated: bool = False
    contradictions: Dict[str, int] = Field(default_factory=dict)
    margin_score: int = 0
    claims: List[CitedClaim]
    cited_uids: List[str]                  # Winner's cited UIDs only
    contested_uids: List[str] = Field(default_factory=list)  # Losing side's cited UIDs
    evaluations: List[EvidenceEvaluation]
    claim_entailments: List[ClaimEntailment]
    degraded_capability_mode: bool
