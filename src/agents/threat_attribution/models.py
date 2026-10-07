"""Validated contracts for an attribution result and its evidence."""

from datetime import datetime
from pydantic import BaseModel, Field


class ObservedTTP(BaseModel):
    technique_id: str
    time: datetime
    evidence_uids: list[str] = Field(min_length=1)
    threat_intel_refs: list[str] = Field(default_factory=list)


class ThreatActorCandidate(BaseModel):
    actor_id: str
    name: str
    jaccard: float = Field(ge=0, le=1)
    smith_waterman: float = Field(ge=0, le=1)
    combined_score: float = Field(ge=0, le=1)
    matched_techniques: list[str]
    profile_techniques: list[str]
    sequence_available: bool
    sequence_basis: str | None = None
    source_hash: str | None = None
    source_version: str | None = None


class ThreatAttributionResult(BaseModel):
    observed_ttps: list[ObservedTTP]
    candidate_actors: list[ThreatActorCandidate]
    top_candidate: ThreatActorCandidate | None
    overall_confidence: float = Field(ge=0, le=1)
    confidence_lower: float = Field(ge=0, le=1)
    confidence_upper: float = Field(ge=0, le=1)
    confidence_basis: str
    dfkg_refs: list[str]
    threat_intel_refs: list[str]
    corpus_version: str | None = None
    corpus_hash: str | None = None
    degraded_flags: list[str] = Field(default_factory=list)
    narrative: str
    summary: str
    algorithm_version: str = "jaccard-sw-v1"
    scoring_parameters: dict = Field(default_factory=lambda: {
        "jaccard_weight": 0.4, "smith_waterman_weight": 0.6,
        "match": 2, "mismatch": -1, "gap": -1,
    })
