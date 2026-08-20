"""
Specula OCSF Base Event Envelope.

Defines the canonical Pydantic v2 base model that every source normalizer
maps into. All fields listed here are mandatory on every ingested event,
with defaults only where the v6 plan explicitly specifies one.

Reference: specula_ingestion_final_plan.md §2.1
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class OCSFBaseEvent(BaseModel):
    """
    Base OCSF event envelope. Every normaliser's output must be a subclass
    of this model or validate against it.

    Field semantics (do not deviate):
    - case_id:  Active investigation case UUID, or "UNASSIGNED_CONTINUOUS"
                for background telemetry not yet scoped to a case.
                Never None — a None case_id silently breaks every Kafka
                partition-key computation and every downstream Cypher
                WHERE case_id = $case_id filter.
    - trace_id: W3C trace-context identifier, generated at the ingestion
                boundary (Step 1), not later.
    - ocsf_version: Pinned schema version. Bump only via explicit migration.
    - time:     Corrected UTC timestamp (ISO 8601). This is NOT the raw
                source string — see raw_source_timestamp for that.
    - raw_source_timestamp: Original, unedited timestamp string exactly as
                it appeared at the source. Never overwritten by any
                downstream step. Required for Daubert admissibility.
    - clock_skew_offset_ms: Signed integer offset applied so that
                time = parse(raw_source_timestamp) + clock_skew_offset_ms.
                0 means verified zero skew, not "unknown" — see
                clock_skew_unverified for the unknown case.
    - clock_skew_unverified: True when no anchor (e.g. DC) was available to
                verify clock skew. Distinguishes "verified zero offset" from
                "no anchor available, offset assumed zero."
    - security_scan_degraded: True when the event was processed under Rebuff
                fallback (local heuristic) rather than full Rebuff scanning.
    - uid:      Deterministic content-hash UID. See uid_generator.py.
    """

    # --- Mandatory observability & case-lifecycle metadata ---
    case_id: str = Field(
        default="UNASSIGNED_CONTINUOUS",
        description="Active investigation case UUID, or UNASSIGNED_CONTINUOUS.",
    )
    trace_id: str = Field(
        ...,
        description="W3C trace-context identifier, generated at ingestion boundary.",
    )
    ocsf_version: str = Field(
        default="1.2.0",
        description="Pinned OCSF schema version. Bump only via explicit migration.",
    )

    # --- OCSF class identifiers ---
    activity_id: int = Field(..., description="OCSF activity identifier.")
    class_uid: int = Field(..., description="OCSF class unique identifier.")
    category_uid: int = Field(..., description="OCSF category unique identifier.")
    severity_id: int = Field(..., description="OCSF severity identifier (0-6).")

    # --- Dual timestamps (Daubert admissibility requirement) ---
    time: datetime = Field(
        ...,
        description=(
            "Corrected UTC timestamp (ISO 8601). "
            "This is the adjusted value, NOT the raw source string."
        ),
    )
    raw_source_timestamp: str = Field(
        ...,
        description=(
            "Original, unedited timestamp string as it appeared at the source. "
            "Never overwritten by any downstream step."
        ),
    )
    clock_skew_offset_ms: int = Field(
        default=0,
        description=(
            "Signed integer offset (ms) applied to derive 'time' from "
            "raw_source_timestamp. 0 = verified zero skew, not unknown."
        ),
    )
    clock_skew_unverified: bool = Field(
        default=False,
        description=(
            "True when no anchor (e.g. domain controller) was available "
            "to verify clock skew. Distinguishes verified zero-offset "
            "from unverifiable assumed-zero."
        ),
    )

    # --- Security gate metadata ---
    security_scan_degraded: bool = Field(
        default=False,
        description=(
            "True if this event was processed under Rebuff fallback mode "
            "(local heuristic) rather than full Rebuff scanning."
        ),
    )

    # --- Deterministic entity UID ---
    uid: str = Field(
        ...,
        description="Deterministic content-hash UID. See uid_generator.py.",
    )

    # --- Optional fields for downstream agent consumption ---
    canonical_host_id: Optional[str] = Field(
        default=None,
        description="Resolved canonical host identifier.",
    )
    is_summary: bool = Field(
        default=False,
        description="Flag indicating if event is an entropy summary.",
    )
    status: Optional[str] = Field(
        default=None,
        description="Status of the event (e.g. Success, Failure).",
    )

    @field_validator("case_id", mode="before")
    @classmethod
    def case_id_must_not_be_none(cls, v: Optional[str]) -> str:
        """
        Reject None explicitly. A None case_id breaks Kafka partition-key
        computation and Cypher WHERE filters silently (matches nothing
        instead of erroring).
        """
        if v is None:
            raise ValueError(
                "case_id must not be None. Use 'UNASSIGNED_CONTINUOUS' "
                "for events not yet scoped to a case."
            )
        return v

    model_config = {
        "json_schema_extra": {
            "description": (
                "Specula OCSF base event envelope. All ingested events "
                "must conform to this schema or a subclass of it."
            ),
        },
    }
