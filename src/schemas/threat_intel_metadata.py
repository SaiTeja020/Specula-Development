"""
Pydantic v2 metadata schema for FAISS threat-intel corpus records.

Deliberately parallel to -- but distinct from -- vector_metadata.py.
Threat-intel records are global and not case-scoped; forcing them through
VectorFindingMetadata (which requires case_id + trace_id) would mean
inventing meaningless placeholder values, which is exactly the kind of
silent semantic corruption the deterministic-UID doc warns against.

Reference: faiss_threat_intel_implementation_plan.md §5
"""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class ThreatIntelRecordMetadata(BaseModel):
    """Metadata payload attached to each threat-intel record in the FAISS corpus."""

    record_id: str = Field(
        ...,
        description=(
            "Stable, source-assigned identifier. "
            "ATT&CK technique: e.g. 'T1059.001'. "
            "ATT&CK group: e.g. 'G0016'. "
            "CVE: e.g. 'CVE-2024-1234'."
        ),
    )
    record_type: Literal["attack_technique", "attack_group", "cve"] = Field(
        ...,
        description="Discriminator for post-search filtering.",
    )
    title: str = Field(..., description="Short human-readable name of the record.")
    description: str = Field(
        default="",
        description="Full sanitized description text used to produce the embedding.",
    )
    source: Literal["mitre_attack_stix", "nvd_cve"] = Field(
        ...,
        description="Authoritative data source.",
    )
    source_version: str = Field(
        ...,
        description=(
            "STIX bundle release tag (e.g. 'ATT&CK-v15.1') "
            "or NVD feed snapshot date (e.g. '2026-08-18')."
        ),
    )
    embedding_model_version: str = Field(
        default="mxbai-embed-large-v1",
        description="Versioned identifier of the embedding model used at build time.",
    )
    tags: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional categorical tags. "
            "ATT&CK: tactic names (e.g. ['execution', 'persistence']). "
            "CVE: CWE IDs (e.g. ['CWE-79', 'CWE-89'])."
        ),
    )

    def to_dict(self) -> dict:
        """Return primitive-only dict (JSON-serializable, safe for metadata stores)."""
        return self.model_dump(mode="json")
