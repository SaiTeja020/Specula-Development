"""
Pydantic v2 metadata schema for vector retrieval embeddings.

Reference: vector_retrieval_implementation_plan.md §3.3
"""

from datetime import datetime, timezone
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator


class VectorFindingMetadata(BaseModel):
    """Metadata payload attached to each vector embedding in the vector store."""
    finding_id: str = Field(..., description="Deterministic UID of the finding or case record")
    case_id: str = Field(..., description="Canonical active case ID or UNASSIGNED_CONTINUOUS")
    trace_id: str = Field(..., description="OpenTelemetry trace identifier")
    agent_role: str = Field(..., description="Originating agent role or system process")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of record creation")
    embedding_model_version: str = Field(
        default="mxbai-embed-large-v1",
        description="Versioned identifier of embedding model"
    )
    source: Literal["dfkg_finding", "closed_case_archive"] = Field(
        default="dfkg_finding",
        description="Origin source of vector payload"
    )

    @field_validator("timestamp", mode="before")
    def validate_timestamp_format(cls, v):
        if isinstance(v, datetime):
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            return v.isoformat()
        if isinstance(v, str):
            return v
        raise ValueError("timestamp must be an ISO 8601 string or datetime object")

    def to_dict(self) -> dict:
        """Return primitive dictionary representation suitable for ChromaDB metadata."""
        return {
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "trace_id": self.trace_id,
            "agent_role": self.agent_role,
            "timestamp": self.timestamp,
            "embedding_model_version": self.embedding_model_version,
            "source": self.source,
        }
