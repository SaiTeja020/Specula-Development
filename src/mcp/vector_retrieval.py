"""
Vector Retrieval MCP Server Implementation (Section 2.5 & mcp-vector-retrieval).

Exposes semantic similarity search over historical DFKG findings and closed-case archives.
Enforces read-only agent roles, strict case isolation, and scratchpad anti-pollution.

Reference: vector_retrieval_implementation_plan.md §3 & §4
"""

import logging
import time
from typing import Any, Dict, List, Optional

from src.ingestion.indexing.vector_store import (
    ChromaVectorStore,
    EmbeddingGenerator,
    InMemoryVectorStore,
    VectorStoreAdapter,
)
from src.schemas.vector_metadata import VectorFindingMetadata

logger = logging.getLogger("VectorRetrievalMCP")


# Role-Based Access Control Lists (RBAC) per plan §3.1 & §4
READ_ONLY_EVENT_ROLES = {
    "Judge",
    "Confidence-Scorer",
    "Timeline-Agent",
    "Report-Agent",
    "System",
    "TestRunner",
    # [RESOLVED item #44] Log-Analysis-Agent: event-level read + retrieve_similar_events only.
    # NOT granted case-level read (READ_ONLY_CASE_ROLES) or any write permission.
    "Log-Analysis-Agent",
}

READ_ONLY_CASE_ROLES = {
    "Judge",
    "Report-Agent",
    "System",
    "TestRunner",
}

ALLOWED_SYSTEM_WRITE_ROLES = {
    "System",
    "Pipeline",
    "APOC_Trigger",
    "TestRunner",
}


class VectorRetrievalMCPServer:
    """MCP Server exposing vector search and system indexing capabilities."""

    def __init__(
        self,
        vector_store: Optional[VectorStoreAdapter] = None,
        embedding_generator: Optional[EmbeddingGenerator] = None,
        model_version: str = "mxbai-embed-large-v1",
    ):
        self.embedding_generator = embedding_generator or EmbeddingGenerator(model_version=model_version)
        self.vector_store = vector_store or InMemoryVectorStore()
        self.model_version = model_version
        self._is_healthy = True

    def retrieve_similar_events(
        self,
        query_text: str,
        case_id: Optional[str] = None,
        top_k: int = 5,
        min_score: float = -1.0,
        caller_role: Optional[str] = None,
    ) -> Dict[str, Any]:

        """
        Tool: retrieve_similar_events
        Callable by: Judge, Confidence-Scorer, Timeline-Agent, Report-Agent.
        Implements similarity search over promoted findings.
        """
        if caller_role and caller_role not in READ_ONLY_EVENT_ROLES:
            raise PermissionError(f"Agent role '{caller_role}' is not authorized to execute event retrieval.")

        if not query_text or not query_text.strip():
            return {"status": "ok", "count": 0, "results": []}

        query_vector = self.embedding_generator.embed(query_text)
        results = self.vector_store.query(
            query_vector=query_vector,
            case_id=case_id,
            source="dfkg_finding",
            top_k=top_k,
            min_score=min_score,
        )

        return {
            "status": "ok",
            "count": len(results),
            "case_id_filter": case_id,
            "results": results,
        }

    def retrieve_similar_cases(
        self,
        case_summary: str,
        top_k: int = 3,
        min_score: float = -1.0,
        caller_role: Optional[str] = None,
    ) -> Dict[str, Any]:

        """
        Tool: retrieve_similar_cases
        Callable by: Judge, Report-Agent.
        Cross-case analogy search over closed-case archives.
        """
        if caller_role and caller_role not in READ_ONLY_CASE_ROLES:
            raise PermissionError(f"Agent role '{caller_role}' is not authorized to execute cross-case retrieval.")

        if not case_summary or not case_summary.strip():
            return {"status": "ok", "count": 0, "results": []}

        query_vector = self.embedding_generator.embed(case_summary)
        results = self.vector_store.query(
            query_vector=query_vector,
            case_id=None,
            source="closed_case_archive",
            top_k=top_k,
            min_score=min_score,
        )

        return {
            "status": "ok",
            "count": len(results),
            "results": results,
        }

    def upsert_finding_embedding(
        self,
        finding_id: str,
        text: str,
        metadata: Dict[str, Any],
        caller_role: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Tool: upsert_finding_embedding
        Internal-only system write interface.
        Rejects calls from standard agent roles to prevent scratchpad pollution.
        """
        if caller_role and caller_role not in ALLOWED_SYSTEM_WRITE_ROLES:
            raise PermissionError(
                f"Agent role '{caller_role}' cannot write directly to vector store. "
                "Only promoted graph findings via system triggers may be indexed."
            )

        validated_meta = VectorFindingMetadata(**metadata)
        validated_meta.finding_id = finding_id
        validated_meta.embedding_model_version = self.model_version

        vector = self.embedding_generator.embed(text)
        self.vector_store.upsert(
            record_id=finding_id,
            text=text,
            vector=vector,
            metadata=validated_meta.to_dict(),
        )

        return {
            "status": "success",
            "finding_id": finding_id,
            "source": validated_meta.source,
            "stored_at": time.time(),
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Tool: health_check
        Returns health status, record count, and store type.
        """
        count = self.vector_store.count()
        store_type = type(self.vector_store).__name__

        return {
            "status": "healthy" if self._is_healthy else "degraded",
            "vector_store_backend": store_type,
            "total_records": count,
            "embedding_model_version": self.model_version,
        }
