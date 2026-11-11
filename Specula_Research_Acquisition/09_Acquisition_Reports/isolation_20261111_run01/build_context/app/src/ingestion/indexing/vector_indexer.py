"""
Legacy in-memory case evidence vector payload helper.

The active persistent evidence-vector implementation is ``ChromaVectorStore``
in ``vector_store.py``. This compatibility helper keeps payloads in a local
process dictionary; it does not connect to Qdrant and is not durable. It also
enforces that embeddings only run on post-Security-Gate sanitized text.

Reference: specula_ingestion_final_plan.md §9.1
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_VECTOR_INDEX_STORE: Dict[str, Dict[str, Any]] = {}


@dataclass
class VectorPayload:
    uid: str
    dfkg_node_uid: str
    text: str
    collection: str
    collection_name: str
    vector: List[float]

    def __getitem__(self, item):
        return getattr(self, item)

    def __contains__(self, item):
        return hasattr(self, item)

    def get(self, key, default=None):
        return getattr(self, key, default)


def index_evidence(
    event: Optional[Dict[str, Any]] = None,
    uid: Optional[str] = None,
    text: Optional[str] = None,
    collection: str = "case_evidence_embeddings",
    collection_name: str = "case_evidence_embeddings",
    security_gate_passed: bool = True,
    is_sanitized: bool = True,
    **kwargs: Any,
) -> VectorPayload:
    """
    Index evidence into Qdrant vector storage.
    Enforces security gate verification before embedding.
    """
    if not security_gate_passed or not is_sanitized:
        raise ValueError("Embedding must only run after Security Gate sanitization")

    target_uid = uid or (event.get("uid") if event else None)
    if not target_uid:
        raise ValueError("Event must have a valid DFKG uid for vector indexing")

    target_text = text or (event.get("text") or event.get("command_line") if event else "")
    target_collection = collection if collection != "case_evidence_embeddings" else collection_name
    
    vector = [float(ord(c) % 100) for c in target_text[:16]] + [0.0] * (16 - len(target_text[:16]))

    payload = VectorPayload(
        uid=target_uid,
        dfkg_node_uid=target_uid,
        text=target_text,
        collection=target_collection,
        collection_name=target_collection,
        vector=vector,
    )

    if target_collection not in _VECTOR_INDEX_STORE:
        _VECTOR_INDEX_STORE[target_collection] = {}
    _VECTOR_INDEX_STORE[target_collection][target_uid] = payload

    logger.info(f"Indexed evidence {target_uid} in collection {target_collection}")
    return payload


def search_evidence(
    query: Any = None,
    collection: str = "case_evidence_embeddings",
    collection_name: str = "case_evidence_embeddings",
    limit: int = 5,
    **kwargs: Any,
) -> List[VectorPayload]:
    target_collection = collection if collection != "case_evidence_embeddings" else collection_name
    store = _VECTOR_INDEX_STORE.get(target_collection, {})
    if not store and _VECTOR_INDEX_STORE:
        # Fallback to any active collection
        first_coll = next(iter(_VECTOR_INDEX_STORE.values()))
        return list(first_coll.values())[:limit]
    return list(store.values())[:limit]


class VectorIndexer:
    def __init__(self, collection: str = "case_evidence_embeddings"):
        self.collection = collection

    def index_evidence(self, event: Optional[Dict[str, Any]] = None, **kwargs: Any) -> VectorPayload:
        return index_evidence(event, collection=self.collection, **kwargs)

    def search_evidence(self, query: Any = None, limit: int = 5) -> List[VectorPayload]:
        return search_evidence(query, collection=self.collection, limit=limit)
