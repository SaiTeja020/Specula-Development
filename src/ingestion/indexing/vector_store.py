"""
Vector Store Engine Abstraction Layer for Specula.

Provides a unified interface (VectorStoreAdapter) with implementations:
1. ChromaVectorStore: Native ChromaDB persistent storage client wrapper.
2. InMemoryVectorStore: Zero-dependency in-memory cosine similarity store for testing.

Reference: vector_retrieval_implementation_plan.md §1 & §3
"""

import abc
import hashlib
import logging
import math
from typing import Any, Dict, List, Optional

logger = logging.getLogger("VectorStore")


class EmbeddingGenerator:
    """
    Embedding generator for vector retrieval.
    
    Attempts to use `sentence-transformers` if available; otherwise produces
    deterministic 384-dimensional unit-length float vectors based on text hashing.
    """

    def __init__(self, model_version: str = "mxbai-embed-large-v1", dimension: int = 384, use_st: bool = False):
        self.model_version = model_version
        self.dimension = dimension
        self._st_model = None

        if use_st:
            try:
                from sentence_transformers import SentenceTransformer
                self._st_model = SentenceTransformer("all-MiniLM-L6-v2")
                logger.info("SentenceTransformer initialized for vector embeddings.")
            except Exception:
                logger.info("SentenceTransformer not loaded; using deterministic hash-embedding fallback.")


    def embed(self, text: str) -> List[float]:
        """Generate a normalized float vector for input text."""
        if not text:
            return [0.0] * self.dimension

        if self._st_model is not None:
            vec = self._st_model.encode(text).tolist()
            return vec

        # Deterministic pseudo-embedding for zero-dependency execution
        raw_hash = hashlib.sha384(text.encode("utf-8")).digest()
        vec = []
        for i in range(self.dimension):
            byte_val = raw_hash[i % len(raw_hash)]
            val = (byte_val - 128) / 128.0
            vec.append(val)

        # Normalize vector length to 1.0 (unit vector for cosine similarity)
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec


class VectorStoreAdapter(abc.ABC):
    """Abstract interface for vector database implementations."""

    @abc.abstractmethod
    def upsert(self, record_id: str, text: str, vector: List[float], metadata: Dict[str, Any]) -> None:
        """Upsert a vector record into the store."""
        pass

    @abc.abstractmethod
    def query(
        self,
        query_vector: List[float],
        case_id: Optional[str] = None,
        source: Optional[str] = None,
        top_k: int = 5,
        min_score: float = -1.0,
    ) -> List[Dict[str, Any]]:
        """Query similar records using cosine similarity and metadata filters."""
        pass


    @abc.abstractmethod
    def delete(self, record_id: str) -> bool:
        """Delete a record by ID."""
        pass

    @abc.abstractmethod
    def count(self) -> int:
        """Return total record count in store."""
        pass


class InMemoryVectorStore(VectorStoreAdapter):
    """Zero-dependency in-memory vector store with cosine similarity math."""

    def __init__(self):
        self._records: Dict[str, Dict[str, Any]] = {}

    def upsert(self, record_id: str, text: str, vector: List[float], metadata: Dict[str, Any]) -> None:
        self._records[record_id] = {
            "id": record_id,
            "text": text,
            "vector": vector,
            "metadata": dict(metadata),
        }

    def query(
        self,
        query_vector: List[float],
        case_id: Optional[str] = None,
        source: Optional[str] = None,
        top_k: int = 5,
        min_score: float = -1.0,
    ) -> List[Dict[str, Any]]:

        results = []

        q_norm = math.sqrt(sum(v * v for v in query_vector))
        if q_norm == 0:
            return []

        for record in self._records.values():
            meta = record["metadata"]

            # Metadata filtering (Strict Case & Source Isolation)
            if case_id is not None and meta.get("case_id") != case_id:
                continue
            if source is not None and meta.get("source") != source:
                continue

            r_vec = record["vector"]
            r_norm = math.sqrt(sum(v * v for v in r_vec))
            if r_norm == 0:
                continue

            # Cosine similarity calculation
            dot_product = sum(q * r for q, r in zip(query_vector, r_vec))
            score = dot_product / (q_norm * r_norm)

            if score >= min_score:
                results.append({
                    "id": record["id"],
                    "score": float(score),
                    "text": record["text"],
                    "metadata": record["metadata"],
                })

        # Sort descending by similarity score
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def delete(self, record_id: str) -> bool:
        if record_id in self._records:
            del self._records[record_id]
            return True
        return False

    def count(self) -> int:
        return len(self._records)


class ChromaVectorStore(VectorStoreAdapter):
    """
    ChromaDB vector store adapter. Falls back to InMemoryVectorStore if chromadb
    is not installed on the system.
    """

    def __init__(self, collection_name: str = "specula_dfkg_vectors", persist_dir: Optional[str] = None):
        self.collection_name = collection_name
        self.fallback = None
        self.collection = None

        try:
            import chromadb
            import os
            if persist_dir:
                self.client = chromadb.PersistentClient(path=persist_dir)
            else:
                host = os.environ.get("CHROMA_HOST", "localhost")
                port = int(os.environ.get("CHROMA_PORT", 8000))
                self.client = chromadb.HttpClient(host=host, port=port)
            self.collection = self.client.get_or_create_collection(name=collection_name)
            logger.info(f"Initialized ChromaDB collection: {collection_name}")
        except Exception as e:
            logger.warning(f"ChromaDB unavailable ({e}); falling back to InMemoryVectorStore.")
            self.fallback = InMemoryVectorStore()

    def upsert(self, record_id: str, text: str, vector: List[float], metadata: Dict[str, Any]) -> None:
        if self.fallback is not None:
            return self.fallback.upsert(record_id, text, vector, metadata)

        self.collection.upsert(
            ids=[record_id],
            documents=[text],
            embeddings=[vector],
            metadatas=[metadata],
        )

    def query(
        self,
        query_vector: List[float],
        case_id: Optional[str] = None,
        source: Optional[str] = None,
        top_k: int = 5,
        min_score: float = -1.0,
    ) -> List[Dict[str, Any]]:
        if self.fallback is not None:
            return self.fallback.query(query_vector, case_id=case_id, source=source, top_k=top_k, min_score=min_score)

        where_clause = {}
        if case_id and source:
            where_clause = {"$and": [{"case_id": case_id}, {"source": source}]}
        elif case_id:
            where_clause = {"case_id": case_id}
        elif source:
            where_clause = {"source": source}

        res = self.collection.query(
            query_embeddings=[query_vector],
            n_results=top_k,
            where=where_clause if where_clause else None,
        )

        out = []
        if res and "ids" in res and res["ids"]:
            ids = res["ids"][0]
            distances = res.get("distances", [[]])[0]
            docs = res.get("documents", [[]])[0]
            metas = res.get("metadatas", [[]])[0]

            for rid, dist, doc, meta in zip(ids, distances, docs, metas):
                # ChromaDB default metric is L2 distance or cosine distance: score = 1 - distance
                score = 1.0 - dist if dist <= 1.0 else 1.0 / (1.0 + dist)
                if score >= min_score:
                    out.append({
                        "id": rid,
                        "score": float(score),
                        "text": doc,
                        "metadata": meta,
                    })

        return out

    def delete(self, record_id: str) -> bool:
        if self.fallback is not None:
            return self.fallback.delete(record_id)
        try:
            self.collection.delete(ids=[record_id])
            return True
        except Exception:
            return False

    def count(self) -> int:
        if self.fallback is not None:
            return self.fallback.count()
        return self.collection.count()
