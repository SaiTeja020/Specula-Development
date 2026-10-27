"""Durable, case-isolated semantic evidence indexing with local Ollama."""
import json
import math
import os
from hashlib import sha256

import requests
from src.agents.ollama_backend import OllamaLLM


class LocalEmbeddings:
    def __init__(self):
        self.model = os.getenv("SPECULA_EMBEDDING_MODEL", "qwen3-embedding:0.6b")
        self.base = OllamaLLM(self.model, os.getenv("SPECULA_OLLAMA_BASE_URL", "http://127.0.0.1:11434")).base_url
        with requests.Session() as s:
            s.trust_env = False
            r = s.get(self.base+"/api/tags", timeout=10, allow_redirects=False)
            r.raise_for_status()
            model = next((m for m in r.json().get("models", []) if m["name"] == self.model), None)
        if not model or model.get("remote_host") or model.get("remote_model"):
            raise RuntimeError("Installed local semantic embedding model unavailable")
        self.digest = model["digest"]

    def embed_batch(self, texts):
        with requests.Session() as s:
            s.trust_env = False
            r = s.post(self.base+"/api/embed", json={"model": self.model, "input": texts, "truncate": False},
                       timeout=(10, 180), allow_redirects=False)
            r.raise_for_status()
            vectors = r.json().get("embeddings", [])
        if len(vectors) != len(texts) or not vectors or any(not v or not all(math.isfinite(x) for x in v) for v in vectors):
            raise RuntimeError("Semantic embedding response incomplete")
        return vectors


def chroma_client():
    import chromadb
    return chromadb.HttpClient(host=os.getenv("CHROMA_HOST", "localhost"), port=int(os.getenv("CHROMA_PORT", "8000")))


class CaseEvidenceRetriever:
    """Saved-case access does not require starting the embedding service."""
    def retrieve_similar_events(self,*args,**kwargs):
        return CaseEvidenceIndex().retrieve_similar_events(*args,**kwargs)


class CaseEvidenceIndex:
    def __init__(self, client=None, embedder=None):
        self.embedder = embedder or LocalEmbeddings()
        self.client = client or chroma_client()
        self.name = "specula_case_evidence_"+sha256(self.embedder.digest.encode()).hexdigest()[:16]
        self.collection = self.client.get_or_create_collection(self.name, metadata={
            "hnsw:space": "cosine", "embedding_model": self.embedder.model,
            "model_digest": self.embedder.digest, "source": "case_evidence"})

    def index(self, case_id, events):
        unique = {e["uid"]: e for e in events}
        if not unique:
            raise ValueError("Cannot verify a semantic index with no case evidence")
        existing=self.collection.get(where={'case_id':case_id},include=['metadatas'])
        stored_hashes={key:meta.get('document_sha256') for key,meta in zip(existing['ids'],existing['metadatas'])}
        chunks=[];expected=set()
        for e in unique.values():
            # Case membership is enforced by metadata; a shared event's first-writer tag is not evidence content.
            full=json.dumps({k:v for k,v in e.items() if k!='case_id'},sort_keys=True,default=str)
            pieces=[full[i:i+2000] for i in range(0,len(full),2000)]
            for i,text in enumerate(pieces):
                key=sha256((case_id+':'+e['uid']+(':'+str(i) if i else '')).encode()).hexdigest()
                expected.add(key)
                digest=sha256(text.encode()).hexdigest()
                if stored_hashes.get(key)==digest:
                    continue
                meta={'case_id':case_id,'uid':e['uid'],'source':'case_evidence',
                      'embedding_model':self.embedder.model,'model_digest':self.embedder.digest,
                      'class_uid':e.get('class_uid',0),'host':e.get('canonical_host_id') or 'unknown',
                      'chunk_index':i,'chunk_count':len(pieces),'document_sha256':digest}
                chunks.append((key,text,meta))
        for offset in range(0,len(chunks),32):
            batch=chunks[offset:offset+32]
            texts=[row[1] for row in batch]
            self.collection.upsert(ids=[row[0] for row in batch],documents=texts,
                embeddings=self.embedder.embed_batch(texts),metadatas=[row[2] for row in batch])
        stored = self.collection.get(where={"case_id": case_id}, include=["metadatas"])
        stored_uids = {m["uid"] for m in stored["metadatas"]}
        if not set(unique) <= stored_uids or not expected <= set(stored['ids']):
            raise RuntimeError("Chroma write receipt does not cover case evidence")
        # Retire obsolete derived chunks only for this successfully indexed batch.
        # Other events/cases and their preserved source records remain untouched.
        obsolete=[key for key,meta in zip(stored['ids'],stored['metadatas'])
                  if meta['uid'] in unique and key not in expected]
        if obsolete:
            self.collection.delete(ids=obsolete)
        return {"status": "verified", "collection": self.name, "case_id": case_id,
                "submitted": len(unique), "stored": len(stored_uids), "chunks":len(expected),
                "embedding_model": self.embedder.model, "model_digest": self.embedder.digest}

    def retrieve_similar_events(self, query_text, case_id=None, top_k=5, min_score=-1, caller_role=None):
        from src.mcp.vector_retrieval import READ_ONLY_EVENT_ROLES
        if not case_id or (caller_role and caller_role not in READ_ONLY_EVENT_ROLES):
            raise PermissionError("Evidence retrieval requires a case and authorized event reader")
        count = len(self.collection.get(where={"case_id": case_id}, include=[])['ids'])
        if not count:
            return {"status": "ok", "count": 0, "results": []}
        data = self.collection.query(query_embeddings=self.embedder.embed_batch([query_text]),
            where={"case_id": case_id}, n_results=min(top_k, count), include=["documents", "metadatas", "distances"])
        results = []
        for text, meta, distance in zip(data['documents'][0], data['metadatas'][0], data['distances'][0]):
            if meta["case_id"] != case_id:
                raise RuntimeError("Vector store returned another case's evidence")
            if 1-distance >= min_score:
                results.append({"citation_uid": meta["uid"], "prose": text, "metadata": meta, "score": 1-distance})
        return {"status": "ok", "count": len(results), "results": results}


def case_chroma_view(case_id, limit=300):
    try:
        collections, records, total, event_uids = [], [], 0, set()
        for entry in chroma_client().list_collections():
            name = entry.name if hasattr(entry, "name") else str(entry)
            if not name.startswith("specula_case_evidence_"):
                continue
            collection = chroma_client().get_collection(name)
            all_rows = collection.get(where={"case_id": case_id}, include=['metadatas'])
            ids=all_rows['ids']
            event_uids.update(m['uid'] for m in all_rows['metadatas'])
            if not ids:
                continue
            total += len(ids)
            collections.append({"name": name, "count": len(ids), **(collection.metadata or {})})
            data = collection.get(where={"case_id": case_id}, limit=limit, include=["metadatas"])
            records.extend(data["metadatas"])
        return {"status": "success", "source": "chromadb", "scope": "case", "case_id": case_id,
                "collections": collections, "total_vectors": total, "total_events":len(event_uids), "records": records[:limit], "display_limit": limit}
    except Exception as error:
        return {"status": "unavailable", "source": "chromadb", "case_id": case_id,
                "detail": "Case semantic index could not be read", "error_type": type(error).__name__, "collections": []}
