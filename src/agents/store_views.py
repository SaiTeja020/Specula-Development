"""Actual store metadata for the local dashboard; unavailable stores stay explicit."""
import os
import json


def quickwit_view(query="*", max_hits=10):
    import requests
    try:
        response = requests.post(os.getenv("QUICKWIT_ENDPOINT", "http://localhost:7280") +
            "/api/v1/specula_raw_evidence/search", json={"query": query, "max_hits": max_hits}, timeout=5)
        response.raise_for_status()
        result = response.json()
        return {"status": "success", "source": "quickwit", "logs": result.get("hits", []),
                "total_records": result.get("num_hits", len(result.get("hits", []))),
                "display_limit": max_hits}
    except Exception:
        return {"status": "unavailable", "source": "quickwit", "logs": []}


def chroma_view():
    import chromadb
    try:
        client = chromadb.HttpClient(host=os.getenv("CHROMA_HOST", "localhost"), port=int(os.getenv("CHROMA_PORT", "8000")))
        collections = client.list_collections()
        counts = []
        for item in collections:
            name = item.name if hasattr(item, 'name') else str(item)
            counts.append({"name": name, "count": client.get_collection(name).count()})
        return {"status": "success", "source": "chromadb",
                "collections": [item['name'] for item in counts], "collection_counts": counts,
                "total_vectors": sum(item['count'] for item in counts)}
    except Exception:
        return {"status": "unavailable", "source": "chromadb", "collections": []}


def faiss_view():
    from src.mcp.threat_intel_mcp import ThreatIntelMCPServer
    health = ThreatIntelMCPServer(index_dir=os.getenv("SPECULA_THREAT_INTEL_DIR", "data/threat_intel")).health_check()
    return {"status": health["status"], "source": "faiss", "total_vectors": health["corpus_size"],
            "corpus_hash": health["corpus_hash"], "scope": "shared_threat_intelligence"}


def case_store_view(store, case_id, snapshot):
    """Never substitute global evidence for an empty case checkpoint."""
    if store == "chroma":
        from src.ingestion.indexing.case_evidence import case_chroma_view
        payload = case_chroma_view(case_id)
        receipt = (snapshot.get('ingestion_provenance') or {}).get('vector_index') or {}
        if payload.get('status') == 'success' and receipt.get('status') == 'verified' and payload.get('total_events', 0) < receipt.get('stored', 0):
            payload['warning'] = 'The current case index contains fewer events than its historical indexing receipt. The saved receipt does not confirm present availability.'
        return payload
    if store == "duckdb":
        from .case_analytics import case_analytics_view
        return case_analytics_view(case_id)
    if store == "quickwit":
        records = (snapshot.get("evidence_collection") or {}).get("records", [])
        identifiers = sorted({("trace_id", str(record["trace_id"])) if record.get("trace_id")
                              else ("uid", str(record["uid"]))
                              for record in records if record.get("trace_id") or record.get("uid")})
        if identifiers:
            query = " OR ".join(field + ":" + json.dumps(value) for field, value in identifiers)
            payload = quickwit_view(query, max_hits=300)
        else:
            payload = {"status": "success", "source": "quickwit", "logs": [],
                       "detail": "No preserved evidence identifiers in this case checkpoint"}
        return {**payload, "case_id": case_id, "scope": "case",
                "evidence_identifiers": len(identifiers), "display_limit": 300}
    if store == "faiss":
        return {**faiss_view(), "case_id": case_id, "scope": "shared_threat_intelligence",
                "detail": "Shared threat intelligence; case attribution is saved in Agents"}
    return {"status": "unavailable", "source": store, "case_id": case_id, "scope": "case",
            "detail": "No case-specific store integration is available",
            "collections": [], "tables": []}
