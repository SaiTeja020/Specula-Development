"""Actual store metadata for the local dashboard; unavailable stores stay explicit."""
import os


def quickwit_view():
    import requests
    try:
        response = requests.post(os.getenv("QUICKWIT_ENDPOINT", "http://localhost:7280") +
            "/api/v1/specula_raw_evidence/search", json={"query": "*", "max_hits": 10}, timeout=5)
        response.raise_for_status()
        return {"status": "success", "source": "quickwit", "logs": response.json().get("hits", [])}
    except Exception:
        return {"status": "unavailable", "source": "quickwit", "logs": []}


def chroma_view():
    import chromadb
    try:
        client = chromadb.HttpClient(host=os.getenv("CHROMA_HOST", "localhost"), port=int(os.getenv("CHROMA_PORT", "8000")))
        collections = client.list_collections()
        return {"status": "success", "source": "chromadb",
                "collections": [item.name if hasattr(item, "name") else str(item) for item in collections],
                "recent_queries": []}
    except Exception:
        return {"status": "unavailable", "source": "chromadb", "collections": [], "recent_queries": []}


def faiss_view():
    from src.mcp.threat_intel_mcp import ThreatIntelMCPServer
    health = ThreatIntelMCPServer(index_dir=os.getenv("SPECULA_THREAT_INTEL_DIR", "data/threat_intel")).health_check()
    return {"status": health["status"], "source": "faiss", "total_vectors": health["corpus_size"],
            "corpus_hash": health["corpus_hash"], "recent_hits": []}
