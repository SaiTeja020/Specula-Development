"""Readiness checks for the existing local stack; never starts or deletes services."""
import asyncio
import os


def register_readiness_route(app, get_driver):
    @app.get("/api/system/readiness")
    async def readiness():
        def checks():
            import requests
            import redis
            import chromadb
            from confluent_kafka.admin import AdminClient
            probes = {
                "redis": lambda: redis.Redis(host=os.getenv("REDIS_HOST", "localhost"),
                    port=int(os.getenv("REDIS_PORT", "6379")), socket_timeout=3).ping(),
                "kafka": lambda: AdminClient({"bootstrap.servers": os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")}).list_topics(timeout=3),
                "quickwit": lambda: requests.get(os.getenv("QUICKWIT_ENDPOINT", "http://localhost:7280") + "/health/livez", timeout=3).raise_for_status(),
                "neo4j": lambda: get_driver().verify_connectivity(),
                "chroma": lambda: chromadb.HttpClient(host=os.getenv("CHROMA_HOST", "localhost"),
                    port=int(os.getenv("CHROMA_PORT", "8000"))).heartbeat(),
            }
            results = {}
            for name, probe in probes.items():
                try:
                    probe()
                    results[name] = {"status": "ready"}
                except Exception:
                    results[name] = {"status": "unavailable"}
            try:
                from src.mcp.threat_intel_mcp import ThreatIntelMCPServer
                corpus = ThreatIntelMCPServer(index_dir=os.getenv(
                    "SPECULA_THREAT_INTEL_DIR", "data/threat_intel")).health_check()
                results["threat_intel"] = {
                    "status": "ready" if corpus.get("status") == "ready"
                    and corpus.get("artifacts_verified") is True
                    and not corpus.get("is_stale") else "unavailable",
                    "corpus_size": corpus.get("corpus_size", 0),
                    "artifacts_verified": corpus.get("artifacts_verified", False),
                }
            except Exception:
                results["threat_intel"] = {"status": "unavailable", "corpus_size": 0,
                                           "artifacts_verified": False}
            # This reports configuration; provider inference has a separate live oracle.
            results["llm"] = {"status": "configured", "backend": os.getenv("SPECULA_LLM_BACKEND", "stub")}
            return {"status": "success" if all(item["status"] != "unavailable" for item in results.values()) else "error",
                    "services": results, "message": "Checked existing services; model inference is not verified."}
        return await asyncio.to_thread(checks)
    return readiness
