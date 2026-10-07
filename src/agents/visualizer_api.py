"""Real-time monitoring and visualization API for Specula LangGraph — §9.

This standalone microservice provides:
- GET /api/graph/topology: Returns the nodes and edges for React Flow.
- WS  /api/graph/stream: WebSocket streaming for active node tracking and state updates.
- POST /api/investigations: Executes an ingested case and streams actual graph updates.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from dotenv import load_dotenv

load_dotenv()  # Load local configuration before readiness or cached drivers.

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy-loaded heavy dependencies (neo4j, langgraph pull in numpy which
# fatally crashes on Python 3.13 + Windows MINGW builds if loaded eagerly
# at module-import time).  We defer their import to first use so that the
# FastAPI server can start immediately for boot / health / websocket.
# ---------------------------------------------------------------------------
_neo4j_driver = None
_specula_graph = None


def _get_neo4j_driver():
    """Return the Neo4j driver, creating it on first call."""
    global _neo4j_driver
    if _neo4j_driver is None:
        try:
            from neo4j import GraphDatabase
            import os
            uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
            password = os.environ.get("NEO4J_PASSWORD", "")
            auth = (os.environ.get("NEO4J_USER", "neo4j"), password) if password else None
            _neo4j_driver = GraphDatabase.driver(uri, auth=auth)
        except Exception as e:
            log.warning(f"Neo4j driver initialization failed: {e}")
    return _neo4j_driver


def _get_specula_graph():
    """Return the compiled LangGraph, building it on first call."""
    global _specula_graph
    if _specula_graph is None:
        try:
            from langgraph.checkpoint.memory import InMemorySaver
            from .graph import build_graph
            checkpointer = InMemorySaver()
            from src.mcp.threat_intel_mcp import ThreatIntelMCPServer
            from redis import Redis
            _specula_graph = build_graph(checkpointer=checkpointer, neo4j_driver=_get_neo4j_driver(),
                redis_client=Redis(host=os.getenv("REDIS_HOST", "localhost"), port=int(os.getenv("REDIS_PORT", "6379"))),
                threat_intel=ThreatIntelMCPServer(index_dir=os.getenv("SPECULA_THREAT_INTEL_DIR", "data/threat_intel")))
        except Exception as e:
            log.warning(f"LangGraph initialization failed: {e}")
    return _specula_graph


# ---------------------------------------------------------------------------
# FastAPI app — lightweight, starts without numpy
# ---------------------------------------------------------------------------
app = FastAPI(title="Specula Visualizer API", version="1.0.0")

# Allow CORS for the Vite frontend (usually runs on port 5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global set of active websocket connections
active_connections: set[WebSocket] = set()

@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint to verify API is active."""
    return {"status": "ok"}


@app.get("/api/graph/topology")
async def get_topology() -> dict[str, Any]:
    """Extract and return the graph's nodes and edges in a format suitable for React Flow."""
    graph = _get_specula_graph()
    if graph is None:
        return {"nodes": [], "edges": [], "error": "Graph not available (numpy/langgraph not loaded)"}

    # LangGraph exposes the underlying graph structure
    g = graph.get_graph()
    
    react_nodes = []
    react_edges = []
    
    # Assign some arbitrary coordinates, React Flow can use dagre/elk to layout,
    # or we can do a simple layout. We will rely on the frontend for layouting.
    for node_id, node_data in g.nodes.items():
        react_nodes.append({
            "id": node_id,
            "position": {"x": 0, "y": 0}, # Frontend will compute layout
            "data": {"label": node_id.replace("_", " ").title()}
        })
        
    for idx, edge in enumerate(g.edges):
        react_edges.append({
            "id": f"e_{edge.source}_{edge.target}_{idx}",
            "source": edge.source,
            "target": edge.target,
            "animated": False
        })
        
    return {
        "nodes": react_nodes,
        "edges": react_edges
    }


@app.websocket("/api/graph/stream")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint to stream real-time graph events."""
    await websocket.accept()
    active_connections.add(websocket)
    log.info(f"WebSocket client connected. Total clients: {len(active_connections)}")
    try:
        while True:
            # Keep connection alive, wait for client messages if any
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        active_connections.discard(websocket)
        log.info(f"WebSocket client disconnected. Total clients: {len(active_connections)}")


async def broadcast_event(event_type: str, payload: dict):
    """Broadcast an event to all connected WebSocket clients."""
    if not active_connections:
        return
        
    message = json.dumps({"type": event_type, "payload": payload})
    stale_connections = set()
    
    for connection in list(active_connections):
        try:
            await asyncio.wait_for(connection.send_text(message), timeout=1)
        except Exception:
            stale_connections.add(connection)
            
    # Clean up dead connections
    for connection in stale_connections:
        active_connections.discard(connection)


# ---------------------------------------------------------------------------
# System Boot — Docker teardown + recreate
# ---------------------------------------------------------------------------
boot_lock = asyncio.Lock()

@app.post("/api/system/boot")
async def system_boot():
    """Compatibility endpoint: inspect an existing stack without rebuilding it."""
    return await system_readiness()


from .runtime_readiness import register_readiness_route

system_readiness = register_readiness_route(app, _get_neo4j_driver)

# ---------------------------------------------------------------------------
# Pipeline trigger
# ---------------------------------------------------------------------------
from .investigation_api import register_investigation_routes

register_investigation_routes(app, _get_specula_graph, _get_neo4j_driver, broadcast_event)


# ---------------------------------------------------------------------------
# Data-store proxy endpoints
# ---------------------------------------------------------------------------
@app.get("/api/data/neo4j")
async def get_neo4j_data():
    """Proxy endpoint to fetch Neo4j graph data for the visualizer."""
    driver = _get_neo4j_driver()
    if driver is None:
        return {"status": "error", "message": "Neo4j driver not available"}
    try:
        nodes_dict = {}
        edges_list = []
        with driver.session() as session:
            result = session.run("MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 100")
            for record in result:
                n = record["n"]
                m = record["m"]
                r = record["r"]
                
                if n.element_id not in nodes_dict:
                    nodes_dict[n.element_id] = {
                        "id": str(n.element_id),
                        "label": list(n.labels)[0] if n.labels else "Node",
                        "properties": dict(n.items())
                    }
                if m.element_id not in nodes_dict:
                    nodes_dict[m.element_id] = {
                        "id": str(m.element_id),
                        "label": list(m.labels)[0] if m.labels else "Node",
                        "properties": dict(m.items())
                    }
                
                edges_list.append({
                    "id": str(r.element_id),
                    "source": str(n.element_id),
                    "target": str(m.element_id),
                    "type": r.type
                })
                
        return {
            "status": "success",
            "source": "neo4j",
            "nodes": list(nodes_dict.values()),
            "edges": edges_list
        }
    except Exception:
        return {"status": "unavailable", "source": "neo4j", "nodes": [], "edges": []}


from .store_views import quickwit_view, chroma_view, faiss_view

@app.get("/api/data/quickwit")
async def get_quickwit_data():
    return await asyncio.to_thread(quickwit_view)

@app.get("/api/data/chroma")
async def get_chroma_data():
    return await asyncio.to_thread(chroma_view)

@app.get("/api/data/duckdb")
async def get_duckdb_data():
    return {"status": "unavailable", "source": "duckdb", "tables": [], "metrics": {}}

@app.get("/api/data/faiss")
async def get_faiss_data():
    return await asyncio.to_thread(faiss_view)


if __name__ == "__main__":
    log.info("Starting Visualizer API on port 8300")
    uvicorn.run(app, host="0.0.0.0", port=8300)
