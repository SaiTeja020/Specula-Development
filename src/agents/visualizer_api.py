"""Real-time monitoring and visualization API for Specula LangGraph — §9.

This standalone microservice provides:
- GET  /api/graph/topology: Returns the nodes and edges for React Flow.
- WS   /api/graph/stream: WebSocket streaming for active node tracking and state updates.
- POST /api/graph/run_mock: Triggers a mock execution sequence to demonstrate flow.
- GET  /api/logs/search: Proxy to Quickwit search API for forensic log browsing.
- GET  /api/neo4j/summary: Returns Neo4j knowledge graph statistics.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import httpx
import uvicorn
from langgraph.checkpoint.memory import InMemorySaver

from .graph import build_graph

log = logging.getLogger(__name__)

app = FastAPI(title="Specula Visualizer API", version="1.0.0")

# Allow CORS for the Vite frontend (usually runs on port 5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global set of active websocket connections
active_connections: set[WebSocket] = set()

# Initialize the graph
checkpointer = InMemorySaver()
specula_graph = build_graph(checkpointer=checkpointer)

@app.get("/api/graph/topology")
async def get_topology() -> dict[str, Any]:
    """Extract and return the graph's nodes and edges in a format suitable for React Flow."""
    # LangGraph exposes the underlying graph structure
    g = specula_graph.get_graph()
    
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
        active_connections.remove(websocket)
        log.info(f"WebSocket client disconnected. Total clients: {len(active_connections)}")


async def broadcast_event(event_type: str, payload: dict):
    """Broadcast an event to all connected WebSocket clients."""
    if not active_connections:
        return
        
    message = json.dumps({"type": event_type, "payload": payload})
    stale_connections = set()
    
    for connection in active_connections:
        try:
            await connection.send_text(message)
        except Exception:
            stale_connections.add(connection)
            
    # Clean up dead connections
    for connection in stale_connections:
        active_connections.remove(connection)


@app.post("/api/graph/run_mock")
async def trigger_mock_run():
    """Trigger a mock execution to demonstrate real-time graph monitoring."""
    
    # We will simulate a flow traversing the graph so the UI can highlight active nodes.
    # Normally this would hook into LangGraph's astream or a pub/sub topic.
    
    mock_sequence = [
        {"node": "__start__", "data": {"case_id": "C-1234"}},
        {"node": "supervisor", "data": {"status": "routing"}},
        # Fan out
        {"node": "evidence_collection", "data": {"status": "collecting", "findings": 2}},
        {"node": "log_analysis", "data": {"status": "parsing", "findings": 5}},
        {"node": "network_forensics", "data": {"status": "sniffing", "findings": 1}},
        {"node": "primary_tier_join", "data": {"status": "joined"}},
        
        # Dead end triggers specialists
        {"node": "memory_forensics", "data": {"status": "dump analysis"}},
        {"node": "specialist_join", "data": {"status": "specialists joined"}},
        
        {"node": "timeline_reconstruction", "data": {"status": "building timeline"}},
        {"node": "threat_attribution", "data": {"status": "attributing actor"}},
        
        # Debate loop
        {"node": "proponent", "data": {"status": "proposing hypothesis"}},
        {"node": "critic", "data": {"status": "critiquing hypothesis"}},
        {"node": "judge", "data": {"status": "judging debate"}},
        
        # Guardrails
        {"node": "guardrail_tier1", "data": {"status": "checking tier 1"}},
        {"node": "guardrail_tier2", "data": {"status": "checking tier 2"}},
        {"node": "guardrail_tier3", "data": {"status": "checking tier 3"}},
        
        # Reports
        {"node": "report_generation", "data": {"status": "generating report"}},
        {"node": "timeline_artifact_generation", "data": {"status": "generating artifacts"}},
        {"node": "final_output_join", "data": {"status": "complete"}},
    ]
    
    async def simulate_run():
        for step in mock_sequence:
            await broadcast_event("node_active", step)
            await asyncio.sleep(1.5) # Wait to allow visualizer to show passage
            await broadcast_event("node_complete", {"node": step["node"]})
            
        await broadcast_event("run_complete", {"case_id": "C-1234"})

    # Fire and forget the simulation task
    asyncio.create_task(simulate_run())
    
    return {"status": "mock run initiated"}


# ---------------------------------------------------------------------------
# Quickwit log search proxy
# ---------------------------------------------------------------------------

QUICKWIT_ENDPOINT = os.environ.get("QUICKWIT_ENDPOINT", "http://localhost:7280")
QUICKWIT_INDEX = os.environ.get("QUICKWIT_INDEX", "specula_raw_evidence")


@app.get("/api/logs/search")
async def search_logs(
    q: str = Query(default="*", description="Lucene query string"),
    max_hits: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """Proxy search requests to Quickwit so the browser avoids CORS issues."""
    search_url = f"{QUICKWIT_ENDPOINT}/api/v1/{QUICKWIT_INDEX}/search"
    body = {"query": q, "max_hits": max_hits}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                search_url,
                json=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        return {"error": "Quickwit is not reachable", "hits": [], "num_hits": 0}
    except httpx.HTTPStatusError as e:
        return {"error": f"Quickwit returned {e.response.status_code}", "hits": [], "num_hits": 0}
    except Exception as e:
        return {"error": str(e), "hits": [], "num_hits": 0}


@app.get("/api/logs/indexes")
async def list_indexes() -> dict[str, Any]:
    """List available Quickwit indexes for the frontend dropdown."""
    url = f"{QUICKWIT_ENDPOINT}/api/v1/indexes"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            indexes = resp.json()
            names = [idx.get("index_config", {}).get("index_id", idx.get("index_id", "unknown")) for idx in indexes]
            return {"indexes": names}
    except Exception:
        return {"indexes": [QUICKWIT_INDEX]}


# ---------------------------------------------------------------------------
# Neo4j knowledge graph summary
# ---------------------------------------------------------------------------

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")


@app.get("/api/neo4j/summary")
async def neo4j_summary() -> dict[str, Any]:
    """Return a high-level summary of the Neo4j knowledge graph."""
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return {"error": "neo4j driver not installed", "connected": False}

    auth = (NEO4J_USER, NEO4J_PASSWORD) if NEO4J_PASSWORD else None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=auth)
        driver.verify_connectivity()

        with driver.session() as session:
            # Node count by label
            node_result = session.run(
                "CALL db.labels() YIELD label "
                "CALL apoc.cypher.run('MATCH (n:`' + label + '`) RETURN count(n) AS cnt', {}) "
                "YIELD value RETURN label, value.cnt AS count"
            )
            labels = {}
            try:
                for record in node_result:
                    labels[record["label"]] = record["count"]
            except Exception:
                # APOC may not be installed; fall back to simple count
                simple = session.run("MATCH (n) RETURN count(n) AS cnt")
                labels = {"all": simple.single()["cnt"]}

            # Relationship count
            rel_result = session.run("MATCH ()-[r]->() RETURN count(r) AS cnt")
            rel_count = rel_result.single()["cnt"]

            # Sample recent nodes (top 10)
            sample_result = session.run(
                "MATCH (n) RETURN labels(n) AS labels, "
                "properties(n) AS props LIMIT 10"
            )
            samples = [
                {"labels": list(r["labels"]), "props": dict(r["props"])}
                for r in sample_result
            ]

        driver.close()

        return {
            "connected": True,
            "node_labels": labels,
            "total_nodes": sum(labels.values()),
            "total_relationships": rel_count,
            "samples": samples,
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}


if __name__ == "__main__":
    log.info("Starting Visualizer API on port 8300")
    uvicorn.run(app, host="0.0.0.0", port=8300)
