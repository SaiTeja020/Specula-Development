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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from dotenv import load_dotenv
from .api_auth import install_http_auth, authenticate_websocket, authorize, refresh_principal

load_dotenv()  # Load local configuration before readiness or cached drivers.

log = logging.getLogger(__name__)
CASE_GRAPH_TYPE_LIMIT = 300

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
            from .checkpointer import build_persistent_checkpointer
            from .graph import build_graph
            checkpointer = build_persistent_checkpointer()
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
install_http_auth(app)

# Allow CORS for the Vite frontend (usually runs on port 5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global set of active websocket connections
active_connections: set[WebSocket] = set()
connection_authorizations = {}

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
    identity = await authenticate_websocket(websocket, _get_neo4j_driver())
    if identity is None:
        return
    principal, selected_case = identity
    connection_authorizations[websocket] = identity
    active_connections.add(websocket)
    log.info(f"WebSocket client connected. Total clients: {len(active_connections)}")
    try:
        while True:
            # Keep connection alive, wait for client messages if any
            import time
            remaining = principal.expires_at - time.time()
            if remaining <= 0:
                await websocket.close(code=1008)
                break
            data = await asyncio.wait_for(websocket.receive_text(), timeout=remaining)
            if data == "ping":
                principal = await asyncio.to_thread(refresh_principal, principal)
                await asyncio.to_thread(authorize, principal, selected_case, driver=_get_neo4j_driver())
                connection_authorizations[websocket] = (principal, selected_case)
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        await websocket.close(code=1008)
    except HTTPException:
        await websocket.close(code=1008)
    finally:
        active_connections.discard(websocket)
        connection_authorizations.pop(websocket, None)
        log.info(f"WebSocket client disconnected. Total clients: {len(active_connections)}")


async def broadcast_event(event_type: str, payload: dict):
    """Broadcast an event to all connected WebSocket clients."""
    if not active_connections:
        return
        
    message = json.dumps({"type": event_type, "payload": payload})
    stale_connections = set()
    
    for connection in list(active_connections):
        try:
            identity = connection_authorizations.get(connection)
            if identity is None:
                continue
            principal, selected_case = identity
            principal = await asyncio.to_thread(refresh_principal, principal)
            connection_authorizations[connection] = (principal, selected_case)
            case_id = payload.get("case_id")
            await asyncio.to_thread(authorize, principal, case_id, administrator=not bool(case_id),
                                    driver=_get_neo4j_driver())
            if selected_case is not None and selected_case != case_id:
                continue
            await asyncio.wait_for(connection.send_text(message), timeout=1)
        except HTTPException:
            continue
        except Exception:
            stale_connections.add(connection)
            
    # Clean up dead connections
    for connection in stale_connections:
        active_connections.discard(connection)
        connection_authorizations.pop(connection, None)


# ---------------------------------------------------------------------------
# The Docker controller runs on the host so it survives Compose teardown.
# ---------------------------------------------------------------------------
@app.post("/api/system/boot")
async def system_boot():
    raise HTTPException(409, "Start the local boot controller on port 8400")


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
async def get_neo4j_data(request: Request, case_id: str | None = None):
    """Return a bounded case graph with complete counts and explicit derived links."""
    driver = _get_neo4j_driver()
    if driver is None:
        return {"status": "error", "message": "Neo4j driver not available"}
    try:
        principal = request.state.principal
        with driver.session() as session:
            rows = list(session.run(
                "MATCH (c:Case) WHERE $all_cases OR c.owner_user_id = $subject "
                "OR $subject IN coalesce(c.member_user_ids, []) OR c.uid IN $cases "
                "RETURN c.uid AS uid ORDER BY c.uid",
                all_cases=principal.role == "admin" and "*" in principal.cases,
                subject=principal.subject, cases=list(principal.cases)))
            cases = [row["uid"] for row in rows]
            selected = case_id or (cases[-1] if cases else None)
            if selected and selected not in cases:
                raise HTTPException(403, "Case access denied")
            if not selected:
                return {"status": "success", "source": "neo4j", "cases": [],
                        "case_id": None, "nodes": [], "edges": [], "totals": {}, "sampled": False}

            nodes, edges, counts = {}, [], {}
            root = session.run("MATCH (c:Case {uid: $case_id}) RETURN c", case_id=selected).single()["c"]

            def add(node):
                node_id = str(node.element_id)
                nodes[node_id] = {"id": node_id, "label": next(iter(node.labels), "Node"),
                                  "properties": dict(node.items())}
                return node_id

            root_id = add(root)
            counts["Event"] = session.run(
                "MATCH (:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event) "
                "RETURN count(DISTINCT e) AS n", case_id=selected).single()["n"]
            for row in session.run(
                "MATCH (c:Case {uid: $case_id})-[r:HAS_EVENT]->(e:Event) "
                "RETURN e, r ORDER BY e.time DESC, e.uid LIMIT $limit",
                case_id=selected, limit=CASE_GRAPH_TYPE_LIMIT):
                node_id = add(row["e"])
                edges.append({"id": str(row["r"].element_id), "source": root_id,
                              "target": node_id, "type": "HAS_EVENT", "derived": False})

            for label in ("Process", "DetectionFinding", "Entity", "Host"):
                # Labels are a fixed allowlist, never interpolated from a request.
                counts[label] = session.run(
                    f"MATCH (n:{label} {{case_id: $case_id}}) RETURN count(n) AS n",
                    case_id=selected).single()["n"]
                for row in session.run(
                    f"MATCH (n:{label} {{case_id: $case_id}}) RETURN n "
                    "ORDER BY n.severity_id DESC, n.first_seen DESC, n.uid LIMIT $limit",
                    case_id=selected, limit=CASE_GRAPH_TYPE_LIMIT):
                    node_id = add(row["n"])
                    edges.append({"id": f"case-member-{node_id}", "source": root_id,
                                  "target": node_id, "type": "CASE_TAG", "derived": True})

            for label, relation in (("AgentRun", "HAS_AGENT_RUN"),
                                    ("Report", "HAS_REPORT")):
                counts[label] = session.run(
                    f"MATCH (:Case {{uid: $case_id}})-[:{relation}]->(n:{label}) "
                    "RETURN count(n) AS n", case_id=selected).single()["n"]
                for row in session.run(
                    f"MATCH (c:Case {{uid: $case_id}})-[r:{relation}]->(n:{label}) "
                    "RETURN n, r ORDER BY n.sequence, n.generated_at LIMIT $limit",
                    case_id=selected, limit=CASE_GRAPH_TYPE_LIMIT):
                    node_id = add(row["n"])
                    edges.append({"id": str(row["r"].element_id), "source": root_id,
                                  "target": node_id, "type": relation, "derived": False})

            ids = list(nodes)
            for row in session.run(
                "MATCH (a)-[r]->(b) WHERE elementId(a) IN $ids AND elementId(b) IN $ids "
                "AND NOT type(r) IN ['HAS_EVENT', 'HAS_AGENT_RUN', 'HAS_REPORT'] "
                "RETURN a, r, b LIMIT $limit", ids=ids, limit=CASE_GRAPH_TYPE_LIMIT * 7):
                edges.append({"id": str(row["r"].element_id),
                              "source": str(row["a"].element_id), "target": str(row["b"].element_id),
                              "type": row["r"].type, "derived": False})
        return {
            "status": "success", "source": "neo4j", "cases": cases, "case_id": selected,
            "nodes": list(nodes.values()), "edges": edges, "totals": {"Case": 1, **counts},
            "per_type_limit": CASE_GRAPH_TYPE_LIMIT,
            "sampled": any(counts[label] > sum(n["label"] == label for n in nodes.values())
                           for label in counts),
        }
    except HTTPException:
        raise
    except Exception:
        log.exception("Case graph view failed")
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
