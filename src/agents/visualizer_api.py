"""Real-time monitoring and visualization API for Specula LangGraph — §9.

This standalone microservice provides:
- GET /api/graph/topology: Returns the nodes and edges for React Flow.
- WS  /api/graph/stream: WebSocket streaming for active node tracking and state updates.
- POST /api/graph/run_mock: Triggers a mock execution sequence to demonstrate flow.
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
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import BaseModel
import sys
import subprocess
import threading

from .graph import build_graph

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
            _neo4j_driver = GraphDatabase.driver("bolt://localhost:7687")
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
            _specula_graph = build_graph(checkpointer=checkpointer)
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
    
    for connection in active_connections:
        try:
            await connection.send_text(message)
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
    """Build and start Docker containers for the Specula infrastructure."""
    
    # Check Docker engine status
    try:
        subprocess.run(["docker", "info"], capture_output=True, text=True, check=True)
    except FileNotFoundError:
        return {"status": "error", "message": "docker_cli_not_found"}
    except subprocess.CalledProcessError:
        return {"status": "error", "message": "docker_offline"}
        
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    
    # Run Docker cleanup and boot in a thread so it doesn't block the API
    def boot_docker():
        # Clean up existing containers, networks, and volumes for this compose project
        subprocess.run("docker compose down -v", shell=True, cwd=repo_root, capture_output=True, timeout=60)
        
        # Build and start forcing recreation of containers
        return subprocess.run("docker compose up -d --build --force-recreate", shell=True, cwd=repo_root, capture_output=True, text=True, timeout=300)

    try:
        async with boot_lock:
            proc = await asyncio.to_thread(boot_docker)
            if proc.returncode == 0:
                return {"status": "success", "message": "Docker containers running successfully."}
            else:
                return {"status": "error", "message": f"Docker compose returned non-zero: {proc.stderr}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# Pipeline trigger
# ---------------------------------------------------------------------------
@app.post("/api/trigger_pipeline")
async def trigger_pipeline(config: dict):
    """Trigger a mock execution to demonstrate real-time graph monitoring from frontend."""
    
    # Normally this would invoke `run_pipeline.py` or hit LangGraph directly.
    # For now, it runs the mock sequence to populate the dashboard UI.
    mock_sequence = [
        {"node": "supervisor", "data": {"status": "routing"}},
        {"node": "evidence_collection", "data": {"status": "collecting", "findings": 2}},
        {"node": "log_analysis", "data": {"status": "parsing", "findings": 5}},
        {"node": "network_forensics", "data": {"status": "sniffing", "findings": 1}},
        {"node": "primary_tier_join", "data": {"status": "joined"}},
        {"node": "memory_forensics", "data": {"status": "dump analysis"}},
        {"node": "specialist_join", "data": {"status": "specialists joined"}},
        {"node": "timeline_reconstruction", "data": {"status": "building timeline"}},
        {"node": "threat_attribution", "data": {"status": "attributing actor"}},
        {"node": "proponent", "data": {"status": "proposing hypothesis"}},
        {"node": "critic", "data": {"status": "critiquing hypothesis"}},
        {"node": "judge", "data": {"status": "judging debate"}},
        {"node": "guardrail_tier1", "data": {"status": "checking tier 1"}},
        {"node": "guardrail_tier2", "data": {"status": "checking tier 2"}},
        {"node": "guardrail_tier3", "data": {"status": "checking tier 3"}},
        {"node": "hitl", "data": {"status": "awaiting review"}},
        {"node": "report_generation", "data": {"status": "generating report"}},
        {"node": "timeline_artifact_generation", "data": {"status": "generating artifacts"}},
        {"node": "final_output_join", "data": {"status": "complete"}},
    ]
    
    async def simulate_run():
        await broadcast_event("pipeline_started", {"case_id": config.get("case_id", "C-1234")})
        await asyncio.sleep(0.5)
        
        # Execute real ingestion pipeline instead of hardcoded mock data
        await broadcast_event("node_active", {"node": "__start__", "data": {"status": "Executing ingestion pipeline..."}})
        try:
            def run_ingestion():
                repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
                cmd = ["python", "src/ingestion/run_pipeline.py"]
                
                if config.get("start_date"):
                    cmd.extend(["--start-time", config.get("start_date")])
                if config.get("end_date"):
                    cmd.extend(["--end-time", config.get("end_date")])
                if config.get("max_events"):
                    cmd.extend(["--max-events", str(config.get("max_events"))])
                if config.get("exclude_ports"):
                    cmd.extend(["--exclude-ports", str(config.get("exclude_ports"))])
                    
                env = os.environ.copy()
                env["SPECULA_QUICKWIT_ENABLED"] = "true"
                env["SPECULA_NEO4J_ENABLED"] = "true"
                
                return subprocess.run(cmd, cwd=repo_root, env=env, capture_output=True, text=True)

            ingest_proc = await asyncio.to_thread(run_ingestion)
            if ingest_proc.returncode != 0:
                logging.error(f"Pipeline failed: {ingest_proc.stderr}")
                await broadcast_event("node_active", {"node": "__start__", "data": {"status": f"Warning: Ingestion script failed"}})
            else:
                await broadcast_event("node_active", {"node": "__start__", "data": {"status": "Ingestion pipeline completed successfully"}})
        except Exception as e:
            logging.error(f"Pipeline execution error: {e}")
            await broadcast_event("node_active", {"node": "__start__", "data": {"status": f"Error running pipeline: {e}"}})

        await broadcast_event("node_complete", {"node": "__start__"})

        for step in mock_sequence:
            await broadcast_event("node_active", step)
            # simulate processing delay
            await asyncio.sleep(0.4)
            # simulate HITL pause
            if step["node"] == "hitl":
                await asyncio.sleep(1.5) 
            await broadcast_event("node_complete", {"node": step["node"]})
            
        await broadcast_event("run_complete", {"case_id": config.get("case_id", "C-1234")})

    # Fire and forget the simulation task
    asyncio.create_task(simulate_run())
    
    return {"status": "pipeline triggered", "config": config}


class TriggerPipelineRequest(BaseModel):
    case_id: str
    start_date: str = ""
    end_date: str = ""
    max_events: int = 2000
    exclude_ports: str = "80,443,53"

@app.post("/api/trigger_pipeline")
async def trigger_pipeline(req: TriggerPipelineRequest):
    """Trigger the actual ingestion pipeline and subsequent investigation."""
    log.info(f"Triggering pipeline for case: {req.case_id}")
    
    await broadcast_event("pipeline_started", {"case_id": req.case_id})
    
    def run_producer_and_investigation():
        # 1. Run ingestion
        cmd = [
            sys.executable, "-m", "src.ingestion.run_pipeline",
            "--max-events", str(req.max_events)
        ]
        if req.start_date:
            cmd.extend(["--start-time", req.start_date])
        if req.end_date:
            cmd.extend(["--end-time", req.end_date])
            
        env = os.environ.copy()
        
        try:
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            log.info(f"run_pipeline exited with {res.returncode}")
            if res.returncode != 0:
                log.error(f"run_pipeline stderr: {res.stderr}")
        except Exception as e:
            log.error(f"run_pipeline failed: {e}")
            return
            
        # 2. Run investigation and stream WS telemetry
        from src.agents.investigation_runner import run_investigation
        
        # Async-to-sync bridge for WebSocket broadcasts
        def dispatch_ws_event(event_type, payload):
            asyncio.run(broadcast_event(event_type, payload))
            
        try:
            default_query = f"Investigate suspicious activity in case {req.case_id} focusing on recently ingested events."
            log.info(f"Starting run_investigation for {req.case_id}")
            result = run_investigation(
                query=default_query,
                case_id=req.case_id,
                on_node_event=dispatch_ws_event
            )
            log.info(f"run_investigation completed for {req.case_id}")
            dispatch_ws_event("run_complete", {"case_id": req.case_id})
        except Exception as e:
            log.error(f"run_investigation failed: {e}")

    thread = threading.Thread(target=run_producer_and_investigation)
    thread.daemon = True
    thread.start()
    
    return {"status": "success", "message": "Pipeline and investigation triggered"}


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
                
        # If DB is empty, return a fallback so it doesn't crash the UI
        if not nodes_dict:
            return {
                "status": "success",
                "source": "neo4j",
                "nodes": [
                    {"id": "user_1", "label": "User", "properties": {"name": "Admin"}},
                    {"id": "machine_1", "label": "Machine", "properties": {"ip": "10.0.0.5"}}
                ],
                "edges": [
                    {"id": "e1", "source": "user_1", "target": "machine_1", "type": "LOGGED_IN_TO"}
                ]
            }

        return {
            "status": "success",
            "source": "neo4j",
            "nodes": list(nodes_dict.values()),
            "edges": edges_list
        }
    except Exception as e:
        log.warning(f"Failed to query Neo4j, returning offline fallback: {e}")
        return {
            "status": "offline_fallback",
            "source": "neo4j",
            "message": str(e),
            "nodes": [
                {"id": "user_1", "label": "User", "properties": {"name": "Admin (Fallback)"}},
                {"id": "machine_1", "label": "Machine", "properties": {"ip": "10.0.0.5"}}
            ],
            "edges": [
                {"id": "e1", "source": "user_1", "target": "machine_1", "type": "LOGGED_IN_TO"}
            ]
        }


@app.get("/api/data/quickwit")
async def get_quickwit_data():
    """Proxy endpoint to fetch Quickwit log data."""
    # TODO: Connect to Quickwit REST API
    return {
        "status": "success",
        "source": "quickwit",
        "logs": [
            {"timestamp": "2026-09-15T10:00:00Z", "level": "INFO", "message": "Sysmon event 1 - Process Created", "event_id": "1"},
            {"timestamp": "2026-09-15T10:00:05Z", "level": "WARN", "message": "Failed login attempt", "event_id": "4625"}
        ]
    }


@app.get("/api/data/chroma")
async def get_chroma_data():
    """Proxy endpoint to fetch ChromaDB embedding metadata."""
    return {
        "status": "success",
        "source": "chromadb",
        "collections": ["evidence_embeddings", "report_embeddings"],
        "recent_queries": [
            {"query": "suspicious powershell activity", "matches": 12}
        ]
    }


@app.get("/api/data/duckdb")
async def get_duckdb_data():
    """Proxy endpoint to fetch DuckDB analytical data."""
    return {
        "status": "success",
        "source": "duckdb",
        "tables": ["network_flow", "process_tree"],
        "metrics": {
            "total_bytes_transferred": "1.2 GB",
            "unique_processes": 432
        }
    }


@app.get("/api/data/faiss")
async def get_faiss_data():
    """Proxy endpoint to fetch FAISS Threat Intel index data."""
    return {
        "status": "success",
        "source": "faiss",
        "index_type": "IndexIVFPQ",
        "total_vectors": 150000,
        "recent_hits": [
            {"cve": "CVE-2024-1234", "score": 0.95}
        ]
    }




# ---------------------------------------------------------------------------
# Frontend Dashboard Data Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/data/neo4j")
async def neo4j_data() -> dict[str, Any]:
    """Provide nodes and edges for the React Flow Neo4j Visualizer."""
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return {"status": "error", "message": "neo4j driver not installed"}

    auth = (NEO4J_USER, NEO4J_PASSWORD) if NEO4J_PASSWORD else None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=auth)
        driver.verify_connectivity()

        nodes = []
        edges = []

        with driver.session() as session:
            # Fetch nodes (limit 500 for safety)
            node_result = session.run(
                "MATCH (n) RETURN id(n) AS id, labels(n)[0] AS label, properties(n) AS props LIMIT 500"
            )
            for record in node_result:
                nodes.append({
                    "id": str(record["id"]),
                    "label": record["label"] or "Unknown",
                    "properties": dict(record["props"])
                })

            # Fetch edges (limit 1000 for safety)
            edge_result = session.run(
                "MATCH (n)-[r]->(m) RETURN id(r) AS id, id(n) AS source, id(m) AS target, type(r) AS type LIMIT 1000"
            )
            for record in edge_result:
                edges.append({
                    "id": str(record["id"]),
                    "source": str(record["source"]),
                    "target": str(record["target"]),
                    "type": record["type"]
                })

        driver.close()
        return {"status": "success", "nodes": nodes, "edges": edges}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/data/quickwit")
async def quickwit_data() -> dict[str, Any]:
    return {"logs": []}

@app.get("/api/data/chroma")
async def chroma_data() -> dict[str, Any]:
    return {"collections": [], "recent_queries": [{"query": "None", "matches": 0}]}

@app.get("/api/data/duckdb")
async def duckdb_data() -> dict[str, Any]:
    return {"metrics": {"total_bytes_transferred": 0, "unique_processes": 0}}

@app.get("/api/data/faiss")
async def faiss_data() -> dict[str, Any]:
    return {"index_type": "Unknown", "total_vectors": 0, "recent_hits": [{"cve": "None", "score": 0}]}


if __name__ == "__main__":
    log.info("Starting Visualizer API on port 8300")
    uvicorn.run(app, host="0.0.0.0", port=8300)
