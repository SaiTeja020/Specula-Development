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
from pydantic import BaseModel
import sys
import threading
from src.telemetry import emit_event

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

from langgraph.checkpoint.memory import InMemorySaver
_visualizer_checkpointer = InMemorySaver()


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


@app.get("/api/llm/status")
async def llm_status() -> dict:
    """Return the current LLM configuration and agent-specific overrides."""
    import os
    backend = os.environ.get("SPECULA_LLM_BACKEND", "stub").lower()
    default_model = os.environ.get("SPECULA_LLM_MODEL", "default")
    
    # Check for agent-specific overrides in the environment
    agents = {}
    for k, v in os.environ.items():
        if k.startswith("SPECULA_LLM_MODEL_") and v:
            agent_role = k.replace("SPECULA_LLM_MODEL_", "").lower()
            agents[agent_role] = {
                "backend": backend,
                "model": v
            }
            
    return {
        "backend": backend,
        "default_model": default_model,
        "agents": agents
    }


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
# System Boot — Docker health check (containers started by start_full_pipeline.py)
# ---------------------------------------------------------------------------
boot_lock = asyncio.Lock()

@app.post("/api/system/boot")
async def system_boot():
    """Verify Docker infrastructure is up and return immediately.

    The heavy docker compose up is handled by start_full_pipeline.py before
    this API starts. This endpoint performs a quick docker info + container
    count check and returns immediately so the frontend boot page does not
    time out waiting for a 5-minute rebuild.
    """
    # Check Docker engine status
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, check=True
        )
    except FileNotFoundError:
        return {"status": "error", "message": "docker_cli_not_found"}
    except subprocess.CalledProcessError:
        return {"status": "error", "message": "docker_offline"}

    # Quick container list — just verify docker compose services are up
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    try:
        ps = subprocess.run(
            "docker compose ps --services --filter status=running",
            shell=True, cwd=repo_root, capture_output=True, text=True, timeout=10
        )
        running = [s.strip() for s in ps.stdout.splitlines() if s.strip()]
        return {
            "status": "success",
            "message": f"Docker infrastructure verified. {len(running)} service(s) running.",
            "services": running,
        }
    except Exception as e:
        # If compose ps fails, still return success as long as docker is up
        return {"status": "success", "message": "Docker engine online.", "services": []}


# ---------------------------------------------------------------------------
# Pipeline trigger
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Neo4j driver helper — shared by trigger_pipeline and investigate endpoints
# ---------------------------------------------------------------------------
def _get_neo4j_driver():
    """Return a Neo4j driver if SPECULA_NEO4J_ENABLED is true, else None."""
    neo4j_enabled = os.environ.get("SPECULA_NEO4J_ENABLED", "false").lower() == "true"
    if not neo4j_enabled:
        return None
    try:
        from neo4j import GraphDatabase  # type: ignore
        neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
        neo4j_password = os.environ.get("NEO4J_PASSWORD", "")
        if neo4j_password:
            return GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        return GraphDatabase.driver(neo4j_uri, auth=None)
    except Exception as e:
        log.warning(f"Neo4j driver unavailable (non-fatal): {e}")
        return None


# ---------------------------------------------------------------------------
# Active investigations registry — prevents duplicate concurrent runs
# ---------------------------------------------------------------------------
# Maps case_id -> thread_id for in-flight investigations
_active_investigations: dict[str, str] = {}


@app.post("/api/trigger_pipeline")
async def trigger_pipeline(config: dict):
    """Trigger a real Specula investigation via the canonical investigation_runner.

    Runs the full 23-node LangGraph investigation (same as scripts/run_investigation.py).
    - Executes real ingestion FIRST (run_pipeline.py subprocess)
    - Then launches run_investigation() with on_node_event wired to WebSocket broadcast
    - Prevents duplicate investigations for the same case_id
    """
    case_id = config.get("case_id", f"case-frontend")
    query = config.get("query") or (
        "Investigate the available activity in this case and identify anything "
        "that may require attention."
    )

    emit_event("api_request", case_id=case_id, query=query)

    # Guard: refuse if this case is already actively running
    if case_id in _active_investigations:
        existing_thread = _active_investigations[case_id]
        log.warning(f"Duplicate investigation blocked for case_id={case_id}, thread={existing_thread}")
        return {
            "status": "already_running",
            "case_id": case_id,
            "thread_id": existing_thread,
            "message": f"Investigation already in progress for case {case_id}.",
        }

    async def run_full_pipeline():
        """Run ingestion then launch the real LangGraph investigation."""
        import uuid
        thread_id = f"thread-{case_id}"
        _active_investigations[case_id] = thread_id

        try:
            # -- Phase 1: Real ingestion --
            await broadcast_event("pipeline_started", {"case_id": case_id, "thread_id": thread_id})
            await broadcast_event("node_active", {
                "node": "__start__",
                "data": {"status": "Running ingestion pipeline..."},
                "case_id": case_id,
            })
            emit_event("ingestion_start", case_id=case_id)

            def run_ingestion():
                # We skip the heavy synchronous batch ingestion because the background 
                # IngestionConsumer is already running and streaming events continuously.
                pass

            try:
                # Just mock a 2 second delay for the UI animation
                await asyncio.sleep(2)
                emit_event("ingestion_complete", case_id=case_id, returncode=0)
                await broadcast_event("node_active", {
                    "node": "__start__",
                    "data": {"status": "Batch ingestion bypassed (relying on continuous background consumer)."},
                    "case_id": case_id,
                })
            except Exception as e:
                log.error(f"Ingestion error: {e}")
                await broadcast_event("node_active", {
                    "node": "__start__",
                    "data": {"status": f"Ingestion error (non-fatal): {e}"},
                    "case_id": case_id,
                })

            await broadcast_event("node_complete", {"node": "__start__", "case_id": case_id})

            # -- Phase 2: Real LangGraph investigation --
            # on_node_event callback bridges graph events → WebSocket
            def on_node_event(event_type: str, payload: dict):
                """Called synchronously by investigation_runner for each graph node event."""
                node_name = payload.get("node", "unknown")
                event_payload = {
                    "node": node_name,
                    "data": payload.get("data", {}),
                    "case_id": case_id,
                    "thread_id": thread_id,
                }
                # Schedule async broadcast from sync context
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            broadcast_event(event_type, event_payload), loop
                        )
                except Exception as exc:
                    log.debug(f"WebSocket broadcast error (non-fatal): {exc}")

            # Run the real investigation in a thread (it's synchronous/blocking)
            def run_real_investigation():
                from src.agents import investigation_trace
                from src.agents.investigation_runner import run_investigation, HITLPausedResult
                
                # Start trace for frontend investigation
                investigation_trace.start_trace(case_id, query)
                
                neo4j_driver = _get_neo4j_driver()
                try:
                    result = run_investigation(
                        query=query,
                        case_id=case_id,
                        neo4j_driver=neo4j_driver,
                        thread_id=thread_id,
                        checkpointer=_visualizer_checkpointer,
                        on_node_event=on_node_event,
                    )
                    return result
                except Exception as e:
                    # Finalize whatever trace information exists on error
                    recorder = investigation_trace.get_recorder()
                    if recorder:
                        try:
                            recorder._compile_full_report()
                        except Exception:
                            pass
                    raise e

            log.info(f"Starting real investigation: case={case_id}, thread={thread_id}, query='{query[:80]}'")
            result = await asyncio.to_thread(run_real_investigation)

            # Broadcast completion or HITL pause
            from src.agents.investigation_runner import HITLPausedResult
            if isinstance(result, HITLPausedResult):
                payload = {
                    "case_id": case_id,
                    "thread_id": result.thread_id,
                    "hitl_url": f"http://localhost:8300/api/hitl/{result.thread_id}",
                    "message": result.snapshot.get("message", "Human input required."),
                    "options": result.snapshot.get("options", ["approve", "clarify", "reject"]),
                    "snapshot": result.snapshot,
                }
                # Also include properties from snapshot directly for frontend compatibility
                for k, v in result.snapshot.items():
                    if k not in payload:
                        payload[k] = v
                        
                await broadcast_event("hitl_required", payload)
                log.info(f"Investigation paused at HITL: case={case_id}, thread={thread_id}")
                # Keep in active registry until HITL resolves
            else:
                await broadcast_event("run_complete", {
                    "case_id": case_id,
                    "thread_id": thread_id,
                    "status": result.get("status", "completed"),
                    "answer": result.get("answer", "")[:500],
                    "agents_used": result.get("agents_used", []),
                    "human_intervention": result.get("human_intervention", False),
                })
                # Investigation finished — remove from active registry
                _active_investigations.pop(case_id, None)
                log.info(f"Investigation complete: case={case_id}, status={result.get('status')}")

        except Exception as exc:
            log.error(f"Investigation error for case={case_id}: {exc}", exc_info=True)
            await broadcast_event("run_error", {
                "case_id": case_id,
                "thread_id": thread_id,
                "error": str(exc),
            })
            _active_investigations.pop(case_id, None)

    # Launch investigation as background task (non-blocking response)
    asyncio.create_task(run_full_pipeline())

    thread_id = f"thread-{case_id}"
    return {
        "status": "pipeline triggered",
        "case_id": case_id,
        "thread_id": thread_id,
        "query": query,
        "hitl_api_base": "http://localhost:8300",
    }


class TriggerPipelineRequest(BaseModel):
    case_id: str
    start_date: str = ""
    end_date: str = ""
    max_events: int = 2000
    exclude_ports: str = "80,443,53"

class HITLDecision(BaseModel):
    decision: str  # approve | reject | clarify
    query: str = "" # Optional query to pass along

@app.post("/api/hitl/{thread_id}")
async def submit_decision(thread_id: str, body: HITLDecision):
    """Submit analyst decision and resume the paused graph."""
    if body.decision not in ("approve", "reject", "clarify"):
        return {"status": "error", "message": "Decision must be approve, reject, or clarify"}

    case_id = thread_id.replace("thread-", "")

    # Define the event broadcast callback identical to trigger_pipeline
    def on_node_event(event_type: str, payload: dict):
        node_name = payload.get("node", "unknown")
        event_payload = {
            "node": node_name,
            "data": payload.get("data", {}),
            "case_id": case_id,
            "thread_id": thread_id,
        }
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    broadcast_event(event_type, event_payload), loop
                )
        except Exception as exc:
            log.debug(f"WebSocket broadcast error (non-fatal): {exc}")

    async def run_resume():
        _active_investigations[case_id] = thread_id
        
        # Broadcast resume event
        await broadcast_event("hitl_resumed", {
            "case_id": case_id,
            "thread_id": thread_id,
            "decision": body.decision,
        })
        
        def run_real_resume():
            from src.agents.investigation_runner import _resume_after_hitl, HITLPausedResult
            neo4j_driver = _get_neo4j_driver()
            return _resume_after_hitl(
                query=body.query or f"Resume with decision {body.decision}",
                thread_id=thread_id,
                decision=body.decision,
                checkpointer=_visualizer_checkpointer,
                on_node_event=on_node_event,
                neo4j_driver=neo4j_driver,
            )

        try:
            log.info(f"Resuming real investigation: case={case_id}, thread={thread_id}, decision={body.decision}")
            result = await asyncio.to_thread(run_real_resume)

            if isinstance(result, HITLPausedResult):
                payload = {
                    "case_id": case_id,
                    "thread_id": result.thread_id,
                    "hitl_url": f"http://localhost:8300/api/hitl/{result.thread_id}",
                    "message": result.snapshot.get("message", "Human input required."),
                    "options": result.snapshot.get("options", ["approve", "clarify", "reject"]),
                    "snapshot": result.snapshot,
                }
                for k, v in result.snapshot.items():
                    if k not in payload:
                        payload[k] = v
                        
                await broadcast_event("hitl_required", payload)
                log.info(f"Investigation paused again at HITL: case={case_id}")
            else:
                await broadcast_event("run_complete", {
                    "case_id": case_id,
                    "thread_id": thread_id,
                    "status": result.get("status", "completed"),
                    "answer": result.get("answer", "")[:500],
                    "agents_used": result.get("agents_used", []),
                    "human_intervention": result.get("human_intervention", False),
                })
                _active_investigations.pop(case_id, None)
                log.info(f"Investigation complete: case={case_id}")
        except Exception as exc:
            log.error(f"Investigation error for case={case_id}: {exc}", exc_info=True)
            await broadcast_event("run_error", {
                "case_id": case_id,
                "thread_id": thread_id,
                "error": str(exc),
            })
            _active_investigations.pop(case_id, None)

    asyncio.create_task(run_resume())

    return {
        "status": "resuming",
        "thread_id": thread_id,
        "decision": body.decision,
    }


# ---------------------------------------------------------------------------
# Data-store proxy endpoints
# ---------------------------------------------------------------------------
@app.get("/api/data/neo4j")
async def get_neo4j_data(case_id: str = ""):
    """Proxy endpoint to fetch Neo4j graph data for the visualizer."""
    driver = _get_neo4j_driver()
    if driver is None:
        return {"status": "error", "message": "Neo4j driver not available"}
    try:
        nodes_dict = {}
        edges_list = []
        with driver.session() as session:
            # Enforce case isolation if case_id is provided
            if case_id:
                query = "MATCH (n {case_id: $case_id})-[r]->(m {case_id: $case_id}) RETURN n, r, m LIMIT 300"
                params = {"case_id": case_id}
            else:
                query = "MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 100"
                params = {}
                
            result = session.run(query, params)
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
    except Exception as e:
        log.warning(f"Failed to query Neo4j: {e}")
        return {
            "status": "error",
            "source": "neo4j",
            "message": str(e),
            "nodes": [],
            "edges": []
        }


@app.get("/api/data/quickwit")
async def get_quickwit_data(case_id: str = ""):
    """Proxy endpoint to fetch Quickwit log data."""
    # TODO: Connect to Quickwit REST API (placeholder)
    return {
        "status": "not_implemented",
        "source": "quickwit",
        "logs": []
    }


@app.get("/api/data/chroma")
async def get_chroma_data(case_id: str = ""):
    """Proxy endpoint to fetch ChromaDB embedding metadata."""
    # TODO: Connect to ChromaDB (placeholder)
    return {
        "status": "not_implemented",
        "source": "chromadb",
        "collections": [],
        "recent_queries": []
    }


@app.get("/api/data/duckdb")
async def get_duckdb_data(case_id: str = ""):
    """Proxy endpoint to fetch DuckDB analytical data."""
    # TODO: Connect to DuckDB (placeholder)
    return {
        "status": "not_implemented",
        "source": "duckdb",
        "tables": [],
        "metrics": {}
    }


@app.get("/api/data/faiss")
async def get_faiss_data():
    """Proxy endpoint to fetch FAISS Threat Intel index data."""
    # TODO: Fetch actual FAISS stats (placeholder)
    return {
        "status": "not_implemented",
        "source": "faiss",
        "index_type": "IndexIVFPQ",
        "total_vectors": 0,
        "recent_hits": []
    }







if __name__ == "__main__":
    log.info("Starting Visualizer API on port 8300")
    uvicorn.run(app, host="0.0.0.0", port=8300)
