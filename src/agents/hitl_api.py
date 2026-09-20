"""Specula Investigation & HITL Gateway — §8.

Endpoints:
  POST /investigate              — submit a user text query, run full investigation
  GET  /hitl/{thread_id}         — fetch snapshot of paused case
  POST /hitl/{thread_id}         — submit decision (approve/reject/clarify), resume graph
  GET  /investigation/{thread_id}/result — retrieve synthesis result for completed run

Runs on uvicorn per AGENTS.md rule.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from langgraph.checkpoint.memory import InMemorySaver

log = logging.getLogger(__name__)

app = FastAPI(title="Specula Investigation Gateway", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Graph instance set by the caller before starting uvicorn
_graph = None

# Shared checkpointer — allows HITL resume of runs started via /investigate
_checkpointer = InMemorySaver()

# In-memory result cache: thread_id -> InvestigationResult
_result_cache: dict = {}


class InvestigateRequest(BaseModel):
    query: str
    case_id: Optional[str] = None
    neo4j_enabled: bool = False   # set True only when Neo4j is reachable


class HITLDecision(BaseModel):
    decision: str  # approve | reject | clarify


def set_graph(graph) -> None:
    """Inject the compiled graph instance into this module."""
    global _graph
    _graph = graph


@app.post("/investigate")
async def investigate(body: InvestigateRequest):
    """Run a full Specula investigation from a user text query.

    Returns either the completed InvestigationResult (JSON) or a HITL pause
    payload that requires human review via POST /hitl/{thread_id}.
    """
    from src.agents.investigation_runner import run_investigation, HITLPausedResult

    neo4j_driver = None
    if body.neo4j_enabled:
        try:
            from neo4j import GraphDatabase
            uri  = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
            user = os.environ.get("NEO4J_USER", "neo4j")
            pw   = os.environ.get("NEO4J_PASSWORD", "")
            neo4j_driver = GraphDatabase.driver(uri, auth=(user, pw))
        except Exception as exc:
            log.warning("Neo4j unavailable for /investigate: %s", exc)

    try:
        result = run_investigation(
            query=body.query,
            case_id=body.case_id,
            neo4j_driver=neo4j_driver,
            checkpointer=_checkpointer,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        if neo4j_driver:
            neo4j_driver.close()

    if isinstance(result, HITLPausedResult):
        return result.as_dict()

    result_dict = dict(result)
    thread_key = f"thread-{result['case_id']}"
    _result_cache[thread_key] = result_dict
    return result_dict


@app.get("/investigation/{thread_id}/result")
async def get_investigation_result(thread_id: str):
    """Retrieve the plain-English synthesis result for a completed investigation."""
    result = _result_cache.get(thread_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"No result found for thread '{thread_id}'. "
                   "The investigation may be paused at HITL or not yet started.",
        )
    return result


@app.get("/hitl/{thread_id}")
async def get_snapshot(thread_id: str):
    """Fetch the HITL case snapshot for a paused graph run."""
    if _graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialised")

    config = {"configurable": {"thread_id": thread_id}}
    try:
        state = _graph.get_state(config)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    values = state.values if hasattr(state, "values") else {}
    return {
        "thread_id": thread_id,
        "case_id": values.get("case_id"),
        "case_status": values.get("case_status"),
        "findings_count": len(values.get("findings", [])),
        "debate_outcome": values.get("debate_outcome"),
        "guardrail_fail_tier": values.get("guardrail_fail_tier"),
        "paused_at": list(state.next) if hasattr(state, "next") and state.next else [],
    }


@app.post("/hitl/{thread_id}")
async def submit_decision(thread_id: str, body: HITLDecision):
    """Submit analyst decision and resume the paused graph."""
    if _graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialised")

    if body.decision not in ("approve", "reject", "clarify"):
        raise HTTPException(status_code=400, detail="Decision must be approve, reject, or clarify")

    config = {"configurable": {"thread_id": thread_id}}

    from langgraph.types import Command
    try:
        result = _graph.invoke(Command(resume=body.decision), config)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "status": "resumed",
        "thread_id": thread_id,
        "case_status": result.get("case_status"),
        "final_output_ref": result.get("final_output_ref"),
    }


# ---------------------------------------------------------------------------
# Entry point — run with: python -m src.agents.hitl_api
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    from langgraph.checkpoint.memory import InMemorySaver

    from .graph import build_graph

    graph = build_graph(checkpointer=InMemorySaver())
    set_graph(graph)

    log.info("Starting HITL API on port 8200")
    uvicorn.run(app, host="0.0.0.0", port=8200)
