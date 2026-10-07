"""Minimal HITL HTTP endpoint — §8.

Two endpoints:
  GET  /hitl/{thread_id}  — fetch snapshot of paused case
  POST /hitl/{thread_id}  — submit decision (approve/reject/clarify), resume graph

Runs on uvicorn per AGENTS.md rule. No React frontend, no tiered timeouts,
no agreement-rate tracking — purely a mechanism to prove interrupt/resume
works across a real process boundary.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

log = logging.getLogger(__name__)

app = FastAPI(title="Specula HITL Gateway", version="0.1.0")

# Graph instance set by the caller before starting uvicorn
_graph = None


class HITLDecision(BaseModel):
    decision: str  # approve | reject | clarify


def set_graph(graph) -> None:
    """Inject the compiled graph instance into this module."""
    global _graph
    _graph = graph


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
    import os
    import uvicorn
    from langgraph.checkpoint.memory import InMemorySaver
    from neo4j import GraphDatabase

    from .graph import build_graph

    password = os.environ.get("NEO4J_PASSWORD", "")
    auth = (os.environ.get("NEO4J_USER", "neo4j"), password) if password else None
    neo4j_driver = GraphDatabase.driver(os.environ.get("NEO4J_URI", "bolt://localhost:7687"), auth=auth)
    graph = build_graph(checkpointer=InMemorySaver(), neo4j_driver=neo4j_driver)
    set_graph(graph)

    log.info("Starting HITL API on port 8200")
    uvicorn.run(app, host="0.0.0.0", port=8200)
