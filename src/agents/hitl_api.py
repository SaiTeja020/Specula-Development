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

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from .api_auth import install_http_auth, authorize

log = logging.getLogger(__name__)

app = FastAPI(title="Specula HITL Gateway", version="0.1.0")
install_http_auth(app)

# Graph instance set by the caller before starting uvicorn
_graph = None


def get_graph():
    global _graph
    if _graph is None:
        from .visualizer_api import _get_specula_graph
        _graph = _get_specula_graph()
    return _graph


class HITLDecision(BaseModel):
    decision: str  # approve | reject | clarify


def set_graph(graph) -> None:
    """Inject the compiled graph instance into this module."""
    global _graph
    _graph = graph


@app.get("/hitl/{thread_id}")
async def get_snapshot(thread_id: str, request: Request):
    """Fetch the HITL case snapshot for a paused graph run."""
    from .visualizer_api import _get_neo4j_driver
    authorize(request.state.principal, thread_id, driver=_get_neo4j_driver())
    graph = get_graph()
    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialised")

    config = {"configurable": {"thread_id": thread_id}}
    try:
        state = graph.get_state(config)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    values = state.values if hasattr(state, "values") else {}
    if not values:
        raise HTTPException(404, "Investigation not found")
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
async def submit_decision(thread_id: str, body: HITLDecision, request: Request):
    """Submit analyst decision and resume the paused graph."""
    from .visualizer_api import _get_neo4j_driver
    authorize(request.state.principal, thread_id, write=True, driver=_get_neo4j_driver())
    graph = get_graph()
    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialised")

    if body.decision not in ("approve", "reject", "clarify"):
        raise HTTPException(status_code=400, detail="Decision must be approve, reject, or clarify")

    config = {"configurable": {"thread_id": thread_id}}

    from langgraph.types import Command
    try:
        import asyncio
        from .checkpointer import durable_case_lock, CheckpointBusyError
        def resume():
            with durable_case_lock(graph.checkpointer, thread_id):
                if "hitl" not in graph.get_state(config).next:
                    raise HTTPException(409, "Investigation is not awaiting analyst review")
                return graph.invoke(Command(resume=body.decision), config)
        result = await asyncio.to_thread(resume)
    except CheckpointBusyError:
        raise HTTPException(409, "Investigation is already running in another worker") from None
    except HTTPException:
        raise
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
    graph = get_graph()
    set_graph(graph)

    log.info("Starting HITL API on port 8200")
    uvicorn.run(app, host="0.0.0.0", port=8200)
