"""Local investigation HTTP routes sharing one graph/checkpointer with HITL."""
import asyncio
import logging
import uuid
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


class InvestigationRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=200)
    raw_input: str = Field(default="Investigate preserved case evidence", max_length=10000)


class ReviewRequest(BaseModel):
    decision: Literal["approve", "reject", "clarify"]


def register_investigation_routes(app, get_graph, get_driver, broadcast):
    locks = {}

    def graph_for_case(case_id):
        graph = get_graph()
        if graph is None:
            raise HTTPException(503, "Investigation graph unavailable")
        return graph, {"configurable": {"thread_id": case_id}}

    def snapshot(graph, config):
        state = graph.get_state(config)
        if not state.values:
            raise HTTPException(404, "Investigation not found")
        values = state.values
        return {"case_id": values.get("case_id"), "case_status": values.get("case_status"),
                "paused_at": list(state.next), "findings": values.get("findings", []),
                "agent_traces": values.get("agent_traces", []),
                "attribution": values.get("attribution"), "timeline": values.get("timeline"),
                "final_output_ref": values.get("final_output_ref")}

    async def execute(graph, config, value):
        loop = asyncio.get_running_loop()
        def emit(event_type, payload):
            future = asyncio.run_coroutine_threadsafe(broadcast(event_type, payload), loop)
            try:
                future.result(timeout=3)
            except Exception:
                future.cancel()
                log.warning("Live update delivery unavailable; investigation continues")
        def stream():
            for update in graph.stream(value, config, stream_mode="updates"):
                for node, data in update.items():
                    if node == "__interrupt__":
                        continue
                    payload = {"node": node, "case_id": config["configurable"]["thread_id"],
                               "data": {"status": "completed", "update": data}}
                    emit("node_active", payload)
                    emit("node_complete", payload)
            return snapshot(graph, config)
        result = await asyncio.to_thread(stream)
        if result["paused_at"]:
            await broadcast("node_active", {"node": "hitl", "case_id": result["case_id"],
                                            "data": {"status": "awaiting analyst decision"}})
            await broadcast("hitl_required", result)
        elif result["case_status"] == "closed":
            await broadcast("run_complete", result)
        return result

    @app.post("/api/investigations")
    @app.post("/api/trigger_pipeline")
    async def run_case(body: InvestigationRequest):
        graph, config = graph_for_case(body.case_id)
        lock = locks.setdefault(body.case_id, asyncio.Lock())
        if lock.locked():
            raise HTTPException(409, "Investigation is already running")
        async with lock:
            if graph.get_state(config).values:
                raise HTTPException(409, "Investigation already exists; review or select a new case")
            driver = get_driver()
            if driver is None:
                raise HTTPException(503, "Evidence graph unavailable")
            records, _, _ = await asyncio.to_thread(driver.execute_query,
                "MATCH (c:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event) RETURN count(e) AS count",
                case_id=body.case_id)
            if not records or not records[0]["count"]:
                raise HTTPException(404, "No ingested evidence exists for this case")
            await broadcast("pipeline_started", {"case_id": body.case_id})
            return await execute(graph, config, {
                "case_id": body.case_id, "trace_id": uuid.uuid4().hex,
                "input_type": "siem_alert", "raw_input": body.raw_input,
                "case_status": "open", "findings": [], "agent_traces": [],
                "debate_round": 1, "debate_history": [], "specialists_completed": [],
                "dead_end_detected": False, "dead_end_categories": [], "loop_count": 0,
            })

    @app.get("/api/investigations/{case_id}")
    async def get_case(case_id: str):
        graph, config = graph_for_case(case_id)
        return snapshot(graph, config)

    @app.post("/api/investigations/{case_id}/review")
    async def review_case(case_id: str, body: ReviewRequest):
        from langgraph.types import Command
        graph, config = graph_for_case(case_id)
        lock = locks.setdefault(case_id, asyncio.Lock())
        if lock.locked():
            raise HTTPException(409, "Investigation is already running")
        async with lock:
            current = snapshot(graph, config)
            if "hitl" not in current["paused_at"]:
                raise HTTPException(409, "Investigation is not awaiting analyst review")
            return await execute(graph, config, Command(resume=body.decision))
