"""Local investigation HTTP routes sharing one graph/checkpointer with HITL."""
import asyncio
import logging
import json
from hashlib import sha256
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, Field
from .api_auth import authorize

log = logging.getLogger(__name__)


def _has_attack_analysis(values):
    return bool(values.get("attack_graph")) or any(
        finding.get("agent_role") == "dag" for finding in values.get("findings") or []
    )


class InvestigationRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=200)
    raw_input: str = Field(default="Investigate preserved case evidence", max_length=10000)


class ReviewRequest(BaseModel):
    decision: Literal["approve", "reject", "clarify"]


class QARequest(BaseModel):
    query: str = Field(min_length=1, max_length=5000)
    top_k: int = Field(default=5, ge=1, le=50)
    min_score: float = Field(default=0.0, ge=-1.0, le=1.0)
    dry_run: bool = Field(default=False)


def register_investigation_routes(app, get_graph, get_driver, broadcast):
    locks = {}

    @app.get("/api/cases")
    async def list_cases(request: Request):
        principal = request.state.principal
        driver = get_driver()
        if driver is None:
            raise HTTPException(503, "Evidence graph unavailable")
        rows, _, _ = await asyncio.to_thread(driver.execute_query,
            "MATCH (c:Case) WHERE $all_cases OR c.owner_user_id = $subject "
            "OR $subject IN coalesce(c.member_user_ids, []) OR c.uid IN $cases "
            "RETURN c.uid AS uid ORDER BY c.uid",
            all_cases=principal.role == "admin" and "*" in principal.cases,
            subject=principal.subject, cases=list(principal.cases))
        return {"cases": [row["uid"] for row in rows]}

    @app.post("/api/cases")
    async def create_case(request: Request):
        principal = authorize(request.state.principal, write=True)
        driver = get_driver()
        if driver is None:
            raise HTTPException(503, "Evidence graph unavailable")
        case_id = "CASE-" + uuid.uuid4().hex
        await asyncio.to_thread(driver.execute_query,
            "CREATE (c:Case {uid: $case_id, owner_user_id: $subject, member_user_ids: []})",
            case_id=case_id, subject=principal.subject)
        return {"case_id": case_id, "owner_user_id": principal.subject}

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
                "started_at": values.get("report_generated_at"),
                "paused_at": list(state.next), "findings": values.get("findings", []),
                "failed_nodes": [task.name for task in state.tasks if task.error],
                "agent_traces": values.get("agent_traces", []),
                "investigation_plan": values.get('investigation_plan'),
                "followup_status": values.get('followup_status'),
                "acquisition_reanalysis_count":values.get('acquisition_reanalysis_count',0),
                "followup_pending": values.get('followup_pending', []),
                "followup_history": values.get('followup_history', []),
                "evidence_requests": values.get('evidence_requests', []),
                "sandbox_runs": values.get('sandbox_runs', []),
                "attribution": values.get("attribution"), "timeline": values.get("timeline"),
                "exploit_topology":values.get('exploit_topology'),
                "attack_graph": values.get("attack_graph"),
                "review_status": values.get("review_status"), "judge_verdict": values.get("judge_verdict"),
                "proponent_review": values.get("proponent_review"), "critic_review": values.get("critic_review"),
                "judge_review": values.get("judge_review"), "debate_history": values.get("debate_history", []),
                "evidence_collection": values.get("evidence_collection"),
                "ingestion_provenance": values.get("ingestion_provenance"),
                "report_output": values.get("report_output"),
                "report_metadata": values.get("report_metadata"),
                "report_documents": values.get("report_documents"),
                "timeline_artifact": values.get("timeline_artifact"),
                "timeline_artifact_metadata": values.get("timeline_artifact_metadata"),
                "acceptance_status": values.get("acceptance_status"),
                "final_output_ref": values.get("final_output_ref")}

    @app.get("/api/investigations/history")
    async def investigation_history(request: Request):
        principal = request.state.principal
        driver = get_driver()
        graph = get_graph()
        if driver is None or graph is None:
            raise HTTPException(503, "Investigation history unavailable")
        rows, _, _ = await asyncio.to_thread(driver.execute_query,
            "MATCH (c:Case) WHERE $all_cases OR c.owner_user_id = $subject "
            "OR $subject IN coalesce(c.member_user_ids, []) OR c.uid IN $cases "
            "OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:Event) "
            "RETURN c.uid AS uid, count(DISTINCT e) AS event_count",
            all_cases=principal.role == "admin" and "*" in principal.cases,
            subject=principal.subject, cases=list(principal.cases))

        def summaries():
            result = []
            for row in rows:
                case_id = row["uid"]
                state = graph.get_state({"configurable": {"thread_id": case_id}})
                if not state.values:
                    continue
                values = state.values
                result.append({
                    "case_id": case_id,
                    "started_at": values.get("report_generated_at"),
                    "case_status": values.get("case_status"),
                    "acceptance_status": values.get("acceptance_status"),
                    "paused_at": list(state.next),
                    "agent_count": len(values.get("agent_traces") or []),
                    "finding_count": len(values.get("findings") or []),
                    "event_count": row["event_count"],
                    "has_timeline": bool(values.get("timeline_artifact") or
                                         (values.get("timeline") or {}).get("events")),
                    "has_attack_analysis": _has_attack_analysis(values),
                    "has_report": bool(values.get("report_output")),
                    "report_status": (values.get("report_metadata") or {}).get("status"),
                })
            result.sort(key=lambda item: item["started_at"] or "", reverse=True)
            return result

        return {"investigations": await asyncio.to_thread(summaries)}

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
            from .checkpointer import durable_case_lock, CheckpointBusyError
            from .agent_graph import persist_case_execution
            try:
                with durable_case_lock(graph.checkpointer, config["configurable"]["thread_id"]):
                    current = graph.get_state(config)
                    trace_index = len(current.values.get("agent_traces", [])) if current.values else 0
                    if isinstance(value, dict) and current.values:
                        raise HTTPException(409, "Investigation already exists; review or select a new case")
                    if value is None and (not current.next or "hitl" in current.next):
                        raise HTTPException(409, "Investigation has no pending work to retry; use analyst review for HITL")
                    if value is not None and not isinstance(value, dict) and "hitl" not in current.next:
                        raise HTTPException(409, "Investigation is not awaiting analyst review")
                    for update in graph.stream(value, config, stream_mode="updates"):
                        for node, data in update.items():
                            if node == "__interrupt__":
                                continue
                            if isinstance(data, dict):
                                traces = data.get("agent_traces") or []
                                try:
                                    if traces or data.get("report_output"):
                                        persist_case_execution(get_driver(), config["configurable"]["thread_id"],
                                            traces, data.get("findings") or [], data.get("report_output"),
                                            data.get("report_metadata"), trace_index)
                                except Exception:
                                    log.exception("Agent graph projection failed; checkpoint remains authoritative")
                                trace_index += len(traces)
                            payload = {"node": node, "case_id": config["configurable"]["thread_id"],
                                       "data": {"status": "completed", "update": data}}
                            emit("node_complete", payload)
                        # Checkpoint data is authoritative; analytics is a durable query projection.
                        current = graph.get_state(config)
                        if any(isinstance(d,dict) and ('timeline' in d or 'attack_graph' in d) for d in update.values()):
                            from .agent_graph import persist_case_analysis
                            persist_case_analysis(get_driver(),config['configurable']['thread_id'],current.values)
                        if (current.values.get("evidence_collection") or {}).get("records"):
                            from .case_analytics import write_case_analytics
                            write_case_analytics(config["configurable"]["thread_id"],
                                current.values["evidence_collection"]["records"],
                                current.values.get("findings", []), current.values.get("agent_traces", []))
                    return snapshot(graph, config)
            except CheckpointBusyError:
                raise HTTPException(409, "Investigation is already running in another worker") from None
        try:
            result = await asyncio.to_thread(stream)
        except HTTPException:
            raise
        except Exception:
            log.exception("Investigation stopped; checkpoint retained for retry")
            raise HTTPException(503, "Investigation stopped; restore dependencies and retry the saved checkpoint") from None
        if result["paused_at"]:
            await broadcast("node_active", {"node": "hitl", "case_id": result["case_id"],
                                            "data": {"status": "awaiting analyst decision"}})
            await broadcast("hitl_required", result)
        elif result["case_status"] == "closed":
            await broadcast("run_complete", result)
        return result

    @app.post("/api/investigations")
    @app.post("/api/trigger_pipeline")
    async def run_case(body: InvestigationRequest, request: Request):
        await asyncio.to_thread(authorize, request.state.principal, body.case_id,
                                write=True, driver=get_driver())
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
                "MATCH (c:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event) "
                "RETURN count(e) AS count, c.ingestion_provenance_json AS provenance",
                case_id=body.case_id)
            if not records or not records[0]["count"]:
                raise HTTPException(404, "No ingested evidence exists for this case")
            await broadcast("pipeline_started", {"case_id": body.case_id})
            from .examination_reports import runtime_manifest
            return await execute(graph, config, {
                "case_id": body.case_id, "trace_id": uuid.uuid4().hex,
                "report_generated_at": datetime.now(timezone.utc).isoformat(),
                "ingestion_provenance": json.loads(records[0].get("provenance") or "{}"),
                "execution_manifest": runtime_manifest(),
                "evidence_review_required": True,
                "input_type": "siem_alert", "raw_input": body.raw_input,
                "case_status": "open", "findings": [], "agent_traces": [],
                "debate_round": 1, "debate_history": [], "specialists_completed": [],
                "dead_end_detected": False, "dead_end_categories": [], "loop_count": 0,
            })

    @app.get("/api/investigations/{case_id}")
    async def get_case(case_id: str, request: Request):
        await asyncio.to_thread(authorize, request.state.principal, case_id, driver=get_driver())
        graph, config = graph_for_case(case_id)
        return snapshot(graph, config)

    @app.get("/api/investigations/{case_id}/stores/{store}")
    async def get_case_store(case_id: str, store: Literal["quickwit", "chroma", "faiss", "duckdb"], request: Request):
        await asyncio.to_thread(authorize, request.state.principal, case_id, driver=get_driver())
        graph, config = graph_for_case(case_id)
        from .store_views import case_store_view
        saved = await asyncio.to_thread(snapshot, graph, config)
        return await asyncio.to_thread(case_store_view, store, case_id, saved)

    @app.post('/api/investigations/{case_id}/reindex')
    async def reindex_case(case_id:str,request:Request):
        await asyncio.to_thread(authorize,request.state.principal,case_id,write=True,driver=get_driver())
        graph,config=graph_for_case(case_id)
        def rebuild():
            from .checkpointer import durable_case_lock
            from .case_analysis import decode_record
            from .case_analytics import write_case_analytics
            from .agent_graph import persist_case_analysis
            from src.ingestion.indexing.case_evidence import CaseEvidenceIndex
            with durable_case_lock(graph.checkpointer,case_id):
                saved=graph.get_state(config).values or {}
                rows,_,_=get_driver().execute_query('MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(e:Event) RETURN e',case_id=case_id)
                events=[decode_record(row['e']) for row in rows]
                if not events:raise HTTPException(409,'No preserved case evidence to index')
                receipt=CaseEvidenceIndex().index(case_id,events)
                analytics=write_case_analytics(case_id,events,saved.get('findings',[]),saved.get('agent_traces',[]))
                from src.graph.process_lineage import persist_lineage
                lineage=persist_lineage(get_driver(),case_id)
                persist_case_analysis(get_driver(),case_id,saved)
                get_driver().execute_query('MATCH (c:Case {uid:$case_id}) SET c.store_receipts_json=$receipt',
                    case_id=case_id,receipt=json.dumps({'chroma':receipt,'duckdb':analytics}))
                return {'case_id':case_id,'chroma':receipt,'duckdb':analytics,'lineage':lineage}
        from .checkpointer import CheckpointBusyError
        try:return await asyncio.to_thread(rebuild)
        except CheckpointBusyError:raise HTTPException(409,'Investigation is already running in another worker') from None

    @app.post('/api/investigations/{case_id}/exploit-topology')
    async def review_exploit_topology(case_id:str,body:dict,request:Request):
        await asyncio.to_thread(authorize,request.state.principal,case_id,write=True,driver=get_driver())
        graph,config=graph_for_case(case_id)
        def reviewed():
            from .checkpointer import durable_case_lock
            from .exploit_paths import calculate_reviewed_path
            from .agent_graph import persist_case_analysis
            with durable_case_lock(graph.checkpointer,case_id):
                current=graph.get_state(config)
                if 'hitl' not in current.next:
                    raise HTTPException(409,'Exploit topology review requires an investigation paused for analyst review')
                refs={e['uid'] for e in (current.values.get('evidence_collection') or {}).get('records',[])}
                try:result=calculate_reviewed_path(body,refs,request.state.principal.subject)
                except ValueError as error:raise HTTPException(422,str(error)) from None
                graph.update_state(config,{'exploit_topology':result})
                persist_case_analysis(get_driver(),case_id,{**current.values,'exploit_topology':result})
                return result
        from .checkpointer import CheckpointBusyError
        try:return await asyncio.to_thread(reviewed)
        except CheckpointBusyError:raise HTTPException(409,'Investigation is already running in another worker') from None

    @app.get('/api/investigations/{case_id}/sandbox/{receipt_id}/report')
    async def get_sandbox_report(case_id: str, receipt_id: str, request: Request):
        await asyncio.to_thread(authorize, request.state.principal, case_id, driver=get_driver())
        from .cape_sandbox import CapeStore, store_path
        def read():
            path = store_path()
            if not path.is_file():
                raise FileNotFoundError
            return CapeStore(path).report(case_id, receipt_id)
        try:
            document = await asyncio.to_thread(read)
        except FileNotFoundError:
            raise HTTPException(404, 'Preserved sandbox report unavailable') from None
        except ValueError:
            raise HTTPException(409, 'Sandbox report identity or digest check failed') from None
        return Response(document, media_type='application/json', headers={
            'Content-Disposition': 'attachment; filename="cape-report.json"',
            'X-Report-SHA256': sha256(document).hexdigest(),
            'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'"})

    @app.get("/api/investigations/{case_id}/reports/{kind}")
    async def get_examination_report(case_id: str, kind: Literal["court", "technical"], request: Request):
        await asyncio.to_thread(authorize, request.state.principal, case_id, driver=get_driver())
        graph, config = graph_for_case(case_id)
        state = await asyncio.to_thread(graph.get_state, config)
        if not state.values or not state.values.get("report_output"):
            raise HTTPException(409, "Final report generation has not completed for this case")
        document = state.values.get(f"{kind}_report_output")
        if not document:
            from .examination_reports import render_examination_report
            document, _ = await asyncio.to_thread(render_examination_report, dict(state.values), kind)
        return Response(document, media_type="text/html", headers={
            "Content-Disposition": f'attachment; filename="specula-{kind}-report.html"',
            "X-Report-SHA256": sha256(document.encode()).hexdigest(),
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
        })

    @app.post("/api/investigations/{case_id}/retry")
    async def retry_case(case_id: str, request: Request):
        await asyncio.to_thread(authorize, request.state.principal, case_id, write=True, driver=get_driver())
        graph, config = graph_for_case(case_id)
        lock = locks.setdefault(case_id, asyncio.Lock())
        if lock.locked():
            raise HTTPException(409, "Investigation is already running")
        async with lock:
            snapshot(graph, config)
            return await execute(graph, config, None)

    @app.post("/api/investigations/{case_id}/review")
    async def review_case(case_id: str, body: ReviewRequest, request: Request):
        await asyncio.to_thread(authorize, request.state.principal, case_id, write=True, driver=get_driver())
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

    @app.post("/api/investigations/{case_id}/qa")
    async def case_qa(case_id: str, body: QARequest, request: Request):
        await asyncio.to_thread(authorize, request.state.principal, case_id, driver=get_driver())
        from src.agents.rag.qa_service import ForensicQAService
        qa = ForensicQAService(neo4j_client=get_driver())
        return await asyncio.to_thread(qa.ask, query=body.query, case_id=case_id, top_k=body.top_k, min_score=body.min_score, dry_run=body.dry_run)

    @app.post("/api/qa")
    async def global_qa(body: QARequest, request: Request):
        from src.agents.rag.qa_service import ForensicQAService
        qa = ForensicQAService(neo4j_client=get_driver())
        return await asyncio.to_thread(qa.ask, query=body.query, top_k=body.top_k, min_score=body.min_score, dry_run=body.dry_run)
