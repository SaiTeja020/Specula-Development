"""Programmatic investigation runner for Specula.

Provides run_investigation() — the single function that maps:
  (query: str, case_id: str) → InvestigationResult

This is the integration glue between:
  - The user-facing entrypoint (CLI / FastAPI)
  - The existing build_graph() LangGraph orchestration
  - The existing synthesis.py plain-English formatter

Design decisions:
  - Reuses build_graph() exactly as-is. No graph modifications.
  - Uses InMemorySaver by default (appropriate for single-run investigations).
    Pass a real checkpointer for HITL interrupt/resume across HTTP requests.
  - If the graph pauses at HITL interrupt(), the caller receives a
    HITLPausedResult instead of an InvestigationResult, with the thread_id
    needed to resume via hitl_api.py.
  - Kafka, Neo4j, and Redis are optional. Absence degrades gracefully.
"""
from __future__ import annotations

import logging
import os
import uuid
from typing import Any, Optional

from langgraph.checkpoint.memory import InMemorySaver

from src.agents import investigation_trace
from src.agents.graph import build_graph
from src.agents.synthesis import synthesize_plain_english, InvestigationResult

logger = logging.getLogger("InvestigationRunner")


class HITLPausedResult:
    """Returned when the graph pauses at a HITL interrupt() checkpoint.

    The caller must POST to /hitl/{thread_id} with {"decision": "approve"|"reject"|"clarify"}
    to resume. See hitl_api.py.
    """
    def __init__(self, thread_id: str, case_id: str, snapshot: dict):
        self.thread_id = thread_id
        self.case_id = case_id
        self.snapshot = snapshot
        self.paused = True

    def as_dict(self) -> dict:
        return {
            "status": "paused_hitl",
            "thread_id": self.thread_id,
            "case_id": self.case_id,
            "message": (
                "The investigation requires human review before proceeding. "
                f"Submit a decision to /hitl/{self.thread_id} "
                "with {{\"decision\": \"approve\"}} to continue, "
                "\"reject\" to close, or \"clarify\" to re-enter supervision."
            ),
            "snapshot": self.snapshot,
        }


def run_investigation(
    query: str,
    case_id: Optional[str] = None,
    *,
    neo4j_driver=None,
    redis_client=None,
    checkpointer=None,
    thread_id: Optional[str] = None,
    raw_input_prefix: str = "",
    on_node_event=None,
) -> InvestigationResult | HITLPausedResult:
    """Run a complete Specula investigation from a user text query.

    Args:
        query:           Natural language investigation question.
        case_id:         Case identifier. Auto-generated if None.
        neo4j_driver:    Optional neo4j.Driver for live DFKG queries.
                         If None, agents fall back to NotYetImplementedTool.
        redis_client:    Optional redis.Redis for scratchpad persistence.
                         If None, a null scratchpad is used in-process.
        checkpointer:    LangGraph checkpointer. Defaults to InMemorySaver().
                         Pass a persistent checkpointer to support HITL resume.
        thread_id:       Explicit thread ID (for resuming a previous run).
        raw_input_prefix: Optional prefix prepended to raw_input (for test injection).

    Returns:
        InvestigationResult (completed) or HITLPausedResult (paused at HITL).
    """
    if case_id is None:
        case_id = f"case-{uuid.uuid4().hex[:8]}"

    if thread_id is None:
        thread_id = f"thread-{case_id}"

    if checkpointer is None:
        checkpointer = InMemorySaver()

    trace_id = uuid.uuid4().hex[:12]

    logger.info(f"Starting investigation: case={case_id}, thread={thread_id}, query='{query[:80]}'")

    # Build the graph with the provided infrastructure
    graph = build_graph(
        checkpointer=checkpointer,
        redis_client=redis_client,
        neo4j_driver=neo4j_driver,
    )

    # Construct the initial SpeculaState
    # raw_input carries the user query through the graph — the Supervisor reads it
    raw_input = f"{raw_input_prefix}{query}" if raw_input_prefix else query

    initial_state = {
        "case_id": case_id,
        "trace_id": trace_id,
        "input_type": "investigator_query",
        "raw_input": raw_input,
        "case_status": "open",
        "findings": [],
        "agent_traces": [],
        "dead_end_detected": False,
        "dead_end_categories": [],
        "next_agents": [],
        "specialists_dispatched": [],
        "specialists_completed": [],
        "debate_round": 1,
        "debate_history": [],
        "hitl_required": False,
    }

    config = {"configurable": {"thread_id": thread_id}}

    # --- Invoke the graph ---
    try:
        investigation_trace.record_event("runner", "user_query", {"query": query, "case_id": case_id})
        if on_node_event:
            result_state = dict(initial_state)
            for s in graph.stream(initial_state, config):
                for node_id, state_update in s.items():
                    on_node_event("node_active", {"node": node_id, "data": {"status": "Processing"}})
                    # Ensure state updates correctly
                    if isinstance(state_update, dict):
                        result_state.update(state_update)
                    on_node_event("node_complete", {"node": node_id})
            
            # Ensure we get the very final state from checkpointer if available
            try:
                result_state = graph.get_state(config).values
            except:
                pass
        else:
            result_state = graph.invoke(initial_state, config)
    except Exception as exc:
        # Check if this is a LangGraph interrupt (HITL pause)
        # LangGraph raises GraphInterrupt when interrupt() is called
        if _is_hitl_interrupt(exc):
            return _handle_hitl_pause(graph, config, thread_id, case_id)
        logger.error(f"Graph invocation failed: {exc}")
        raise

    # --- Check if graph ended at HITL without exception (some LG versions) ---
    try:
        graph_state = graph.get_state(config)
        paused_at = list(graph_state.next) if hasattr(graph_state, "next") and graph_state.next else []
        if "hitl" in paused_at:
            return _handle_hitl_pause(graph, config, thread_id, case_id)
    except Exception:
        pass  # Cannot read state — proceed with result

    logger.info(
        f"Investigation complete: case={case_id}, "
        f"status={result_state.get('case_status')}, "
        f"findings={len(result_state.get('findings', []))}"
    )

    # --- Synthesise plain-English answer ---
    result = synthesize_plain_english(result_state, query)
    investigation_trace.record_event("runner", "investigation_complete", {"case_id": case_id, "status": result_state.get('case_status')})
    return result


def run_investigation_with_hitl_stdin(
    query: str,
    case_id: Optional[str] = None,
    **kwargs,
) -> InvestigationResult:
    """CLI-friendly wrapper: if HITL pauses, read decision from stdin.

    This allows the CLI to handle HITL without a separate HTTP server.
    For production use, use run_investigation() with the HITL API instead.
    """
    checkpointer = InMemorySaver()
    result = run_investigation(query, case_id, checkpointer=checkpointer, **kwargs)

    while isinstance(result, HITLPausedResult):
        print("\n" + "=" * 60)
        print("SPECULA HITL — HUMAN REVIEW REQUIRED")
        print("=" * 60)
        snapshot = result.snapshot
        print(f"Case: {result.case_id}")
        print(f"Thread: {result.thread_id}")
        if snapshot:
            print(f"Paused reason: {snapshot.get('entry_reason', 'unknown')}")
            print(f"Guardrail tier: {snapshot.get('guardrail_fail_tier', 'none')}")
            print(f"Debate outcome: {snapshot.get('debate_outcome', 'none')}")
        print("\nOptions: approve / reject / clarify")
        try:
            decision = input("Your decision: ").strip().lower()
        except EOFError:
            decision = "approve"  # non-interactive fallback

        if decision not in ("approve", "reject", "clarify"):
            print(f"Invalid decision '{decision}'. Defaulting to 'approve'.")
            decision = "approve"

        # Resume the graph with the HITL decision
        result = _resume_after_hitl(
            query, result.thread_id, decision, checkpointer, **kwargs
        )

    return result


def _resume_after_hitl(
    query: str,
    thread_id: str,
    decision: str,
    checkpointer,
    **kwargs,
) -> InvestigationResult | HITLPausedResult:
    """Resume a graph that was paused at HITL with a human decision."""
    from langgraph.types import Command

    graph = build_graph(checkpointer=checkpointer, **{
        k: v for k, v in kwargs.items()
        if k in ("neo4j_driver", "redis_client")
    })
    config = {"configurable": {"thread_id": thread_id}}

    try:
        result_state = graph.invoke(Command(resume=decision), config)
    except Exception as exc:
        if _is_hitl_interrupt(exc):
            return _handle_hitl_pause(graph, config, thread_id, "unknown")
        raise

    return synthesize_plain_english(result_state, query)


def _is_hitl_interrupt(exc: Exception) -> bool:
    """Detect whether an exception is a LangGraph GraphInterrupt (HITL pause)."""
    exc_type = type(exc).__name__
    exc_module = type(exc).__module__
    return "GraphInterrupt" in exc_type or "Interrupt" in exc_type


def _handle_hitl_pause(
    graph, config: dict, thread_id: str, case_id: str
) -> HITLPausedResult:
    """Extract snapshot from a paused graph and return HITLPausedResult."""
    try:
        graph_state = graph.get_state(config)
        values = graph_state.values if hasattr(graph_state, "values") else {}
        snapshot = {
            "case_id": values.get("case_id"),
            "findings_count": len(values.get("findings", [])),
            "debate_outcome": values.get("debate_outcome"),
            "guardrail_fail_tier": values.get("guardrail_fail_tier"),
            "entry_reason": (
                "guardrail_failure"
                if values.get("guardrail_fail_tier") is not None
                else "debate_exhaustion"
            ),
        }
    except Exception:
        snapshot = {}

    logger.info(f"Graph paused at HITL: case={case_id}, thread={thread_id}")
    investigation_trace.record_event("hitl", "hitl_pause", snapshot)
    return HITLPausedResult(thread_id=thread_id, case_id=case_id, snapshot=snapshot)
