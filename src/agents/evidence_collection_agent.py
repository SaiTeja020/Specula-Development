"""Evidence Collection Agent — real ReAct loop, Stage 3.

Fixes applied from docs/imp_plan.md:
  A1/B1: Node is returned from a factory `make_evidence_collection_node(redis_client,
          neo4j_driver)` so LangGraph calls it as `node(state)` — one argument only.
  A2: `_llm_call` extracts `.content` with the same `hasattr(response, "content")`
       guard that `_run_agent` already uses — fixes crash on `.strip()` against a
       raw _StubResponse object.
  B2: This node never calls `_run_agent`, so no double-publish. The
       KafkaPublishFindingTool in the loop is the ONLY publish path.
  C1: `TrackingDFKGQueryTool` accumulates UIDs returned by `query_dfkg` calls
       during the loop; `dfkg_refs` in the finding is populated from them instead
       of being hardcoded to [].
"""
from __future__ import annotations

import datetime
from typing import Callable

import redis
from neo4j import Driver

from src.agents.react_engine import (
    LoopBudget, Scratchpad, Tool, ToolResult, run_react_loop,
)
from src.agents.react_tools import DFKGQueryTool, KafkaPublishFindingTool


# ---------------------------------------------------------------------------
# C1: Tracking wrapper — accumulates DFKG UIDs from tool results in the loop
# ---------------------------------------------------------------------------

class TrackingDFKGQueryTool(DFKGQueryTool):
    """Wraps DFKGQueryTool to collect 'uid' values from query results so that
    dfkg_refs in the final finding can be populated without changing the engine.
    """

    def __init__(self, driver: Driver, case_id: str):
        super().__init__(driver, case_id)
        self.collected_uids: list[str] = []

    def run(self, cypher: str, params: dict | None = None) -> ToolResult:
        result = super().run(cypher, params)
        if result.ok and result.data:
            for record in result.data:
                uid = record.get("uid") or record.get("e.uid") or record.get("n.uid")
                if uid:
                    self.collected_uids.append(str(uid))
        return result


# ---------------------------------------------------------------------------
# The deterministic relevance rules, preserved from the consolidated plan,
# exposed as a callable tool rather than the agent's entire behavior.
# ---------------------------------------------------------------------------

LOW_SIGNAL_CLASS_UIDS = {3002}  # Authentication, per the consolidated plan

def _is_routine_authentication(event: dict) -> bool:
    """N1 correction, preserved verbatim: failed auth is never routine."""
    return event.get("status") == "Success" and event.get("activity_id") in (1, 2)


class RelevanceCheckTool(Tool):
    """Exposes the deterministic triage rules (C1/N1 from the consolidated
    plan) as a tool. NOTE the discard path remains gated per C1's reasoning
    — is_summary does not exist until Stage 4b's entropy distillation ships,
    so this tool can only ever return KEEP or ESCALATE, never DISCARD, until
    Stage 4b lands. This gating is preserved exactly, not silently dropped."""

    name = "check_relevance"
    description = (
        "Deterministically classify one evidence UID as KEEP or ESCALATE "
        "(DISCARD is gated until Stage 4b — is_summary does not exist yet). "
        "Args: event (dict)."
    )

    def run(self, event: dict) -> ToolResult:
        class_uid = event.get("class_uid")
        if class_uid in LOW_SIGNAL_CLASS_UIDS and _is_routine_authentication(event):
            # Would be DISCARD once Stage 4b's is_summary flag exists.
            # For now: KEEP, with the reasoning made explicit so the agent
            # (and anyone reading agent_traces) understands why.
            return ToolResult(
                ok=True,
                observation=(
                    "Routine successful authentication — would DISCARD once "
                    "Stage 4b's entropy-distillation is_summary flag ships. "
                    "Currently forced to KEEP (discard path gated, see C1)."
                ),
                data={"verdict": "KEEP", "reason_code": "routine_auth_discard_gated"},
            )
        severity = event.get("severity_id", 0)
        if severity >= 4:  # high/critical
            return ToolResult(
                ok=True, observation="High-severity event — escalate for full review.",
                data={"verdict": "ESCALATE", "reason_code": "high_severity"},
            )
        return ToolResult(
            ok=True, observation="No strong signal either way — keep for correlation.",
            data={"verdict": "KEEP", "reason_code": "default_keep"},
        )


# ---------------------------------------------------------------------------
# LLM call / parse glue
# ---------------------------------------------------------------------------

def _build_system_prompt(state: dict) -> str:
    return (
        "You are the Evidence Collection agent investigating case "
        f"{state.get('case_id')}. Use check_relevance on each candidate "
        "evidence UID, use query_dfkg if you need case context, and "
        "publish_finding to findings.evidence_collection when your batch "
        "triage is complete. When done, respond with FINAL_ANSWER: <summary>."
    )


def _llm_call(system_prompt: str, steps: list) -> str:
    """A2: Extract .content with hasattr guard — same pattern as _run_agent."""
    from src.agents.config import get_llm
    llm = get_llm("evidence_collection")
    transcript = "\n".join(f"[{s.iteration}] {s.thought} -> {s.observation}" for s in steps)
    response = llm.invoke(f"{system_prompt}\n\nTranscript so far:\n{transcript}")
    # A2: must extract .content before returning — raw response may be _StubResponse
    return response.content if hasattr(response, "content") else str(response)


def _parse_llm_output(raw: str) -> tuple[str, str | None, dict, str | None]:
    """Minimal parser — stub-LLM-compatible for now (Stage 1 pattern)."""
    if raw.strip().upper().startswith("FINAL_ANSWER:"):
        return raw, None, {}, raw.split(":", 1)[1].strip()
    if raw.strip().upper().startswith("ACTION:"):
        import json
        _, rest = raw.split(":", 1)
        action_name, _, arg_json = rest.strip().partition(" ")
        try:
            action_input = json.loads(arg_json) if arg_json else {}
        except json.JSONDecodeError:
            action_input = {}
        return raw, action_name, action_input, None
    return raw, None, {}, None


# ---------------------------------------------------------------------------
# B1: Factory — returns a single-argument node function suitable for
#     builder.add_node("evidence_collection", make_evidence_collection_node(...))
# ---------------------------------------------------------------------------

def make_evidence_collection_node(redis_client, neo4j_driver):
    """Closure factory. Build once in build_graph(); the returned function has
    the correct `(state: dict) -> dict` signature LangGraph expects.

    redis_client / neo4j_driver may be None (e.g. in unit tests that don't
    exercise the real tool path); the ReAct loop degrades gracefully via
    NotYetImplementedTool semantics when either is None.
    """
    def evidence_collection_node(state: dict) -> dict:
        case_id = state.get("case_id", "unknown")
        trace_id = state.get("trace_id", "")

        # C1: Use TrackingDFKGQueryTool so dfkg_refs gets populated
        if neo4j_driver is not None:
            dfkg_tool = TrackingDFKGQueryTool(neo4j_driver, case_id)
        else:
            from src.agents.react_engine import NotYetImplementedTool
            dfkg_tool = NotYetImplementedTool("query_dfkg", "Stage 3 (requires neo4j_driver)")

        tools: dict[str, Tool] = {
            "check_relevance": RelevanceCheckTool(),
            "query_dfkg": dfkg_tool,
            "publish_finding": KafkaPublishFindingTool(case_id, trace_id, "evidence_collection"),
        }

        if redis_client is not None:
            scratchpad = Scratchpad(redis_client, case_id, "evidence_collection")
        else:
            # Null-object scratchpad for unit tests without Redis
            class _NullScratchpad:
                def append(self, step): pass
                def all_steps(self): return []
                def clear(self): pass
            scratchpad = _NullScratchpad()

        budget = LoopBudget(max_iterations=10, max_tool_calls=15, timeout_seconds=60.0)

        result = run_react_loop(
            system_prompt=_build_system_prompt(state),
            tools=tools,
            llm_call=_llm_call,
            parse_llm_output=_parse_llm_output,
            budget=budget,
            scratchpad=scratchpad,
        )

        if result.terminal:
            scratchpad.clear()  # promote to findings; scratchpad is now disposable
            summary = result.final_answer
        else:
            # Budget/timeout exhausted — report partial observation, per §9.5
            summary = f"INCOMPLETE ({result.termination_reason}): partial triage only."

        # C1: Collect UIDs from any query_dfkg calls that returned records
        dfkg_refs: list[str] = []
        if isinstance(dfkg_tool, TrackingDFKGQueryTool):
            dfkg_refs = dfkg_tool.collected_uids

        trace_entry = {
            "agent_role": "evidence_collection",
            "thought": "; ".join(s.thought for s in result.steps[-1:]),
            "action": "react_loop",
            "observation": summary,
            "model_used": "evidence_collection",
            "latency_ms": None,
            "terminal": result.terminal,
            "termination_reason": result.termination_reason,
        }
        finding = {
            "agent_role": "evidence_collection",
            "summary": summary,
            "dfkg_refs": dfkg_refs,  # C1: real refs, not hardcoded []
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "kafka_offset": None,
        }

        # B2: No _run_agent call here — KafkaPublishFindingTool in the loop
        # is the ONLY publish path for this agent, eliminating double-publish.
        return {
            "findings": [finding],
            "agent_traces": [trace_entry],
        }

    return evidence_collection_node
