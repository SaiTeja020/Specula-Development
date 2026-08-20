"""Evidence Collection Agent — real ReAct loop, Stage 3.

This SUPERSEDES the consolidated plan's M1 correction ("purely deterministic,
no LLM invoked"). Per the project's stated architecture ("all agents in our
architecture are ReAct agents"), Evidence Collection gets a real ReAct loop
here, consistent with every other agent. The deterministic relevance-filter
LOGIC from the consolidated plan (severity/host/class_uid checks, the
routine-authentication carve-out) is preserved and exposed AS A TOOL the
agent can call — this keeps the auditable, testable deterministic rules
(good instinct in the original design) while restoring the agent's ability
to actually reason about ambiguous cases the fixed rule set doesn't cleanly
resolve, which is the whole point of it being an agent rather than a filter.

Wiring notes / assumptions (confirm against your actual nodes.py):
  - Assumes `_run_agent`-style Command-based routing is still how nodes
    return control to the graph. Adjust the `Command(...)` call at the
    bottom to match your actual graph.py routing signature.
  - Assumes `state["findings"]`-append pattern from Stage 1's SpeculaState
    is unchanged.
"""
from __future__ import annotations

from typing import Literal

import redis
from langgraph.types import Command

from src.agents.react_engine import (
    LoopBudget, Scratchpad, Tool, ToolResult, run_react_loop,
)
from src.agents.react_tools import DFKGQueryTool, KafkaPublishFindingTool


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
# LLM call / parse glue — adjust to match your actual config.py StubLLM /
# ChatOpenAI wiring from Stage 1.
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
    # Wire to your actual config.py model resolution (StubLLM / ChatOpenAI).
    from src.agents.config import get_llm
    llm = get_llm("evidence_collection")
    transcript = "\n".join(f"[{s.iteration}] {s.thought} -> {s.observation}" for s in steps)
    return llm.invoke(f"{system_prompt}\n\nTranscript so far:\n{transcript}")


def _parse_llm_output(raw: str) -> tuple[str, str | None, dict, str | None]:
    """Minimal parser — replace with your actual structured-output / tool-
    calling parse logic once real models are wired in (Stage 13's model
    matrix uses real tool-calling APIs; this is a stub-LLM-compatible parser
    for now, matching Stage 1's StubLLM pattern)."""
    if raw.strip().upper().startswith("FINAL_ANSWER:"):
        return raw, None, {}, raw.split(":", 1)[1].strip()
    if raw.strip().upper().startswith("ACTION:"):
        # Expected stub format: "ACTION: check_relevance {\"event\": {...}}"
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
# The node itself
# ---------------------------------------------------------------------------

def evidence_collection_node(state: dict, deps: dict) -> Command[Literal["primary_tier_join"]]:
    """deps must supply: redis_client, neo4j_driver — matching whatever
    dependency-injection pattern your nodes.py already uses (adjust if
    Stage 1 wires these globally instead of via a deps dict)."""
    case_id = state["case_id"]
    trace_id = state["trace_id"]

    tools = {
        "check_relevance": RelevanceCheckTool(),
        "query_dfkg": DFKGQueryTool(deps["neo4j_driver"], case_id),
        "publish_finding": KafkaPublishFindingTool(case_id, trace_id, "evidence_collection"),
    }
    scratchpad = Scratchpad(deps["redis_client"], case_id, "evidence_collection")
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
        observation = summary
    else:
        # Budget/timeout exhausted — report a partial observation to the
        # Supervisor, per §9.5's explicit degradation policy. Do NOT
        # fabricate a plausible-looking finding.
        summary = f"INCOMPLETE ({result.termination_reason}): partial triage only."
        observation = summary

    trace_entry = {
        "agent_role": "evidence_collection",
        "thought": "; ".join(s.thought for s in result.steps[-1:]),
        "observation": observation,
        "model_used": "evidence_collection",
        "latency_ms": None,
        "terminal": result.terminal,
        "termination_reason": result.termination_reason,
    }
    finding = {"agent_role": "evidence_collection", "summary": summary, "dfkg_refs": []}

    return Command(
        update={
            "agent_traces": [trace_entry],
            "findings": [finding],
        },
        goto="primary_tier_join",
    )
