"""Generic ReAct loop engine — Stage 3 (§9.5 harness, §3 of the roadmap).

Every agent's internal loop: Thought -> Action -> Observation -> revised Thought,
until FINAL_ANSWER, a loop-budget cap, or a timeout. This module is
agent-agnostic; each agent supplies its own tool set and system prompt.

Design points carried over from the Stage 1/2 review discussion:
  - Loop budgets are enforced here, not left to the LLM's judgment.
  - A budget/timeout exhaustion returns a PARTIAL observation to the caller
    (the Supervisor), never an unhandled exception and never a hallucinated
    "done" answer.
  - In-flight, unconfirmed reasoning lives in Redis under SCRATCHPAD_PREFIX
    (see redis_keys.py) and is NEVER written to agent_traces/findings until
    the loop reaches FINAL_ANSWER — this is the scratchpad/DFKG separation
    called out in harness §9.5, made concrete.
  - Tool failures (including "not yet implemented" placeholders) are caught
    and fed back into the loop as an Observation, never allowed to crash it.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import redis

from src.agents import investigation_trace
from src.agents.redis_keys import SCRATCHPAD_PREFIX


# ---------------------------------------------------------------------------
# Tool interface
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    ok: bool
    observation: str
    data: Any = None


class Tool:
    """Base class every real tool implements. Subclasses override `run`."""

    name: str = "unnamed_tool"
    description: str = ""

    def run(self, **kwargs) -> ToolResult:
        raise NotImplementedError


class NotYetImplementedTool(Tool):
    """Placeholder for tools that arrive in later stages (sandbox detonation,
    threat-intel lookup, etc.). Fails gracefully with a clear observation
    instead of crashing the loop or being silently absent from the tool list —
    an agent that reaches for one of these gets an honest 'not available yet'
    answer it can reason around."""

    def __init__(self, name: str, arrives_in_stage: str):
        self.name = name
        self.description = f"NOT YET IMPLEMENTED — arrives in {arrives_in_stage}."
        self._arrives_in_stage = arrives_in_stage

    def run(self, **kwargs) -> ToolResult:
        return ToolResult(
            ok=False,
            observation=(
                f"Tool '{self.name}' is not yet implemented "
                f"(scheduled for {self._arrives_in_stage}). Reason around its "
                f"absence; do not assume a result."
            ),
        )


# ---------------------------------------------------------------------------
# Loop budget configuration
# ---------------------------------------------------------------------------

@dataclass
class LoopBudget:
    max_iterations: int = 10
    max_tool_calls: int = 15
    timeout_seconds: float = 60.0


@dataclass
class ReActStep:
    iteration: int
    thought: str
    action: Optional[str]
    action_input: dict
    observation: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class ReActResult:
    terminal: bool             # True if FINAL_ANSWER reached, False if budget/timeout exhausted
    final_answer: Optional[str]
    steps: list[ReActStep]
    tool_calls_used: int
    iterations_used: int
    termination_reason: str    # "final_answer" | "max_iterations" | "max_tool_calls" | "timeout"


# ---------------------------------------------------------------------------
# Scratchpad — in-flight state, never promoted until FINAL_ANSWER
# ---------------------------------------------------------------------------

class Scratchpad:
    def __init__(self, redis_client: redis.Redis, case_id: str, agent_role: str):
        self._r = redis_client
        self._key = f"{SCRATCHPAD_PREFIX}{case_id}:{agent_role}"

    def append(self, step: ReActStep) -> None:
        self._r.rpush(self._key, json.dumps(step.__dict__))
        self._r.expire(self._key, 3600)  # 1h TTL — genuinely disposable working memory

    def all_steps(self) -> list[dict]:
        return [json.loads(s) for s in self._r.lrange(self._key, 0, -1)]

    def clear(self) -> None:
        self._r.delete(self._key)


# ---------------------------------------------------------------------------
# The loop itself
# ---------------------------------------------------------------------------

# LLM call signature the engine expects: (system_prompt, transcript) -> raw text
LLMCallFn = Callable[[str, list[ReActStep]], str]

# Parser signature: raw LLM text -> (thought, action_name_or_None, action_input, final_answer_or_None)
ParseFn = Callable[[str], tuple[str, Optional[str], dict, Optional[str]]]


def run_react_loop(
    *,
    system_prompt: str,
    tools: dict[str, Tool],
    llm_call: LLMCallFn,
    parse_llm_output: ParseFn,
    budget: LoopBudget,
    scratchpad: Scratchpad,
    agent_role: str = "agent",
) -> ReActResult:
    """Runs one agent's ReAct loop to completion or exhaustion.

    Caller (the agent node) owns: constructing system_prompt from state,
    building the tool dict, and deciding what to do with a non-terminal
    ReActResult (typically: report a partial observation to the Supervisor).
    """
    # Start trace
    investigation_trace.set_active_agent(agent_role)
    
    import os
    from src.agents.config import AGENT_CONFIG
    
    cfg = AGENT_CONFIG.get(agent_role, {})
    actual_model = cfg.get("model_id", "LLM")
    
    backend = os.environ.get("SPECULA_LLM_BACKEND", "").lower()
    if backend == "ollama":
        actual_model = os.environ.get("SPECULA_LLM_MODEL", "qwen2.5-coder:1.5b")
    elif backend == "lmstudio":
        actual_model = os.environ.get("SPECULA_LLM_MODEL", "local-model")
        
    investigation_trace.record_event(agent_role, "agent_start", {"model": actual_model})

    steps: list[ReActStep] = []
    tool_calls_used = 0
    start = time.monotonic()

    for iteration in range(1, budget.max_iterations + 1):
        if time.monotonic() - start > budget.timeout_seconds:
            return ReActResult(
                terminal=False, final_answer=None, steps=steps,
                tool_calls_used=tool_calls_used, iterations_used=iteration - 1,
                termination_reason="timeout",
            )

        raw = llm_call(system_prompt, steps)
        thought, action, action_input, final_answer = parse_llm_output(raw)

        if final_answer is not None:
            step = ReActStep(iteration, thought, None, {}, f"FINAL_ANSWER: {final_answer}")
            steps.append(step)
            scratchpad.append(step)
            return ReActResult(
                terminal=True, final_answer=final_answer, steps=steps,
                tool_calls_used=tool_calls_used, iterations_used=iteration,
                termination_reason="final_answer",
            )

        if action is None:
            # Malformed LLM output — no action, no final answer. Treat as a
            # wasted iteration with an explicit observation, not a crash.
            step = ReActStep(iteration, thought, None, {}, "No valid action or final answer parsed.")
            steps.append(step)
            scratchpad.append(step)
            continue

        if tool_calls_used >= budget.max_tool_calls:
            return ReActResult(
                terminal=False, final_answer=None, steps=steps,
                tool_calls_used=tool_calls_used, iterations_used=iteration,
                termination_reason="max_tool_calls",
            )

        tool = tools.get(action)
        if tool is None:
            observation = f"Unknown tool '{action}'. Available tools: {list(tools)}"
        else:
            try:
                result = tool.run(**action_input)
                observation = result.observation
            except Exception as exc:  # tool failures are Observations, not crashes
                observation = f"Tool '{action}' raised an error: {exc}"
            tool_calls_used += 1

        step = ReActStep(iteration, thought, action, action_input, observation)
        steps.append(step)
        scratchpad.append(step)
        
        # Trace action and observation
        investigation_trace.record_event(agent_role, "agent_action", {"action": action, "action_input": action_input})
        investigation_trace.record_event(agent_role, "agent_observation", {"observation": observation})

    return ReActResult(
        terminal=False, final_answer=None, steps=steps,
        tool_calls_used=tool_calls_used, iterations_used=budget.max_iterations,
        termination_reason="max_iterations",
    )
