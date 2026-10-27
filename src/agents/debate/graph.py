"""Debate LangGraph state machine — Plan v3 §7.

Routers rely only on code-derived state variables; LLM control-flow text is ignored.
round_index is advanced ONLY by the (code-managed) judge node; the judge also resets
validation_attempts to 0 and convergence_status to the fresh verdict each round.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from langgraph.graph import END, StateGraph

from .middleware import check_debate_gate, make_debate_run_id
from .nodes import DebateDeps, make_critic_node, make_judge_node, make_proponent_node
from .schemas import DebateGraphState

# Every status that must end in a human (plan §7.1 degradation policy + v3 additions).
_HITL_STATUSES = (
    "VALIDATION_EXHAUSTED", "TOOL_TIMEOUT", "PAYLOAD_MISSING",
    "INSUFFICIENT_EVIDENCE", "DEADLOCK_TIE", "JUDGE_OUTPUT_INVALID",
)
_CONVERGED = ("CONVERGED_DOMINANT", "CONVERGED_STABLE")
# Case reopened mid-debate (late write): abort; the caller restarts under a new run id.
_ABORT = "CASE_REOPENED"


def router_after_proponent(state: DebateGraphState) -> str:
    status = state["convergence_status"]
    if status == _ABORT: return "abort_debate"
    if status in _HITL_STATUSES: return "escalate_to_hitl"
    if state["validation_attempts"] > 0: return "proponent_node"  # Retry
    return "critic_node"


def router_after_critic(state: DebateGraphState) -> str:
    status = state["convergence_status"]
    if status == _ABORT: return "abort_debate"
    if status in _HITL_STATUSES: return "escalate_to_hitl"
    if state["validation_attempts"] > 0: return "critic_node"  # Retry
    return "judge_node"


def router_after_judge(state: DebateGraphState) -> str:
    status = state["convergence_status"]
    if status == _ABORT:
        return "abort_debate"
    if status in _HITL_STATUSES:
        return "escalate_to_hitl"
    # Round cap guard: a PENDING verdict at max rounds cannot loop back to Proponent
    if state.get("round_index", 1) > 3 and status == "PENDING":
        return "escalate_to_hitl"
    if status in _CONVERGED:
        # M5: any model fallback forces a human to confirm the verdict.
        if state.get("degraded_capability_mode"):
            return "escalate_to_hitl"
        return "route_to_guardrails"
    # M4: If an agent failed claim entailment (validation_attempts > 0 or entailment_attempts > 0), route back to that agent's node
    if state.get("validation_attempts", 0) > 0 or state.get("entailment_attempts", 0) > 0:
        if state.get("active_turn") == "CRITIC":
            return "critic_node"
        return "proponent_node"
    # Otherwise, normal PENDING verdict: new round ALWAYS restarts at Proponent (defect 6)
    return "proponent_node"


def build_debate_graph(deps: DebateDeps):
    def route_to_guardrails(state: DebateGraphState) -> Dict[str, Any]:
        return {}

    def abort_debate(state: DebateGraphState) -> Dict[str, Any]:
        deps.ledger.append_interaction(
            state["trace_id"], "DEBATE_ABORTED_CASE_REOPENED",
            {"debate_run_id": state["debate_run_id"], "round_index": state["round_index"]},
        )
        return {}

    def escalate_to_hitl(state: DebateGraphState) -> Dict[str, Any]:
        # case_state -> HITL: suspend ephemeral TTLs so payloads survive review.
        deps.store.suspend_ttl(state["case_id"])
        prop_hyp, crit_hyp = "", ""
        prop_data, crit_data = None, None
        payload_load_errors: List[str] = []
        try:
            if state.get("proponent_payload_uid"):
                p = deps.store.load_payload(state["case_id"], state["proponent_payload_uid"])
                prop_hyp = p.hypothesis
                prop_data = p.model_dump()
            if state.get("critic_payload_uid"):
                c = deps.store.load_payload(state["case_id"], state["critic_payload_uid"])
                crit_hyp = c.hypothesis
                crit_data = c.model_dump()
        except Exception as exc:
            payload_load_errors.append(f"payload_load_failure: {exc}")

        latest_rec: Dict[str, Any] = {}
        for r_idx in range(state.get("round_index", 1), 0, -1):
            try:
                rec = deps.store.load_judge_record(state["case_id"], state["debate_run_id"], r_idx)
                if rec:
                    latest_rec = rec
                    break
            except Exception as exc:
                if r_idx == 1:
                    payload_load_errors.append(f"judge_record_load_failure: {exc}")

        payload = {
            "case_id": state["case_id"],
            "trace_id": state["trace_id"],
            "debate_run_id": state["debate_run_id"],
            "convergence_status": state["convergence_status"],
            "reason": state.get("convergence_status"),
            "round_index": state["round_index"],
            "p_h1": state["p_h1"],
            "p_h2": state["p_h2"],
            "proponent_hypothesis": prop_hyp,
            "critic_hypothesis": crit_hyp,
            "proponent_payload": prop_data,
            "critic_payload": crit_data,
            "matrix": latest_rec.get("verdict"),
            "blind_map": latest_rec.get("blind_map"),
            "claim_entailments": latest_rec.get("claim_entailments"),
            "degraded_capability_mode": state.get("degraded_capability_mode", False),
            "models": dict(deps.models),
            "payload_load_error": "; ".join(payload_load_errors) if payload_load_errors else None,
        }
        deps.ledger.append_interaction(state["trace_id"], "HITL_ESCALATION", payload)
        if deps.hitl_sink:
            deps.hitl_sink(payload)
        else:
            import logging
            logging.getLogger(__name__).warning("No hitl_sink configured; HITL escalation recorded to VCT ledger only.")
        return {}

    g = StateGraph(DebateGraphState)
    g.add_node("proponent_node", make_proponent_node(deps))
    g.add_node("critic_node", make_critic_node(deps))
    g.add_node("judge_node", make_judge_node(deps))
    g.add_node("route_to_guardrails", route_to_guardrails)
    g.add_node("escalate_to_hitl", escalate_to_hitl)
    g.add_node("abort_debate", abort_debate)

    g.set_entry_point("proponent_node")
    g.add_conditional_edges("proponent_node", router_after_proponent, {
        "proponent_node": "proponent_node", "critic_node": "critic_node",
        "escalate_to_hitl": "escalate_to_hitl", "abort_debate": "abort_debate",
    })
    g.add_conditional_edges("critic_node", router_after_critic, {
        "critic_node": "critic_node", "judge_node": "judge_node",
        "escalate_to_hitl": "escalate_to_hitl", "abort_debate": "abort_debate",
    })
    g.add_conditional_edges("judge_node", router_after_judge, {
        "proponent_node": "proponent_node", "critic_node": "critic_node",
        "route_to_guardrails": "route_to_guardrails",
        "escalate_to_hitl": "escalate_to_hitl", "abort_debate": "abort_debate",
    })
    g.add_edge("route_to_guardrails", END)
    g.add_edge("escalate_to_hitl", END)
    g.add_edge("abort_debate", END)
    return g.compile()


def initial_debate_state(
    case_id: str, trace_id: str, debate_run_id: str, degraded: bool = False,
    models: Optional[Dict[str, str]] = None,
) -> DebateGraphState:
    import time
    return {
        "case_id": case_id, "trace_id": trace_id, "debate_run_id": debate_run_id,
        "round_index": 1, "validation_attempts": 0, "entailment_attempts": 0, "active_turn": "PROPONENT",
        "proponent_payload_uid": "", "critic_payload_uid": "",
        "p_h1": None, "p_h2": None, "degraded_capability_mode": degraded,
        "models_used": dict(models or {}),
        "start_time": time.time(),
        "convergence_status": "PENDING",
        "debate_result": None,
    }


async def run_debate(
    deps: DebateDeps,
    case_id: str,
    trace_id: str,
    case_state: str,
    dispatched_agents: Sequence[str],
    completed_agents: Sequence[str],
    lagging_consumer_writes: bool = False,
    attempt: int = 0,
    debate_run_id: Optional[str] = None,
) -> DebateGraphState:
    """Gate-checked entry point (§1). Raises DebateGateError if the gate is closed.

    `attempt` increments on every restart after a CASE_REOPENED abort, giving each run
    its own deterministic run id (and therefore its own keys and blind seeds)."""
    check_debate_gate(case_state, dispatched_agents, completed_agents, lagging_consumer_writes)
    run_id = debate_run_id or make_debate_run_id(case_id, trace_id, attempt)
    graph = build_debate_graph(deps)
    return await graph.ainvoke(
        initial_debate_state(case_id, trace_id, run_id, deps.degraded_capability_mode),
        {"recursion_limit": 50},
    )
