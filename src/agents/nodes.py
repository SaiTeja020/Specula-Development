"""All 23 node functions for the Specula orchestration skeleton — §3–4, §7–8.

Node types:
  16 ReAct-stub LLM agent nodes
   2 non-LLM real nodes (Guardrail Tier 1, Tier 2)
   1 real HTTP node (HITL — uses interrupt())
   4 control-only nodes (joins + terminal)
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Literal

from langgraph.types import Command, interrupt

from .config import AGENT_CONFIG, get_llm
from .guardrails import run_tier1_checks, run_tier2_checks
from .kafka_utils import ROLE_TOPIC_MAP, publish_finding
# NOTE: evidence_collection_node is no longer defined here.
# Import make_evidence_collection_node from evidence_collection_agent and wire
# it in build_graph() via the closure pattern (B1 fix).


# ===================================================================
# Helper: common single-pass LLM call
# ===================================================================

def _run_agent(role: str, state: dict, **extra_ctx) -> tuple[dict, dict]:
    """Execute a single-pass LLM call for *role*. Returns (finding, trace).

    Extra keyword args are merged into the prompt template format dict.
    D4: passes case_id to get_llm so StubLLM can fill {case_id} in responses
    without fragile regex extraction from the formatted prompt.
    """
    cfg = AGENT_CONFIG.get(role, AGENT_CONFIG["supervisor"])
    # D4: forward case_id so StubLLM fills report template without prompt regex
    llm = get_llm(role, case_id=state.get("case_id", "unknown"))

    fmt = {
        "case_id": state.get("case_id", "unknown"),
        "raw_input": str(state.get("raw_input", ""))[:500],
        "findings_summary": _summarise_findings(state),
        "timeline_summary": str(state.get("timeline", {}).get("summary", ""))[:300],
        "attribution_summary": str(state.get("attribution", {}).get("summary", ""))[:300],
        "proponent_argument": str(state.get("proponent_argument", ""))[:300],
        "critic_argument": str(state.get("critic_argument", ""))[:300],
        "debate_round": str(state.get("debate_round", 1)),
        "evidence_summary": _summarise_findings(state)[:300],
        "output_summary": _summarise_output(state)[:500],
    }
    fmt.update(extra_ctx)

    prompt = cfg["system_prompt_template"].format_map(
        _SafeFormatDict(fmt)
    )

    start = time.time()
    response = llm.invoke(prompt)
    latency_ms = round((time.time() - start) * 1000, 1)

    content = response.content if hasattr(response, "content") else str(response)

    finding = {
        "agent_role": role,
        "summary": content,
        "dfkg_refs": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kafka_offset": None,
    }

    trace = {
        "agent_role": role,
        "thought": f"Analysing case as {role}",
        "action": "single_pass_llm_call",
        "observation": content[:200],
        "model_used": cfg["model_id"],
        "latency_ms": latency_ms,
    }

    # Fire-and-forget Kafka publish
    topic = ROLE_TOPIC_MAP.get(role)
    if topic:
        publish_finding(topic, finding, state.get("trace_id"))

    return finding, trace


class _SafeFormatDict(dict):
    """Returns '' for missing keys instead of raising KeyError."""
    def __missing__(self, key):
        return ""


def _summarise_findings(state: dict) -> str:
    findings = state.get("findings", [])
    if not findings:
        return "No findings yet."
    parts = [f"[{f.get('agent_role', '?')}] {f.get('summary', '')[:80]}" for f in findings[-6:]]
    return "; ".join(parts)


def _summarise_output(state: dict) -> str:
    parts = []
    for f in state.get("findings", [])[-4:]:
        parts.append(f.get("summary", "")[:100])
    if state.get("timeline"):
        parts.append(str(state["timeline"].get("summary", ""))[:100])
    if state.get("attribution"):
        parts.append(str(state["attribution"].get("summary", ""))[:100])
    return " | ".join(parts) if parts else "No output to validate."


# ===================================================================
# 16 ReAct-stub LLM agent nodes
# ===================================================================

# --- 1. Supervisor (§3 row 1, §4 entry) ---
def supervisor_node(state: dict) -> dict:
    """Entry point. Evaluates input, dispatches primary tier.

    D1: Dead-end detection is no longer performed here — it has been moved to
    primary_tier_join_node (via make_primary_tier_join_node factory), which is
    the correct evaluation point: AFTER primary agents have run and their
    findings are available. The DEAD_END:category raw_input signal is removed.
    test_control injection for dead-end still works via detect_dead_end() inside
    primary_tier_join_node, which reads state["test_control"]["dead_end_categories"].
    """
    finding, trace = _run_agent("supervisor", state)

    return {
        "case_status": "primary_tier",
        "findings": [finding],
        "agent_traces": [trace],
        # Reset on re-entry (HITL clarify loop)
        "guardrail_fail_tier": None,
        "guardrail_tier1_result": None,
        "guardrail_tier2_result": None,
        "guardrail_tier3_result": None,
        "debate_outcome": None,
        "debate_round": 1,
        "hitl_decision": None,
        "hitl_required": False,
        "report_output": None,
        "timeline_artifact": None,
        "final_output_ref": None,
    }


# --- 2–4. Primary tier (parallel) ---
# B1: evidence_collection_node is now a factory in evidence_collection_agent.py.
# The node function itself is wired into the graph by build_graph() via:
#   builder.add_node("evidence_collection", make_evidence_collection_node(redis, neo4j))
# Do NOT call evidence_collection_node directly from nodes.py.

def log_analysis_node(state: dict) -> dict:
    finding, trace = _run_agent("log_analysis", state)
    return {"findings": [finding], "agent_traces": [trace]}


def network_forensics_node(state: dict) -> dict:
    finding, trace = _run_agent("network_forensics", state)
    return {"findings": [finding], "agent_traces": [trace]}


# --- 5. Timeline Reconstruction ---
def timeline_reconstruction_node(state: dict) -> dict:
    finding, trace = _run_agent("timeline_reconstruction", state)
    return {
        "case_status": "synthesis",
        "timeline": {"summary": finding["summary"], "dfkg_refs": finding["dfkg_refs"]},
        "findings": [finding],
        "agent_traces": [trace],
    }


# --- 6. Threat Attribution ---
def threat_attribution_node(state: dict) -> dict:
    finding, trace = _run_agent("threat_attribution", state)
    return {
        "attribution": {"summary": finding["summary"], "dfkg_refs": finding["dfkg_refs"]},
        "findings": [finding],
        "agent_traces": [trace],
    }


# --- 7–10. Specialist tier (conditional, parallel-if-multiple) ---
def memory_forensics_node(state: dict) -> dict:
    finding, trace = _run_agent("memory_forensics", state)
    return {
        "findings": [finding],
        "agent_traces": [trace],
        "specialists_completed": ["memory"],
    }


def identity_cloud_node(state: dict) -> dict:
    finding, trace = _run_agent("identity_cloud", state)
    return {
        "findings": [finding],
        "agent_traces": [trace],
        "specialists_completed": ["identity"],
    }


def malware_stylometry_node(state: dict) -> dict:
    finding, trace = _run_agent("malware_stylometry", state)
    return {
        "findings": [finding],
        "agent_traces": [trace],
        "specialists_completed": ["malware"],
    }


def insider_threat_node(state: dict) -> dict:
    finding, trace = _run_agent("insider_threat", state)
    return {
        "findings": [finding],
        "agent_traces": [trace],
        "specialists_completed": ["insider"],
    }


# --- 11. Proponent ---
def proponent_node(state: dict) -> dict:
    finding, trace = _run_agent("proponent", state)
    return {
        "case_status": "debate",
        "proponent_argument": finding["summary"],
        "findings": [finding],
        "agent_traces": [trace],
    }


# --- 12. Critic ---
def critic_node(state: dict) -> dict:
    finding, trace = _run_agent("critic", state)
    return {
        "critic_argument": finding["summary"],
        "findings": [finding],
        "agent_traces": [trace],
    }


# --- 13. Judge (returns Command — §4 debate loop routing) ---
def judge_node(state: dict) -> Command[Literal[
    "guardrail_tier1", "proponent", "hitl"
]]:
    finding, trace = _run_agent("judge", state)
    content = finding["summary"]
    round_num = state.get("debate_round", 1)

    # Parse verdict from LLM output / test overrides
    raw_input = str(state.get("raw_input", ""))

    # Per-round control: FORCE_JUDGE_REJECT_ROUNDS:N rejects rounds 1..N,
    # accepts from round N+1 onward. FORCE_JUDGE_REJECT (no :N) rejects all.
    rounds_match = re.search(r"FORCE_JUDGE_REJECT_ROUNDS:(\d+)", raw_input)
    if rounds_match:
        reject_until = int(rounds_match.group(1))
        verdict = "reject" if round_num <= reject_until else "accept"
    elif "FORCE_JUDGE_REJECT" in raw_input:
        verdict = "reject"
    elif "VERDICT: REJECT" in content.upper():
        verdict = "reject"
    elif "VERDICT: ACCEPT" in content.upper():
        verdict = "accept"
    else:
        verdict = "accept"



    # Parse confidence from output
    conf_match = re.search(r"Confidence:\s*(\d+(?:\.\d+)?)", content, re.IGNORECASE)
    current_confidence = float(conf_match.group(1)) if conf_match else 0.85



    # Compute confidence delta (undefined on round 1 per §2.5)
    prev_history = state.get("debate_history", [])
    if round_num >= 2 and prev_history:
        prev_conf = prev_history[-1].get("confidence", 0.85)
        confidence_delta = abs(current_confidence - prev_conf)
    else:
        confidence_delta = None

    # Build debate history entry
    history_entry = {
        "round": round_num,
        "proponent": state.get("proponent_argument", ""),
        "critic": state.get("critic_argument", ""),
        "verdict": verdict,
        "confidence": current_confidence,
    }

    base_update = {
        "judge_verdict": verdict,
        "confidence_delta": confidence_delta,
        "debate_history": [history_entry],
        "findings": [finding],
        "agent_traces": [trace],
    }

    # §4 routing logic (evaluated in order):
    # 1. accept → guardrail_tier1 (converged)
    if verdict == "accept":
        base_update["debate_outcome"] = "converged"
        return Command(update=base_update, goto="guardrail_tier1")

    # 2. round >= 2 AND confidence_delta < 0.05 AND verdict != 'reject' → guardrail_tier1 (early exit)
    if (verdict != "reject"
            and round_num >= 2
            and confidence_delta is not None
            and confidence_delta < 0.05):
        base_update["debate_outcome"] = "converged"
        return Command(update=base_update, goto="guardrail_tier1")


    # 3. reject AND round < 3 → loop back to proponent
    if verdict == "reject" and round_num < 3:
        base_update["debate_round"] = round_num + 1
        return Command(update=base_update, goto="proponent")

    # 4. round == 3 exhausted → HITL
    base_update["debate_outcome"] = "round_cap_exhausted"
    base_update["hitl_required"] = True
    base_update["case_status"] = "hitl_review"
    return Command(update=base_update, goto="hitl")


# --- 14. Guardrail Tier 3 (LLM semantic validation, returns Command) ---
def guardrail_tier3_node(state: dict) -> Command[Literal[
    "hitl", "report_generation", "timeline_artifact_generation"
]]:
    finding, trace = _run_agent("guardrail_tier3", state)
    content = finding["summary"]

    raw_input = str(state.get("raw_input", ""))
    if "FORCE_GUARDRAIL3_FAIL" in raw_input:
        result = "fail"
    elif "RESULT: FAIL" in content.upper():
        result = "fail"
    else:
        result = "pass"

    update: dict = {
        "guardrail_tier3_result": result,
        "case_status": "guardrail",
        "agent_traces": [trace],
    }

    if result == "fail":
        update["guardrail_fail_tier"] = 3
        update["hitl_required"] = True
        update["case_status"] = "hitl_review"
        return Command(update=update, goto="hitl")

    return Command(
        update=update,
        goto=["report_generation", "timeline_artifact_generation"],
    )


# --- 15. Report Generation ---
def report_generation_node(state: dict) -> dict:
    finding, trace = _run_agent("report_generation", state)
    return {
        "case_status": "report",
        "report_output": finding["summary"],
        "findings": [finding],
        "agent_traces": [trace],
    }


# --- 16. Timeline Artifact Generation ---
def timeline_artifact_generation_node(state: dict) -> dict:
    finding, trace = _run_agent("timeline_artifact_generation", state)
    return {
        "timeline_artifact": finding["summary"],
        "findings": [finding],
        "agent_traces": [trace],
    }


# ===================================================================
# 2 non-LLM real nodes — Guardrail Tier 1 & 2 (return Command)
# ===================================================================

def guardrail_tier1_node(state: dict) -> Command[Literal[
    "hitl", "guardrail_tier2"
]]:
    """Tier 1: regex/AST checks (§7). Deterministic, no LLM."""
    # Collect all agent output text AND raw_input for checking
    text_to_check = " ".join(
        f.get("summary", "") for f in state.get("findings", [])
    )
    raw_input = str(state.get("raw_input", ""))
    text_to_check = f"{raw_input} {text_to_check}"
    if "FORCE_GUARDRAIL1_FAIL" in raw_input:
        result, fired = "fail", ["forced_test_failure"]
    else:
        result, fired = run_tier1_checks(text_to_check)

    update: dict = {
        "guardrail_tier1_result": result,
        "case_status": "guardrail",
    }
    if result == "fail":
        update["guardrail_fail_tier"] = 1
        update["hitl_required"] = True
        update["case_status"] = "hitl_review"
        return Command(update=update, goto="hitl")
    return Command(update=update, goto="guardrail_tier2")


def guardrail_tier2_node(state: dict) -> Command[Literal[
    "hitl", "guardrail_tier3"
]]:
    """Tier 2: embedding similarity classifier (§7). No LLM."""
    texts_to_check = [str(state.get("raw_input", ""))] + [
        f.get("summary", "") for f in state.get("findings", [])
    ]
    
    result = "pass"
    for text in texts_to_check:
        if not text.strip(): continue
        res, sim = run_tier2_checks(text)
        if res == "fail":
            result = "fail"
            break

    raw_input = str(state.get("raw_input", ""))
    if "FORCE_GUARDRAIL2_FAIL" in raw_input:
        result = "fail"

    update: dict = {
        "guardrail_tier2_result": result,
        "case_status": "guardrail",
    }
    if result == "fail":
        update["guardrail_fail_tier"] = 2
        update["hitl_required"] = True
        update["case_status"] = "hitl_review"
        return Command(update=update, goto="hitl")
    return Command(update=update, goto="guardrail_tier3")


# ===================================================================
# 1 real HTTP node — HITL (uses interrupt, returns Command)
# ===================================================================

def hitl_node(state: dict) -> Command[Literal[
    "report_generation", "timeline_artifact_generation",
    "guardrail_tier1", "case_closed_rejected", "supervisor"
]]:
    """HITL approval gate — §8.

    Dual-entry routing:
      guardrail failure  → approve routes to report generation
      debate exhaustion  → approve routes to guardrail tier 1
      reject (either)    → case_closed_rejected terminal
      clarify (either)   → supervisor re-entry
    """
    # Determine entry reason from state (§4/§8 distinction)
    entry_reason = (
        "guardrail_failure"
        if state.get("guardrail_fail_tier") is not None
        else "debate_exhaustion"
    )

    snapshot = {
        "case_id": state.get("case_id"),
        "findings_count": len(state.get("findings", [])),
        "debate_outcome": state.get("debate_outcome"),
        "guardrail_fail_tier": state.get("guardrail_fail_tier"),
        "entry_reason": entry_reason,
        "judge_verdict": state.get("judge_verdict"),
        "debate_round": state.get("debate_round"),
    }

    # Note: case_status="hitl_review" is explicitly set by the routing nodes
    # (guardrail/judge) *before* transitioning to this node. This ensures
    # the status is correctly visible in the state checkpoint while the graph
    # is paused here at the interrupt().
    decision = interrupt(snapshot)

    update: dict = {
        "hitl_decision": decision,
        "hitl_case_snapshot": snapshot,
        "case_status": "hitl_review",
    }

    if decision == "reject":
        return Command(update=update, goto="case_closed_rejected")

    if decision == "clarify":
        return Command(update=update, goto="supervisor")

    # approve
    if entry_reason == "guardrail_failure":
        # Guardrail ran and failed — analyst overrides, skip to report
        return Command(
            update=update,
            goto=["report_generation", "timeline_artifact_generation"],
        )
    else:
        # Debate exhausted, guardrail never ran — must run guardrail first
        return Command(update=update, goto="guardrail_tier1")


# ===================================================================
# 4 control-only nodes (no agent identity, no agent_traces entry)
# ===================================================================

def make_primary_tier_join_node(redis_client):
    """D1: Factory that closes over redis_client for the real dead-end heuristic.

    The returned node is called by LangGraph as `node(state)` after all three
    primary agents have completed their fan-out and their findings are merged
    into state. This is the correct place to evaluate whether a dead-end exists
    (findings are available here; they were NOT available at Supervisor entry).

    redis_client=None is safe — detect_dead_end handles it gracefully (returns
    (False, []) unless test_control is set in state).
    """
    from .dead_end_detector import detect_dead_end

    def primary_tier_join_node(state: dict) -> dict:
        dead_end, categories = detect_dead_end(state, redis_client)
        return {
            "dead_end_detected": dead_end,
            "dead_end_categories": categories,
            "specialists_dispatched": categories if dead_end else [],
        }

    return primary_tier_join_node


def specialist_join_node(state: dict) -> dict:
    """Fan-in after specialist tier. Marks specialist stage complete."""
    return {"case_status": "specialist_tier"}


def final_output_join_node(state: dict) -> dict:
    """Converges report + timeline artifact into final output."""
    ref = None
    if state.get("report_output") and state.get("timeline_artifact"):
        ref = f"case-{state.get('case_id', 'unknown')}-final"
    return {
        "final_output_ref": ref,
        "case_status": "closed",
    }


def case_closed_rejected_node(state: dict) -> dict:
    """Terminal state for HITL reject. No report, no timeline artifact."""
    return {"case_status": "closed"}
