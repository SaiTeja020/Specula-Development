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

from src.agents import investigation_trace

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
    
    # Trace agent start
    investigation_trace.set_active_agent(role)
    actual_model = getattr(llm, "model", cfg.get("model_id", "unknown"))
    investigation_trace.record_event(role, "agent_start", {"model": actual_model})
    
    response = llm.invoke(prompt)
    latency_ms = round((time.time() - start) * 1000, 1)

    content = response.content if hasattr(response, "content") else str(response)
    if isinstance(content, list):
        text_parts = []
        for part in content:
            if isinstance(part, dict) and "text" in part:
                text_parts.append(part["text"])
            elif isinstance(part, str):
                text_parts.append(part)
        content = "\n".join(text_parts)
    
    # Trace action/observation
    investigation_trace.record_event(role, "agent_observation", {"observation": content})

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
        "model_used": actual_model,
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

def make_supervisor_node(neo4j_driver):
    """Factory for the Supervisor node, allowing it to query the DFKG for context
    instead of relying on the ephemeral LangGraph findings array.
    """
    def supervisor_node(state: dict) -> dict:
        case_id = state.get("case_id", "unknown")
        
        dfkg_summary = "No prior findings."
        if neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    res = session.run(
                        "MATCH (f:AgentFinding)-[:BELONGS_TO]->(c:Case {case_id: $case_id}) "
                        "RETURN f.agent_role AS role, f.summary AS summary "
                        "ORDER BY f.timestamp DESC LIMIT 10",
                        case_id=case_id
                    )
                    records = [r.data() for r in res]
                    if records:
                        parts = [f"[{r['role']}] {str(r['summary'])[:200]}" for r in records]
                        dfkg_summary = ";\n".join(parts)
            except Exception as e:
                dfkg_summary = f"Error querying DFKG: {e}"

        # Inject DFKG summary explicitly, overriding the state array fallback
        finding, trace = _run_agent("supervisor", state, findings_summary=dfkg_summary)

        # Parse dynamic routing command
        content = finding.get("summary", "")
        # Fallback to default primary tier if the model didn't output a ROUTE line
        next_agents = ["evidence_collection", "log_analysis", "network_forensics"]
        
        # Test injection override
        raw_input = str(state.get("raw_input", ""))
        match = re.search(r"FORCE_SUPERVISOR_ROUTE:\s*(.+)", raw_input)
        if not match:
            match = re.search(r"ROUTE:\s*(.+)", content)
            
        if match:
            route_str = match.group(1).strip()
            if route_str == "wait":
                next_agents = []
            else:
                # Strip markdown (e.g., **, _) but keep valid alphanumeric agent names
                next_agents = [re.sub(r'[^a-zA-Z0-9_]', '', x.strip()) for x in route_str.split(",") if x.strip()]

        investigation_trace.record_event("supervisor", "supervisor_route", {"next_agents": next_agents})

        return {
            "case_status": "primary_tier",
            "findings": [finding],
            "agent_traces": [trace],
            "next_agents": next_agents,
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
    return supervisor_node


# --- 2–4. Primary tier (parallel) ---
# B1: evidence_collection_node is now a factory in evidence_collection_agent.py.
# The node function itself is wired into the graph by build_graph() via:
#   builder.add_node("evidence_collection", make_evidence_collection_node(redis, neo4j))
# Do NOT call evidence_collection_node directly from nodes.py.







# --- 7–10. Specialist tier (conditional, parallel-if-multiple) ---
# (Memory forensics moved to src/agents/memory_forensics_agent.py)


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


# --- 11/12/13. Proponent / Critic / Judge ---
# Replaced by factory functions in debate_agents.py (Phase H.4).
# Import make_proponent_node / make_critic_node / make_judge_node from there
# and wire them in build_graph() via the closure pattern.


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
    
    investigation_trace.record_event("hitl", "hitl_decision", {"decision": decision})

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
