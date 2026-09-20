"""LangGraph StateGraph assembly — §4 graph topology & conditional routing.

23 nodes, wired per the implementation plan's control-flow topology.
Uses Send for primary-tier and specialist fan-out, Command for debate
loop routing and guardrail/HITL branching.
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from .nodes import (
    case_closed_rejected_node,
    critic_node,
    final_output_join_node,
    guardrail_tier1_node,
    guardrail_tier2_node,
    guardrail_tier3_node,
    hitl_node,
    identity_cloud_node,
    insider_threat_node,
    judge_node,
    malware_stylometry_node,
    memory_forensics_node,
    network_forensics_node,
    make_primary_tier_join_node,  # D1: factory replaces the no-op node
    proponent_node,
    report_generation_node,
    specialist_join_node,
    supervisor_node,
    timeline_artifact_generation_node,
)
from .evidence_collection_agent import make_evidence_collection_node  # B1: factory
from .network_forensics_agent import make_network_forensics_node
from .log_analysis_agent import make_log_analysis_node
from .timeline_reconstruction_agent import make_timeline_reconstruction_node
from .threat_attribution_agent import make_threat_attribution_node # Phase G: factory
from .state import SpeculaState


# ===================================================================
# Routing functions for conditional edges
# ===================================================================

def _supervisor_primary_dispatch(state: dict) -> list[Send]:
    """§4: Supervisor -> fan-out to 3 primary agents via Send."""
    s = dict(state)
    return [
        Send("evidence_collection", s),
        Send("log_analysis", s),
        Send("network_forensics", s),
    ]


_SPECIALIST_MAP = {
    "memory":  "memory_forensics",
    "identity": "identity_cloud",
    "malware": "malware_stylometry",
    "insider": "insider_threat",
}


def _dead_end_route(state: dict) -> str | list[Send]:
    """§4: After primary-tier join, route based on dead-end signal.

    No dead-end -> skip directly to Timeline Reconstruction.
    Dead-end   -> conditional Send to relevant specialists.
    """
    if not state.get("dead_end_detected") or not state.get("dead_end_categories"):
        return "timeline_reconstruction"

    s = dict(state)
    sends = [
        Send(_SPECIALIST_MAP[cat], s)
        for cat in state["dead_end_categories"]
        if cat in _SPECIALIST_MAP
    ]
    return sends if sends else "timeline_reconstruction"


# ===================================================================
# Graph builder
# ===================================================================

def build_graph(*, checkpointer=None, redis_client=None, neo4j_driver=None):
    """Assemble and compile the full 23-node orchestration graph.

    Args:
        checkpointer:  LangGraph checkpointer instance. Required for HITL
                       interrupt/resume. Use InMemorySaver for tests,
                       Redis-backed for production (§5.3).
        redis_client:  redis.Redis instance for the dead-end heuristic and
                       evidence-collection scratchpad. None is safe for unit
                       tests — degrades gracefully (test_control injection
                       still works; real heuristic is skipped).
        neo4j_driver:  neo4j.Driver for DFKG queries from evidence_collection.
                       None is safe for tests — DFKG tool degrades to
                       NotYetImplementedTool with a clear observation message.
    """
    builder = StateGraph(SpeculaState)

    # ---- Add all 23 nodes ----

    # 16 ReAct-stub LLM agent nodes
    builder.add_node("supervisor", supervisor_node)
    # B1: evidence_collection gets the real ReAct loop; factory closes over infra clients
    builder.add_node("evidence_collection", make_evidence_collection_node(redis_client, neo4j_driver))
    builder.add_node("log_analysis", make_log_analysis_node(redis_client, neo4j_driver))
    builder.add_node("network_forensics", make_network_forensics_node(redis_client, neo4j_driver))
    builder.add_node("timeline_reconstruction", make_timeline_reconstruction_node(redis_client, neo4j_driver))
    builder.add_node("threat_attribution", make_threat_attribution_node(redis_client, neo4j_driver))
    builder.add_node("memory_forensics", memory_forensics_node)
    builder.add_node("identity_cloud", identity_cloud_node)
    builder.add_node("malware_stylometry", malware_stylometry_node)
    builder.add_node("insider_threat", insider_threat_node)
    builder.add_node("proponent", proponent_node)
    builder.add_node("critic", critic_node)
    builder.add_node("judge", judge_node)          # returns Command
    builder.add_node("guardrail_tier3", guardrail_tier3_node)  # returns Command
    builder.add_node("report_generation", report_generation_node)
    builder.add_node("timeline_artifact_generation", timeline_artifact_generation_node)

    # 2 non-LLM real nodes (return Command)
    builder.add_node("guardrail_tier1", guardrail_tier1_node)
    builder.add_node("guardrail_tier2", guardrail_tier2_node)

    # 1 real HTTP node (uses interrupt, returns Command)
    builder.add_node("hitl", hitl_node)

    # 4 control-only nodes
    # D1: primary_tier_join is now a factory node with real detect_dead_end logic
    builder.add_node("primary_tier_join", make_primary_tier_join_node(redis_client))
    builder.add_node("specialist_join", specialist_join_node)
    builder.add_node("final_output_join", final_output_join_node)
    builder.add_node("case_closed_rejected", case_closed_rejected_node)

    # ---- Wire edges ----

    # Stage 0: Entry
    builder.add_edge(START, "supervisor")

    # Supervisor -> primary tier fan-out (Send)
    builder.add_conditional_edges(
        "supervisor",
        _supervisor_primary_dispatch,
        ["evidence_collection", "log_analysis", "network_forensics"],
    )

    # Primary agents -> join
    builder.add_edge("evidence_collection", "primary_tier_join")
    builder.add_edge("log_analysis", "primary_tier_join")
    builder.add_edge("network_forensics", "primary_tier_join")

    # Primary-tier join -> dead-end check
    builder.add_conditional_edges(
        "primary_tier_join",
        _dead_end_route,
        [
            "timeline_reconstruction",
            "memory_forensics",
            "identity_cloud",
            "malware_stylometry",
            "insider_threat",
        ],
    )

    # Specialist agents -> join
    builder.add_edge("memory_forensics", "specialist_join")
    builder.add_edge("identity_cloud", "specialist_join")
    builder.add_edge("malware_stylometry", "specialist_join")
    builder.add_edge("insider_threat", "specialist_join")

    # Specialist join -> Timeline Reconstruction (both paths converge here)
    builder.add_edge("specialist_join", "timeline_reconstruction")

    # Sequential synthesis
    builder.add_edge("timeline_reconstruction", "threat_attribution")

    # Threat attribution -> debate subgraph entry
    builder.add_edge("threat_attribution", "proponent")

    # Debate loop (linear within a round)
    builder.add_edge("proponent", "critic")
    builder.add_edge("critic", "judge")
    # Judge routing via Command (no static edges from judge)
    # -> guardrail_tier1 (accept/early-exit)
    # -> proponent (reject, round < 3)
    # -> hitl (round-cap exhausted)

    # Guardrail chain: routing via Command (no static edges)
    # Tier 1 -> hitl | tier2
    # Tier 2 -> hitl | tier3
    # Tier 3 -> hitl | [report_generation, timeline_artifact_generation]

    # HITL routing via Command (no static edges)
    # -> [report_generation, timeline_artifact_generation] (approve + guardrail entry)
    # -> guardrail_tier1 (approve + debate entry)
    # -> case_closed_rejected (reject)
    # -> supervisor (clarify — only edge that re-enters top of graph)

    # Report Generation + Timeline Artifact Generation -> final join
    builder.add_edge("report_generation", "final_output_join")
    builder.add_edge("timeline_artifact_generation", "final_output_join")

    # Final join -> END
    builder.add_edge("final_output_join", END)

    # Case Closed Rejected -> END
    builder.add_edge("case_closed_rejected", END)

    # ---- Compile ----
    return builder.compile(checkpointer=checkpointer)
