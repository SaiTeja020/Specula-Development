from langgraph.graph import StateGraph, START, END
from src.agents.supervisor_agent import (
    SupervisorState,
    dispatch_primary_tier,
    evaluate_dead_end,
    dispatch_specialist_tier,
    dispatch_synthesis,
    handoff_to_debate,
    hitl_feedback_loop,
    route_nl_query
)

def _start_router(state: SupervisorState):
    if state.get("nl_query"):
        return "route_nl_query"
    return "dispatch_primary_tier"


def _dead_end_router(state: SupervisorState):
    if state.get("dead_end_detected"):
        return "dispatch_specialist_tier"
    return "dispatch_synthesis"

def _hitl_router(state: SupervisorState):
    """Routes after human-in-the-loop feedback.

    BUG-3 FIX: The previous fallback returned 'dispatch_synthesis', which caused an immediate
    NotReadyError crash because dispatched_agents contained debate agents while completed_agents
    was empty. The correct retry target is handoff_to_debate — re-enter the debate with the
    human's updated context until either APPROVE or MANUAL_OVERRIDE_REQUIRED is reached.
    """
    if state.get("terminal_state") in ["MANUAL_OVERRIDE_REQUIRED", "RESOLVED"]:
        return END
    return "handoff_to_debate"

def _debate_router(state: SupervisorState):
    if state.get("active_tier") == "HITL":
        return "hitl_feedback_loop"
    return END

def build_supervisor_graph():
    builder = StateGraph(SupervisorState)
    
    # Add nodes
    builder.add_node("dispatch_primary_tier", dispatch_primary_tier)
    builder.add_node("route_nl_query", route_nl_query)
    builder.add_node("evaluate_dead_end", evaluate_dead_end)
    builder.add_node("dispatch_specialist_tier", dispatch_specialist_tier)
    builder.add_node("dispatch_synthesis", dispatch_synthesis)
    builder.add_node("handoff_to_debate", handoff_to_debate)
    builder.add_node("hitl_feedback_loop", hitl_feedback_loop)
    
    # Edges
    builder.add_conditional_edges(
        START,
        _start_router,
        {
            "route_nl_query": "route_nl_query",
            "dispatch_primary_tier": "dispatch_primary_tier"
        }
    )
    
    builder.add_edge("route_nl_query", "dispatch_synthesis")
    builder.add_edge("dispatch_primary_tier", "evaluate_dead_end")

    
    builder.add_conditional_edges(
        "evaluate_dead_end",
        _dead_end_router,
        {
            "dispatch_specialist_tier": "dispatch_specialist_tier",
            "dispatch_synthesis": "dispatch_synthesis"
        }
    )
    
    builder.add_edge("dispatch_specialist_tier", "dispatch_synthesis")
    builder.add_edge("dispatch_synthesis", "handoff_to_debate")
    
    builder.add_conditional_edges(
        "handoff_to_debate",
        _debate_router,
        {
            "hitl_feedback_loop": "hitl_feedback_loop",
            END: END
        }
    )
    
    builder.add_conditional_edges(
        "hitl_feedback_loop",
        _hitl_router,
        {
            END: END,
            "handoff_to_debate": "handoff_to_debate"  # BUG-3 FIX: retry via debate, not synthesis
        }
    )
    
    return builder.compile()
