from langgraph.graph import StateGraph, START, END
from src.agents.supervisor_agent import (
    SupervisorState,
    dispatch_primary_tier,
    evaluate_dead_end,
    dispatch_specialist_tier,
    dispatch_synthesis,
    handoff_to_debate,
    hitl_feedback_loop
)

def _dead_end_router(state: SupervisorState):
    if state.get("dead_end_detected"):
        return "dispatch_specialist_tier"
    return "dispatch_synthesis"

def _hitl_router(state: SupervisorState):
    if state.get("terminal_state") in ["MANUAL_OVERRIDE_REQUIRED", "RESOLVED"]:
        return END
    return "dispatch_synthesis"

def _debate_router(state: SupervisorState):
    if state.get("active_tier") == "HITL":
        return "hitl_feedback_loop"
    return END

def build_supervisor_graph():
    builder = StateGraph(SupervisorState)
    
    # Add nodes
    builder.add_node("dispatch_primary_tier", dispatch_primary_tier)
    builder.add_node("evaluate_dead_end", evaluate_dead_end)
    builder.add_node("dispatch_specialist_tier", dispatch_specialist_tier)
    builder.add_node("dispatch_synthesis", dispatch_synthesis)
    builder.add_node("handoff_to_debate", handoff_to_debate)
    builder.add_node("hitl_feedback_loop", hitl_feedback_loop)
    
    # Edges
    builder.add_edge(START, "dispatch_primary_tier")
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
            "dispatch_synthesis": "dispatch_synthesis"
        }
    )
    
    return builder.compile()
