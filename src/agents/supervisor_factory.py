"""Factory for Supervisor Node."""
import logging
from src.agents.supervisor_agent import route_nl_query, SupervisorState
from src.agents.nodes import _run_agent

logger = logging.getLogger(__name__)

def make_supervisor_node():
    def supervisor_node(state: dict) -> dict:
        # Standard ReAct stub as fallback/baseline
        finding, trace = _run_agent("supervisor", state)
        
        # Restore legacy test injection for test_skeleton_graph.py
        raw_input = state.get("raw_input", "")
        test_control = state.get("test_control", {})
        if "DEAD_END:" in raw_input:
            import re
            match = re.search(r"DEAD_END:([a-z,_]+)", raw_input)
            if match:
                test_control = dict(test_control)
                test_control["dead_end_categories"] = match.group(1).split(",")
                # The primary_tier_join_node expects it to be in the state dict returned
                # but we can't return it directly unless we add it to the update_dict
        
        # Build SupervisorState to use its internal logic
        sup_state = SupervisorState(
            case_id=state.get("case_id", ""),
            trace_id=state.get("trace_id", ""),
            control_flags=test_control,
            active_tier="PRIMARY",
            dispatched_agents=[],
            completed_agents=[],
            dead_end_detected=False,
            hitl_attempt_count=0,
            terminal_state="",
            nl_query=state.get("raw_input") if state.get("input_type") == "investigator_query" else None,
            query_routing_decision=None,
            degraded_capability_mode=None
        )
        
        # If there's an NL query, try to route it
        if sup_state["nl_query"]:
            try:
                sup_state = route_nl_query(sup_state)
            except Exception as e:
                logger.error(f"Failed to route NL query: {e}")
                
        # Merge back into SpeculaState
        update_dict = {
            "case_status": "primary_tier" if sup_state["active_tier"] == "PRIMARY" else "specialist_tier",
            "findings": [finding],
            "agent_traces": [trace],
            # Pass along any routing decision
            "specialists_dispatched": sup_state["dispatched_agents"] if sup_state["active_tier"] == "SPECIALIST" else [],
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
        
        # If an NL query bypassed the primary tier, we should save that so dispatch can use it.
        # We can add 'supervisor_routing_decision' to state if needed.
        if sup_state.get("query_routing_decision"):
            update_dict["supervisor_routing_decision"] = sup_state["query_routing_decision"]
            
        if test_control:
            update_dict["test_control"] = test_control
            
        return update_dict

    return supervisor_node
