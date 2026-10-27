"""Factory for Supervisor Node."""
import logging
from src.agents.supervisor_agent import route_nl_query, SupervisorState
from src.agents.nodes import _run_agent

logger = logging.getLogger(__name__)

def make_supervisor_node(neo4j_driver=None):
    def supervisor_node(state: dict) -> dict:
        # Standard ReAct stub as fallback/baseline
        if neo4j_driver is not None:
            from .case_analysis import observation, review
            rows, _, _ = neo4j_driver.execute_query(
                "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(e:Event) RETURN e ORDER BY e.uid", case_id=state["case_id"])
            from collections import defaultdict
            groups=defaultdict(list)
            for row in rows:
                event=dict(row['e']);groups[(event.get('canonical_host_id'),event.get('source_type'),event.get('class_uid'))].append(event)
            facts=[{'summary':f'Source cohort: host={host}; source={source}; OCSF class={kind}; {len(events)} preserved records. '
                    'Mandatory workers follow source types; this count is not a malicious verdict.',
                    'canonical_host_id':host,'dfkg_refs':[e['uid'] for e in events]}
                   for (host,source,kind),events in groups.items()]
            trace = review("supervisor", state, facts)
            trace['review_unit']='source_host_class_cohort'
            trace['preserved_event_count']=len(rows)
            from .investigative_review import plan
            investigation_plan=plan({**state,'evidence_collection':{'records':[dict(row['e']) for row in rows]}})
            trace['investigation_plan']=investigation_plan
            finding = {"agent_role": "supervisor", "summary": f"Primary agents dispatched for {len(rows)} case events in {len(facts)} source cohorts; specialist routing follows actual evidence after collection.",
                       "dfkg_refs": [], "timestamp": trace["timestamp"], "kafka_offset": None}
        else:
            if state.get('evidence_review_required'):
                raise RuntimeError('Supervisor requires preserved case evidence for its work plan')
            finding, trace = _run_agent("supervisor", state)
            investigation_plan=None
        
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
            "followup_cycle": state.get('followup_cycle', 0) if state.get('followup_reanalysis_pending') else state.get('followup_cycle', 0)+1,
            "followup_round": state.get('followup_round',0) if state.get('followup_reanalysis_pending') else 0,
            "followup_reanalysis_pending": False,
            "acquisition_reanalysis_count": state.get('acquisition_reanalysis_count',0) if state.get('followup_reanalysis_pending') else 0,
            "followup_pending": [],
            "followup_status": None,
            "evidence_requests": [],
            "investigation_plan": investigation_plan,
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
            "proponent_review": None, "critic_review": None, "judge_review": None,
            "review_status": None,
            "debate_feedback": None,
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
