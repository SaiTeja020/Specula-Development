import pytest
from src.agents.supervisor_agent import route_nl_query

def test_nl_routing_network_forensics():
    state = {"nl_query": "Did the attacker use lateral movement to access other machines?"}
    new_state = route_nl_query(state)
    assert new_state["query_routing_decision"] == "network_forensics"
    assert new_state["active_tier"] == "SPECIALIST"
    assert new_state["dispatched_agents"] == ["network_forensics"]
    assert new_state["completed_agents"] == ["network_forensics"]

def test_nl_routing_memory_forensics():
    state = {"nl_query": "Show me the process memory for any suspicious payloads."}
    new_state = route_nl_query(state)
    assert new_state["query_routing_decision"] == "memory_forensics"

def test_nl_routing_default_log_analysis():
    state = {"nl_query": "What happened?"}
    new_state = route_nl_query(state)
    assert new_state["query_routing_decision"] == "log_analysis"
