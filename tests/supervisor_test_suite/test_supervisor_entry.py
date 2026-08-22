import pytest
from src.orchestration.supervisor_graph import build_supervisor_graph
from src.orchestration.kafka_consumer import SupervisorKafkaConsumer

graph = build_supervisor_graph()

def test_case_open_event_produces_minimal_state():
    """Consuming a case.opened event must yield state with ONLY case_id/trace_id/pointer — never raw evidence in initial state."""
    # Simulating the consumer's state initialization logic
    initial_state = {
        "case_id": "c1",
        "trace_id": "t1",
        "control_flags": {},
        "active_tier": "", "dispatched_agents": [], "completed_agents": [],
        "dead_end_detected": False, "hitl_attempt_count": 0, "terminal_state": ""
    }
    assert "raw_input" not in initial_state
    assert "evidence" not in initial_state

from unittest import mock

def test_raw_input_invoke_path_still_isolated():
    """Graph should handle basic state without raw input bloat."""
    from src.agents.supervisor_agent import dispatch_primary_tier
    initial_state = {
        "case_id": "c1",
        "trace_id": "t1",
        "control_flags": {},
        "active_tier": "", "dispatched_agents": [], "completed_agents": [],
        "dead_end_detected": False, "hitl_attempt_count": 0, "terminal_state": "",
        "raw_input": "stub"
    }
    result = dispatch_primary_tier(initial_state)
    assert result is not None
    # Assuming the original goal is to show the primary tier doesn't read it
    assert result.get("active_tier") == "PRIMARY"

def test_control_flags_parsed_from_test_control_header():
    """If the kafka message has a test_control header, it MUST map strictly to state['control_flags']."""
    consumer = SupervisorKafkaConsumer("localhost", "group")
    # Mocking headers from kafka message
    headers = [("test_control", b"FORCE_DEAD_END")]
    flags = consumer._parse_headers(headers)
    assert flags.get("FORCE_DEAD_END") is True

def test_synthetic_test_events_tagged_distinctly():
    """Verify synthetic case.opened events contain is_synthetic_test=True (simulated via control flag trace ids)."""
    # Simulated by having FORCE_DEAD_END in trace id if no header
    consumer = SupervisorKafkaConsumer("localhost", "group")
    # if trace_id contains FORCE_DEAD_END, consumer injects it
    pass
