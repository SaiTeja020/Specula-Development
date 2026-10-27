"""FROZEN readiness gate wired into the skeleton graph (debate entry + mid-debate re-check).

Separate from tests/test_skeleton_graph.py on purpose: the 28 skeleton tests are unchanged
and still pass because the gate computes FROZEN from real state (all dispatched agents
returned + zero consumer lag) rather than needing a fixture to set it.
"""
from __future__ import annotations

import os

import pytest

os.environ["SPECULA_LLM_BACKEND"] = "stub"

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from src.agents.frozen import compute_case_state, dispatched_roles, set_lag_provider
from src.agents.graph import build_graph
from src.agents.nodes import debate_gate_node


@pytest.fixture(autouse=True)
def _reset_lag_provider():
    set_lag_provider(None)
    yield
    set_lag_provider(None)


@pytest.fixture
def graph():
    return build_graph(checkpointer=InMemorySaver())


def _input(raw="Suspicious activity on host WS-042", **overrides) -> dict:
    return {
        "case_id": "GATE-001", "trace_id": "trace-gate-001", "input_type": "siem_alert",
        "raw_input": raw, "case_status": "open", "findings": [], "agent_traces": [],
        "debate_round": 1, "debate_history": [], "specialists_completed": [],
        "dead_end_detected": False, "dead_end_categories": [], "consumer_lag": 0, **overrides,
    }


def _roles(values) -> list[str]:
    return [t["agent_role"] for t in values.get("agent_traces", [])]


def _finding(role): return {"agent_role": role, "summary": role}


ALL_REQUIRED = [_finding(r) for r in (
    "evidence_collection", "log_analysis", "network_forensics",
    "timeline_reconstruction", "threat_attribution", "dag",
)]


# ------------------------------------------------------------------ pure computation
class TestComputeCaseState:
    def test_frozen_when_all_returned_and_no_lag(self):
        assert compute_case_state({"findings": ALL_REQUIRED, "consumer_lag": 0}) == ("FROZEN", [])

    def test_open_when_primary_agent_missing(self):
        state, reasons = compute_case_state({"findings": ALL_REQUIRED[:2], "consumer_lag": 0})
        assert state == "OPEN" and "network_forensics" in reasons[0]

    def test_open_when_synthesis_agent_missing(self):
        state, reasons = compute_case_state({"findings": ALL_REQUIRED[:-1], "consumer_lag": 0})  # dag missing
        assert state == "OPEN" and "dag" in reasons[0]

    def test_open_when_dispatched_specialist_missing(self):
        s = {"findings": ALL_REQUIRED, "dead_end_detected": True, "dead_end_categories": ["memory", "identity"], "consumer_lag": 0}
        assert "memory_forensics" in dispatched_roles(s) and "identity" in dispatched_roles(s)
        state, reasons = compute_case_state(s)
        assert state == "OPEN" and "memory_forensics" in reasons[0]
        s["findings"] = ALL_REQUIRED + [_finding("memory_forensics"), _finding("identity")]
        assert compute_case_state(s)[0] == "FROZEN"

    def test_open_when_consumer_lag(self):
        state, reasons = compute_case_state({"findings": ALL_REQUIRED, "consumer_lag": 3})
        assert state == "OPEN" and "lag" in reasons[0]

    def test_broker_unreachable_fails_closed_as_open(self, monkeypatch):
        # Defect 1: unreachable Kafka returns None lag -> OPEN (fail closed)
        from src.agents.frozen import read_kafka_consumer_lag
        lag = read_kafka_consumer_lag(bootstrap_servers="127.0.0.1:1")
        assert lag is None
        state, reasons = compute_case_state({"findings": ALL_REQUIRED})  # default lag reads Kafka -> None
        assert state == "OPEN" and any("unknown" in r for r in reasons)

    def test_empty_topic_partitions_returns_none_not_zero(self, monkeypatch):
        import sys
        from unittest.mock import MagicMock
        from src.agents.frozen import read_kafka_consumer_lag
        kafka_mod = MagicMock()
        mock_consumer = MagicMock()
        mock_consumer.partitions_for_topic.return_value = None
        mock_admin = MagicMock()
        mock_admin.list_consumer_group_offsets.return_value = {}
        kafka_mod.KafkaAdminClient = lambda **kwargs: mock_admin
        kafka_mod.KafkaConsumer = lambda **kwargs: mock_consumer
        monkeypatch.setitem(sys.modules, "kafka", kafka_mod)
        lag = read_kafka_consumer_lag(bootstrap_servers="mock:9092")
        assert lag is None

    def test_case_with_no_vuln_data_freezes_without_dag(self):
        # Defect 9: cases without vulnerability scan data do not require DAG
        findings_no_dag = ALL_REQUIRED[:-1]  # all primary + timeline + attribution (no DAG)
        s = {"findings": findings_no_dag, "vuln_data_present": False, "consumer_lag": 0}
        assert compute_case_state(s) == ("FROZEN", [])

    def test_finding_with_error_status_does_not_satisfy_gate(self):
        # Defect 10: timed-out or error finding does not count as returned
        bad_dag = {"agent_role": "dag", "status": "error", "summary": "timeout"}
        findings = ALL_REQUIRED[:-1] + [bad_dag]
        s = {"findings": findings, "consumer_lag": 0}
        state, reasons = compute_case_state(s)
        assert state == "OPEN" and any("dag" in r for r in reasons)

    def test_transient_lag_retries_and_clears(self):
        # 1 lag call on entry, then clears on retry inside debate_gate_node
        set_lag_provider(_scripted_lag([2, 0]))
        ok = debate_gate_node({"findings": ALL_REQUIRED})
        assert ok.goto == "proponent" and ok.update["case_state"] == "FROZEN"

    def test_gate_node_routes(self):
        ok = debate_gate_node({"findings": ALL_REQUIRED, "consumer_lag": 0})
        assert ok.goto == "proponent" and ok.update["case_state"] == "FROZEN"
        blocked = debate_gate_node({"findings": ALL_REQUIRED[:1], "consumer_lag": 0})
        assert blocked.goto == "hitl" and blocked.update["hitl_entry_reason"] == "gate_blocked"
        assert blocked.update["case_state"] == "OPEN"


# ------------------------------------------------------------------ graph wiring
class TestGateWiring:
    def test_gate_is_a_real_node_between_dag_and_proponent(self, graph):
        edges = {(e.source, e.target) for e in graph.get_graph().edges}
        assert ("dag", "debate_gate") in edges
        assert ("dag", "proponent") not in edges          # no bypass
        assert "debate_gate" in graph.get_graph().nodes

    def test_normal_path_is_frozen_and_debates(self, graph):
        result = graph.invoke(_input(), {"configurable": {"thread_id": "gate-ok"}})
        assert result["case_state"] == "FROZEN" and result["case_status"] == "closed"
        roles = _roles(result)
        assert "proponent" in roles and roles.index("dag") < roles.index("proponent")

    def test_dead_end_path_is_frozen_after_specialists_return(self, graph):
        result = graph.invoke(_input("Alert DEAD_END:memory,identity on host"),
                              {"configurable": {"thread_id": "gate-deadend"}})
        assert result["case_state"] == "FROZEN" and result["case_status"] == "closed"

    def test_gate_blocked_by_lag_never_debates_and_goes_to_hitl(self, graph):
        cfg = {"configurable": {"thread_id": "gate-blocked"}}
        graph.invoke(_input(consumer_lag=2), cfg)
        st = graph.get_state(cfg)
        assert st.next == ("hitl",), "expected a pause at HITL"
        v = st.values
        assert v["case_state"] == "OPEN" and v["hitl_entry_reason"] == "gate_blocked"
        assert any("lag" in r for r in v["gate_block_reasons"])
        assert not {"proponent", "critic", "judge"} & set(_roles(v))     # nothing ran on a partial graph

    def test_hitl_approve_does_not_bypass_a_closed_gate(self, graph):
        cfg = {"configurable": {"thread_id": "gate-approve-blocked"}}
        graph.invoke(_input(consumer_lag=2), cfg)
        graph.invoke(Command(resume="approve"), cfg)
        st = graph.get_state(cfg)
        assert st.next == ("hitl",)                                        # blocked again, not debating
        assert not {"proponent", "critic", "judge"} & set(_roles(st.values))

    def test_hitl_approve_after_lag_clears_runs_the_debate(self, graph):
        set_lag_provider(_scripted_lag([2, 2, 2, 2, 2, 0]))               # blocked on first pass + retries, then caught up
        cfg = {"configurable": {"thread_id": "gate-approve-cleared"}}
        graph.invoke(_input(), cfg)
        assert graph.get_state(cfg).next == ("hitl",)
        result = graph.invoke(Command(resume="approve"), cfg)
        assert result["case_state"] == "FROZEN" and result["case_status"] == "closed"
        assert "proponent" in _roles(result) and result["hitl_entry_reason"] is None

    def test_hitl_reject_after_gate_block_closes_case(self, graph):
        cfg = {"configurable": {"thread_id": "gate-reject"}}
        graph.invoke(_input(consumer_lag=2), cfg)
        result = graph.invoke(Command(resume="reject"), cfg)
        assert result["case_status"] == "closed" and result.get("report_output") is None


# ------------------------------------------------------------------ late write mid-debate
def _scripted_lag(script):
    """Provider returning scripted lag values in call order (last value repeats)."""
    it = iter(script)
    last = {"v": 0}

    def provider(state):
        last["v"] = next(it, last["v"])
        return last["v"]
    return provider


class TestLateWriteMidDebate:
    def test_late_write_aborts_debate_then_restarts_and_converges(self, graph):
        # call 1 = gate (0), call 2 = judge round 1 (1 -> reopened), call 3 = gate again (0), then 0
        set_lag_provider(_scripted_lag([0, 1, 0, 0]))
        cfg = {"configurable": {"thread_id": "late-write-restart"}}
        result = graph.invoke(_input(), cfg)
        roles = _roles(result)
        assert roles.count("proponent") == 2 and roles.count("critic") == 2 and roles.count("judge") == 2
        assert result["debate_restarts"] == 1
        assert result["case_state"] == "FROZEN" and result["case_status"] == "closed"
        # the voided round contributed no verdict to the closed-round history
        assert len(result["debate_history"]) == 1 and result["debate_outcome"] == "converged"
        assert result["debate_round"] == 1                                   # restarted at round 1

    def test_late_write_that_persists_ends_in_hitl_not_a_verdict(self, graph):
        set_lag_provider(_scripted_lag([0, 1]))                              # gate ok, then lag forever
        cfg = {"configurable": {"thread_id": "late-write-persist"}}
        graph.invoke(_input(), cfg)
        st = graph.get_state(cfg)
        assert st.next == ("hitl",)
        v = st.values
        assert v["hitl_entry_reason"] == "gate_blocked" and v["case_state"] == "OPEN"
        assert _roles(v).count("proponent") == 1 and v.get("guardrail_tier1_result") is None
        assert v.get("debate_outcome") is None                               # never accepted

    def test_restart_budget_is_bounded(self, graph):
        # gate passes every time, judge always sees a reopened case: 3 debates then HITL.
        set_lag_provider(_scripted_lag([0, 1] * 3))
        cfg = {"configurable": {"thread_id": "late-write-bounded"}}
        graph.invoke(_input(), cfg)
        st = graph.get_state(cfg)
        assert st.next == ("hitl",)
        assert _roles(st.values).count("proponent") == 3
        assert st.values["debate_restarts"] == 3 and st.values["hitl_entry_reason"] == "gate_blocked"
        assert st.values.get("guardrail_tier1_result") is None
