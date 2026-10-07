import copy
import pytest

from src.agents.threat_attribution_factory import make_threat_attribution_node
from tests.agents.test_threat_attribution_agent import STATE, FakeGraph, FakeIntel


class Producer:
    def __init__(self, outcome):
        self.outcome = outcome
        self.callback = None

    def produce(self, **kwargs):
        if self.outcome == "enqueue_failure":
            raise RuntimeError("queue full")
        self.callback = kwargs["on_delivery"]

    def poll(self, timeout):
        if self.outcome == "acknowledged": self.callback(None, None)
        if self.outcome == "failed": self.callback("delivery failed", None)


@pytest.mark.parametrize("outcome,expected,flag", [
    ("acknowledged", "acknowledged", None),
    ("pending", "pending", "kafka_delivery_unconfirmed"),
    ("failed", "failed", "kafka_publication_failed"),
    ("enqueue_failure", "failed", "kafka_publication_failed"),
])
def test_delivery_status_distinguishes_queueing_and_acknowledgement(outcome, expected, flag):
    result = make_threat_attribution_node(FakeGraph(), Producer(outcome), FakeIntel())(STATE)
    assert result["agent_traces"][0]["kafka_publication"]["status"] == expected
    assert result["findings"][0]["kafka_publication"]["status"] == expected
    if flag: assert flag in result["attribution"]["degraded_flags"]


def test_late_failure_logs_without_mutating_returned_state(caplog):
    producer = Producer("pending")
    result = make_threat_attribution_node(FakeGraph(), producer, FakeIntel())(STATE)
    saved = copy.deepcopy(result)
    producer.callback("late broker failure", None)
    assert result == saved
    assert "late broker failure" in caplog.text


def test_missing_producer_is_reported(monkeypatch):
    monkeypatch.setattr("src.agents.threat_attribution_factory._get_producer", lambda: None)
    result = make_threat_attribution_node(FakeGraph(), None, FakeIntel())(STATE)
    assert result["agent_traces"][0]["kafka_publication"]["status"] == "unavailable"
    assert "kafka_unavailable" in result["attribution"]["degraded_flags"]
