"""
Unit tests for Cloud & Container Forensics Factory Node (TASK-4.10b).
"""
import pytest
from src.agents.cloud_container_factory import make_cloud_container_node


def test_factory_creates_callable_node():
    node = make_cloud_container_node()
    assert callable(node)


def test_factory_node_handles_empty_events():
    node = make_cloud_container_node(event_provider=lambda case_id: [])
    state = {"case_id": "case-test-empty"}
    result = node(state)

    assert "specialists_completed" in result
    assert "cloud_container" in result["specialists_completed"]
    assert "specialist_statuses" in result
    assert result["specialist_statuses"]["cloud_container"] == "no_events"
    assert len(result["findings"]) == 0
    assert len(result["agent_traces"]) == 1
    assert result["agent_traces"][0]["status"] == "no_events"


def test_factory_node_handles_findings():
    events = [
        {
            "case_id": "case-test-findings",
            "uid": "evt-fac-1",
            "class_uid": 6003,
            "api_service": "cloudtrail.amazonaws.com",
            "api_operation": "StopLogging",
            "cloud_account_id": "123456789012",
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    node = make_cloud_container_node(event_provider=lambda c: events)
    state = {"case_id": "case-test-findings"}
    result = node(state)

    assert result["specialist_statuses"]["cloud_container"] == "ok"
    assert "cloud_container" in result["specialists_completed"]
    assert len(result["findings"]) == 1
    assert result["findings"][0]["rule_id"] == "CLOUD-001"
    assert result["findings"][0]["severity"] == "CRITICAL"
