"""
Tests for finding_builder.py — Implementation Plan §9 test 1.

Covers:
  - dfkg_refs=[] → ValueError
  - Valid input → output dict has exactly the required key set (item #19)
  - Invalid severity (e.g. "critical") → ValueError
  - config.CONSUMED_CLASS_UIDS == {1007, 1001} matches frozen class_uid
    defaults on ProcessActivityEvent / FileActivityEvent (belt-and-braces
    assertion, not just trusting the constant independently)
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from src.agents.log_analysis import config
from src.agents.log_analysis.finding_builder import build_finding, get_required_keys
from src.schemas.ocsf_phase2_events import FileActivityEvent, ProcessActivityEvent


# ─── Fixtures ────────────────────────────────────────────────────────────────


def _make_process_event(**overrides) -> ProcessActivityEvent:
    """Minimal valid ProcessActivityEvent for testing."""
    base = dict(
        trace_id="trace-test-001",
        activity_id=1,
        class_uid=1007,
        category_uid=1,
        severity_id=3,
        time=datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc),
        raw_source_timestamp="2026-08-22T10:00:00Z",
        uid="uid-process-abc123",
        process_name="cmd.exe",
        process_pid=1234,
    )
    base.update(overrides)
    return ProcessActivityEvent(**base)


def _make_file_event(**overrides) -> FileActivityEvent:
    """Minimal valid FileActivityEvent for testing."""
    base = dict(
        trace_id="trace-test-002",
        activity_id=1,
        class_uid=1001,
        category_uid=1,
        severity_id=2,
        time=datetime(2026, 8, 22, 11, 0, 0, tzinfo=timezone.utc),
        raw_source_timestamp="2026-08-22T11:00:00Z",
        uid="uid-file-def456",
    )
    base.update(overrides)
    return FileActivityEvent(**base)


def _valid_kwargs(source_event=None) -> dict:
    """Return a complete set of valid build_finding kwargs."""
    if source_event is None:
        source_event = _make_process_event()
    return dict(
        source_event=source_event,
        agent_role=config.AGENT_ROLE,
        summary="Suspicious parent process detected.",
        severity="high",
        pattern="unusual_parent_process",
        affected_count=1,
        timeline_range=("2026-08-22T10:00:00+00:00", "2026-08-22T10:05:00+00:00"),
        dfkg_refs=["dfkg-node-uid-001"],
        kafka_offset=42,
        confidence=0.9,
    )


# ─── Test 1a: empty dfkg_refs raises ValueError (item #20) ───────────────────


def test_empty_dfkg_refs_raises():
    kwargs = _valid_kwargs()
    kwargs["dfkg_refs"] = []
    with pytest.raises(ValueError, match="dfkg_refs must be non-empty"):
        build_finding(**kwargs)


# ─── Test 1b: valid input → exact required key set (item #19) ────────────────


def test_valid_finding_has_exact_keys():
    finding = build_finding(**_valid_kwargs())
    required = get_required_keys()
    # Output must contain at minimum all required keys.
    for key in required:
        assert key in finding, f"Missing required key: {key!r}"
    # Confidence is attached as a bonus key — that's acceptable.
    # But no unexpected keys beyond the known bonus "confidence" key.
    extra_keys = set(finding.keys()) - required - {"confidence"}
    assert not extra_keys, f"Unexpected extra keys in finding: {extra_keys}"


def test_valid_finding_values():
    evt = _make_process_event()
    finding = build_finding(
        source_event=evt,
        agent_role=config.AGENT_ROLE,
        summary="Test summary.",
        severity="medium",
        pattern="brute_force",
        affected_count=3,
        timeline_range=("2026-08-22T10:00:00+00:00", "2026-08-22T10:15:00+00:00"),
        dfkg_refs=["uid-a", "uid-b"],
        kafka_offset=7,
        confidence=0.85,
    )
    assert finding["agent_role"] == config.AGENT_ROLE
    assert finding["severity"] == "medium"
    assert finding["pattern"] == "brute_force"
    assert finding["affected_count"] == 3
    assert finding["dfkg_refs"] == ["uid-a", "uid-b"]
    assert finding["kafka_offset"] == 7
    assert finding["confidence"] == 0.85
    # timestamp derives from source_event.time
    assert "2026-08-22" in finding["timestamp"]


# ─── Test 1c: invalid severity raises ValueError (item #21) ──────────────────


@pytest.mark.parametrize("bad_severity", ["critical", "CRITICAL", "info", "fatal", "", "LOW"])
def test_invalid_severity_raises(bad_severity):
    kwargs = _valid_kwargs()
    kwargs["severity"] = bad_severity
    with pytest.raises(ValueError, match="Invalid severity"):
        build_finding(**kwargs)


def test_valid_severities_do_not_raise():
    for sev in config.SEVERITY_LEVELS:
        kwargs = _valid_kwargs()
        kwargs["severity"] = sev
        result = build_finding(**kwargs)
        assert result["severity"] == sev


# ─── Test 1d: CONSUMED_CLASS_UIDS matches frozen class_uid defaults ───────────
# Belt-and-braces — assert equality in a test rather than hardcoding twice.


def test_consumed_class_uids_match_frozen_defaults():
    """
    config.CONSUMED_CLASS_UIDS must exactly match the frozen class_uid values
    on ProcessActivityEvent and FileActivityEvent, as specified in item #3
    of the resolved-decisions memo.
    """
    process_uid = ProcessActivityEvent.model_fields["class_uid"].default
    file_uid = FileActivityEvent.model_fields["class_uid"].default

    assert process_uid in config.CONSUMED_CLASS_UIDS, (
        f"ProcessActivityEvent.class_uid={process_uid} not in "
        f"CONSUMED_CLASS_UIDS={config.CONSUMED_CLASS_UIDS}"
    )
    assert file_uid in config.CONSUMED_CLASS_UIDS, (
        f"FileActivityEvent.class_uid={file_uid} not in "
        f"CONSUMED_CLASS_UIDS={config.CONSUMED_CLASS_UIDS}"
    )
    assert config.CONSUMED_CLASS_UIDS == frozenset({process_uid, file_uid}), (
        "CONSUMED_CLASS_UIDS contains UIDs not present on "
        "ProcessActivityEvent/FileActivityEvent — possible stale constant."
    )


# ─── Test 1e: bad timeline_range type raises TypeError ────────────────────────


@pytest.mark.parametrize("bad_range", [
    ("only_one",),          # 1-tuple
    ("a", "b", "c"),        # 3-tuple
    "2026-08-22T10:00:00",  # bare string
    [1, 2],                 # ints instead of strings
    None,
])
def test_invalid_timeline_range_raises(bad_range):
    kwargs = _valid_kwargs()
    kwargs["timeline_range"] = bad_range
    with pytest.raises((TypeError, ValueError)):
        build_finding(**kwargs)
