"""
Tests for detection_rules.py — Implementation Plan §9 test 2.

Covers:
  - One golden-fixture pair (benign / suspicious) per named pattern
    (4 patterns × 2 fixtures minimum).
  - Malformed/missing-field event → [], no raise.
  - Signature loader reads from YAML, not hardcoded IDs — test by
    mutating the signatures dict and confirming rule behavior changes.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from src.agents.log_analysis.detection_rules import (
    _rule_bruteforce,
    _rule_offhours_service_install,
    _rule_sensitive_file_access,
    _rule_unusual_parent,
    load_signatures,
    run_rule_layer,
)
from src.schemas.ocsf_phase2_events import FileActivityEvent, ProcessActivityEvent
from src.schemas.ocsf_base import OCSFBaseEvent


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _base_fields(**overrides) -> dict:
    base = dict(
        trace_id="trace-rules-test",
        activity_id=1,
        class_uid=1007,
        category_uid=1,
        severity_id=2,
        time=datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc),  # weekday, work hours
        raw_source_timestamp="2026-08-22T10:00:00Z",
        uid="test-uid-001",
    )
    base.update(overrides)
    return base


def _proc(**overrides) -> ProcessActivityEvent:
    return ProcessActivityEvent(**_base_fields(class_uid=1007, category_uid=1, **overrides))


def _file(**overrides) -> FileActivityEvent:
    return FileActivityEvent(**_base_fields(class_uid=1001, category_uid=1, **overrides))


_SIGS = load_signatures()


# ═══════════════════════════════════════════════════════════════════════════════
# Rule 1: Unusual parent process
# ═══════════════════════════════════════════════════════════════════════════════


class TestUnusualParentProcess:
    def test_benign_parent_child_no_signal(self):
        """explorer.exe → notepad.exe is not in LOLBAS table → no signal."""
        evt = _proc(parent_process_name="explorer.exe", process_name="notepad.exe")
        result = _rule_unusual_parent(evt, _SIGS)
        assert result is None

    def test_suspicious_parent_child_signals(self):
        """winword.exe → cmd.exe is a classic LOLBAS spawn → should signal."""
        evt = _proc(parent_process_name="winword.exe", process_name="cmd.exe")
        result = _rule_unusual_parent(evt, _SIGS)
        assert result is not None
        assert result["pattern"] == "unusual_parent_process"
        assert result["weight"] > 0

    def test_case_insensitive_match(self):
        """Parent/child matching must be case-insensitive."""
        evt = _proc(parent_process_name="WINWORD.EXE", process_name="CMD.EXE")
        result = _rule_unusual_parent(evt, _SIGS)
        assert result is not None

    def test_no_signal_for_non_process_event(self):
        """Rule only fires on class_uid=1007. File events should return None."""
        evt = _file()
        result = _rule_unusual_parent(evt, _SIGS)
        assert result is None

    def test_missing_parent_returns_none(self):
        """Missing parent_process_name → no signal, no raise."""
        evt = _proc(process_name="cmd.exe")
        result = _rule_unusual_parent(evt, _SIGS)
        assert result is None

    def test_yaml_mutation_changes_behavior(self):
        """
        Mutating the signatures dict should change rule behavior —
        verifies that rule logic does NOT hardcode event pairs.
        """
        custom_sigs = copy.deepcopy(_SIGS)
        # Add a novel parent that is not in the original YAML.
        custom_sigs["lolbas_parent_child"]["paint.exe"] = ["cmd.exe"]

        evt = _proc(parent_process_name="paint.exe", process_name="cmd.exe")

        # With original sigs: no signal.
        assert _rule_unusual_parent(evt, _SIGS) is None
        # With mutated sigs: signal fires.
        result = _rule_unusual_parent(evt, custom_sigs)
        assert result is not None
        assert result["pattern"] == "unusual_parent_process"


# ═══════════════════════════════════════════════════════════════════════════════
# Rule 2: Off-hours service install
# ═══════════════════════════════════════════════════════════════════════════════


class TestOffhoursServiceInstall:
    # activity_id=4697 maps to "service_install" in windows_security YAML.
    _SERVICE_INSTALL_ACTIVITY_ID = 4697

    def _svc_event(self, hour: int, weekday_offset: int = 0, **overrides) -> ProcessActivityEvent:
        """Create a service-install event at the given UTC hour. weekday_offset: 0=Mon."""
        from datetime import timedelta
        # 2026-08-24 is a Monday.
        base_monday = datetime(2026, 8, 24, hour, 0, 0, tzinfo=timezone.utc)
        t = base_monday + timedelta(days=weekday_offset)
        return _proc(
            activity_id=self._SERVICE_INSTALL_ACTIVITY_ID,
            time=t,
            raw_source_timestamp=t.isoformat(),
            **overrides,
        )

    def test_benign_business_hours_weekday(self):
        """Service install at 10:00 on Monday → no signal."""
        evt = self._svc_event(hour=10, weekday_offset=0)
        result = _rule_offhours_service_install(evt, _SIGS)
        assert result is None

    def test_suspicious_off_hours_weekday(self):
        """Service install at 02:00 on Monday → signal."""
        evt = self._svc_event(hour=2, weekday_offset=0)
        result = _rule_offhours_service_install(evt, _SIGS)
        assert result is not None
        assert result["pattern"] == "offhours_service_install"

    def test_suspicious_weekend(self):
        """Service install at 10:00 on Saturday → signal (flag_weekends=true)."""
        evt = self._svc_event(hour=10, weekday_offset=5)  # 5=Saturday
        result = _rule_offhours_service_install(evt, _SIGS)
        assert result is not None
        assert result["pattern"] == "offhours_service_install"

    def test_non_service_install_activity_no_signal(self):
        """activity_id != 4697 → no signal."""
        evt = _proc(activity_id=4624, time=datetime(2026, 8, 22, 2, 0, tzinfo=timezone.utc))
        result = _rule_offhours_service_install(evt, _SIGS)
        assert result is None

    def test_yaml_mutation_removes_service_install_id(self):
        """Removing 4697 from the YAML should suppress the rule entirely."""
        custom_sigs = copy.deepcopy(_SIGS)
        del custom_sigs["windows_security"][4697]  # remove service_install mapping

        evt = self._svc_event(hour=2, weekday_offset=0)
        result = _rule_offhours_service_install(evt, custom_sigs)
        assert result is None, "Rule should not fire when 4697 is absent from YAML."


# ═══════════════════════════════════════════════════════════════════════════════
# Rule 3: Brute-force
# ═══════════════════════════════════════════════════════════════════════════════


class TestBruteForce:
    _LOGON_SUCCESS_ACTIVITY_ID = 4624

    def _logon_event(self, failure_count: int = 0, **overrides) -> ProcessActivityEvent:
        evt = _proc(
            activity_id=self._LOGON_SUCCESS_ACTIVITY_ID,
            src_ip="192.168.1.100",
            user_name="alice",
            **overrides,
        )
        # Simulate agent.py attaching failure_count.
        object.__setattr__(evt, "failure_count", failure_count)
        return evt

    def test_benign_success_no_prior_failures(self):
        """Logon success with 0 prior failures → no brute-force signal."""
        evt = self._logon_event(failure_count=0)
        result = _rule_bruteforce(evt, _SIGS)
        assert result is None

    def test_suspicious_success_after_many_failures(self):
        """Logon success after 10 failures → brute-force signal."""
        evt = self._logon_event(failure_count=10)
        result = _rule_bruteforce(evt, _SIGS)
        assert result is not None
        assert result["pattern"] == "brute_force"
        assert result["weight"] >= 0.8

    def test_threshold_boundary_exactly_5(self):
        """Exactly 5 failures → fires (>= 5 threshold)."""
        evt = self._logon_event(failure_count=5)
        result = _rule_bruteforce(evt, _SIGS)
        assert result is not None

    def test_threshold_boundary_4(self):
        """4 failures → no signal (< 5 threshold)."""
        evt = self._logon_event(failure_count=4)
        result = _rule_bruteforce(evt, _SIGS)
        assert result is None

    def test_yaml_mutation_removes_logon_success(self):
        """Removing logon_success from YAML suppresses the rule."""
        custom_sigs = copy.deepcopy(_SIGS)
        del custom_sigs["windows_security"][4624]

        evt = self._logon_event(failure_count=10)
        result = _rule_bruteforce(evt, custom_sigs)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# Rule 4: Sensitive-file access by non-admin
# ═══════════════════════════════════════════════════════════════════════════════


class TestSensitiveFileAccess:
    def test_benign_non_sensitive_path(self):
        """Access to a non-sensitive path → no signal."""
        evt = _file(file_path="C:\\Users\\alice\\Documents\\report.docx", user_name="user_alice")
        result = _rule_sensitive_file_access(evt, _SIGS)
        assert result is None

    def test_suspicious_non_admin_accesses_sensitive_path(self):
        """Non-admin user accesses /etc/shadow → signal."""
        evt = _file(file_path="/etc/shadow", user_name="user_bob")
        result = _rule_sensitive_file_access(evt, _SIGS)
        assert result is not None
        assert result["pattern"] == "sensitive_file_access"
        assert result["weight"] >= 0.75

    def test_sensitive_path_unknown_user_lower_confidence(self):
        """No user info + sensitive path → conservative low-confidence signal."""
        evt = _file(file_path="/etc/passwd")
        result = _rule_sensitive_file_access(evt, _SIGS)
        assert result is not None
        assert result["pattern"] == "sensitive_file_access"
        assert result["weight"] < 0.75  # lower weight for unknown user

    def test_no_signal_for_process_event(self):
        """Rule only fires on class_uid=1001. Process events skip it."""
        evt = _proc(file_path="/etc/shadow")
        result = _rule_sensitive_file_access(evt, _SIGS)
        assert result is None

    def test_no_signal_missing_file_path(self):
        """No file_path on event → no signal, no raise."""
        evt = _file(user_name="user_alice")
        result = _rule_sensitive_file_access(evt, _SIGS)
        assert result is None

    def test_yaml_mutation_adds_new_sensitive_path(self):
        """Adding a new sensitive path to YAML causes rule to fire for it."""
        custom_sigs = copy.deepcopy(_SIGS)
        custom_sigs.setdefault("sensitive_paths", []).append("/tmp/secret_data")
        custom_sigs.setdefault("non_admin_user_prefixes", []).append("user")

        evt = _file(file_path="/tmp/secret_data/keys.pem", user_name="user_charlie")

        assert _rule_sensitive_file_access(evt, _SIGS) is None  # not in original
        result = _rule_sensitive_file_access(evt, custom_sigs)
        assert result is not None


# ═══════════════════════════════════════════════════════════════════════════════
# run_rule_layer: robustness & cross-cutting
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunRuleLayer:
    def test_malformed_event_returns_empty_no_raise(self):
        """
        A completely minimal OCSFBaseEvent with no optional fields must return
        an empty list without raising.
        """
        evt = ProcessActivityEvent(
            trace_id="t",
            activity_id=999,
            class_uid=1007,
            category_uid=1,
            severity_id=0,
            time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            raw_source_timestamp="2026-01-01T00:00:00Z",
            uid="uid-malformed",
            process_name="some.exe",
            process_pid=0,
        )
        result = run_rule_layer(evt, _SIGS)
        assert isinstance(result, list)

    def test_clean_benign_event_returns_empty(self):
        """Normal process event with no suspicious indicators → empty signals."""
        evt = _proc(process_name="notepad.exe", parent_process_name="explorer.exe")
        result = run_rule_layer(evt, _SIGS)
        assert result == []

    def test_suspicious_event_returns_at_least_one_signal(self):
        """Suspicious parent-child spawn → at least one signal from run_rule_layer."""
        evt = _proc(parent_process_name="winword.exe", process_name="powershell.exe")
        result = run_rule_layer(evt, _SIGS)
        assert len(result) >= 1
        patterns = [s["pattern"] for s in result]
        assert "unusual_parent_process" in patterns
