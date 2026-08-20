import pytest
from src.agents.evidence_collection.agent_verdict import AgentVerdict
from src.agents.evidence_collection.relevance_filter import classify_event, _conjunctive_discard_path, CaseContext, LOW_SIGNAL_CLASS_UIDS
from src.schemas.ocsf_base import OCSFBaseEvent


class MockEvent:
    def __init__(self, uid, canonical_host_id=None, severity_id=99, class_uid=0, is_summary=False, status=None, activity_id=None):
        self.uid = uid
        if canonical_host_id is not False:  # allow testing missing attribute by passing False
            self.canonical_host_id = canonical_host_id
        self.severity_id = severity_id
        self.class_uid = class_uid
        self.is_summary = is_summary
        self.status = status
        self.activity_id = activity_id


def test_unresolved_host_escalates_never_discards():
    ctx = CaseContext(case_id="case1", known_host_uids={"hostA"})
    
    # Event with missing host
    event = MockEvent(
        uid="evt1",
        canonical_host_id=None,
        severity_id=1,
        class_uid=list(LOW_SIGNAL_CLASS_UIDS)[0],
        is_summary=True
    )
    
    result = classify_event(event, ctx)
    assert result.verdict == AgentVerdict.ESCALATE
    assert result.reason_code == "ESCALATE_UNRESOLVED_HOST"

def test_discard_path_disabled_until_stage_4b_regression():
    """
    REGRESSION TEST: Ensures DISCARD remains unreachable until Stage 4b.
    """
    from src.schemas.ocsf_base import OCSFBaseEvent
    
    event = MockEvent(
        uid="test-uid-for-stage-4b",
        severity_id=1,  # Informational
        class_uid=3002,  # Authentication
        canonical_host_id="unknown-host-12345",
        is_summary=True,  # This flag is set by Stage 4b entropy clustering
        status="Success"
    )
    
    ctx = CaseContext(
        case_id="test-case",
        known_host_uids={"known-host-1", "known-host-2"}
    )
    
    result = classify_event(event, ctx)
    
    assert result.verdict == AgentVerdict.KEEP, (
        f"Stage 4b may have shipped! If entropy distillation is now live, "
        f"uncomment _conjunctive_discard_path() and re-wire classify_event(). "
        f"Got verdict={result.verdict.value} instead of KEEP."
    )
    assert "V1_DISCARD_DISABLED_PENDING_STAGE_4B" in result.reason_code, (
        f"Reason code suggests DISCARD path was re-enabled without updating this test. "
        f"Got: {result.reason_code}"
    )


def test_discard_conjunction_v1_disabled_but_documented_for_stage_4b():
    """
    Light documentation test ensuring _conjunctive_discard_path() exists and
    is syntactically correct, even though it's disabled in v1.
    """
    from src.agents.evidence_collection.relevance_filter import _conjunctive_discard_path
    assert callable(_conjunctive_discard_path)

def test_authentication_failure_never_discarded():
    """
    Criterion 3 enforcement: failed authentication is high-signal, never discarded.
    """
    # Create a FAILED authentication event
    failed_auth_event = MockEvent(
        uid="failed-auth-uid",
        severity_id=1,  # Low severity (routine log entry)
        class_uid=3002,  # Authentication
        canonical_host_id="new-host",  # Not in case context
        status="Failure",  # ← KEY: Failed, not successful
        is_summary=True,  # Would otherwise satisfy criterion 4
    )
    
    ctx = CaseContext(
        case_id="test-case",
        known_host_uids={"known-host"}  # new-host is unknown
    )
    
    result = _conjunctive_discard_path(failed_auth_event, ctx)
    assert result.verdict == AgentVerdict.KEEP, (
        f"Failed authentication should never be discarded, but got {result.verdict.value}"
    )


def test_discard_requires_all_four_criteria_conjunctively_with_auth_check():
    """
    Test the updated criterion 3 with authentication-status awareness.
    Only successful auth should be low-signal; failures are always kept.
    """
    # Successful authentication (low-signal candidate)
    successful_auth = MockEvent(
        uid="success-auth",
        severity_id=1,
        class_uid=3002,
        canonical_host_id="new-host",
        status="Success",  # ← Successful
        is_summary=True,
    )
    
    ctx = CaseContext(
        case_id="test-case",
        known_host_uids={"known-host"}
    )
    
    result = _conjunctive_discard_path(successful_auth, ctx)
    
    # All four criteria satisfied; should be DISCARD
    assert result.verdict == AgentVerdict.DISCARD, (
        f"Successful auth from new host with all criteria met should DISCARD, "
        f"but got {result.verdict.value}"
    )

def test_discard_requires_all_four_criteria_conjunctively():
    ctx = CaseContext(case_id="case1", known_host_uids={"hostA"})
    
    # Satisfies 1, 2, 4 but not 3 (class_uid not in allowlist)
    event = MockEvent(
        uid="evt1",
        canonical_host_id="hostB",  # criteria 2 (confirmed unknown)
        severity_id=1,              # criteria 1 (low severity)
        class_uid=9999,             # FAILS criteria 3
        is_summary=True             # criteria 4 (is summary)
    )
    
    result = _conjunctive_discard_path(event, ctx)
    assert result.verdict == AgentVerdict.KEEP
    assert result.reason_code == "KEEP_DEFAULT"

def test_confirmed_unknown_host_is_discard_eligible():
    ctx = CaseContext(case_id="case1", known_host_uids={"hostA"})
    
    # Event with confirmed unknown host, satisfying all other criteria
    event = MockEvent(
        uid="evt1",
        canonical_host_id="hostB",  # NOT in known_host_uids
        severity_id=1,
        class_uid=3002,
        status="Success",
        is_summary=True
    )
    
    result = _conjunctive_discard_path(event, ctx)
    assert result.verdict == AgentVerdict.DISCARD
    assert result.reason_code == "DISCARD_ALL_FOUR_CRITERIA_MET"
