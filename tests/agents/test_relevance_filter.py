import pytest
from src.agents.evidence_collection.agent_verdict import AgentVerdict
from src.agents.evidence_collection.relevance_filter import classify_event, CaseContext, LOW_SIGNAL_CLASS_UIDS
from src.schemas.ocsf_base import OCSFBaseEvent


class MockEvent:
    def __init__(self, uid, canonical_host_id=None, severity_id=99, class_uid=0, is_summary=False):
        self.uid = uid
        if canonical_host_id is not False:  # allow testing missing attribute by passing False
            self.canonical_host_id = canonical_host_id
        self.severity_id = severity_id
        self.class_uid = class_uid
        self.is_summary = is_summary


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
    
    result = classify_event(event, ctx)
    assert result.verdict == AgentVerdict.KEEP
    assert result.reason_code == "KEEP_DEFAULT"

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

def test_confirmed_unknown_host_is_discard_eligible():
    ctx = CaseContext(case_id="case1", known_host_uids={"hostA"})
    
    # Event with confirmed unknown host, satisfying all other criteria
    event = MockEvent(
        uid="evt1",
        canonical_host_id="hostB",  # NOT in known_host_uids
        severity_id=1,
        class_uid=list(LOW_SIGNAL_CLASS_UIDS)[0],
        is_summary=True
    )
    
    result = classify_event(event, ctx)
    assert result.verdict == AgentVerdict.DISCARD
    assert result.reason_code == "DISCARD_ALL_FOUR_CRITERIA_MET"

def test_every_verdict_carries_a_reason_code():
    ctx = CaseContext(case_id="case1", known_host_uids={"hostA"})
    
    # KEEP
    event_keep = MockEvent(uid="evt1", canonical_host_id="hostA", severity_id=99)
    res_keep = classify_event(event_keep, ctx)
    assert res_keep.verdict == AgentVerdict.KEEP
    assert res_keep.reason_code is not None

    # DISCARD
    event_discard = MockEvent(uid="evt2", canonical_host_id="hostB", severity_id=1, class_uid=list(LOW_SIGNAL_CLASS_UIDS)[0], is_summary=True)
    res_discard = classify_event(event_discard, ctx)
    assert res_discard.verdict == AgentVerdict.DISCARD
    assert res_discard.reason_code is not None

    # ESCALATE
    event_esc = MockEvent(uid="evt3", canonical_host_id=None)
    res_esc = classify_event(event_esc, ctx)
    assert res_esc.verdict == AgentVerdict.ESCALATE
    assert res_esc.reason_code is not None

def test_is_summary_flag_trusted_not_recomputed():
    ctx = CaseContext(case_id="case1", known_host_uids={"hostA"})
    
    # Event satisfies all criteria, relies on is_summary=True flag without raw fields
    event = MockEvent(
        uid="evt1",
        canonical_host_id="hostB",
        severity_id=1,
        class_uid=list(LOW_SIGNAL_CLASS_UIDS)[0],
        is_summary=True
    )
    # The function uses boolean evaluation of the property, not trying to compute anything else
    result = classify_event(event, ctx)
    assert result.verdict == AgentVerdict.DISCARD
    assert result.reason_code == "DISCARD_ALL_FOUR_CRITERIA_MET"
