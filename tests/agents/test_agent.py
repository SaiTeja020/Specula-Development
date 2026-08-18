import pytest
from src.agents.evidence_collection.agent import run_evidence_collection
from src.agents.evidence_collection.state import EvidenceCollectionState
from src.agents.evidence_collection.relevance_filter import CaseContext


class MockEvent:
    def __init__(self, uid, canonical_host_id=None, severity_id=99, class_uid=0, is_summary=False):
        self.uid = uid
        self.canonical_host_id = canonical_host_id
        self.severity_id = severity_id
        self.class_uid = class_uid
        self.is_summary = is_summary


class MockProducer:
    def __init__(self):
        self.produced_messages = []

    def produce(self, topic, key, value):
        self.produced_messages.append({"topic": topic, "key": key, "value": value})


class MockDeps:
    def __init__(self, uid_to_case, uid_to_event, known_hosts=None):
        self.uid_to_case = uid_to_case
        self.uid_to_event = uid_to_event
        self.known_hosts = known_hosts or set()
        self.kafka_producer = MockProducer()

    def lookup_case_id(self, uid):
        return self.uid_to_case.get(uid, "unknown_case")

    def load_case_context(self, case_id):
        return CaseContext(case_id=case_id, known_host_uids=self.known_hosts)

    def fetch_event(self, uid):
        return self.uid_to_event.get(uid)


def create_initial_state(batch_uids, case_id="case1", max_iterations=100) -> EvidenceCollectionState:
    return {
        "case_id": case_id,
        "trace_id": "trace1",
        "batch_uids": batch_uids,
        "kept_uids": [],
        "discarded_uids": [],
        "escalated_uids": [],
        "discard_reason_codes": {},
        "iteration_count": 0,
        "max_iterations": max_iterations,
        "dead_end": False,
        "status": "running"
    }


def test_batch_spanning_multiple_case_ids_raises():
    deps = MockDeps(
        uid_to_case={"evt1": "case1", "evt2": "case2"},
        uid_to_event={}
    )
    state = create_initial_state(["evt1", "evt2"])
    
    with pytest.raises(ValueError, match="multiple case_ids"):
        run_evidence_collection(state, deps)


def test_max_iterations_truncates_and_flags_dead_end():
    deps = MockDeps(
        uid_to_case={"evt1": "case1", "evt2": "case1", "evt3": "case1"},
        uid_to_event={
            "evt1": MockEvent("evt1", canonical_host_id="hostA"),
            "evt2": MockEvent("evt2", canonical_host_id="hostA"),
            "evt3": MockEvent("evt3", canonical_host_id="hostA"),
        }
    )
    # Batch size 3, max iterations 2
    state = create_initial_state(["evt1", "evt2", "evt3"], max_iterations=2)
    
    result_state = run_evidence_collection(state, deps)
    
    assert result_state["dead_end"] is True
    assert result_state["iteration_count"] == 2
    assert len(result_state["discard_reason_codes"]) == 2
    assert result_state["status"] == "complete"


def test_deps_substitutable_with_fakes():
    deps = MockDeps(
        uid_to_case={"evt1": "case1"},
        uid_to_event={
            "evt1": MockEvent("evt1", canonical_host_id="hostA"),
        }
    )
    state = create_initial_state(["evt1"])
    
    result_state = run_evidence_collection(state, deps)
    
    assert result_state["status"] == "complete"
    assert len(deps.kafka_producer.produced_messages) == 1
    msg = deps.kafka_producer.produced_messages[0]
    assert msg["topic"] == "findings.evidence_collection"
