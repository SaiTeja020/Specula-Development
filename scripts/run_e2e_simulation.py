import json
import uuid
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.schemas.ocsf_base import OCSFBaseEvent
from src.agents.evidence_collection.agent import run_evidence_collection_triage
from src.agents.evidence_collection.state import EvidenceCollectionState

class MockEvent:
    def __init__(self, raw, uid):
        self.uid = uid
        self.raw = raw
        self.canonical_host_id = "HOST-1"
        self.message = raw.get("message", "")
        self.activity_id = raw.get("activity_id", 0)
        self.class_uid = raw.get("class_uid", 0)
        self.type_uid = raw.get("type_uid", 0)
        self.severity_id = raw.get("severity_id", 1)

class MockKafka:
    def produce(self, topic, key, value):
        pass
    def flush(self):
        pass

class MockDeps:
    def __init__(self, events):
        self.events = events
        self.kafka_producer = MockKafka()

    def lookup_case_id(self, uid):
        return "CASE-123"

    def fetch_event(self, uid):
        return self.events[uid]

    def load_case_context(self, case_id):
        from src.agents.evidence_collection.relevance_filter import CaseContext
        return CaseContext(
            case_id=case_id,
            known_host_uids={"HOST-1"}
        )

def main():
    print("1. Ingestion: Running the ingestion pipeline to extract logs live...")
    from src.ingestion.run_pipeline import main as run_ingestion
    try:
        run_ingestion()
    except Exception as e:
        print(f"Ingestion failed or finished with warnings: {e}")

    print("\nLoading validated OCSF events...")
    try:
        with open("data/extracted_logs/ocsf_system_events.json", "r", encoding="utf-8") as f:
            raw_events = json.load(f)
    except FileNotFoundError:
        print("Run pipeline first: python src/ingestion/run_pipeline.py")
        sys.exit(1)

    print(f"Loaded {len(raw_events)} events.")
    print("2. Normalization: Mapping to canonical internal structures...")
    events_by_uid = {}
    for r in raw_events:
        uid = str(uuid.uuid4())
        events_by_uid[uid] = MockEvent(r, uid)

    print("3. Evidence Collection: Running Triage Filter Agent...")
    state = EvidenceCollectionState(
        case_id="CASE-123",
        trace_id="TRACE-456",
        batch_uids=list(events_by_uid.keys()),
        max_iterations=1000,
        iteration_count=0,
        kept_uids=[],
        discarded_uids=[],
        escalated_uids=[],
        discard_reason_codes={},
        status="pending",
        dead_end=False
    )

    deps = MockDeps(events_by_uid)
    result = run_evidence_collection_triage(state, deps)

    print("\n================ Triage Results ================")
    print(f"Total processed: {result['iteration_count']}")
    print(f"Kept: {len(result['kept_uids'])}")
    print(f"Escalated: {len(result['escalated_uids'])}")
    print(f"Discarded: {len(result['discarded_uids'])}")
    print("================================================")
    
if __name__ == "__main__":
    main()
