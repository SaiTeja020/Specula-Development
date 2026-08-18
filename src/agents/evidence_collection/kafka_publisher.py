import hashlib
from src.agents.evidence_collection.state import EvidenceCollectionState
from src.agents.evidence_collection.agent_findings import EvidenceCollectionFinding

FINDING_TOPIC = "findings.evidence_collection"


def build_finding(state: EvidenceCollectionState) -> EvidenceCollectionFinding:
    return EvidenceCollectionFinding(
        case_id=state["case_id"],
        trace_id=state["trace_id"],
        kept_uids=state["kept_uids"],
        discarded_uids=state["discarded_uids"],
        escalated_uids=state["escalated_uids"],
        discard_reason_codes=state["discard_reason_codes"],
        batch_size=len(state["batch_uids"]),
        dead_end=state["dead_end"],
    )


def publish_finding(state: EvidenceCollectionState, producer, deps=None) -> None:
    """
    Publishes to FINDING_TOPIC, partitioned by hash(canonical_host_id) of
    the FIRST uid in batch_uids's originating host — matching ingestion
    plan §6.4's rule (partition by host, never by case_id). If a batch
    spans multiple hosts (it should not, per §5 Mistakes below), this
    is a bug to surface, not paper over with a fallback partition key.
    """
    if not state["batch_uids"]:
        # Nothing to publish if batch is empty
        return

    first_uid = state["batch_uids"][0]
    
    # We need to get the canonical_host_id for the first event to use as partition key.
    # We will get it from deps if available, otherwise just use a fallback or raise.
    canonical_host_id = None
    if deps is not None:
        event = deps.fetch_event(first_uid)
        canonical_host_id = getattr(event, "canonical_host_id", None)
        
    if canonical_host_id is None:
        raise ValueError(f"Cannot partition finding: Event {first_uid} lacks canonical_host_id.")
        
    partition_key = str(hashlib.sha256(canonical_host_id.encode('utf-8')).hexdigest())

    finding = build_finding(state)
    
    producer.produce(
        topic=FINDING_TOPIC,
        key=partition_key,
        value=finding.model_dump_json()
    )
