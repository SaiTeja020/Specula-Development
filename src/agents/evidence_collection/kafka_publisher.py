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
    Publishes to FINDING_TOPIC, partitioned by hash(canonical_host_id).
    
    Batches are guaranteed single-host by Supervisor dispatch enforcement.
    Partition key is computed from the FIRST (and only) host in the batch.
    This preserves per-host chronological ordering at the Kafka level,
    matching the ingestion pipeline's partitioning discipline.
    """
    if not state["batch_uids"]:
        raise ValueError("Cannot publish empty batch")

    first_uid = state["batch_uids"][0]
    
    # Lookup the host of the first event; it's the only host (by Supervisor contract)
    canonical_host_id = None
    if deps is not None:
        event = deps.fetch_event(first_uid)
        canonical_host_id = getattr(event, "canonical_host_id", None)
        
    if canonical_host_id is None:
        raise ValueError(f"Cannot partition finding: Event {first_uid} lacks canonical_host_id.")
        
    partition_key = f"host:{canonical_host_id}"

    finding = build_finding(state)
    
    producer.produce(
        topic=FINDING_TOPIC,
        key=partition_key,
        value=finding.model_dump_json()
    )
