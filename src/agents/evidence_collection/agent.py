from src.agents.evidence_collection.state import EvidenceCollectionState
from src.agents.evidence_collection.relevance_filter import classify_event, CaseContext
from src.agents.evidence_collection.kafka_publisher import build_finding, publish_finding
from src.agents.evidence_collection.agent_verdict import AgentVerdict


def run_evidence_collection_triage(state: EvidenceCollectionState, deps) -> EvidenceCollectionState:
    """
    Deterministic evidence-relevance triage filter, not a ReAct agent.
    
    Classifies DFKG events as KEEP, ESCALATE, or DISCARD (v1: DISCARD disabled).
    Does not invoke any LLM; this is a utility component, not an agent role.
    
    Enforces:
      - exactly one case_id per invocation (raises otherwise)
      - loop budget: state["iteration_count"] must not exceed state["max_iterations"];
        on exceeding, return partial results with dead_end=True rather than 
        looping unboundedly (runtime harness §9.5).
    """
    case_ids_in_batch = {deps.lookup_case_id(uid) for uid in state["batch_uids"]}
    if len(case_ids_in_batch) > 1:
        raise ValueError(
            f"EvidenceCollectionAgent invoked with a batch spanning "
            f"multiple case_ids: {case_ids_in_batch}. Supervisor dispatch "
            f"bug — one case per invocation, no exceptions."
        )

    # NEW: Enforce single-host batches so partition key is unambiguous
    # Using deps.fetch_event since lookup_host_id might not be implemented
    host_ids_in_batch = {getattr(deps.fetch_event(uid), "canonical_host_id", None) for uid in state["batch_uids"]}
    if len(host_ids_in_batch) > 1:
        raise ValueError(
            f"EvidenceCollectionAgent invoked with a batch spanning multiple hosts: "
            f"{host_ids_in_batch}. Supervisor dispatch bug — one host per batch. "
            f"Evidence-collection triage must preserve per-host ordering; split into "
            f"per-host batches at the dispatch boundary."
        )

    # Loads all hosts tagged with this case_id via indexed MATCH query.
    # NOT a bounded BFS (which is for multi-hop context). This is a flat lookup.
    ctx = deps.load_case_context(state["case_id"])

    for uid in state["batch_uids"]:
        if state["iteration_count"] >= state["max_iterations"]:
            state["dead_end"] = True
            break
        event = deps.fetch_event(uid)
        result = classify_event(event, ctx)
        state["discard_reason_codes"][uid] = result.reason_code
        if result.verdict == AgentVerdict.KEEP:
            state["kept_uids"].append(uid)
        elif result.verdict == AgentVerdict.DISCARD:
            state["discarded_uids"].append(uid)
        else:
            state["escalated_uids"].append(uid)
        state["iteration_count"] += 1

    publish_finding(state, deps.kafka_producer, deps=deps)
    state["status"] = "complete"
    return state
