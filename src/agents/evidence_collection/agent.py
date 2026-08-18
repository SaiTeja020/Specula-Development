from src.agents.evidence_collection.state import EvidenceCollectionState
from src.agents.evidence_collection.relevance_filter import classify_event, CaseContext
from src.agents.evidence_collection.kafka_publisher import build_finding, publish_finding
from src.agents.evidence_collection.agent_verdict import AgentVerdict


def run_evidence_collection(state: EvidenceCollectionState, deps) -> EvidenceCollectionState:
    """
    Single entrypoint. `deps` bundles the mcp-dfkg-cypher client and the
    Kafka producer — injected, not constructed inside this function, so
    the node is testable against fakes (matches FakeNeo4j / FakeKafkaTopic
    fixtures already established in tests/conftest.py).

    Enforces:
      - exactly one case_id per invocation (raises otherwise)
      - loop budget: state["iteration_count"] must not exceed
        state["max_iterations"]; on exceeding, return partial results
        with dead_end=True rather than looping unboundedly (runtime
        harness §9.5's "graceful timeout returning a partial observation").
    """
    case_ids_in_batch = {deps.lookup_case_id(uid) for uid in state["batch_uids"]}
    if len(case_ids_in_batch) > 1:
        raise ValueError(
            f"EvidenceCollectionAgent invoked with a batch spanning "
            f"multiple case_ids: {case_ids_in_batch}. Supervisor dispatch "
            f"bug — one case per invocation, no exceptions."
        )

    ctx = deps.load_case_context(state["case_id"])  # bounded DFKG query, §3.1

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
