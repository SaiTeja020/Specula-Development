from typing import Any
from src.agents.network_forensics.state import NetworkForensicsState
from src.agents.network_forensics.anomaly_detector import analyze_network_events
from src.agents.network_forensics.kafka_publisher import publish_finding

def run_network_forensics_analysis(state: NetworkForensicsState, deps: Any) -> NetworkForensicsState:
    """
    Deterministic anomaly detection filter for network forensics.
    Classifies DFKG network events for C2 Beaconing, DNS Tunneling, and Data Exfiltration.
    """
    case_ids_in_batch = {deps.lookup_case_id(uid) for uid in state["batch_uids"]}
    if len(case_ids_in_batch) > 1:
        raise ValueError(
            f"NetworkForensicsAgent invoked with a batch spanning "
            f"multiple case_ids: {case_ids_in_batch}. Supervisor dispatch "
            f"bug — one case per invocation, no exceptions."
        )

    # Enforce single-host batches so partition key is unambiguous
    host_ids_in_batch = {getattr(deps.fetch_event(uid), "canonical_host_id", None) for uid in state["batch_uids"]}
    if len(host_ids_in_batch) > 1:
        raise ValueError(
            f"NetworkForensicsAgent invoked with a batch spanning multiple hosts: "
            f"{host_ids_in_batch}. Supervisor dispatch bug — one host per batch. "
        )

    if state.get("iteration_count", 0) >= state.get("max_iterations", 1):
        state["dead_end"] = True
        return state

    # Fetch all events in batch
    events = [deps.fetch_event(uid) for uid in state["batch_uids"]]
    
    # Convert events to dictionaries if they are objects for the anomaly detector
    event_dicts = [e if isinstance(e, dict) else e.__dict__ for e in events]
    
    anomalies = analyze_network_events(event_dicts)
    state["anomalies_detected"] = anomalies
    
    publish_finding(state, deps.kafka_producer, deps=deps)
    state["iteration_count"] = state.get("iteration_count", 0) + 1
    state["status"] = "complete"
    
    return state
