"""Case and host scoped network evidence analysis."""

from typing import Any
import logging
from src.agents.network_forensics.state import NetworkForensicsState
from src.agents.network_forensics.anomaly_detector import analyze_network_events
from src.agents.network_forensics.kafka_publisher import publish_finding

log = logging.getLogger(__name__)

def run_network_forensics_analysis(state: NetworkForensicsState, deps: Any) -> NetworkForensicsState:
    """
    Deterministic anomaly detection filter for network forensics.
    Classifies DFKG network events for C2 Beaconing, DNS Tunneling, and Data Exfiltration.
    """
    case_ids_in_batch = {deps.lookup_case_id(uid) for uid in state["batch_uids"]}
    if len(case_ids_in_batch) > 1 or (case_ids_in_batch and case_ids_in_batch != {state["case_id"]}):
        raise ValueError(
            f"NetworkForensicsAgent invoked with a batch spanning "
            f"multiple case_ids: {case_ids_in_batch}. Supervisor dispatch "
            f"bug — one case per invocation, no exceptions."
        )

    events = {uid: deps.fetch_event(uid) for uid in state["batch_uids"]}

    # Enforce single-host batches so partition key is unambiguous
    event_dicts = [event if isinstance(event, dict) else (
        event.model_dump(mode="json") if hasattr(event, "model_dump") else vars(event)
    ) for event in events.values()]
    host_ids_in_batch = {event.get("canonical_host_id") for event in event_dicts}
    if len(host_ids_in_batch) > 1 or None in host_ids_in_batch or "" in host_ids_in_batch:
        raise ValueError(
            f"NetworkForensicsAgent invoked with a batch spanning multiple hosts: "
            f"{host_ids_in_batch}. Supervisor dispatch bug — one host per batch. "
        )

    if state.get("iteration_count", 0) >= state.get("max_iterations", 1):
        return {**state, "dead_end": True, "status": "partial"}

    anomalies = analyze_network_events(event_dicts)
    result = {**state, "anomalies_detected": anomalies,
              "iteration_count": state.get("iteration_count", 0) + 1,
              "status": "complete"}
    if anomalies and getattr(deps, "kafka_producer", None) is not None:
        try:
            publish_finding(result, deps.kafka_producer, deps=deps)
        except Exception as exc:
            log.warning("Network finding publication failed: %s", exc)
            result["status"] = "partial"
    return result
