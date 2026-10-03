"""LangGraph adapter for the Network Forensics Agent's DFKG evidence read."""

from datetime import datetime, timezone
import json
import logging
from typing import Any

from src.agents.network_forensics.agent import run_network_forensics_analysis
from src.agents.network_forensics.state import NetworkForensicsState

log = logging.getLogger(__name__)


class NetworkForensicsDepsAdapter:
    def __init__(self, events_by_uid: dict[str, dict], case_id: str, kafka_producer: Any):
        self._events_by_uid = events_by_uid
        self._case_id = case_id
        self.kafka_producer = kafka_producer

    def lookup_case_id(self, uid: str) -> str:
        return self._events_by_uid[uid].get("case_id", self._case_id)

    def fetch_event(self, uid: str) -> dict:
        return self._events_by_uid[uid]


def _event_dict(record: Any) -> dict:
    event = record.get("e") if hasattr(record, "get") else record["e"]
    if hasattr(event, "items"):
        result = dict(event.items())
    else:
        result = dict(event)
    for field in ("src_endpoint", "dst_endpoint", "traffic", "dns"):
        if isinstance(result.get(field), str):
            try:
                result[field] = json.loads(result[field])
            except json.JSONDecodeError:
                result[field] = {}
    return result


def make_network_forensics_node(neo4j_driver: Any, kafka_producer: Any):
    def network_forensics_node(state: dict) -> dict:
        case_id = state.get("case_id")
        trace_id = state.get("trace_id", "")
        if not case_id:
            raise ValueError("Network Forensics requires case_id")
        if neo4j_driver is None:
            return {"findings": [], "agent_traces": [{
                "agent_role": "network_forensics", "action": "query_dfkg",
                "observation": "DFKG unavailable; no network evidence analyzed.",
                "model_used": "deterministic_rules", "latency_ms": 0,
            }]}

        query = """
        MATCH (c:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event {class_uid: 4001})
        RETURN e
        """
        try:
            records, _, _ = neo4j_driver.execute_query(query, case_id=case_id)
        except Exception as exc:
            log.warning("Network DFKG read failed for case %s: %s", case_id, exc)
            return {"findings": [], "agent_traces": [{
                "agent_role": "network_forensics", "action": "query_dfkg",
                "observation": "DFKG read failed; analysis incomplete.",
                "model_used": "deterministic_rules", "latency_ms": 0,
            }]}

        events_by_host: dict[str, list[str]] = {}
        events_by_uid: dict[str, dict] = {}
        for record in records:
            event = _event_dict(record)
            uid, host = event.get("uid"), event.get("canonical_host_id")
            if not uid or not host or event.get("class_uid") != 4001:
                continue
            # Case membership is proven by the HAS_EVENT relationship, which
            # allows one immutable event to be referenced by multiple cases.
            event["case_id"] = case_id
            events_by_uid[uid] = event
            events_by_host.setdefault(host, []).append(uid)

        findings = []
        partial_batches = 0
        for host, uids in events_by_host.items():
            deps = NetworkForensicsDepsAdapter(events_by_uid, case_id, kafka_producer)
            agent_state = NetworkForensicsState(
                case_id=case_id, trace_id=trace_id, batch_uids=uids,
                iteration_count=0, max_iterations=1, dead_end=False,
                anomalies_detected=[], status="pending",
            )
            result = run_network_forensics_analysis(agent_state, deps)
            partial_batches += result["status"] != "complete"
            for anomaly in result["anomalies_detected"]:
                findings.append({
                    "agent_role": "network_forensics", "case_id": case_id,
                    "trace_id": trace_id, "canonical_host_id": host,
                    "summary": anomaly["description"],
                    "finding_type": anomaly["type"],
                    "severity_id": anomaly["severity_id"],
                    "attacks": [anomaly["technique"]],
                    "dfkg_refs": anomaly["dfkg_refs"],
                    "bytes_out": anomaly.get("bytes_out", 0),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "kafka_offset": None,
                })

        return {"findings": findings, "agent_traces": [{
            "agent_role": "network_forensics",
            "thought": f"Read {len(events_by_uid)} OCSF 4001 events across {len(events_by_host)} hosts.",
            "action": "deterministic_network_analysis",
            "observation": f"Produced {len(findings)} evidence-backed findings; {partial_batches} partial batches.",
            "model_used": "deterministic_rules", "latency_ms": 0,
        }]}

    return network_forensics_node
