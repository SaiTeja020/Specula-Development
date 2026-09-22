"""Factory for Network Forensics Node."""
import datetime
import json
from typing import Any, Dict
from src.agents.network_forensics.state import NetworkForensicsState
from src.agents.network_forensics.agent import run_network_forensics_analysis

class NetworkForensicsDepsAdapter:
    def __init__(self, events_by_uid: dict, case_id: str, kafka_producer: Any):
        self._events_by_uid = events_by_uid
        self._case_id = case_id
        self.kafka_producer = kafka_producer
        self.published_findings = []
        
        # Wrap kafka_producer to intercept findings if we want to add them to SpeculaState
        if hasattr(self.kafka_producer, "produce"):
            self._real_produce = self.kafka_producer.produce
        else:
            self._real_produce = None

    def lookup_case_id(self, uid: str) -> str:
        return self._case_id

    def fetch_event(self, uid: str) -> dict:
        return self._events_by_uid[uid]


def make_network_forensics_node(neo4j_driver: Any, kafka_producer: Any):
    def network_forensics_node(state: dict) -> dict:
        case_id = state.get("case_id", "unknown")
        trace_id = state.get("trace_id", "")
        
        if not neo4j_driver:
            # Fallback stub behavior if no DB
            from src.agents.nodes import _run_agent
            finding, trace = _run_agent("network_forensics", state)
            return {"findings": [finding], "agent_traces": [trace]}
            
        # 1. Fetch Network Activity events (class_uid = 4001) for this case from DFKG
        query = """
        MATCH (c:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event {class_uid: 4001})
        RETURN e
        """
        records, _, _ = neo4j_driver.execute_query(query, case_id=case_id)
        
        # Group events by canonical_host_id
        events_by_host = {}
        events_by_uid = {}
        for r in records:
            event_node = r["e"]
            event_dict = dict(event_node.items())
            
            uid = event_dict.get("uid")
            if not uid:
                continue
                
            # Try to extract canonical_host_id. If missing, default to "unknown_host"
            host_id = event_dict.get("canonical_host_id", "unknown_host")
            
            # Need to parse JSON strings back to dicts if they were stored as stringified JSON in neo4j
            for field in ["src_endpoint", "dst_endpoint", "traffic", "dns"]:
                if isinstance(event_dict.get(field), str):
                    try:
                        event_dict[field] = json.loads(event_dict[field])
                    except:
                        pass
            
            events_by_uid[uid] = event_dict
            events_by_host.setdefault(host_id, []).append(uid)
            
        if not events_by_uid:
            # No network events
            return {"findings": [], "agent_traces": []}
            
        all_findings = []
        # 2. Run analysis per host batch
        for host_id, batch_uids in events_by_host.items():
            deps = NetworkForensicsDepsAdapter(events_by_uid, case_id, kafka_producer)
            
            nf_state = NetworkForensicsState(
                case_id=case_id,
                trace_id=trace_id,
                batch_uids=batch_uids,
                iteration_count=0,
                max_iterations=1,
                dead_end=False,
                anomalies_detected=[],
                status="pending"
            )
            
            # Run the deterministic logic
            result_state = run_network_forensics_analysis(nf_state, deps)
            
            # For LangGraph integration, we must convert anomalies into a 'finding' object
            if result_state.get("anomalies_detected"):
                summary_lines = [f"Network Forensics detected anomalies on host {host_id}:"]
                for anomaly in result_state["anomalies_detected"]:
                    summary_lines.append(f"- {anomaly.get('type')}: {anomaly.get('description', '')}")
                    
                finding = {
                    "agent_role": "network_forensics",
                    "summary": "\n".join(summary_lines),
                    "dfkg_refs": batch_uids,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "kafka_offset": None,
                }
                all_findings.append(finding)
        
        # Create a trace indicating the analysis ran
        trace = {
            "agent_role": "network_forensics",
            "thought": f"Analyzed {len(events_by_uid)} network events across {len(events_by_host)} hosts.",
            "action": "deterministic_anomaly_detection",
            "observation": f"Found {len(all_findings)} anomaly sets.",
            "model_used": "deterministic_rules",
            "latency_ms": 10,
        }
        
        return {"findings": all_findings, "agent_traces": [trace]}
        
    return network_forensics_node
