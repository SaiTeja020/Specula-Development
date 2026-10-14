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
    for field in ("unmapped", "src_endpoint", "dst_endpoint", "traffic", "dns"):
        if field not in result and field + "_json" in result:
            result[field] = result[field + "_json"]
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
            if state.get('evidence_review_required'):
                raise RuntimeError('Network analysis requires the preserved evidence graph')
            return {"findings": [], "agent_traces": [{
                "agent_role": "network_forensics", "action": "query_dfkg",
                "observation": "DFKG unavailable; no network evidence analyzed.",
                "model_used": "deterministic_rules", "latency_ms": 0,
            }]}

        query = """
        MATCH (c:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event)
        RETURN e
        """
        try:
            records, _, _ = neo4j_driver.execute_query(query, case_id=case_id)
        except Exception as exc:
            log.warning("Network DFKG read failed for case %s: %s", case_id, exc)
            raise RuntimeError('Network evidence read failed; analysis did not execute') from exc

        events_by_host: dict[str, list[str]] = {}
        events_by_uid: dict[str, dict] = {}
        case_events = [_event_dict(record) for record in records]
        for event in case_events:
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
            # Publish only after authorization/context enrichment below.
            deps = NetworkForensicsDepsAdapter(events_by_uid, case_id, None)
            agent_state = NetworkForensicsState(
                case_id=case_id, trace_id=trace_id, batch_uids=uids,
                iteration_count=0, max_iterations=1, dead_end=False,
                anomalies_detected=[], status="pending",
            )
            result = run_network_forensics_analysis(agent_state, deps)
            if result['status']!='complete':
                raise RuntimeError('Network analysis batch incomplete; preserved evidence must be retried')
            partial_batches += result["status"] != "complete"
            for anomaly in result["anomalies_detected"]:
                from .evidence_correlations import authorized_job
                controls_by_event=[authorized_job(events_by_uid[ref],case_events) for ref in anomaly['dfkg_refs']]
                benign=bool(controls_by_event) and all(controls_by_event)
                from .case_analysis import context,outcome
                source_outcomes={ref:outcome(context(events_by_uid[ref])) for ref in anomaly['dfkg_refs']}
                outcomes=set(source_outcomes.values())
                operation_outcome=next(iter(outcomes)) if len(outcomes)==1 else 'mixed'
                failed=outcomes=={'failed'}
                controls=list({r['uid']:r for rows in controls_by_event for r in rows}.values())
                evidence_times = []
                for evidence_uid in anomaly["dfkg_refs"]:
                    value = events_by_uid.get(evidence_uid, {}).get("time")
                    if value:
                        try:
                            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                            evidence_times.append(moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc))
                        except ValueError:
                            pass
                findings.append({
                    "agent_role": "network_forensics", "case_id": case_id,
                    "trace_id": trace_id, "canonical_host_id": host,
                    "summary": anomaly["description"] + (" Source-reported scheduled job has matching authorized completion counter-evidence." if benign else ""),
                    "finding_type": anomaly["type"],
                    "severity_id": 1 if benign or failed else anomaly["severity_id"],
                    "attacks": [anomaly["technique"]] if anomaly.get("technique") and not benign and not failed else [],
                    "source": "validated_case_rule",
                    "classification": "benign" if benign else "failed" if failed else "suspicious",
                    "operation_outcome": operation_outcome,
                    "source_outcomes": source_outcomes,
                    "dfkg_refs": sorted(set(anomaly["dfkg_refs"] + [row["uid"] for row in controls])),
                    "event_time": min(evidence_times).isoformat() if evidence_times else None,
                    "bytes_out": anomaly.get("bytes_out", 0),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "kafka_offset": None,
                })

        if kafka_producer is not None:
            from .network_forensics.kafka_publisher import build_ocsf_2004_finding, FINDING_TOPIC
            for finding in findings:
                enriched={'type':finding['finding_type'],'description':finding['summary'],
                    'dfkg_refs':finding['dfkg_refs'],'severity_id':finding['severity_id'],
                    'technique':next(iter(finding['attacks']),None),'bytes_out':finding['bytes_out']}
                payload=build_ocsf_2004_finding(enriched,{'case_id':case_id,'trace_id':trace_id},finding['canonical_host_id'])
                payload.update(classification=finding['classification'],source='validated_case_rule',operation_outcome=finding['operation_outcome'])
                kafka_producer.produce(topic=FINDING_TOPIC,key=('host:'+finding['canonical_host_id']).encode(),value=json.dumps(payload).encode())
        return {"findings": findings, "agent_traces": [{
            "agent_role": "network_forensics",
            "thought": f"Read {len(events_by_uid)} OCSF 4001 events across {len(events_by_host)} hosts.",
            "action": "deterministic_network_analysis",
            "observation": f"Produced {len(findings)} evidence-backed findings; {partial_batches} partial batches.",
            "model_used": "deterministic_rules", "latency_ms": 0,
        }]}

    return network_forensics_node
