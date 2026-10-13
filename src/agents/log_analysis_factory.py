"""Factory for Log Analysis Node."""
import json
import logging
import time
from typing import Any
from src.agents.config import get_llm
from src.agents.log_analysis.agent import LogAnalysisAgent
from src.schemas.ocsf_base import OCSFBaseEvent

logger = logging.getLogger(__name__)

class CaseLogRecord(OCSFBaseEvent):
    """Retain fields from already validated case evidence for detection rules."""
    model_config = {**OCSFBaseEvent.model_config, "extra": "allow"}

class DummyProducer:
    def __init__(self):
        self.messages = []
    def produce(self, topic, key, value):
        self.messages.append((topic, key, value))

class CaseDFKGClient:
    def __init__(self, neo4j_driver, case_id):
        self.neo4j_driver = neo4j_driver
        self.case_id = case_id
    def query(self, uid: str):
        rows, _, _ = self.neo4j_driver.execute_query(
            "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(e:Event {uid:$uid}) RETURN e.uid AS uid",
            case_id=self.case_id, uid=uid)
        return [row["uid"] for row in rows]

class DummyRedis:
    def get(self, key):
        return None
    def setex(self, key, ttl, value):
        pass


def make_log_analysis_node(kafka_producer: Any, vector_client: Any, redis_client: Any, neo4j_driver: Any):
    def log_analysis_node(state: dict) -> dict:
        started = time.monotonic()
        invocations = 0
        model_outputs = []
        case_id = state.get("case_id", "unknown")
        
        if not neo4j_driver:
            from src.agents.nodes import _run_agent
            finding, trace = _run_agent("log_analysis", state)
            return {"findings": [finding], "agent_traces": [trace]}

        # model_router is just a callable that takes a string prompt and returns a string
        llm = get_llm("log_analysis", case_id=case_id)
        def model_router(prompt: str) -> str:
            nonlocal invocations
            invocations += 1
            response = llm.invoke(prompt)
            text = response.content if hasattr(response, "content") else str(response)
            model_outputs.append(text)
            return text
            
        def real_producer(topic, finding):
            from .kafka_utils import _get_producer
            producer = kafka_producer if kafka_producer is not None else _get_producer()
            finding["model_narrative"] = finding["summary"]
            finding["summary"] = f"Deterministic {finding['pattern']} signal; cited source events: " + ", ".join(finding["dfkg_refs"])
            finding["case_id"] = case_id
            finding["agent_role"] = "log_analysis"
            finding["source"] = "validated_case_rule"
            if producer is None:
                raise RuntimeError("Kafka producer unavailable")
            if callable(producer):
                producer(topic, finding)
            else:
                producer.produce(topic, key=case_id.encode(), value=json.dumps(finding).encode())
                producer.poll(0)
        real_redis = redis_client or DummyRedis()
        dfkg_client = CaseDFKGClient(neo4j_driver, case_id)
        
        agent = LogAnalysisAgent(
            model_router=model_router,
            kafka_consumer=None,
            kafka_producer=real_producer,
            dfkg_read_client=dfkg_client,
            vector_client=vector_client,
            redis_client=real_redis,
        )
        
        # Query DFKG for events with class_uid 1007 (Process) or 1001 (File)
        query = """
        MATCH (c:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event)
        WHERE e.class_uid IN [1001, 1007]
        RETURN e
        """
        records, _, _ = neo4j_driver.execute_query(query, case_id=case_id)
        
        events = []
        for r in records:
            event_node = r["e"]
            event_dict = dict(event_node.items())
            event_dict["case_id"] = case_id  # HAS_EVENT establishes membership, even for shared immutable events.
            events.append(CaseLogRecord(**event_dict))
            
        if not events:
            return {"findings": [], "agent_traces": [{"agent_role": "log_analysis",
                "action": "case_scoped_log_analysis", "observation": "No process or file events were available for log-analysis rules.",
                "model_used": "deterministic_rules", "latency_ms": round((time.monotonic() - started) * 1000, 1)}]}
            
        try:
            findings = agent.run_on_batch(events, kafka_offset=0, case_dedup_ttl_seconds=3600)
            for finding in findings:
                finding["agent_role"] = "log_analysis"
                finding["event_time"] = finding["timestamp"]
                finding.setdefault("model_narrative", finding["summary"])
                from .case_analysis import observation
                cited = next((e for e in events if e.uid in finding["dfkg_refs"]), None)
                finding["summary"] = f"Deterministic {finding['pattern']} signal: " + (observation(cited.model_dump(mode="json")) if cited else "Cited source event")
                finding["source"] = "validated_case_rule"
                finding["finding_type"] = finding["pattern"]
            from .case_analysis import detections
            extra = detections({"case_id": case_id, "trace_id": state.get("trace_id"), "evidence_collection": {"records": [e.model_dump(mode="json") for e in events]}}, "log_analysis")
            findings.extend(extra)
            
            # The agent.run_on_batch() returns a list of finding dicts
            return {
                "findings": findings,
                "agent_traces": [{
                    "agent_role": "log_analysis",
                    "thought": f"Analyzed {len(events)} log events.",
                    "action": "run_on_batch",
                    "observation": f"Produced {len(findings)} findings.",
                    "model_used": (getattr(llm, "model_name", None) or getattr(llm, "model", None) or llm.__class__.__name__)
                                  if invocations else "deterministic_rules",
                    "model_invocations": invocations,
                    "model_output": "\n".join(model_outputs),
                    "model_output_validated": False,
                    "latency_ms": round((time.monotonic() - started) * 1000, 1),
                }]
            }
        except Exception as e:
            logger.error(f"LogAnalysisAgent failed: {e}")
            from src.agents.nodes import _run_agent
            finding, trace = _run_agent("log_analysis", state)
            return {"findings": [finding], "agent_traces": [trace]}

    return log_analysis_node
