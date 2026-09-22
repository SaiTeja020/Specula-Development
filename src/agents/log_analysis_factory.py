"""Factory for Log Analysis Node."""
import json
import logging
from typing import Any
from src.agents.config import get_llm
from src.agents.log_analysis.agent import LogAnalysisAgent
from src.schemas.ocsf_base import OCSFBaseEvent

logger = logging.getLogger(__name__)

class DummyProducer:
    def __init__(self):
        self.messages = []
    def produce(self, topic, key, value):
        self.messages.append((topic, key, value))

class DummyDFKGClient:
    def __init__(self, neo4j_driver):
        self.neo4j_driver = neo4j_driver
    def query(self, uid: str):
        # Stub for the DFKG read client if required by LLM reasoner
        return []

class DummyRedis:
    def get(self, key):
        return None
    def setex(self, key, ttl, value):
        pass


def make_log_analysis_node(kafka_producer: Any, vector_client: Any, redis_client: Any, neo4j_driver: Any):
    def log_analysis_node(state: dict) -> dict:
        case_id = state.get("case_id", "unknown")
        
        if not neo4j_driver:
            from src.agents.nodes import _run_agent
            finding, trace = _run_agent("log_analysis", state)
            return {"findings": [finding], "agent_traces": [trace]}

        # model_router is just a callable that takes a string prompt and returns a string
        llm = get_llm("log_analysis", case_id=case_id)
        def model_router(prompt: str) -> str:
            response = llm.invoke(prompt)
            return response.content if hasattr(response, "content") else str(response)
            
        real_producer = kafka_producer or DummyProducer()
        real_redis = redis_client or DummyRedis()
        dfkg_client = DummyDFKGClient(neo4j_driver)
        
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
            events.append(OCSFBaseEvent(**event_dict))
            
        if not events:
            return {"findings": [], "agent_traces": []}
            
        try:
            findings = agent.run_on_batch(events, kafka_offset=0, case_dedup_ttl_seconds=3600)
            
            # The agent.run_on_batch() returns a list of finding dicts
            return {
                "findings": findings,
                "agent_traces": [{
                    "agent_role": "log_analysis",
                    "thought": f"Analyzed {len(events)} log events.",
                    "action": "run_on_batch",
                    "observation": f"Produced {len(findings)} findings.",
                    "model_used": "hybrid_rules_and_llm",
                    "latency_ms": 10,
                }]
            }
        except Exception as e:
            logger.error(f"LogAnalysisAgent failed: {e}")
            from src.agents.nodes import _run_agent
            finding, trace = _run_agent("log_analysis", state)
            return {"findings": [finding], "agent_traces": [trace]}

    return log_analysis_node
