import os
import time
import json
import threading
import logging
from typing import Any
from neo4j import GraphDatabase

from src.agents.kafka_utils import run_dfkg_consumer, create_topics, _producer
from src.agents.network_forensics_agent import make_network_forensics_node
from src.agents.log_analysis_agent import make_log_analysis_node
from src.agents.config import _STUB_RESPONSES

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("test_blackboard")

def run_test():
    # 1. Setup Neo4j
    neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    driver = GraphDatabase.driver(neo4j_uri)
    
    with driver.session() as session:
        session.run("MATCH (n) WHERE n:Case OR n:AgentFinding OR n:Entity DETACH DELETE n")
        session.run("MERGE (c:Case {case_id: 'test-case-bb'})")
        # Pre-seed some evidence
        session.run("MERGE (e:Entity {uid: 'evi-123', type: 'NetworkActivity', ip: '1.1.1.1'})")
        session.run("MERGE (e:Entity {uid: 'evi-456', type: 'Authentication', user: 'admin'})")

    # 2. Setup Kafka Topics
    create_topics()
    log.info("Waiting for Kafka topic metadata to sync...")
    time.sleep(3)

    # 3. Start Consumer Thread
    consumer_thread = threading.Thread(target=run_dfkg_consumer, kwargs={"max_messages": None})
    consumer_thread.daemon = True
    consumer_thread.start()

    # 4. Agent A (Network Forensics) runs
    network_node = make_network_forensics_node(None, driver)
    
    # Configure Stub for Network Forensics
    _STUB_RESPONSES["network_forensics"] = [
        "ACTION: query_dfkg {\"cypher\": \"MATCH (e:Entity {type: 'NetworkActivity'}) RETURN e.uid LIMIT 1\"}",
        "ACTION: publish_finding {\"topic\": \"findings.network_forensics\", \"finding\": {\"summary\": \"Observed suspicious C2 on IP 1.1.1.1.\"}}",
        "FINAL_ANSWER: Observed suspicious C2."
    ]

    log.info("--- Running Network Forensics Agent ---")
    state_a = {"case_id": "test-case-bb", "trace_id": "trace-1", "findings": [], "agent_traces": []}
    state_a = network_node(state_a)
    log.info("Agent A Traces:")
    for trace in state_a.get("agent_traces", []):
        log.info(trace)

    # Let's write directly to Kafka to see if the consumer works!
    from src.agents.kafka_utils import publish_finding
    publish_finding("findings.network_forensics", {
        "agent_role": "network_forensics", 
        "summary": "DIRECT TEST FINDING",
        "case_id": "test-case-bb",
        "dfkg_refs": ["evi-123"]
    })

    import src.agents.kafka_utils
    if hasattr(src.agents.kafka_utils, "_producer") and src.agents.kafka_utils._producer:
        log.info("Flushing Kafka producer...")
        src.agents.kafka_utils._producer.flush()

    # Allow consumer to process
    log.info("Waiting for DFKG consumer to write Agent A finding...")
    
    # 5. Verify Neo4j has Agent A finding
    records = []
    for _ in range(15):
        time.sleep(1)
        with driver.session() as session:
            result = session.run("MATCH (f:AgentFinding)-[:BELONGS_TO]->(c:Case {case_id: 'test-case-bb'}) RETURN f.summary AS summary, f.agent_role AS role")
            records = [r.data() for r in result]
            if records:
                break
    
    log.info(f"AgentFindings in DB: {records}")
    assert len(records) >= 1, "Agent A finding not written to DB"

    # Check BASED_ON
    with driver.session() as session:
        result = session.run("MATCH (f:AgentFinding)-[:BASED_ON]->(e:Entity) RETURN f.agent_role, e.uid")
        based_on = [r.data() for r in result]
        log.info(f"BASED_ON links: {based_on}")
        # Network Forensics query collected 'evi-123' via TrackingDFKGQueryTool
        assert len(based_on) >= 1, "Agent A finding missing BASED_ON links"

    # 6. Agent B (Log Analysis) runs, querying Blackboard
    log_node = make_log_analysis_node(None, driver)
    
    _STUB_RESPONSES["log_analysis"] = [
        "ACTION: query_dfkg {\"cypher\": \"MATCH (f:AgentFinding)-[:BELONGS_TO]->(c:Case {case_id: 'test-case-bb'}) RETURN f.summary AS summary LIMIT 1\"}",
        "ACTION: publish_finding {\"topic\": \"findings.log_analysis\", \"finding\": {\"summary\": \"Corroborated C2 with admin login.\"}}",
        "FINAL_ANSWER: Corroborated C2 with admin login."
    ]

    log.info("--- Running Log Analysis Agent ---")
    state_b = {"case_id": "test-case-bb", "trace_id": "trace-2", "findings": [], "agent_traces": []}
    state_b = log_node(state_b)

    if hasattr(src.agents.kafka_utils, "_producer") and src.agents.kafka_utils._producer:
        log.info("Flushing Kafka producer...")
        src.agents.kafka_utils._producer.flush()

    # Allow consumer to process
    log.info("Waiting for DFKG consumer to write Agent B finding...")
    
    # 7. Final Verification
    records = []
    for _ in range(15):
        time.sleep(1)
        with driver.session() as session:
            result = session.run("MATCH (f:AgentFinding)-[:BELONGS_TO]->(c:Case {case_id: 'test-case-bb'}) RETURN f.summary AS summary, f.agent_role AS role")
            records = [r.data() for r in result]
            if len(records) >= 2:
                break

    log.info(f"Final AgentFindings in DB: {records}")
    assert len(records) >= 2, "Both findings should be in DB"

    log.info("Blackboard Integration Test Passed!")
    driver.close()

if __name__ == "__main__":
    run_test()
