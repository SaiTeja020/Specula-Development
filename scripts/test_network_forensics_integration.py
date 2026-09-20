import logging
import os
import sys

sys.path.insert(0, os.path.abspath("."))

from src.agents.network_forensics_agent import make_network_forensics_node
from src.graph.neo4j_client import Neo4jClient
from src.agents.rag.gemini_client import GeminiClient

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("NetworkForensicsIntegration")

os.environ["SPECULA_LLM_BACKEND"] = "gemini"

env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(env_path):
    with open(env_path, "r") as f:
        for line in f:
            if line.startswith("GEMINI_API_KEY="):
                os.environ["GEMINI_API_KEY"] = line.split("=", 1)[1].strip()

def run_test():
    logger.info("=== NETWORK FORENSICS INTEGRATION TEST (PHASE H) ===")
    neo4j = Neo4jClient()
    
    node = make_network_forensics_node(redis_client=None, neo4j_driver=neo4j)

    # Let's seed a case timeline describing a suspicious connection to 185.220.101.45
    state = {
        "case_id": "case-999",
        "timeline": {
            "summary": "Suspicious communication to 185.220.101.45 observed. Analyze this connection."
        }
    }
    
    logger.info("\n--- INVOKING AGENT ---")
    result = node(state)
    logger.info("\n--- AGENT RESULTS ---")
    for finding in result.get("findings", []):
        logger.info(f"Agent Role: {finding.get('agent_role')}")
        logger.info(f"Summary:\n{finding.get('summary')}")
        logger.info(f"DFKG Refs: {finding.get('dfkg_refs')}")
        
        # Validation checks
        if "185.220.101.45" not in finding.get('summary', ''):
            logger.error("❌ Agent did not mention the IP.")
        else:
            logger.info("✅ Agent analyzed the IP.")
            
        if len(finding.get('dfkg_refs', [])) > 0:
            logger.info("✅ Agent found and cited DFKG UIDs.")
        else:
            logger.warning("⚠️ Agent did NOT cite any DFKG UIDs. Check graph data or queries.")

    logger.info("\n--- AGENT TRACES ---")
    for trace in result.get("agent_traces", []):
        logger.info(trace.get("thought", ""))

if __name__ == "__main__":
    run_test()
