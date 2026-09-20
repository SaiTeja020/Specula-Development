import logging
import os
import sys

sys.path.insert(0, os.path.abspath("."))

from src.agents.log_analysis_agent import make_log_analysis_node
from src.graph.neo4j_client import Neo4jClient

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("LogAnalysisIntegration")

os.environ["SPECULA_LLM_BACKEND"] = "gemini"

env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(env_path):
    with open(env_path, "r") as f:
        for line in f:
            if line.startswith("GEMINI_API_KEY="):
                os.environ["GEMINI_API_KEY"] = line.split("=", 1)[1].strip()

def run_test():
    logger.info("=== LOG ANALYSIS INTEGRATION TEST (PHASE H.2) ===")
    neo4j = Neo4jClient()
    
    node = make_log_analysis_node(redis_client=None, neo4j_driver=neo4j)

    # Let's seed a case timeline describing suspicious authentication or process execution.
    # The agent should query the DFKG to find the event.
    state = {
        "case_id": "case-log-999",
        "timeline": {
            "summary": "Suspicious login from Administrator observed. Analyze this event."
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
        if len(finding.get('dfkg_refs', [])) > 0:
            logger.info("✅ Agent found and cited DFKG UIDs.")
        else:
            logger.warning("⚠️ Agent did NOT cite any DFKG UIDs. Check graph data or queries.")

if __name__ == "__main__":
    run_test()
