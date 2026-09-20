import logging
import os
import sys

sys.path.insert(0, os.path.abspath("."))

from src.agents.timeline_reconstruction_agent import make_timeline_reconstruction_node
from src.graph.neo4j_client import Neo4jClient

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("TimelineReconIntegration")

os.environ["SPECULA_LLM_BACKEND"] = "gemini"

env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(env_path):
    with open(env_path, "r") as f:
        for line in f:
            if line.startswith("GEMINI_API_KEY="):
                os.environ["GEMINI_API_KEY"] = line.split("=", 1)[1].strip()

def run_test():
    logger.info("=== TIMELINE RECONSTRUCTION INTEGRATION TEST (PHASE H.3) ===")
    neo4j = Neo4jClient()
    
    node = make_timeline_reconstruction_node(redis_client=None, neo4j_driver=neo4j)

    # Let's seed a case timeline describing a process and an auth event.
    # The agent should query the DFKG to find the events and build a timeline.
    state = {
        "case_id": "case-timeline-999",
        "timeline": {
            "summary": "We observed a network connection followed by a suspicious process creation. Chronologically reconstruct this."
        }
    }
    
    logger.info("\n--- INVOKING AGENT ---")
    result = node(state)
    logger.info("\n--- AGENT RESULTS ---")
    
    timeline = result.get("timeline", {})
    logger.info(f"Timeline Summary:\n{timeline.get('summary')}")
    logger.info(f"DFKG Refs: {timeline.get('dfkg_refs')}")
    
    if len(timeline.get('dfkg_refs', [])) > 0:
        logger.info("✅ Agent found and cited DFKG UIDs for the timeline.")
    else:
        logger.warning("⚠️ Agent did NOT cite any DFKG UIDs. Check graph data or queries.")

if __name__ == "__main__":
    run_test()
