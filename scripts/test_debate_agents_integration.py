"""Phase H.4 Debate Layer Integration Test.

Runs Proponent → Critic → Judge against actual DFKG evidence.
Does NOT mock the LLM or the graph — uses the configured Gemini model.
If LLM quota is exhausted, reports exactly what was blocked.

Usage:
    python scripts/test_debate_agents_integration.py
"""
import logging
import os
import sys

sys.path.insert(0, os.path.abspath("."))

# Load env
env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, _, v = line.strip().partition("=")
                os.environ.setdefault(k, v)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("DebateIntegration")


def run_test():
    logger.info("=== DEBATE LAYER INTEGRATION TEST (PHASE H.4) ===\n")

    from src.graph.neo4j_client import Neo4jClient
    from src.agents.debate_agents import make_proponent_node, make_critic_node, make_judge_node

    neo4j = Neo4jClient()
    logger.info("Neo4j connected: %s", neo4j._driver)

    # Build a state with real investigation context from existing data
    state = {
        "case_id": "integration-debate-001",
        "raw_input": "",
        "timeline": {
            "summary": (
                "OBSERVED: Suspicious process cmd.exe spawned by svchost.exe. "
                "OBSERVED: Outbound TCP connection to 185.220.101.45:443 shortly after. "
                "CORRELATION: Process creation preceded network event by ~3 seconds. "
                "INFERENCE: Possible C2 beacon or automated outbound communication."
            )
        },
        "attribution": {
            "summary": (
                "DFKG contains NetworkActivity relationship to known Tor exit node 185.220.101.45. "
                "No confirmed MITRE ATT&CK mapping available from threat intelligence."
            )
        },
        "findings": [
            {
                "agent_role": "network_forensics",
                "summary": "Outbound connection to 185.220.101.45:443 [uid=net-001]",
                "dfkg_refs": ["net-001"],
            },
            {
                "agent_role": "log_analysis",
                "summary": "cmd.exe process created at 2026-09-20T10:00:01Z [uid=proc-001]",
                "dfkg_refs": ["proc-001"],
            },
        ],
        "debate_round": 1,
        "debate_history": [],
    }

    # --- PROPONENT ---
    logger.info("--- PROPONENT AGENT ---")
    proponent_node = make_proponent_node(redis_client=None, neo4j_driver=neo4j._driver)
    try:
        proponent_result = proponent_node(state)
        proponent_arg = proponent_result["proponent_argument"]
        proponent_uids = proponent_result["findings"][0]["dfkg_refs"]
        logger.info("Proponent argument:\n%s", proponent_arg[:600])
        logger.info("Proponent DFKG refs: %s", proponent_uids)
        state["proponent_argument"] = proponent_arg
        state["findings"] = state["findings"] + proponent_result["findings"]
    except Exception as e:
        logger.error("PROPONENT FAILED: %s", e)
        proponent_arg = f"BLOCKED: {e}"
        state["proponent_argument"] = proponent_arg

    # --- CRITIC ---
    logger.info("\n--- CRITIC AGENT ---")
    critic_node = make_critic_node(redis_client=None, neo4j_driver=neo4j._driver)
    try:
        critic_result = critic_node(state)
        critic_arg = critic_result["critic_argument"]
        critic_uids = critic_result["findings"][0]["dfkg_refs"]
        logger.info("Critic argument:\n%s", critic_arg[:600])
        logger.info("Critic DFKG refs: %s", critic_uids)
        state["critic_argument"] = critic_arg
        state["findings"] = state["findings"] + critic_result["findings"]
    except Exception as e:
        logger.error("CRITIC FAILED: %s", e)
        critic_arg = f"BLOCKED: {e}"
        state["critic_argument"] = critic_arg

    # --- JUDGE ---
    logger.info("\n--- JUDGE AGENT ---")
    judge_node = make_judge_node(redis_client=None, neo4j_driver=neo4j._driver)
    try:
        judge_result = judge_node(state)
        verdict = judge_result.update.get("judge_verdict")
        outcome = judge_result.update.get("debate_outcome")
        judge_summary = judge_result.update["findings"][0]["summary"]
        logger.info("Judge verdict: %s", verdict)
        logger.info("Debate outcome: %s", outcome)
        logger.info("Judge routing: → %s", judge_result.goto)
        logger.info("Judge reasoning:\n%s", judge_summary[:600])
    except Exception as e:
        logger.error("JUDGE FAILED: %s", e)
        return

    logger.info("\n=== INTEGRATION SUMMARY ===")
    if proponent_arg.startswith("BLOCKED") or critic_arg.startswith("BLOCKED"):
        logger.warning("⚠️  One or more agents were blocked (LLM quota / connectivity).")
    else:
        logger.info("✅ Full debate cycle completed: Proponent → Critic → Judge")
        logger.info("   Verdict: %s | Outcome: %s | Routing: → %s",
                    verdict, outcome, judge_result.goto)


if __name__ == "__main__":
    run_test()
