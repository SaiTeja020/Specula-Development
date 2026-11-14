"""Project existing local checkpoint traces/reports into Neo4j, idempotently."""

from dotenv import load_dotenv
import requests

from src.agents.agent_graph import persist_case_execution
from src.agents.visualizer_api import _get_neo4j_driver


def main():
    load_dotenv()
    driver = _get_neo4j_driver()
    if driver is None:
        raise RuntimeError("Neo4j unavailable")
    with driver.session() as session:
        case_ids = [row["uid"] for row in session.run(
            "MATCH (c:Case {owner_user_id: 'local-validation'}) RETURN c.uid AS uid ORDER BY uid")]
    headers = {"Origin": "http://localhost:5173", "X-Specula-Local-Boot": "1"}
    with requests.Session() as client:
        client.trust_env = False
        for case_id in case_ids:
            response = client.get(f"http://127.0.0.1:8400/api/local/cases/{case_id}",
                                  headers=headers, timeout=30)
            if response.status_code == 404:
                print(f"{case_id}: no checkpoint")
                continue
            response.raise_for_status()
            snapshot = response.json()
            traces = snapshot.get("agent_traces") or []
            persist_case_execution(driver, case_id, traces,
                                   snapshot.get("findings") or [],
                                   snapshot.get("report_output"),
                                   snapshot.get("report_metadata"))
            print(f"{case_id}: {len(traces)} agent runs, report={bool(snapshot.get('report_output'))}")


if __name__ == "__main__":
    main()
