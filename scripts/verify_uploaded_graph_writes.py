"""Verify uploaded evidence writes in live Neo4j, then roll back every test write.

Run: python -m scripts.verify_uploaded_graph_writes [archive.zip]
Preservation/security are isolated here; this checks actual database writes only.
"""
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from scripts.local_case_pipeline import ingest_uploaded_case
from src.graph.cypher_builder import CypherBuilder
from src.graph.neo4j_client import Neo4jClient
from src.ingestion.upload_archive import validate_archive


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "evidence.zip")
    receipt = validate_archive(path.read_bytes())
    case = "VERIFY-ROLLBACK-" + uuid4().hex
    client = Neo4jClient()
    try:
        with client._driver.session() as session:
            tx = session.begin_transaction()
            accepted_uids = set()
            class TransactionGraph:
                def execute(self, query, params):
                    if params.get("event_uid") and params.get("properties"):
                        accepted_uids.add(params["event_uid"])
                    return [dict(row) for row in tx.run(query, params)]
                def close(self):
                    pass
            try:
                placeholders = tx.run('MATCH (h:Host {uid:"UNKNOWN_HOST"}) RETURN count(h) AS n').single()["n"]
                quickwit = SimpleNamespace(ensure_index=lambda: None, commit_raw_evidence=lambda **values: None)
                with patch("src.graph.neo4j_client.Neo4jClient", TransactionGraph), patch(
                        "src.ingestion.preservation.quickwit_client.QuickwitClient", return_value=quickwit), patch(
                        "src.ingestion.run_pipeline.run_security_gate", return_value=SimpleNamespace(injection_blocked=False)), patch(
                        "src.ingestion.normalization.evtx_normalizer.detect_prompt_injection", return_value=(False, True)), patch(
                        "src.ingestion.normalization.cloud_normalizer.detect_prompt_injection", return_value=(False, True)), patch(
                        "src.ingestion.normalization.mft_usn_normalizer.detect_prompt_injection", return_value=(False, True)):
                    result = ingest_uploaded_case(case, path, receipt, "", "", 5000, [])
                events = tx.run("MATCH (:Case {uid:$case})-[:HAS_EVENT]->(e:Event) RETURN count(e) AS n",
                                case=case).single()["n"]
                assert events == len(accepted_uids) <= result["accepted"]
                for row in tx.run("MATCH (:Case {uid:$case})-[:HAS_EVENT]->(e:Event) RETURN e", case=case):
                    import json
                    event = dict(row["e"])
                    context = json.loads(event.get("unmapped", "{}" ) or "{}").get("source_context", {})
                    if context.get("host"):
                        assert event.get("canonical_host_id") == "host-"+context["host"]
                for cls in (1007, 1001, 2004, 3001, 2005, 2002, 4002, 3002):
                    event = {"uid": case + str(cls), "class_uid": cls, "case_id": case,
                             "time": "2026-10-13T10:00:00Z", "trace_id": "verification",
                             "canonical_host_id": None, "user": {"name": case},
                             "process_name": "fixture", "parent_process_uid": None,
                             "file_name": "fixture.txt", "finding_title": "Fixture source finding",
                             "vulnerability_id": "CVE-TEST", "incident_title": "Fixture incident"}
                    query, params = CypherBuilder.dispatch_event(event)
                    assert params["canonical_host_id"] is None
                    list(tx.run(query, params))
                    event["canonical_host_id"] = case + "-host"
                    query, params = CypherBuilder.dispatch_event(event)
                    list(tx.run(query, params))
                assert tx.run('MATCH (h:Host {uid:"UNKNOWN_HOST"}) RETURN count(h) AS n').single()["n"] == placeholders
                print({"live_case_events": events, "normalized_outputs": result["accepted"], "excluded_records": result["excluded_records"],
                       "host_templates_verified": 8})
            finally:
                tx.rollback()
        assert client.execute_read("MATCH (c:Case {uid:$case}) RETURN count(c) AS n", {"case": case})[0]["n"] == 0
        print("Live graph write verification passed; transaction rolled back, no test case retained.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
