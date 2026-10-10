"""Exercise the deployed local API with an already-ingested synthetic case.

Only ignored local verification credentials and local endpoints are used.
Run the fixture investigation oracle first to create the case evidence.
"""
import json
import argparse
from pathlib import Path
import threading
import time

import requests
from websockets.sync.client import connect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pause-only", action="store_true")
    options = parser.parse_args()
    from tests.api_auth_helpers import local_verification_headers
    headers = local_verification_headers()
    directory = Path("data/verification")
    directory.mkdir(parents=True, exist_ok=True)
    fixture = json.loads((directory / "local_case_latest.json").read_text())
    case_id = fixture["case_id"]
    assert case_id.startswith("VALIDATION-"), "Only synthetic validation cases are allowed"
    base = "http://127.0.0.1:8300"
    result = {"case_id": case_id, "target": base, "probes": {}, "events": [], "issues": []}
    output = directory / "deployed_application_latest.json"

    def save():
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")

    with requests.Session() as client:
        client.trust_env = False
        client.headers.update(headers)
        for endpoint in ("/health", "/api/system/readiness", "/api/data/faiss", "/api/data/duckdb",
                         "/api/data/chroma", "/api/data/quickwit", "/api/data/neo4j"):
            response = client.get(base + endpoint, timeout=30)
            body = response.json()
            probe = {"http_status": response.status_code, "status": body.get("status")}
            if endpoint.startswith("/api/data/") and not endpoint.endswith("neo4j"):
                assert response.status_code == 403, "Global store access must remain restricted"
            if endpoint.endswith("readiness"):
                probe["services"] = body.get("services")
                assert body["services"]["llm"]["backend"] == "ollama"
            if endpoint.endswith("faiss"):
                probe["total_vectors"] = body.get("total_vectors")
            result["probes"][endpoint] = probe
            if body.get("status") in ("unavailable", "not_ready", "error"):
                result["issues"].append("Unavailable: " + endpoint)
        response = client.post(base + "/api/investigations", json={"case_id": "MISSING-VALIDATION-CASE"}, timeout=30)
        result["missing_case_http_status"] = response.status_code
        save()
        stopped = threading.Event()
        with connect("ws://127.0.0.1:8300/api/graph/stream", additional_headers=headers, open_timeout=5, max_queue=None) as websocket:
            assert json.loads(websocket.recv(timeout=5))["type"] == "authenticated"
            def collect():
                while not stopped.is_set():
                    try:
                        event = json.loads(websocket.recv(timeout=1))
                        payload = event.get("payload", {})
                        if payload.get("case_id") == case_id:
                            result["events"].append({"type": event.get("type"), "node": payload.get("node")})
                    except TimeoutError:
                        continue
                    except Exception as error:
                        result["websocket_error"] = type(error).__name__
                        break
            listener = threading.Thread(target=collect, daemon=True)
            listener.start()
            started = time.monotonic()
            try:
                response = client.get(base + f"/api/investigations/{case_id}", timeout=30)
                result["existing_investigation"] = response.status_code == 200
                if response.status_code == 404:
                    response = client.post(base + "/api/investigations", json={"case_id": case_id,
                        "raw_input": "Investigate periodic network egress. FORCE_GUARDRAIL3_FAIL"}, timeout=600)
                result["investigation_http_status"] = response.status_code
                result["investigation_seconds"] = time.monotonic() - started
                if response.status_code == 200:
                    result["paused_snapshot"] = response.json()
                    save()
                    final = response.json()
                    if options.pause_only:
                        assert "hitl" in final.get("paused_at", []), "Expected durable review checkpoint"
                        result["restart_checkpoint_established"] = True
                        save()
                        return 0
                    if final.get("failed_nodes"):
                        retried = client.post(base + f"/api/investigations/{case_id}/retry", timeout=600)
                        retried.raise_for_status()
                        final = retried.json()
                        result["retried_failed_checkpoint"] = True
                        result["completed_snapshot"] = final
                        save()
                    approvals = 0
                    while "hitl" in final.get("paused_at", []) and approvals < 3:
                        reviewed = client.post(base + f"/api/investigations/{case_id}/review",
                            json={"decision": "approve"}, timeout=600)
                        result["review_http_status"] = reviewed.status_code
                        if reviewed.status_code == 200:
                            final = reviewed.json()
                            result["completed_snapshot"] = final
                            approvals += 1
                            save()
                        else:
                            result["issues"].append("Review request failed")
                            break
                    result["analyst_approvals"] = approvals
                    final = result.get("completed_snapshot", result["paused_snapshot"])
                    for trace in final.get("agent_traces", []):
                        if trace.get("terminal") is False:
                            result["issues"].append("Incomplete worker: " + trace["agent_role"])
                    result["attribution_degraded_flags"] = (final.get("attribution") or {}).get("degraded_flags", [])
                    result["case_status"] = final.get("case_status")
                    collection = final.get("evidence_collection") or {}
                    metadata = final.get("report_metadata") or {}
                    assert final.get("case_status") == "closed", "Investigation did not close; report checks deferred"
                    assert collection.get("status") == "complete", "Evidence collection incomplete"
                    assert set(metadata.get("dfkg_refs", [])) == set(collection.get("reference_uids", [])), "Report citations differ from evidence"
                    assert final.get("report_output", "").endswith("END OF SPECULA REPORT"), "Truncated report"
                    assert final.get("timeline_artifact", "").endswith("END OF SPECULA TIMELINE"), "Truncated timeline"
                    result["four_fix_assertions"] = {"evidence_complete": True, "report_cited_and_complete": True}
                else:
                    result["issues"].append("Investigation request failed")
            except requests.RequestException as error:
                result["issues"].append("Investigation transport error: " + type(error).__name__)
            finally:
                stopped.set()
                listener.join(timeout=2)
                result["total_seconds"] = time.monotonic() - started
                save()
    print(json.dumps({key: value for key, value in result.items()
                      if key not in {"paused_snapshot", "completed_snapshot", "events"}}, indent=2))
    return 1 if result["issues"] or result.get("case_status") != "closed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
