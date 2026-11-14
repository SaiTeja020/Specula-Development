"""Verify local case authorization and identical checkpoints across API restarts."""
import argparse
import hashlib
import json
import time
from pathlib import Path

import requests
from tests.api_auth_helpers import local_verification_headers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["capture", "verify", "closed"])
    phase = parser.parse_args().phase
    directory = Path("data/verification")
    fixture = json.loads((directory / "local_case_latest.json").read_text())
    case = fixture["case_id"]
    assert case.startswith("VALIDATION-")
    path = directory / "restart_recovery_latest.json"
    with requests.Session() as client:
        client.trust_env = False
        headers = local_verification_headers()
        for base, endpoint in [("http://127.0.0.1:8300", f"/api/investigations/{case}"),
                               ("http://127.0.0.1:8200", f"/hitl/{case}")]:
            deadline = time.monotonic() + 45
            while True:
                try:
                    response = client.get(base + endpoint, timeout=5)
                    break
                except requests.ConnectionError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.5)
            assert response.status_code == 401
            other = "/api/investigations/OTHER-CASE" if base.endswith("8300") else "/hitl/OTHER-CASE"
            assert client.get(base + other, headers=headers, timeout=30).status_code == 403
            response = client.get(base + endpoint, headers=headers, timeout=30)
            response.raise_for_status()
            snapshot = response.json()
            assert snapshot["case_id"] == case
            if phase != "closed":
                assert "hitl" in snapshot["paused_at"]
            else:
                assert snapshot["case_status"] == "closed"
            if base.endswith("8300"):
                full = snapshot
        digest = hashlib.sha256(json.dumps(full, sort_keys=True).encode()).hexdigest()
        if phase == "capture":
            result = {"case_id": case, "paused_snapshot_sha256": digest,
                      "both_gateways_share_pause": True, "anonymous_http": 401, "other_case_http": 403}
        else:
            result = json.loads(path.read_text())
            if phase == "verify":
                assert digest == result["paused_snapshot_sha256"], "Restart changed or lost checkpoint"
                result["paused_snapshot_identical_after_docker_restart"] = True
            else:
                assert full["evidence_collection"]["status"] == "complete"
                assert set(full["report_metadata"]["dfkg_refs"]) == set(fixture["event_uids"])
                assert full["report_output"].endswith("END OF SPECULA REPORT")
                assert full["timeline_artifact"].endswith("END OF SPECULA TIMELINE")
                result["resumed_and_closed"] = True
                result["report_cites_all_original_events"] = True
                result["acceptance_status"] = full["acceptance_status"]
        path.write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
