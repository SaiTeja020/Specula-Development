"""Live service gates. External failures are failures, never availability skips."""
import json
from pathlib import Path
import subprocess
import sys

import pytest
import requests
from tests.api_auth_helpers import local_verification_headers

pytestmark = pytest.mark.live_infra


def test_deployed_backing_services_are_ready():
    response = requests.get("http://localhost:8300/api/system/readiness", timeout=30, headers=local_verification_headers())
    response.raise_for_status()
    result = response.json()
    assert result["status"] == "success"
    for name in ("kafka", "neo4j", "quickwit", "redis", "chroma"):
        assert result["services"][name]["status"] == "ready", name
    assert requests.get("http://localhost:8081/subjects", timeout=5).status_code == 200


def test_deployed_api_websocket_and_frontend_assets():
    from websockets.sync.client import connect
    topology = requests.get("http://localhost:8300/api/graph/topology", timeout=20, headers=local_verification_headers())
    topology.raise_for_status()
    assert len(topology.json()["nodes"]) >= 23
    with connect("ws://localhost:8300/api/graph/stream", open_timeout=5,
                 additional_headers=local_verification_headers()) as socket:
        assert json.loads(socket.recv(timeout=5))["type"] == "authenticated"
        socket.send("ping")
        assert socket.recv(timeout=5) == "pong"
    frontend = requests.get("http://127.0.0.1:5173", timeout=5)
    assert frontend.status_code == 200 and "@vite/client" in frontend.text
    asset = requests.get("http://127.0.0.1:5173/src/contexts/PipelineContext.jsx", timeout=5)
    assert asset.status_code == 200 and "/api/investigations/" in asset.text
    # This is the actual asset/API contract, not proof of authenticated browser use.


@pytest.mark.parametrize("component", ["gcp", "gemini", "attribution"])
def test_external_ingestion_or_model_endpoint(component):
    result = subprocess.run([sys.executable, "scripts/check_external_services.py", component],
                            capture_output=True, text=True, timeout=45)
    evidence = json.loads(Path(f"data/verification/{component}_latest.json").read_text())
    assert result.returncode == 0, json.dumps(evidence)
    if component == "gcp":
        assert evidence.get("ingestion_verified"), "Authorized log access alone is not ingestion validation"
