import asyncio
import base64
import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from src.agents import api_auth, visualizer_api
from tests.api_auth_helpers import configure_test_auth


@pytest.mark.parametrize("path", ["/api/data/neo4j", "/api/data/quickwit", "/api/data/chroma",
    "/api/graph/topology", "/api/system/readiness", "/api/investigations/PRIVATE", "/openapi.json"])
def test_anonymous_sensitive_access_rejected(path):
    assert TestClient(visualizer_api.app).get(path).status_code == 401


def test_liveness_and_preflight_public():
    client = TestClient(visualizer_api.app)
    assert client.get("/health").status_code == 200
    response = client.options("/api/data/neo4j", headers={"Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
    assert response.status_code == 200


def test_missing_policy_fails_closed(monkeypatch):
    monkeypatch.delenv("SPECULA_AUTH_POLICY_PATH", raising=False)
    response = TestClient(visualizer_api.app).get("/api/graph/topology",
        headers={"Authorization": "Bearer specula_local_" + "x" * 32})
    assert response.status_code == 503


def test_bad_and_expired_token_rejected(api_auth):
    client = TestClient(visualizer_api.app)
    assert client.get("/api/graph/topology", headers={"Authorization": "Bearer specula_local_" + "x" * 40}).status_code == 401
    import os
    from pathlib import Path
    path = Path(os.environ["SPECULA_AUTH_POLICY_PATH"])
    policy = json.loads(path.read_text())
    policy["local_tokens"][0]["expires_at"] = time.time() - 1
    path.write_text(json.dumps(policy))
    assert client.get("/api/graph/topology", headers=api_auth).status_code == 401


def test_positive_admin_access(api_auth):
    assert TestClient(visualizer_api.app).get("/api/graph/topology", headers=api_auth).status_code == 200


def test_viewer_cannot_review_or_start(monkeypatch, tmp_path):
    headers = configure_test_auth(monkeypatch, tmp_path, {"test-user": {"role": "viewer", "cases": ["C1"]}})
    client = TestClient(visualizer_api.app)
    assert client.post("/api/investigations/C1/review", json={"decision": "approve"}, headers=headers).status_code == 403
    assert client.post("/api/investigations", json={"case_id": "C1"}, headers=headers).status_code == 403


def test_other_case_and_global_store_access_denied(monkeypatch, tmp_path):
    headers = configure_test_auth(monkeypatch, tmp_path, {"test-user": {"role": "analyst", "cases": ["C1"]}})
    driver = SimpleNamespace(execute_query=lambda *args, **kwargs: ([], None, None))
    monkeypatch.setattr(visualizer_api, "_neo4j_driver", driver)
    client = TestClient(visualizer_api.app)
    assert client.get("/api/investigations/C2", headers=headers).status_code == 403
    assert client.get("/api/data/quickwit", headers=headers).status_code == 403


def test_owned_or_assigned_case_is_server_checked():
    principal = api_auth.Principal("USER", "analyst", (), time.time() + 60)
    calls = []
    def query(statement, **params):
        calls.append((statement, params))
        return ([{"uid": params["case_id"]}], None, None)
    assert api_auth.authorize(principal, "C1", write=True, driver=SimpleNamespace(execute_query=query)) == principal
    assert calls[0][1] == {"case_id": "C1", "subject": "USER"}
    assert "$subject" in calls[0][0] and "member_user_ids" in calls[0][0]
    with pytest.raises(HTTPException) as error:
        api_auth.authorize(principal, "C2")
    assert error.value.status_code == 403


def test_supabase_verified_identity_ignores_client_role(monkeypatch, tmp_path):
    import requests
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"principals": {}, "authenticated_users": "case_members"}))
    monkeypatch.setenv("SPECULA_AUTH_POLICY_PATH", str(path))
    monkeypatch.setenv("SPECULA_SUPABASE_URL", "https://approved.supabase.co")
    monkeypatch.setenv("SPECULA_SUPABASE_PUBLISHABLE_KEY", "public-key")
    claims = base64.urlsafe_b64encode(json.dumps({"exp": time.time() + 3600, "role": "admin"}).encode()).decode().rstrip("=")
    calls = []
    class Client:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, **kwargs):
            calls.append(url)
            return SimpleNamespace(status_code=200, json=lambda: {"id": "REAL-USER", "user_metadata": {"role": "admin"}})
    monkeypatch.setattr(requests, "Session", Client)
    principal = api_auth.verify_token("header." + claims + ".verified-provider-signature")
    assert principal.subject == "REAL-USER" and principal.role == "analyst" and principal.cases == ()
    assert calls == ["https://approved.supabase.co/auth/v1/user"]
    assert principal.session_token not in repr(principal)
    with pytest.raises(HTTPException):
        api_auth.authorize(principal, administrator=True)


def test_anonymous_websocket_closed(monkeypatch):
    monkeypatch.setattr(visualizer_api, "_get_neo4j_driver", lambda: None)
    with TestClient(visualizer_api.app).websocket_connect("/api/graph/stream") as socket:
        socket.send_json({"type": "ping"})
        with pytest.raises(WebSocketDisconnect):
            socket.receive_json()


def test_authenticated_websocket_and_origin(api_auth, monkeypatch):
    monkeypatch.setattr(visualizer_api, "_get_neo4j_driver", lambda: None)
    with TestClient(visualizer_api.app).websocket_connect("/api/graph/stream", headers=api_auth) as socket:
        assert socket.receive_json()["type"] == "authenticated"
        socket.send_text("ping")
        assert socket.receive_text() == "pong"
    with pytest.raises(WebSocketDisconnect):
        with TestClient(visualizer_api.app).websocket_connect("/api/graph/stream",
            headers={**api_auth, "Origin": "https://unapproved.example"}):
            pass


def test_case_stream_isolation(monkeypatch, tmp_path):
    configure_test_auth(monkeypatch, tmp_path, {"test-user": {"role": "analyst", "cases": ["C1"]}})
    sent = []
    class Socket:
        async def send_text(self, message): sent.append(json.loads(message))
    socket = Socket()
    principal = api_auth.Principal("test-user", "analyst", ("C1",), time.time() + 60)
    monkeypatch.setattr(visualizer_api, "active_connections", {socket})
    monkeypatch.setattr(visualizer_api, "connection_authorizations", {socket: (principal, "C1")})
    monkeypatch.setattr(visualizer_api, "_get_neo4j_driver", lambda: None)
    asyncio.run(visualizer_api.broadcast_event("node_complete", {"case_id": "C2"}))
    assert not sent
    asyncio.run(visualizer_api.broadcast_event("node_complete", {"case_id": "C1"}))
    assert len(sent) == 1 and sent[0]["payload"]["case_id"] == "C1"
