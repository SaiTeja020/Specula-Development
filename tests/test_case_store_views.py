from src.agents import store_views


def test_case_store_never_uses_global_evidence(monkeypatch):
    calls = []
    monkeypatch.setattr(store_views, "quickwit_view", lambda query, max_hits: calls.append((query, max_hits)) or
                        {"status": "success", "logs": []})
    empty = store_views.case_store_view("quickwit", "CASE-A", {})
    assert empty["logs"] == [] and calls == []
    saved = {"evidence_collection": {"records": [
        {"uid": "normalized-event", "trace_id": "case-a-trace"},
        {"uid": "legacy-preserved-id"},
    ]}}
    result = store_views.case_store_view("quickwit", "CASE-A", saved)
    assert result["case_id"] == "CASE-A" and result["scope"] == "case"
    assert calls == [('trace_id:"case-a-trace" OR uid:"legacy-preserved-id"', 300)]
    assert store_views.case_store_view("chroma", "CASE-A", saved)["status"] == "unavailable"


def test_saved_case_stores_enforce_case_access(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from fastapi.testclient import TestClient
    from src.agents import visualizer_api
    from tests.api_auth_helpers import configure_test_auth

    headers = configure_test_auth(monkeypatch, tmp_path,
                                  {"test-user": {"role": "viewer", "cases": ["CASE-A"]}})
    monkeypatch.setattr(visualizer_api, "_neo4j_driver", SimpleNamespace(
        execute_query=lambda *args, **kwargs: ([], None, None)))
    monkeypatch.setattr(visualizer_api, "_specula_graph", SimpleNamespace(
        get_state=lambda config: SimpleNamespace(
            values={"case_id": config["configurable"]["thread_id"]}, next=(), tasks=())))
    client = TestClient(visualizer_api.app)
    assert client.get("/api/investigations/CASE-A/stores/quickwit").status_code == 401
    assert client.get("/api/investigations/CASE-B/stores/quickwit", headers=headers).status_code == 403
    allowed = client.get("/api/investigations/CASE-A/stores/quickwit", headers=headers)
    assert allowed.status_code == 200 and allowed.json()["case_id"] == "CASE-A"
    assert allowed.json()["logs"] == []
