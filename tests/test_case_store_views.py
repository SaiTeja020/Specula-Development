from src.agents import store_views


def test_monitor_counts_are_fetched_again_instead_of_static_placeholders(monkeypatch):
    from types import SimpleNamespace
    import chromadb
    import requests
    counts = {'one': 2, 'two': 3}
    client = SimpleNamespace(list_collections=lambda: list(counts),
                             get_collection=lambda name: SimpleNamespace(count=lambda: counts[name]))
    monkeypatch.setattr(chromadb, 'HttpClient', lambda **kwargs: client)
    first = store_views.chroma_view()
    counts['one'] = 7
    second = store_views.chroma_view()
    assert first['total_vectors'] == 5 and second['total_vectors'] == 10
    assert second['collection_counts'] == [{'name': 'one', 'count': 7}, {'name': 'two', 'count': 3}]
    assert 'recent_queries' not in second
    result = {'num_hits': 12, 'hits': [{'uid': 'actual-record'}]}
    monkeypatch.setattr(requests, 'post', lambda *args, **kwargs: SimpleNamespace(
        raise_for_status=lambda: None, json=lambda: result))
    first = store_views.quickwit_view()
    result['num_hits'] = 13
    second = store_views.quickwit_view()
    assert first['total_records'] == 12 and second['total_records'] == 13
    assert second['logs'] == [{'uid': 'actual-record'}] and second['display_limit'] == 10


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
    from src.ingestion.indexing import case_evidence
    monkeypatch.setattr(case_evidence, "case_chroma_view", lambda case_id: {"status": "success", "case_id": case_id})
    assert store_views.case_store_view("chroma", "CASE-A", saved)["case_id"] == "CASE-A"


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


def test_missing_case_vectors_are_not_hidden_by_historical_receipt(monkeypatch):
    from src.ingestion.indexing import case_evidence
    monkeypatch.setattr(case_evidence, 'case_chroma_view', lambda case_id: {
        'status': 'success', 'case_id': case_id, 'total_vectors': 0, 'total_events': 0})
    snapshot = {'ingestion_provenance': {'vector_index': {'status': 'verified', 'stored': 20}}}
    payload = store_views.case_store_view('chroma', 'CASE-A', snapshot)
    assert payload['total_vectors'] == 0
    assert 'historical indexing receipt' in payload['warning']
