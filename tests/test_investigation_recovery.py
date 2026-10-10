from typing import TypedDict

import pytest
from fastapi.testclient import TestClient
from langgraph.graph import StateGraph, START, END

from src.agents import visualizer_api
from src.agents.checkpointer import SQLiteCheckpointSaver
from tests.api_auth_helpers import configure_test_auth


class RecoveryState(TypedDict, total=False):
    case_id: str
    case_status: str
    counter: int


def make_graph(tmp_path, failing):
    saver = SQLiteCheckpointSaver(tmp_path / "recovery.sqlite3")
    attempts = []
    def work(state):
        attempts.append(True)
        if failing and len(attempts) == 1:
            raise RuntimeError("temporary dependency failure")
        return {"case_status": "closed", "counter": state.get("counter", 0) + 1}
    builder = StateGraph(RecoveryState)
    builder.add_node("work", work)
    builder.add_edge(START, "work")
    builder.add_edge("work", END)
    return builder.compile(checkpointer=saver), saver


def test_failed_checkpoint_retry_preserves_prior_work(api_auth, monkeypatch, tmp_path):
    graph, saver = make_graph(tmp_path, True)
    config = {"configurable": {"thread_id": "C1"}}
    with pytest.raises(RuntimeError):
        graph.invoke({"case_id": "C1", "case_status": "open", "counter": 7}, config)
    monkeypatch.setattr(visualizer_api, "_specula_graph", graph)
    monkeypatch.setattr(visualizer_api, "_neo4j_driver", None)
    monkeypatch.setattr(visualizer_api, "_get_neo4j_driver", lambda: None)
    client = TestClient(visualizer_api.app)
    snapshot = client.get("/api/investigations/C1", headers=api_auth).json()
    assert snapshot["failed_nodes"] == ["work"]
    result = client.post("/api/investigations/C1/retry", headers=api_auth)
    assert result.status_code == 200 and result.json()["case_status"] == "closed"
    assert graph.get_state(config).values["counter"] == 8
    assert client.post("/api/investigations/C1/retry", headers=api_auth).status_code == 409
    saver.close()


def test_retry_requires_case_write_access(monkeypatch, tmp_path):
    headers = configure_test_auth(monkeypatch, tmp_path, {"test-user": {"role": "viewer", "cases": ["C1"]}})
    monkeypatch.setattr(visualizer_api, "_get_neo4j_driver", lambda: None)
    client = TestClient(visualizer_api.app)
    assert client.post("/api/investigations/C1/retry").status_code == 401
    assert client.post("/api/investigations/C1/retry", headers=headers).status_code == 403
    headers = configure_test_auth(monkeypatch, tmp_path, {"test-user": {"role": "analyst", "cases": ["C1"]}})
    assert client.post("/api/investigations/C2/retry", headers=headers).status_code == 403
