from fastapi.testclient import TestClient
from src.agents.visualizer_api import app

client = TestClient(app)

def test_neo4j_endpoint(api_auth):
    response = client.get("/api/data/neo4j", headers=api_auth)
    assert response.status_code == 200
    assert response.json()["source"] == "neo4j"
    assert "nodes" in response.json()


def test_neo4j_unavailable_retains_store_contract(api_auth, monkeypatch):
    monkeypatch.setattr("src.agents.visualizer_api._get_neo4j_driver", lambda: None)
    response = client.get("/api/data/neo4j", headers=api_auth)
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "unavailable"
    assert payload["source"] == "neo4j"
    assert payload["nodes"] == payload["edges"] == []

def test_quickwit_endpoint(api_auth):
    response = client.get("/api/data/quickwit", headers=api_auth)
    assert response.status_code == 200
    assert response.json()["source"] == "quickwit"
    assert "logs" in response.json()

def test_chroma_endpoint(api_auth):
    response = client.get("/api/data/chroma", headers=api_auth)
    assert response.status_code == 200
    assert response.json()["source"] == "chromadb"

def test_duckdb_endpoint(api_auth):
    response = client.get("/api/data/duckdb", headers=api_auth)
    assert response.status_code == 200
    assert response.json()["source"] == "duckdb"

def test_faiss_endpoint(api_auth):
    response = client.get("/api/data/faiss", headers=api_auth)
    assert response.status_code == 200
    assert response.json()["source"] == "faiss"
