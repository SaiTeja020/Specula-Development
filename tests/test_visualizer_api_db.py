from fastapi.testclient import TestClient
from src.agents.visualizer_api import app

client = TestClient(app)

def test_neo4j_endpoint():
    response = client.get("/api/data/neo4j")
    assert response.status_code == 200
    assert response.json()["source"] == "neo4j"
    assert "nodes" in response.json()

def test_quickwit_endpoint():
    response = client.get("/api/data/quickwit")
    assert response.status_code == 200
    assert response.json()["source"] == "quickwit"
    assert "logs" in response.json()

def test_chroma_endpoint():
    response = client.get("/api/data/chroma")
    assert response.status_code == 200
    assert response.json()["source"] == "chromadb"

def test_duckdb_endpoint():
    response = client.get("/api/data/duckdb")
    assert response.status_code == 200
    assert response.json()["source"] == "duckdb"

def test_faiss_endpoint():
    response = client.get("/api/data/faiss")
    assert response.status_code == 200
    assert response.json()["source"] == "faiss"
