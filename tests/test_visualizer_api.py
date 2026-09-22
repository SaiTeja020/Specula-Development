import pytest
from fastapi.testclient import TestClient
from src.agents.visualizer_api import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    # Verify CORS headers
    assert "access-control-allow-origin" in response.headers
    assert response.headers["access-control-allow-origin"] in ["*", "http://localhost:5173"]

def test_get_topology():
    response = client.get("/api/graph/topology")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    # Basic check to ensure it returns nodes
    assert len(data["nodes"]) > 0
    # ensure structure
    assert "id" in data["nodes"][0]
    assert "position" in data["nodes"][0]
    assert "data" in data["nodes"][0]

def test_cors_preflight():
    response = client.options(
        "/api/graph/topology",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
