import pytest
import json
from fastapi.testclient import TestClient
from src.agents.visualizer_api import app, broadcast_event

client = TestClient(app)

def test_websocket_stream_connect_and_ping():
    with client.websocket_connect("/api/graph/stream") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        assert data == "pong"

def test_broadcast_reaches_connected_websocket():
    with TestClient(app) as active_client, active_client.websocket_connect("/api/graph/stream") as websocket:
        websocket.send_text("ping")
        assert websocket.receive_text() == "pong"
        active_client.portal.call(broadcast_event, "node_active", {
            "node": "__start__", "data": {"case_id": "C-1234"},
        })
        data = websocket.receive_text()
        event = json.loads(data)
        
        assert event["type"] == "node_active"
        assert event["payload"]["node"] == "__start__"
        assert event["payload"]["data"]["case_id"] == "C-1234"
