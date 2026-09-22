import pytest
import json
from fastapi.testclient import TestClient
from src.agents.visualizer_api import app

client = TestClient(app)

def test_websocket_stream_connect_and_ping():
    with client.websocket_connect("/api/graph/stream") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        assert data == "pong"

def test_trigger_mock_run_broadcasts_to_websocket():
    # We will connect the websocket, then trigger the mock run and check if we receive events.
    # Because trigger_mock_run uses asyncio.sleep, in a synchronous TestClient, 
    # it might be tricky to test the whole stream synchronously without a real async test.
    # However, TestClient does allow testing websockets. Let's trigger it and read the first event.
    
    with client.websocket_connect("/api/graph/stream") as websocket:
        # Trigger the mock run
        response = client.post("/api/graph/run_mock")
        assert response.status_code == 200
        
        # We should receive the first event which is the __start__ node
        data = websocket.receive_text()
        event = json.loads(data)
        
        assert event["type"] == "node_active"
        assert event["payload"]["node"] == "__start__"
        assert event["payload"]["data"]["case_id"] == "C-1234"
