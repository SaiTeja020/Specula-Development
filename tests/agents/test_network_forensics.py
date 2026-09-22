import pytest
from typing import Dict, Any
from collections import namedtuple

from src.agents.network_forensics.state import NetworkForensicsState
from src.agents.network_forensics.anomaly_detector import analyze_network_events
from src.agents.network_forensics.agent import run_network_forensics_analysis

class MockEvent:
    def __init__(self, uid: str, canonical_host_id: str, payload: Dict[str, Any]):
        self.uid = uid
        self.canonical_host_id = canonical_host_id
        for k, v in payload.items():
            setattr(self, k, v)
            
    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

class MockKafkaProducer:
    def __init__(self):
        self.messages = []
        
    def produce(self, topic: str, key: bytes, value: bytes):
        self.messages.append((topic, key, value))

class MockDeps:
    def __init__(self, events: Dict[str, MockEvent], case_id_mapping: Dict[str, str]):
        self._events = events
        self._case_id_mapping = case_id_mapping
        self.kafka_producer = MockKafkaProducer()
        
    def fetch_event(self, uid: str):
        return self._events[uid]
        
    def lookup_case_id(self, uid: str):
        return self._case_id_mapping[uid]

def test_detect_c2_beaconing():
    events = [
        {"class_uid": 4001, "uid": f"e{i}", "time": 1000 + i * 60, "src_endpoint": {"ip": "10.0.0.1"}, "dst_endpoint": {"ip": "185.220.101.34", "port": 443}}
        for i in range(5)
    ]
    # Adding jitter to timestamps
    events[1]["time"] += 2
    events[2]["time"] -= 3
    events[3]["time"] += 1
    
    anomalies = analyze_network_events(events)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "C2 Beaconing"
    assert anomalies[0]["technique"] == "T1071"
    assert anomalies[0]["severity_id"] == 4
    
def test_detect_dns_tunneling():
    events = [
        {
            "class_uid": 4001,
            "uid": "e1",
            "dns": {
                "query": "a" * 10, # low entropy, short
                "query_type": "TXT"
            }
        },
        {
            "class_uid": 4001,
            "uid": "e2",
            "dns": {
                "query": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345", # long, random
                "query_type": "TXT"
            }
        }
    ]
    
    anomalies = analyze_network_events(events)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "DNS Tunneling"
    assert anomalies[0]["technique"] == "T1071.004"
    assert anomalies[0]["severity_id"] == 5
    
def test_detect_data_exfiltration():
    events = [
        {"class_uid": 4001, "uid": "e1", "dst_endpoint": {"ip": "8.8.8.8"}, "traffic": {"bytes_out": 2_000_000}},
        {"class_uid": 4001, "uid": "e2", "dst_endpoint": {"ip": "9.9.9.9"}, "traffic": {"bytes_out": 800_000}},
        {"class_uid": 4001, "uid": "e3", "dst_endpoint": {"ip": "9.9.9.9"}, "traffic": {"bytes_out": 700_000}}, # Cumulative > 1M
        {"class_uid": 4001, "uid": "e4", "dst_endpoint": {"ip": "9.9.9.9"}, "traffic": {"bytes_out": 700_000}},
        {"class_uid": 4001, "uid": "e5", "dst_endpoint": {"ip": "9.9.9.9"}, "traffic": {"bytes_out": 700_000}},
        {"class_uid": 4001, "uid": "e6", "dst_endpoint": {"ip": "9.9.9.9"}, "traffic": {"bytes_out": 700_000}},
        {"class_uid": 4001, "uid": "e7", "dst_endpoint": {"ip": "9.9.9.9"}, "traffic": {"bytes_out": 700_000}},
        {"class_uid": 4001, "uid": "e8", "dst_endpoint": {"ip": "9.9.9.9"}, "traffic": {"bytes_out": 700_000}},
    ]
    
    anomalies = analyze_network_events(events)
    # Expected: 1 single event exfil (e1), 1 cumulative exfil (9.9.9.9)
    assert len(anomalies) == 2
    types = [a["type"] for a in anomalies]
    assert "Data Exfiltration" in types
    assert "Cumulative Data Exfiltration" in types

def test_agent_multi_case_raises():
    state = NetworkForensicsState(
        case_id="case_1",
        trace_id="t1",
        batch_uids=["u1", "u2"],
        iteration_count=0,
        max_iterations=1,
        dead_end=False,
        anomalies_detected=[],
        status="pending"
    )
    deps = MockDeps(
        events={},
        case_id_mapping={"u1": "case_1", "u2": "case_2"}
    )
    with pytest.raises(ValueError, match="multiple case_ids"):
        run_network_forensics_analysis(state, deps)
        
def test_agent_multi_host_raises():
    state = NetworkForensicsState(
        case_id="case_1",
        trace_id="t1",
        batch_uids=["u1", "u2"],
        iteration_count=0,
        max_iterations=1,
        dead_end=False,
        anomalies_detected=[],
        status="pending"
    )
    e1 = MockEvent("u1", "host_A", {})
    e2 = MockEvent("u2", "host_B", {})
    deps = MockDeps(
        events={"u1": e1, "u2": e2},
        case_id_mapping={"u1": "case_1", "u2": "case_1"}
    )
    with pytest.raises(ValueError, match="multiple hosts"):
        run_network_forensics_analysis(state, deps)

def test_agent_success():
    state = NetworkForensicsState(
        case_id="case_1",
        trace_id="t1",
        batch_uids=["u1"],
        iteration_count=0,
        max_iterations=1,
        dead_end=False,
        anomalies_detected=[],
        status="pending"
    )
    e1 = MockEvent("u1", "host_A", {
        "class_uid": 4001,
        "dns": {"query": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345", "query_type": "TXT"}
    })
    deps = MockDeps(
        events={"u1": e1},
        case_id_mapping={"u1": "case_1"}
    )
    
    new_state = run_network_forensics_analysis(state, deps)
    
    assert new_state["status"] == "complete"
    assert len(new_state["anomalies_detected"]) == 1
    assert len(deps.kafka_producer.messages) == 1
    topic, key, value = deps.kafka_producer.messages[0]
    assert topic == "findings.network_forensics"
