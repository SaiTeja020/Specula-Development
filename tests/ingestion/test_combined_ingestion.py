import json
import pytest

from src.graph.cypher_builder import CypherBuilder

def test_cypher_idempotency_mft():
    event_dict = {
        "class_uid": 1001,
        "activity_id": 1,
        "file_path": "C:\\Windows\\System32\\suspicious.exe",
        "file_name": "suspicious.exe",
        "canonical_host_id": "uuid-local-host",
        "time": "2026-09-20T12:00:00Z",
        "uid": "test-uid-5678"
    }
    query, params = CypherBuilder.build_file_activity(event_dict)
    
    # Assert idempotency properties
    assert "MERGE (f:File {uid: $file_path})" in query
    assert "MERGE (host:Host {uid: $canonical_host_id})" in query
    assert "MERGE (host)-[r:CREATED {uid: $uid}]->(f)" in query
    assert "CREATE (f:File" not in query # Must not forcefully create duplicate nodes

def test_cypher_idempotency_pcap():
    event_dict = {
        "class_uid": 4001,
        "src_ip": "10.10.10.50",
        "dst_ip": "185.220.101.45",
        "protocol": "TCP",
        "time": "2026-09-20T12:00:00Z",
        "uid": "test-uid-1234"
    }
    query, params = CypherBuilder.build_network_activity(event_dict)
    
    assert "MERGE (src:NetworkEndpoint {uid: $src_ip})" in query
    assert "MERGE (dst:NetworkEndpoint {uid: $dst_ip})" in query
    assert "MERGE (src)-[r:COMMUNICATED_WITH {uid: $uid}]->(dst)" in query
    assert "CREATE (src:NetworkEndpoint" not in query
