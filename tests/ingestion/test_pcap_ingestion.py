import io
import time
import socket
import dpkt
from datetime import datetime, timezone
import pytest

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.normalization.network_normalizer import normalize_pcap_stream
from src.ingestion.ingestion_consumer import IngestionPipelineConsumer
from src.graph.cypher_builder import CypherBuilder

def create_sample_pcap():
    f = io.BytesIO()
    writer = dpkt.pcap.Writer(f)
    
    tcp = dpkt.tcp.TCP(
        sport=49152,
        dport=443,
        flags=dpkt.tcp.TH_SYN,
        seq=1000,
        ack=0,
        win=8192,
        data=b"GET / HTTP/1.1\r\n\r\n"
    )
    
    ip = dpkt.ip.IP(
        v=4,
        hl=5,
        p=dpkt.ip.IP_PROTO_TCP,
        src=socket.inet_aton("10.10.10.50"),
        dst=socket.inet_aton("185.220.101.45"),
        data=tcp
    )
    ip.len = len(ip)
    
    eth = dpkt.ethernet.Ethernet(
        src=b'\x00\x11\x22\x33\x44\x55',
        dst=b'\x66\x77\x88\x99\xaa\xbb',
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip
    )
    
    ts = time.time()
    writer.writepkt(eth, ts)
    
    f.seek(0)
    return f

def test_pcap_normalizer():
    f = create_sample_pcap()
    time_normalizer = TimeNormalizer()
    events = list(normalize_pcap_stream(f, time_normalizer, "trace-pcap-test"))
    
    assert len(events) == 1
    event = events[0]
    
    assert event.src_ip == "10.10.10.50"
    assert event.dst_ip == "185.220.101.45"
    assert event.src_port == 49152
    assert event.dst_port == 443
    assert event.protocol == "TCP"
    assert event.bytes_out > 0
    assert event.activity_id == 1

def test_consumer_cypher_generation(monkeypatch):
    monkeypatch.setattr("src.ingestion.ingestion_consumer.NEO4J_ENABLED", False)
    class MockVectorStore:
        def upsert(self, *args, **kwargs):
            pass
            
    monkeypatch.setattr("src.ingestion.ingestion_consumer.ChromaVectorStore", lambda *args, **kwargs: MockVectorStore())
    
    consumer = IngestionPipelineConsumer()
    
    event_dict = {
        "class_uid": 4001,
        "src_ip": "10.10.10.50",
        "dst_ip": "185.220.101.45",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": "TCP",
        "time": "2026-09-20T12:00:00Z",
        "uid": "test-uid-1234"
    }
    
    
    class SpyCypher:
        called = False
        args = None
        @staticmethod
        def build_network_activity(evt):
            SpyCypher.called = True
            SpyCypher.args = evt
            return "MATCH (n) RETURN n", {}

    monkeypatch.setattr(CypherBuilder, "build_network_activity", SpyCypher.build_network_activity)
    
    consumer.process_event(event_dict)
    consumer.flush_batch()
    
    assert SpyCypher.called
    assert SpyCypher.args["src_ip"] == "10.10.10.50"
    assert SpyCypher.args["dst_ip"] == "185.220.101.45"
