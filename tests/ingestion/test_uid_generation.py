import pytest
from src.ingestion.normalization.network_normalizer import normalize_zeek_conn, normalize_pcap_stream
from src.ingestion.normalization.mft_usn_normalizer import normalize_mft_record
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.indexing.vector_store import InMemoryVectorStore, EmbeddingGenerator
import io

from datetime import datetime, timezone

class MockTimeNormalizer(TimeNormalizer):
    def normalize(self, ts):
        return (datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc), 0, False)

def test_network_uid_determinism_and_uniqueness():
    tn = MockTimeNormalizer()
    
    event1 = {
        "ts": "2026-09-20T12:00:00Z",
        "id.orig_h": "10.0.0.1",
        "id.resp_h": "8.8.8.8",
        "id.orig_p": 12345,
        "id.resp_p": 53,
        "proto": "udp"
    }
    
    # Determinism
    norm1 = normalize_zeek_conn(event1, tn, "trace1")
    norm2 = normalize_zeek_conn(event1, tn, "trace1")
    assert norm1.uid == norm2.uid
    assert norm1.uid != "PENDING_UID"
    
    # Uniqueness
    event2 = event1.copy()
    event2["id.orig_h"] = "10.0.0.2"
    norm3 = normalize_zeek_conn(event2, tn, "trace1")
    assert norm1.uid != norm3.uid

def test_mft_uid_determinism_and_uniqueness():
    tn = MockTimeNormalizer()
    
    record1 = {
        "LastRecordChange": "2026-09-20T12:00:00Z",
        "FileName": "test.txt",
        "ParentPath": "C:\\temp",
        "UsnReasonCode": 256
    }
    
    # Determinism
    norm1 = normalize_mft_record(record1, tn, "trace1")
    norm2 = normalize_mft_record(record1, tn, "trace1")
    assert norm1.uid == norm2.uid
    assert norm1.uid != "PENDING_UID"
    
    # Uniqueness
    record2 = record1.copy()
    record2["FileName"] = "test2.txt"
    norm3 = normalize_mft_record(record2, tn, "trace1")
    assert norm1.uid != norm3.uid

@pytest.fixture
def mock_embedder():
    class DummyEmbedder(EmbeddingGenerator):
        def embed(self, text):
            return [0.1] * 384
    return DummyEmbedder()

def test_vector_store_collision_prevention(mock_embedder):
    store = InMemoryVectorStore()
    
    tn = MockTimeNormalizer()
    record1 = {
        "LastRecordChange": "2026-09-20T12:00:00Z",
        "FileName": "test.txt",
        "ParentPath": "C:\\temp",
        "UsnReasonCode": 256
    }
    record2 = record1.copy()
    record2["FileName"] = "test2.txt"
    
    norm1 = normalize_mft_record(record1, tn, "trace1")
    norm2 = normalize_mft_record(record2, tn, "trace1")
    
    store.upsert(norm1.uid, "text1", mock_embedder.embed("text1"), {})
    store.upsert(norm2.uid, "text2", mock_embedder.embed("text2"), {})
    
    # They should not overwrite each other
    assert store.count() == 2
