import json
import os
import pytest

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.normalization.mft_usn_normalizer import normalize_mft_record
from src.schemas.ocsf_phase2_events import FileActivityEvent
from src.ingestion.ingestion_consumer import IngestionPipelineConsumer
from src.graph.cypher_builder import CypherBuilder

MFT_FIXTURE = {
    "LastRecordChange": "2026-09-20T12:00:00Z",
    "FileName": "suspicious.exe",
    "ParentPath": "C:\\Windows\\System32",
    "Created0x10": "2026-09-20T11:50:00Z",
    "Created0x30": "2026-09-20T11:55:00Z",
    "UsnReasonCode": 256,
    "TimestampPrecision": 1
}

def test_mft_normalizer():
    time_normalizer = TimeNormalizer()
    event = normalize_mft_record(MFT_FIXTURE, time_normalizer, "trace-mft-test")
    
    # 2. normalized event has class_uid 1001
    assert event.class_uid == 1001
    assert event.file_name == "suspicious.exe"
    assert event.file_path == "C:\\Windows\\System32"
    
    # 3. forensic timestamp fields survive normalization
    # TimeNormalizer returns (utc_time, skew, unverified), so si_created is a string or dt depending on normalize
    # wait, time_normalizer returns (str, int, bool) typically.
    assert event.si_created is not None
    assert event.fn_created is not None
    
    # 4. USN reason code survives normalization
    assert event.usn_reason_code == 256
    
    # 7. deterministic UID is preserved (previously set to PENDING_UID)
    assert event.uid != "PENDING_UID"
    assert event.uid is not None

def test_consumer_file_cypher_generation(monkeypatch):
    monkeypatch.setattr("src.ingestion.ingestion_consumer.NEO4J_ENABLED", False)
    class MockVectorStore:
        def upsert(self, *args, **kwargs):
            self.last_upsert = kwargs
            
    mock_vs = MockVectorStore()
    monkeypatch.setattr("src.ingestion.ingestion_consumer.ChromaVectorStore", lambda *args, **kwargs: mock_vs)
    
    consumer = IngestionPipelineConsumer()
    
    event_dict = {
        "class_uid": 1001,
        "activity_id": 1,
        "file_path": "C:\\Windows\\System32\\suspicious.exe",
        "file_name": "suspicious.exe",
        "canonical_host_id": "uuid-local-host",
        "si_created": "2026-09-20T11:50:00Z",
        "fn_created": "2026-09-20T11:55:00Z",
        "usn_reason_code": 256,
        "time": "2026-09-20T12:00:00Z",
        "uid": "test-uid-5678",
        "case_id": "test-case-id"
    }
    
    class SpyCypher:
        called = False
        args = None
        @staticmethod
        def build_file_activity(evt):
            SpyCypher.called = True
            SpyCypher.args = evt
            return "MATCH (n) RETURN n", {}

    monkeypatch.setattr(CypherBuilder, "build_file_activity", SpyCypher.build_file_activity)
    
    consumer.process_event(event_dict)
    consumer.flush_batch()
    
    # 5. FileActivity routes to CypherBuilder
    assert SpyCypher.called
    assert SpyCypher.args["file_path"] == "C:\\Windows\\System32\\suspicious.exe"
    
    # 6. semantic text contains meaningful file evidence
    assert hasattr(mock_vs, 'last_upsert')
    text = mock_vs.last_upsert['text']
    assert "File activity observed:" in text
    assert "path=C:\\Windows\\System32\\suspicious.exe" in text
    assert "action=CREATED" in text
    assert "SI creation time=2026-09-20T11:50:00Z" in text
    assert "FN creation time=2026-09-20T11:55:00Z" in text
    assert "USN reason=256" in text
