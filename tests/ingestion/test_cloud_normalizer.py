import pytest
from src.ingestion.normalization.cloud_normalizer import normalize_gcp_audit
from src.ingestion.normalization.time_normalizer import TimeNormalizer

def test_normalize_gcp_audit():
    raw_event = {
        "insertId": "12345",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "methodName": "v1.compute.instances.insert",
            "serviceName": "compute.googleapis.com",
            "requestMetadata": {
                "callerIp": "198.51.100.45",
                "callerSuppliedUserAgent": "google-cloud-sdk/373.0.0"
            },
            "authenticationInfo": {
                "principalEmail": "admin@my-project.iam.gserviceaccount.com"
            }
        },
        "resource": {
            "type": "gce_instance",
            "labels": {
                "project_id": "my-project",
                "location": "us-central1-a",
                "instance_id": "837492837482"
            }
        },
        "timestamp": "2026-07-28T12:05:00Z"
    }

    time_normalizer = TimeNormalizer()
    trace_id = "test-trace"
    
    event = normalize_gcp_audit(raw_event, time_normalizer, trace_id)
    
    # Check field mappings
    assert event.cloud_provider == "GCP"
    assert event.cloud_region == "us-central1-a"
    assert event.cloud_account_id == "my-project"
    assert event.api_operation == "v1.compute.instances.insert"
    assert event.api_service == "compute.googleapis.com"
    assert event.source_ip == "198.51.100.45"
    assert event.user_identity == "admin@my-project.iam.gserviceaccount.com"
    
    # Check dual timestamps and unverified clock skew
    assert event.clock_skew_unverified is True
    assert event.clock_skew_offset_ms == 0
    assert event.raw_source_timestamp == "2026-07-28T12:05:00Z"
    assert event.time is not None
    
    # Check deterministic UID
    assert event.uid is not None
    assert event.uid != ""
    assert "PENDING_UID" not in event.uid
