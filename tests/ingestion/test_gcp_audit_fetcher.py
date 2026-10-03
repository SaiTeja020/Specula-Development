import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
import json
from src.ingestion.extractors.gcp_audit_fetcher import GCPAuditFetcher
from src.ingestion.preservation.sha256_hasher import compute_sha256_bytes
from src.ingestion.normalization.cloud_normalizer import normalize_gcp_audit
from src.ingestion.normalization.time_normalizer import TimeNormalizer

@patch("src.ingestion.extractors.gcp_audit_fetcher.logging_v2.Client")
def test_fetch_audit_logs_filter(mock_client_cls):
    # Setup mock
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    
    mock_entry = MagicMock()
    mock_entry.to_dict.return_value = {"protoPayload": {"@type": "test"}}
    mock_client.list_entries.return_value = [mock_entry]

    fetcher = GCPAuditFetcher(project_id="test-project")
    
    start_time = datetime(2026, 9, 22, 0, 0, tzinfo=timezone.utc)
    end_time = datetime(2026, 9, 22, 2, 0, tzinfo=timezone.utc)
    
    results = list(fetcher.fetch_audit_logs(start_time, end_time))
    
    # Assert filter string
    mock_client.list_entries.assert_called_once()
    called_kwargs = mock_client.list_entries.call_args.kwargs
    
    assert 'filter_' in called_kwargs
    filter_expr = called_kwargs['filter_']
    assert 'timestamp >= "2026-09-22T00:00:00Z"' in filter_expr
    assert 'timestamp <= "2026-09-22T02:00:00Z"' in filter_expr
    assert 'logName:"cloudaudit.googleapis.com"' in filter_expr
    assert called_kwargs['resource_names'] == ["projects/test-project"]

@patch("src.ingestion.extractors.gcp_audit_fetcher.logging_v2.Client")
def test_fetch_audit_logs_pipeline_integration(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    
    sample_cloud = {
        "insertId": "12345",
        "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
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

    mock_entry = MagicMock()
    mock_entry.to_dict.return_value = sample_cloud
    del mock_entry.to_api_repr # Ensure it falls back to to_dict in our code
    
    mock_client.list_entries.return_value = [mock_entry]

    fetcher = GCPAuditFetcher(project_id="test-project")
    results = list(fetcher.fetch_audit_logs(datetime.now(timezone.utc)))
    
    assert len(results) == 1
    raw_log = results[0]
    
    # 1. Pass through compute_sha256_bytes
    raw_bytes = json.dumps(raw_log, sort_keys=True).encode("utf-8")
    sha256_digest = compute_sha256_bytes(raw_bytes)
    assert len(sha256_digest) == 64
    
    # 2. Pass through normalize_gcp_audit without missing key errors
    time_normalizer = TimeNormalizer(dc_anchor_skew_ms=0)
    ocsf_event = normalize_gcp_audit(raw_log, time_normalizer, trace_id="trace123")
    
    assert ocsf_event.cloud_account_id == "my-project"
    assert ocsf_event.api_operation == "v1.compute.instances.insert"
