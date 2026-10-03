"""
Unit & Detection Rule Tests for Cloud & Container Forensics Agent (F13b / TASK-4.10a).
"""
import pytest
from typing import Any, Dict, List

from src.agents.cloud_container.agent import run_cloud_container_agent
from src.agents.cloud_container.detection_rules import (
    RuleContext,
    evaluate_cloud_rules,
    evaluate_container_rules,
    format_summary_field,
)
from src.agents.cloud_container.kafka_publisher import generate_partition_key


@pytest.fixture
def default_ctx() -> RuleContext:
    return RuleContext(
        admin_principals={"arn:aws:iam::123456789012:user/admin"},
        known_ip_baseline={"1.2.3.4", "5.6.7.8"},
        expected_egress_images={"nginx", "apache", "postgres"},
        exfil_threshold_count=5,
    )


class MockKafkaProducer:
    def __init__(self):
        self.published = []

    def produce(self, topic: str, key: bytes, value: bytes):
        self.published.append({"topic": topic, "key": key, "value": value})


# ---------------------------------------------------------------------------
# 1. Cloud Rules Golden Fixture Matrix
# ---------------------------------------------------------------------------

def test_cloud_001_defense_evasion(default_ctx):
    events = [
        {
            "uid": "evt-c001-1",
            "class_uid": 6003,
            "api_service": "cloudtrail.amazonaws.com",
            "api_operation": "StopLogging",
            "user_identity": "arn:aws:iam::123456789012:user/attacker",
            "cloud_account_id": "123456789012",
            "time": "2026-10-03T10:00:00Z",
        },
        {
            "uid": "evt-c001-2",
            "class_uid": 6003,
            "api_service": "securityhub.amazonaws.com",
            "api_operation": "DisableSecurityHub",
            "user_identity": "arn:aws:iam::123456789012:user/attacker",
            "cloud_account_id": "123456789012",
            "time": "2026-10-03T10:01:00Z",
        }
    ]
    findings = evaluate_cloud_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CLOUD-001"
    assert findings[0].count == 2
    assert findings[0].event_uids == ["evt-c001-1", "evt-c001-2"]
    assert findings[0].severity == "CRITICAL"


def test_cloud_002_credential_creation(default_ctx):
    events = [
        {
            "uid": "evt-c002-1",
            "class_uid": 6003,
            "api_service": "iam.amazonaws.com",
            "api_operation": "CreateAccessKey",
            "user_identity": "arn:aws:iam::123456789012:user/malicious",
            "cloud_account_id": "123456789012",
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_cloud_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CLOUD-002"
    assert findings[0].mitre_technique_id == "T1098.001"


def test_cloud_003_identity_trust_mod(default_ctx):
    events = [
        {
            "uid": "evt-c003-1",
            "class_uid": 6003,
            "api_service": "iam.amazonaws.com",
            "api_operation": "CreateSAMLProvider",
            "user_identity": "arn:aws:iam::123456789012:user/rogue",
            "cloud_account_id": "123456789012",
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_cloud_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CLOUD-003"
    assert findings[0].mitre_technique_id == "T1484.002"


def test_cloud_004_privilege_escalation(default_ctx):
    events = [
        {
            "uid": "evt-c004-1",
            "class_uid": 6003,
            "api_service": "iam.amazonaws.com",
            "api_operation": "AttachUserPolicy",
            "user_identity": "arn:aws:iam::123456789012:user/attacker",
            "requestParameters": {"userName": "arn:aws:iam::123456789012:user/dev_user"},
            "cloud_account_id": "123456789012",
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_cloud_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CLOUD-004"
    assert findings[0].mitre_technique_id == "T1098.003"


def test_cloud_005_sts_assume_role_anomaly(default_ctx):
    events = [
        {
            "uid": "evt-c005-1",
            "class_uid": 6003,
            "api_service": "sts.amazonaws.com",
            "api_operation": "AssumeRole",
            "source_ip": "99.88.77.66",  # Untrusted IP not in baseline
            "user_identity": "arn:aws:iam::123456789012:user/guest",
            "cloud_account_id": "123456789012",
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_cloud_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CLOUD-005"
    assert findings[0].mitre_technique_id == "T1078.004"


def test_cloud_006_s3_public_exposure(default_ctx):
    events = [
        {
            "uid": "evt-c006-1",
            "class_uid": 6003,
            "api_service": "s3.amazonaws.com",
            "api_operation": "PutBucketPolicy",
            "requestParameters": {
                "bucketName": "sensitive-data-bucket",
                "policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}'
            },
            "user_identity": "arn:aws:iam::123456789012:user/attacker",
            "cloud_account_id": "123456789012",
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_cloud_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CLOUD-006"
    assert findings[0].finding_type == "posture"


def test_cloud_007_bulk_exfiltration(default_ctx):
    events = [
        {
            "uid": f"evt-c007-{i}",
            "class_uid": 6003,
            "api_service": "s3.amazonaws.com",
            "api_operation": "GetObject",
            "requestParameters": {"bucketName": "exfil-target"},
            "user_identity": "arn:aws:iam::123456789012:user/exfiltrator",
            "cloud_account_id": "123456789012",
            "time": f"2026-10-03T10:00:0{i}Z",
        }
        for i in range(6)  # Exceeds threshold count of 5
    ]
    findings = evaluate_cloud_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CLOUD-007"
    assert findings[0].count == 6
    assert findings[0].mitre_technique_id == "T1530"


# ---------------------------------------------------------------------------
# 2. Container Rules Golden Fixture Matrix
# ---------------------------------------------------------------------------

def test_container_001_interactive_shell(default_ctx):
    events = [
        {
            "uid": "evt-k001-1",
            "class_uid": 1007,
            "process_name": "bash",
            "parent_process_name": "runc",
            "process_pid": 42,
            "command_line": "bash -i",
            "container": {"namespace": "prod", "pod_name": "web-pod-1", "container_id": "c1"},
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_container_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CONTAINER-001"
    assert findings[0].mitre_technique_id == "T1059.004"


def test_container_002_volatile_binary_exec(default_ctx):
    events = [
        {
            "uid": "evt-k002-1",
            "class_uid": 1007,
            "process_name": "malware",
            "command_line": "/tmp/payload.sh",
            "file_path": "/tmp/payload.sh",
            "container": {"namespace": "prod", "pod_name": "app-pod", "container_id": "c2"},
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_container_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CONTAINER-002"


def test_container_003_suspicious_egress(default_ctx):
    events = [
        {
            "uid": "evt-k003-1",
            "class_uid": 4001,
            "dst_ip": "198.51.100.42",
            "container": {"namespace": "prod", "pod_name": "isolated-pod", "image_name": "microservice-v1"},
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_container_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CONTAINER-003"
    assert findings[0].mitre_technique_id == "T1071.001"


def test_container_004_secret_access(default_ctx):
    events = [
        {
            "uid": "evt-k004-1",
            "class_uid": 1001,
            "file_path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "container": {"namespace": "prod", "pod_name": "hacked-pod", "container_id": "c4"},
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_container_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CONTAINER-004"
    assert findings[0].mitre_technique_id == "T1552.007"


def test_container_005_crypto_mining(default_ctx):
    events = [
        {
            "uid": "evt-k005-1",
            "class_uid": 1007,
            "process_name": "xmrig",
            "command_line": "./xmrig -o stratum+tcp://pool.supportxmr.com:5555",
            "container": {"namespace": "prod", "pod_name": "miner-pod", "container_id": "c5"},
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_container_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CONTAINER-005"
    assert findings[0].mitre_technique_id == "T1496"


def test_container_006_escape_attempt(default_ctx):
    events = [
        {
            "uid": "evt-k006-1",
            "class_uid": 1007,
            "process_name": "nsenter",
            "command_line": "nsenter -t 1 -m -u -i -n sh",
            "container": {"namespace": "prod", "pod_name": "escape-pod", "container_id": "c6"},
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    findings = evaluate_container_rules(events, "case-100", default_ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CONTAINER-006"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].mitre_technique_id == "T1611"


# ---------------------------------------------------------------------------
# 3. Agent Runner & Evidence Check Unit Tests
# ---------------------------------------------------------------------------

def test_agent_runner_no_events():
    state = {"case_id": "case-empty"}
    result = run_cloud_container_agent(state, event_provider=lambda c: [])
    assert result["specialist_statuses"]["cloud_container"] == "no_events"
    assert "cloud_container" in result["specialists_completed"]
    assert len(result["findings"]) == 0
    assert result["agent_traces"][0]["status"] == "no_events"


def test_agent_runner_query_error():
    state = {"case_id": "case-err"}
    def err_provider(c):
        raise RuntimeError("Neo4j database timeout")

    result = run_cloud_container_agent(state, event_provider=err_provider)
    assert result["specialist_statuses"]["cloud_container"] == "error"
    assert "cloud_container" in result["specialists_completed"]
    assert len(result["findings"]) == 0
    assert result["agent_traces"][0]["status"] == "error"


def test_agent_runner_successful_execution(default_ctx):
    state = {"case_id": "case-ok"}
    events = [
        {
            "case_id": "case-ok",
            "uid": "evt-1",
            "class_uid": 6003,
            "api_service": "cloudtrail.amazonaws.com",
            "api_operation": "StopLogging",
            "cloud_account_id": "123456789012",
            "time": "2026-10-03T10:00:00Z",
        }
    ]
    producer = MockKafkaProducer()
    result = run_cloud_container_agent(
        state,
        event_provider=lambda c: events,
        rule_context=default_ctx,
        kafka_producer=producer,
    )

    assert result["specialist_statuses"]["cloud_container"] == "ok"
    assert "cloud_container" in result["specialists_completed"]
    assert len(result["findings"]) == 1
    assert len(producer.published) == 1
    assert producer.published[0]["topic"] == "findings.specialist.cloud_container"


def test_cross_case_isolation_raises_value_error():
    state = {"case_id": "case-1"}
    foreign_events = [
        {
            "case_id": "case-99",  # Different case
            "uid": "evt-foreign",
            "class_uid": 6003,
            "api_service": "cloudtrail.amazonaws.com",
            "api_operation": "StopLogging",
        }
    ]
    with pytest.raises(ValueError, match="belonging to case case-99, expected case-1"):
        run_cloud_container_agent(state, event_provider=lambda c: foreign_events)


def test_prompt_injection_summary_formatting():
    malicious_input = "<script>alert('xss')</script> " + "A" * 300
    formatted = format_summary_field(malicious_input, max_len=50)
    assert "&lt;script&gt;" in formatted
    assert formatted.startswith('"') and formatted.endswith('"')
    assert "..." in formatted


def test_kafka_partition_key_determinism():
    key1 = generate_partition_key("account-12345")
    key2 = generate_partition_key("account-12345")
    assert key1 == key2
    assert len(key1) == 64  # SHA-256 hex encoded bytes
