import json

import pytest

from src.agents.memory_forensics.agent import (
    deduplicate_findings,
    run_memory_forensics_analysis,
)
from src.agents.memory_forensics_factory import make_memory_forensics_node


def _artifact(**overrides):
    artifact = {
        "case_id": "CASE-1",
        "canonical_host_id": "HOST-1",
        "source_image_uid": "image-a",
        "uid": "artifact-1",
        "plugin": "psscan",
        "PID": 4812,
        "ImageFileName": "svchost.exe",
        "CreateTime": "2026-09-22T10:00:00Z",
        "physical_offset": "0x1234",
        "visible_in_pslist": False,
    }
    artifact.update(overrides)
    return artifact


def test_hidden_process_finding_is_cited_and_deterministic():
    findings = run_memory_forensics_analysis([_artifact()], case_id="CASE-1")

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "MEM-HIDDEN-PROCESS"
    assert finding["dfkg_refs"] == ["artifact-1"]
    assert finding["source_image_uid"] == "image-a"
    assert "pid=4812" in finding["process_identity"]


def test_injection_lsass_and_memory_yara_rules():
    artifacts = [
        _artifact(plugin="malfind", uid="malfind-1", physical_offset="0x2000"),
        _artifact(
            plugin="handles", uid="handle-1", physical_offset="0x3000",
            target_process_name="lsass.exe", GrantedAccess="0x438",
        ),
        _artifact(
            plugin="yarascan", uid="yara-1", physical_offset="0x4000",
            yara_rule="CobaltStrike_Beacon_v4",
        ),
    ]

    findings = run_memory_forensics_analysis(artifacts, case_id="CASE-1")

    assert {finding["rule_id"] for finding in findings} == {
        "MEM-INJECTED-CODE", "MEM-LSASS-ACCESS", "MEM-YARA-RESIDENT",
    }
    yara = next(finding for finding in findings if finding["rule_id"] == "MEM-YARA-RESIDENT")
    assert yara["detection_context"] == "memory_resident"


def test_lsass_access_requires_bitwise_vm_read_and_sensitive_companion_right():
    terminate_only = _artifact(
        plugin="handles", target_process_name="lsass.exe", GrantedAccess="0x0001",
    )
    read_only = _artifact(
        plugin="handles", target_process_name="lsass.exe", GrantedAccess="0x0010",
    )

    assert run_memory_forensics_analysis([terminate_only, read_only], case_id="CASE-1") == []


def test_deduplication_keeps_same_process_findings_from_separate_memory_images():
    first = _artifact()
    duplicate = _artifact(uid="artifact-duplicate")
    second_image = _artifact(uid="artifact-image-b", source_image_uid="image-b")

    findings = run_memory_forensics_analysis([first, duplicate, second_image], case_id="CASE-1")

    assert len(deduplicate_findings(findings)) == 2
    assert {finding["source_image_uid"] for finding in findings} == {"image-a", "image-b"}


def test_agent_rejects_cross_case_and_cross_host_artifacts():
    with pytest.raises(ValueError, match="another case"):
        run_memory_forensics_analysis([_artifact(case_id="CASE-2")], case_id="CASE-1")
    with pytest.raises(ValueError, match="another host"):
        run_memory_forensics_analysis([_artifact(canonical_host_id="HOST-2")], case_id="CASE-1", canonical_host_id="HOST-1")


class _Producer:
    def __init__(self):
        self.messages = []

    def produce(self, **kwargs):
        self.messages.append(kwargs)


def test_factory_publishes_to_memory_topic_and_returns_specialist_completion():
    producer = _Producer()
    node = make_memory_forensics_node(
        kafka_producer=producer,
        artifact_provider=lambda state: [_artifact()],
    )

    result = node({"case_id": "CASE-1"})

    assert result["specialists_completed"] == ["memory"]
    assert result["agent_traces"][0]["agent_role"] == "memory_forensics"
    assert len(producer.messages) == 1
    message = producer.messages[0]
    assert message["topic"] == "findings.specialist.memory"
    assert json.loads(message["value"])["rule_id"] == "MEM-HIDDEN-PROCESS"
