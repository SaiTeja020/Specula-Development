"""Pure, deterministic rules for Volatility-derived memory artifacts."""
from __future__ import annotations

from typing import Any, Iterable

from src.schemas.uid_generator import generate_deterministic_uid

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
RULE_VERSION = "1.0"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _plugin(artifact: dict[str, Any]) -> str:
    return _text(artifact.get("plugin") or artifact.get("artifact_type")).lower()


def _artifact_uid(artifact: dict[str, Any]) -> str:
    return _text(artifact.get("uid")) or generate_deterministic_uid("memory_artifact", artifact)


def _source_image_uid(artifact: dict[str, Any]) -> str:
    return _text(artifact.get("source_image_uid")) or _artifact_uid(artifact)


def _process_identity(artifact: dict[str, Any]) -> str:
    """Stable within-image identity; PID alone is unsafe because it is reusable."""
    pid = artifact.get("PID", artifact.get("process_pid", artifact.get("pid", "unknown")))
    create_time = _text(
        artifact.get("CreateTime") or artifact.get("process_create_time") or artifact.get("create_time")
    ) or "unknown"
    image = _text(
        artifact.get("ImageFileName") or artifact.get("process_name") or artifact.get("image_name")
    ).lower() or "unknown"
    return f"pid={pid}|create_time={create_time}|image={image}"


def _offset(artifact: dict[str, Any]) -> str:
    return _text(
        artifact.get("physical_offset")
        or artifact.get("virtual_offset")
        or artifact.get("Offset")
        or artifact.get("offset")
    ) or "unknown"


def _finding(artifact: dict[str, Any], *, rule_id: str, title: str, severity_id: int,
             confidence: str, summary: str, technique: str | None = None) -> dict[str, Any]:
    artifact_uid = _artifact_uid(artifact)
    return {
        "agent_role": "memory_forensics",
        "rule_id": rule_id,
        "rule_version": RULE_VERSION,
        "title": title,
        "summary": summary,
        "severity_id": severity_id,
        "confidence": confidence,
        "mitre_attack": technique,
        "source_image_uid": _source_image_uid(artifact),
        "process_identity": _process_identity(artifact),
        "offset": _offset(artifact),
        "canonical_host_id": artifact.get("canonical_host_id"),
        "case_id": artifact.get("case_id"),
        "dfkg_refs": [artifact_uid],
        "evidence": {
            "plugin": _plugin(artifact),
            "artifact_uid": artifact_uid,
            "physical_offset": artifact.get("physical_offset"),
            "virtual_offset": artifact.get("virtual_offset"),
        },
    }


def detect_hidden_processes(artifacts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for artifact in artifacts:
        plugin = _plugin(artifact)
        hidden = artifact.get("visible_in_pslist") is False or artifact.get("in_pslist") is False
        if "psscan" in plugin and hidden:
            findings.append(_finding(
                artifact, rule_id="MEM-HIDDEN-PROCESS", title="Hidden process recovered by pool scan",
                severity_id=4, confidence="High",
                summary="Process was recovered by psscan but is absent from pslist.", technique="T1055",
            ))
    return findings


def detect_injected_memory(artifacts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for artifact in artifacts:
        plugin = _plugin(artifact)
        protection = _text(artifact.get("protection") or artifact.get("Protection")).upper()
        suspicious_vad = bool(artifact.get("is_executable_private")) or (
            artifact.get("vad_type") == "private" and "EXECUTE" in protection
        )
        if any(token in plugin for token in ("malfind", "hollowfind", "injected")) or suspicious_vad:
            findings.append(_finding(
                artifact, rule_id="MEM-INJECTED-CODE", title="Suspicious injected executable memory",
                severity_id=5, confidence="High",
                summary="Volatility evidence indicates executable private memory or process injection.",
                technique="T1055",
            ))
    return findings


def detect_lsass_access(artifacts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for artifact in artifacts:
        target = _text(artifact.get("target_process_name") or artifact.get("target_image")).lower()
        if "handles" not in _plugin(artifact) or target not in {"lsass.exe", "lsass"}:
            continue
        try:
            access_mask = int(artifact.get("access_mask", artifact.get("GrantedAccess", 0)), 0) if isinstance(artifact.get("access_mask", artifact.get("GrantedAccess", 0)), str) else int(artifact.get("access_mask", artifact.get("GrantedAccess", 0)))
        except (TypeError, ValueError):
            continue
        can_read = bool(access_mask & PROCESS_VM_READ)
        can_query = bool(access_mask & PROCESS_QUERY_INFORMATION)
        can_modify = bool(access_mask & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION))
        if can_read and (can_query or can_modify):
            confidence = "High" if can_query and can_modify else "Medium"
            findings.append(_finding(
                artifact, rule_id="MEM-LSASS-ACCESS", title="Suspicious LSASS process handle",
                severity_id=5 if confidence == "High" else 4, confidence=confidence,
                summary=("Handle grants PROCESS_VM_READ together with "
                         f"{'query and memory-modification' if can_query and can_modify else 'additional sensitive'} rights to LSASS."),
                technique="T1003.001",
            ))
    return findings


def detect_memory_resident_yara(artifacts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for artifact in artifacts:
        rule = _text(artifact.get("yara_rule") or artifact.get("rule_name"))
        if rule and ("yara" in _plugin(artifact) or artifact.get("detection_context") == "memory_resident"):
            finding = _finding(
                artifact, rule_id="MEM-YARA-RESIDENT", title="In-memory YARA match",
                severity_id=5, confidence="High",
                summary=f"Memory-resident YARA rule matched: {rule}.", technique="T1055",
            )
            finding["detection_context"] = "memory_resident"
            finding["evidence"]["yara_rule"] = rule
            findings.append(finding)
    return findings


def analyze_memory_artifacts(artifacts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run all supported rules without an LLM or mutable external state."""
    safe_artifacts = [artifact for artifact in artifacts if isinstance(artifact, dict)]
    return [
        *detect_hidden_processes(safe_artifacts),
        *detect_injected_memory(safe_artifacts),
        *detect_lsass_access(safe_artifacts),
        *detect_memory_resident_yara(safe_artifacts),
    ]
