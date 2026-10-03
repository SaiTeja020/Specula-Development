"""Memory Forensics analysis orchestration and source-image-scoped deduplication."""
from __future__ import annotations

from typing import Any, Iterable

from .detection_rules import analyze_memory_artifacts


def finding_dedup_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str]:
    """The forensic dedup contract: never merge findings across memory images."""
    return (
        str(finding.get("source_image_uid") or "unknown"),
        str(finding.get("process_identity") or "unknown"),
        str(finding.get("offset") or "unknown"),
        str(finding.get("rule_id") or "unknown"),
        str(finding.get("rule_version") or "unknown"),
    )


def deduplicate_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for finding in findings:
        key = finding_dedup_key(finding)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def run_memory_forensics_analysis(artifacts: Iterable[dict[str, Any]], *, case_id: str,
                                  canonical_host_id: str | None = None) -> list[dict[str, Any]]:
    """Enforce case/host isolation, run rules, and return cited findings."""
    scoped: list[dict[str, Any]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        artifact_case = artifact.get("case_id")
        artifact_host = artifact.get("canonical_host_id")
        if artifact_case not in (None, case_id):
            raise ValueError("MemoryForensicsAgent received an artifact from another case.")
        if canonical_host_id is not None and artifact_host not in (None, canonical_host_id):
            raise ValueError("MemoryForensicsAgent received an artifact from another host.")
        scoped.append(artifact)
    return deduplicate_findings(analyze_memory_artifacts(scoped))
