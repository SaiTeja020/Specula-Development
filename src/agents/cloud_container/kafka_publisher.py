"""
Kafka publication helper for Cloud & Container Forensics Agent (F13b).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

FINDING_TOPIC = "findings.specialist.cloud_container"


def generate_partition_key(scope: str) -> bytes:
    """Generate SHA-256 partition key bytes from account ID or namespace/pod scope."""
    cleaned_scope = str(scope or "global").encode("utf-8")
    return hashlib.sha256(cleaned_scope).hexdigest().encode("utf-8")


def publish_findings(findings: Iterable[dict[str, Any]], producer: Any) -> None:
    """Publish findings to Kafka with account/pod partition key."""
    if producer is None:
        return
    for finding in findings:
        scope = str(finding.get("scope") or finding.get("case_id") or "global")
        key = generate_partition_key(scope)
        payload = json.dumps(finding, default=str, sort_keys=True).encode("utf-8")
        producer.produce(
            topic=FINDING_TOPIC,
            key=key,
            value=payload,
        )
