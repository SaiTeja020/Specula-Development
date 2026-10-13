"""Kafka publication for deterministic Memory Forensics findings."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

FINDING_TOPIC = "findings.specialist.memory"


def publish_findings(findings: Iterable[dict[str, Any]], producer: Any) -> None:
    """Publish each finding with a host-stable partition key; no direct graph writes."""
    if producer is None:
        return
    for finding in findings:
        host_id = str(finding.get("canonical_host_id") or "unknown_host")
        key = hashlib.sha256(host_id.encode("utf-8")).hexdigest().encode("utf-8")
        producer.produce(
            topic=FINDING_TOPIC,
            key=key,
            value=json.dumps(finding, default=str, sort_keys=True).encode("utf-8"),
        )
