"""
Specula Deterministic UID Generator.

Produces stable, collision-resistant identifiers for forensic entities
by hashing a domain string and canonicalized attribute dictionary.

Reference: specula_ingestion_final_plan.md §2.2

Implementation rule (from v6 "Mistakes to avoid"):
    Do NOT use Python's default dict iteration order or json.dumps
    without sort_keys=True. Non-deterministic key ordering or float
    formatting produces different hashes for identical logical entities,
    silently breaking deduplication — the single most common source of
    "duplicate entities that should have deduplicated."
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _canonical_json(obj: Any) -> str:
    """
    Serialize an object to a canonical JSON string with deterministic
    key ordering and fixed float precision.

    Rules:
    - Keys are always sorted (sort_keys=True).
    - No whitespace between separators.
    - Floats are rounded to 6 decimal places before serialization to
      avoid platform-dependent float formatting drift.
    - ensure_ascii=False so Unicode content hashes identically across
      platforms without escape-sequence variance.
    """
    return json.dumps(
        _normalize_floats(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _normalize_floats(obj: Any) -> Any:
    """
    Recursively round floats to 6 decimal places for deterministic
    serialization. Leaves all other types untouched.
    """
    if isinstance(obj, float):
        return round(obj, 6)
    if isinstance(obj, dict):
        return {k: _normalize_floats(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize_floats(item) for item in obj]
    return obj


def generate_deterministic_uid(domain: str, attributes: dict) -> str:
    """
    Generate a deterministic SHA-256 UID for a forensic entity.

    Args:
        domain: Entity domain namespace (e.g. "host", "process", "file",
                "user", "ip", "network_endpoint").
        attributes: Dictionary of entity-identifying attributes. Key
                    order does not matter — keys are sorted internally.

    Returns:
        Hex-encoded SHA-256 digest string.

    Example:
        >>> generate_deterministic_uid("process", {
        ...     "host_id": "HOST-042",
        ...     "pid": 4812,
        ...     "name": "cmd.exe",
        ...     "start_time": "2026-07-28T10:00:00Z",
        ... })
        'a3f1...'  # deterministic, same inputs always produce same output

    Invariant:
        Two calls with the same (domain, attributes) but different
        dict insertion order MUST produce the identical uid.
    """
    # sorted() on items() ensures insertion-order independence.
    canonical_attrs = _canonical_json(dict(sorted(attributes.items())))
    payload = f"{domain}|{canonical_attrs}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
