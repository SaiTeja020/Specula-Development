"""
Log Analysis Agent — Deduplication Layer.

Provides fingerprint generation and Redis-backed duplicate checking for
published findings. Implements resolved-decisions item #23.

Design:
  - fingerprint() is pure (no I/O) — deterministic hash of
    (pattern, sorted(affected_entity_uids), time_bucket).
  - is_duplicate() is read-only (does NOT write to Redis). The caller
    (agent.py) writes the fingerprint ONLY after a successful Kafka
    publish, so failed publishes don't poison the dedup cache.
  - TTL is not hardcoded here — it is set per-case at runtime by the
    caller using config.DEDUP_FINGERPRINT_TTL_SECONDS as a hint.

IMPORTANT: tests must use a mock Redis client to avoid real network I/O.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol


# ─── Redis client interface (structural typing for testability) ───────────────


class RedisClient(Protocol):
    """Minimal Redis client interface used by this module."""

    def exists(self, key: str) -> int:
        """Returns 1 if key exists, 0 otherwise."""
        ...

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        """Set a key with optional TTL in seconds."""
        ...


# ─── Fingerprint ──────────────────────────────────────────────────────────────


def fingerprint(
    pattern: str,
    affected_entity_uids: list[str],
    time_bucket: str,
) -> str:
    """
    Generate a deterministic deduplication fingerprint.

    Args:
        pattern:               Short pattern name (e.g. "brute_force").
        affected_entity_uids:  List of DFKG entity UIDs involved in this
                               finding. Order does NOT matter — sorted
                               internally for determinism.
        time_bucket:           An ISO 8601 time-bucket string (e.g.
                               "2026-08-22T10" for hourly buckets).

    Returns:
        Hex-encoded SHA-256 fingerprint string.

    Invariant:
        Same (pattern, affected_entity_uids, time_bucket) regardless of
        list ordering → identical fingerprint.
    """
    payload = json.dumps(
        {
            "pattern": pattern,
            "entity_uids": sorted(affected_entity_uids),
            "time_bucket": time_bucket,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ─── Duplicate check ──────────────────────────────────────────────────────────


def is_duplicate(fp: str, redis_client: RedisClient) -> bool:
    """
    Check whether a fingerprint has already been published within the
    active dedup window.

    READ-ONLY — does not write to Redis. The caller (agent.py) must
    call write_fingerprint() AFTER a successful Kafka publish.

    Args:
        fp:           Fingerprint hex string from fingerprint().
        redis_client: A Redis client satisfying the RedisClient protocol.

    Returns:
        True  — fingerprint exists in Redis (duplicate, skip publish).
        False — fingerprint absent (safe to publish).
    """
    dedup_key = _redis_key(fp)
    return bool(redis_client.exists(dedup_key))


def write_fingerprint(
    fp: str,
    redis_client: RedisClient,
    ttl_seconds: int | None = None,
) -> None:
    """
    Write a fingerprint to Redis after a successful Kafka publish.

    Args:
        fp:           Fingerprint hex string from fingerprint().
        redis_client: A Redis client satisfying the RedisClient protocol.
        ttl_seconds:  TTL in seconds. None means no expiry (use only for
                      testing; always pass the case's active window TTL
                      in production per item #23).
    """
    dedup_key = _redis_key(fp)
    redis_client.set(dedup_key, "1", ex=ttl_seconds)


def _redis_key(fp: str) -> str:
    """Namespace the fingerprint in Redis to avoid collisions with other keys."""
    return f"specula:log_analysis:dedup:{fp}"
