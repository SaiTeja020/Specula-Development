"""
Tests for dedup.py — Implementation Plan §9 test 4.

Covers:
  - Same (pattern, affected_entity_uids, time_bucket) → identical fingerprint.
  - Ordering of affected_entity_uids doesn't matter.
  - is_duplicate returns True only after write_fingerprint.
  - Respects TTL expiry (mock Redis TTL simulation).
"""

from __future__ import annotations

import pytest

from src.agents.log_analysis.dedup import fingerprint, is_duplicate, write_fingerprint


# ─── Mock Redis client ────────────────────────────────────────────────────────


class MockRedis:
    """In-memory mock Redis with TTL simulation."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._ttls: dict[str, int | None] = {}

    def exists(self, key: str) -> int:
        return 1 if key in self._store else 0

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = value
        self._ttls[key] = ex

    def simulate_ttl_expiry(self, key: str) -> None:
        """Simulate TTL expiry by removing a key (test helper)."""
        self._store.pop(key, None)
        self._ttls.pop(key, None)

    def get_ttl(self, key: str) -> int | None:
        return self._ttls.get(key)


# ─── Test 4a: deterministic fingerprint ──────────────────────────────────────


def test_same_inputs_same_fingerprint():
    """Same (pattern, uids, time_bucket) always produces identical fingerprint."""
    fp1 = fingerprint("brute_force", ["uid-a", "uid-b"], "2026-08-22T10")
    fp2 = fingerprint("brute_force", ["uid-a", "uid-b"], "2026-08-22T10")
    assert fp1 == fp2


def test_uid_order_does_not_matter():
    """Sorting of affected_entity_uids is internal — order of input doesn't matter."""
    fp1 = fingerprint("brute_force", ["uid-a", "uid-b", "uid-c"], "2026-08-22T10")
    fp2 = fingerprint("brute_force", ["uid-c", "uid-a", "uid-b"], "2026-08-22T10")
    assert fp1 == fp2, "Fingerprint must be order-independent on uid list."


def test_different_patterns_different_fingerprints():
    fp1 = fingerprint("brute_force", ["uid-x"], "2026-08-22T10")
    fp2 = fingerprint("unusual_parent_process", ["uid-x"], "2026-08-22T10")
    assert fp1 != fp2


def test_different_time_buckets_different_fingerprints():
    fp1 = fingerprint("brute_force", ["uid-x"], "2026-08-22T10")
    fp2 = fingerprint("brute_force", ["uid-x"], "2026-08-22T11")
    assert fp1 != fp2


def test_different_uid_sets_different_fingerprints():
    fp1 = fingerprint("brute_force", ["uid-a"], "2026-08-22T10")
    fp2 = fingerprint("brute_force", ["uid-b"], "2026-08-22T10")
    assert fp1 != fp2


# ─── Test 4b: is_duplicate returns True only after write ─────────────────────


def test_not_duplicate_before_write():
    """is_duplicate must return False for a fingerprint not yet written."""
    redis = MockRedis()
    fp = fingerprint("brute_force", ["uid-z"], "2026-08-22T10")
    assert is_duplicate(fp, redis) is False


def test_is_duplicate_after_write():
    """is_duplicate returns True after write_fingerprint called."""
    redis = MockRedis()
    fp = fingerprint("brute_force", ["uid-z"], "2026-08-22T10")
    write_fingerprint(fp, redis, ttl_seconds=3600)
    assert is_duplicate(fp, redis) is True


def test_different_fingerprint_not_duplicate():
    """Writing one fingerprint does not affect a different one."""
    redis = MockRedis()
    fp1 = fingerprint("brute_force", ["uid-a"], "2026-08-22T10")
    fp2 = fingerprint("brute_force", ["uid-b"], "2026-08-22T10")
    write_fingerprint(fp1, redis, ttl_seconds=3600)
    assert is_duplicate(fp2, redis) is False


# ─── Test 4c: respects TTL expiry (simulated) ────────────────────────────────


def test_ttl_expiry_clears_duplicate():
    """
    After simulated TTL expiry, is_duplicate should return False again.
    (Tests that we correctly honor key deletion from Redis.)
    """
    redis = MockRedis()
    fp = fingerprint("sensitive_file_access", ["uid-q"], "2026-08-22T12")
    write_fingerprint(fp, redis, ttl_seconds=60)

    assert is_duplicate(fp, redis) is True  # before expiry

    # Simulate expiry.
    dedup_key = f"specula:log_analysis:dedup:{fp}"
    redis.simulate_ttl_expiry(dedup_key)

    assert is_duplicate(fp, redis) is False  # after expiry


def test_write_fingerprint_sets_correct_ttl():
    """write_fingerprint stores the TTL value correctly in mock Redis."""
    redis = MockRedis()
    fp = fingerprint("offhours_service_install", ["uid-r"], "2026-08-22T03")
    write_fingerprint(fp, redis, ttl_seconds=7200)
    dedup_key = f"specula:log_analysis:dedup:{fp}"
    assert redis.get_ttl(dedup_key) == 7200


def test_write_fingerprint_no_ttl_stores_none():
    """write_fingerprint with no TTL stores None (test-only usage)."""
    redis = MockRedis()
    fp = fingerprint("brute_force", ["uid-s"], "2026-08-22T15")
    write_fingerprint(fp, redis, ttl_seconds=None)
    dedup_key = f"specula:log_analysis:dedup:{fp}"
    assert redis.get_ttl(dedup_key) is None
