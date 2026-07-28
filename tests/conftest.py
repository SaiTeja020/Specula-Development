"""
Pytest configuration and shared fixtures for Specula tests.
"""

import pytest


class MockQuickwit:
    """In-memory mock for Quickwit append-only storage in tests."""

    def __init__(self):
        self._store = {}

    def commit(self, uid: str, raw_bytes: bytes, digest: str):
        if uid in self._store:
            raise RuntimeError(f"UID {uid} already committed (append-only rejection)")
        self._store[uid] = {
            "raw_bytes": raw_bytes,
            "digest": digest,
        }

    def get(self, uid: str):
        return self._store.get(uid)


@pytest.fixture
def quickwit():
    return MockQuickwit()


@pytest.fixture
def canonical_uid():
    return "0000000000000000000000000000000000000000000000000000000000000000"
