"""
Live Integration Test Suite — Quickwit Preservation Layer.

These tests require a real Quickwit instance running at localhost:7280.
They are SKIPPED in normal `pytest` runs and ONLY execute when explicitly
targeted with the live_infra marker:

    docker-compose up -d quickwit
    python scripts/quickwit_setup.py
    pytest tests/ingestion/test_quickwit_live.py -m live_infra -v

Reference: vector_retrieval_implementation_plan.md §5 (Verification Plan)
           specula_ingestion_final_plan.md §3.2
"""

import hashlib
import time
import uuid

import pytest
import requests

from src.ingestion.preservation.quickwit_client import (
    QuickwitClient,
    QuickwitClientError,
    QUICKWIT_ENDPOINT,
)
from src.ingestion.preservation.sha256_hasher import compute_sha256_bytes
from src.ingestion.preservation.integrity_checker import verify_integrity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_quickwit_reachable() -> bool:
    """Quick connectivity probe — used to skip tests gracefully if Quickwit is down."""
    try:
        r = requests.get(f"{QUICKWIT_ENDPOINT}/health/livez", timeout=3.0)
        return r.status_code == 200
    except Exception:
        return False


def _unique_uid() -> str:
    """Generate a test-run-unique UID to prevent cross-test pollution."""
    return f"test-{uuid.uuid4().hex}"


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

@pytest.mark.live_infra
class TestQuickwitLiveIntegration:
    """
    Hits the real Quickwit REST API at localhost:7280.
    All tests are independent; each uses a unique UID to avoid ordering deps.
    """

    @pytest.fixture(autouse=True)
    def require_quickwit(self):
        """Skip entire class if Quickwit is not reachable."""
        if not _is_quickwit_reachable():
            pytest.skip(
                f"Quickwit is not reachable at {QUICKWIT_ENDPOINT}. "
                "Run: docker-compose up -d quickwit"
            )

    @pytest.fixture
    def client(self) -> QuickwitClient:
        """A QuickwitClient pointed at the local dev instance."""
        return QuickwitClient()

    # ------------------------------------------------------------------
    # ensure_index
    # ------------------------------------------------------------------

    def test_ensure_index_is_idempotent(self, client: QuickwitClient):
        """Calling ensure_index() twice must not raise any error."""
        client.ensure_index()
        client.ensure_index()  # second call must be silent

    # ------------------------------------------------------------------
    # commit_raw_evidence + get_evidence roundtrip
    # ------------------------------------------------------------------

    def test_commit_and_retrieve_roundtrip(self, client: QuickwitClient):
        """
        Commit raw bytes to Quickwit then retrieve and verify the digest matches.
        This exercises the full chain: commit → ingest → search → decode.
        """
        client.ensure_index()

        uid = _unique_uid()
        raw = f"synthetic evtx record for uid={uid}".encode("utf-8")
        sha256 = compute_sha256_bytes(raw)
        trace_id = f"trace-{uuid.uuid4().hex[:12]}"

        client.commit_raw_evidence(
            uid=uid,
            trace_id=trace_id,
            sha256_digest=sha256,
            raw_bytes=raw,
            source_type="evtx",
        )

        # Quickwit has a commit_timeout_secs=5; poll for up to 10 seconds
        retrieved = None
        for _ in range(10):
            retrieved = client.get_evidence(uid)
            if retrieved is not None:
                break
            time.sleep(1.0)

        assert retrieved is not None, "Evidence record not found in Quickwit after 10s"
        assert retrieved["uid"] == uid
        assert retrieved["sha256"] == sha256
        assert retrieved["source_type"] == "evtx"
        assert compute_sha256_bytes(retrieved["raw_bytes"]) == sha256

    def test_roundtrip_mft_source_type(self, client: QuickwitClient):
        """Verify source_type='mft' is correctly stored and returned."""
        client.ensure_index()

        uid = _unique_uid()
        raw = b"\x00\x01BINARY-MFT-RECORD\x02\x03" * 5
        sha256 = compute_sha256_bytes(raw)

        client.commit_raw_evidence(
            uid=uid,
            trace_id=f"trace-{uuid.uuid4().hex[:12]}",
            sha256_digest=sha256,
            raw_bytes=raw,
            source_type="mft",
        )

        retrieved = None
        for _ in range(10):
            retrieved = client.get_evidence(uid)
            if retrieved:
                break
            time.sleep(1.0)

        assert retrieved is not None
        assert retrieved["source_type"] == "mft"

    # ------------------------------------------------------------------
    # Integrity checker against real Quickwit
    # ------------------------------------------------------------------

    def test_integrity_checker_passes_on_real_quickwit(self, client: QuickwitClient):
        """verify_integrity() must return True when replay_bytes exactly match stored bytes."""
        client.ensure_index()

        uid = _unique_uid()
        raw = b"chain of custody evidence block"
        sha256 = compute_sha256_bytes(raw)

        client.commit_raw_evidence(
            uid=uid,
            trace_id=f"trace-{uuid.uuid4().hex[:12]}",
            sha256_digest=sha256,
            raw_bytes=raw,
            source_type="evtx",
        )

        # Wait for Quickwit commit
        for _ in range(10):
            if client.get_evidence(uid):
                break
            time.sleep(1.0)

        assert verify_integrity(client, uid=uid, replay_bytes=raw) is True

    def test_integrity_checker_detects_tamper_on_real_quickwit(self, client: QuickwitClient):
        """verify_integrity() must raise ValueError when replay bytes differ from stored."""
        client.ensure_index()

        uid = _unique_uid()
        raw = b"original untampered evidence"
        sha256 = compute_sha256_bytes(raw)

        client.commit_raw_evidence(
            uid=uid,
            trace_id=f"trace-{uuid.uuid4().hex[:12]}",
            sha256_digest=sha256,
            raw_bytes=raw,
            source_type="evtx",
        )

        for _ in range(10):
            if client.get_evidence(uid):
                break
            time.sleep(1.0)

        tampered = b"original untampered evidenceX"
        with pytest.raises(ValueError) as exc_info:
            verify_integrity(client, uid=uid, replay_bytes=tampered)

        assert "TAMPER_DETECTED" in str(exc_info.value)

    # ------------------------------------------------------------------
    # get_evidence for non-existent uid
    # ------------------------------------------------------------------

    def test_get_evidence_returns_none_for_unknown_uid(self, client: QuickwitClient):
        """get_evidence() must return None (not raise) for a uid that was never committed."""
        client.ensure_index()
        result = client.get_evidence("uid-that-does-not-exist-at-all-12345")
        assert result is None

    # ------------------------------------------------------------------
    # Preservation is fatal when Quickwit is unreachable
    # ------------------------------------------------------------------

    def test_commit_raises_on_wrong_port(self):
        """
        If Quickwit is down (wrong port), commit_raw_evidence must raise
        QuickwitClientError — not silently pass.

        This verifies the 'preservation failure MUST halt pipeline' invariant.
        """
        bad_client = QuickwitClient(endpoint="http://localhost:9999")
        with pytest.raises(QuickwitClientError):
            bad_client.commit_raw_evidence(
                uid="test-fatal",
                trace_id="trace-fatal",
                sha256_digest="abc123",
                raw_bytes=b"test",
                source_type="evtx",
            )

    def test_ensure_index_raises_on_wrong_port(self):
        """ensure_index() must raise QuickwitClientError if Quickwit is unreachable."""
        bad_client = QuickwitClient(endpoint="http://localhost:9999")
        with pytest.raises(QuickwitClientError):
            bad_client.ensure_index()
