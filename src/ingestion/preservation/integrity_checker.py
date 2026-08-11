"""
Specula Evidence Integrity Checker.

Verifies that raw evidence stored in Quickwit matches replay bytes,
detecting any tampering or corruption.

Reference: specula_ingestion_final_plan.md §3.3
"""

from typing import Any


def verify_integrity(quickwit: Any, uid: str, replay_bytes: bytes) -> bool:
    """
    Verify integrity of raw evidence stored in Quickwit against replay bytes.

    Compatible with both the real QuickwitClient (which exposes `get_evidence()`)
    and FakeQuickwit used in unit tests (which exposes `get()`). Method resolution
    is done via duck-typing so unit tests need no changes.

    Args:
        quickwit: QuickwitClient instance or FakeQuickwit mock.
        uid: Deterministic UID of the evidence entity.
        replay_bytes: Raw bytes to verify against stored evidence.

    Returns:
        True if raw bytes match stored evidence exactly.

    Raises:
        ValueError: If TAMPER_DETECTED occurs (mismatch or missing record).
    """
    # Real QuickwitClient uses get_evidence(); FakeQuickwit uses get()
    if hasattr(quickwit, "get_evidence"):
        stored = quickwit.get_evidence(uid)
    else:
        stored = quickwit.get(uid)

    if not stored:
        raise ValueError(f"TAMPER_DETECTED: No evidence record found for uid={uid}")

    stored_bytes = stored.get("raw_bytes")
    if stored_bytes != replay_bytes:
        raise ValueError(f"TAMPER_DETECTED: Evidence mismatch for uid={uid}")

    return True
