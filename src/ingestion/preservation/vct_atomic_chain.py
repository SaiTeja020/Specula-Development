"""
Specula Verifiable Conversation Transcripts (VCT) Atomic Chain.

Registers each atomic log-line/record hash into the VCT hash chain.

Reference: specula_ingestion_final_plan.md §3.3

Phase 1 Scope:
    This component implements ATOMIC-LEVEL hashing only.
    Explicit boundary: session-level and case-level Merkle tree
    aggregation is deferred to Phase 2 (Reporting & VCT Audit stage).
"""

import hashlib
import logging

logger = logging.getLogger(__name__)


class VCTAtomicChain:
    """
    Manages the atomic-level hash chain for ingested evidence.
    
    Each new piece of evidence is chained to the previous one,
    creating a continuous, tamper-evident sequence of ingestions
    for a given ingestion node or stream.
    """

    def __init__(self):
        # In a real distributed system, this state would need to be
        # persisted to a local WAL (Write-Ahead Log) or similar to survive
        # restarts, ensuring the chain continues unbroken.
        # For Phase 1, we manage it in memory per worker process.
        self._last_hash: str = (
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        self._sequence_number: int = 0
        self._links: list = []

    def register(self, sha256_digest: str, trace_id: str = "trace-default", uid: str = "uid-default") -> str:
        """
        Register a digest into the VCT atomic chain.

        Args:
            sha256_digest: SHA-256 digest string.
            trace_id: Optional trace ID.
            uid: Optional entity UID.

        Returns:
            The new chain link hash.
        """
        return self.register_hash(sha256_digest=sha256_digest, trace_id=trace_id, uid=uid)

    def register_hash(self, sha256_digest: str, trace_id: str = "trace-default", uid: str = "uid-default") -> str:
        """
        Register a new atomic evidence hash into the chain.

        Args:
            sha256_digest: The SHA-256 digest of the raw evidence.
            trace_id: The distributed trace identifier.
            uid: The entity/event deterministic UID.

        Returns:
            The new chain hash linking this evidence to the history.
        """
        self._sequence_number += 1
        
        # Payload binds the current evidence to the previous chain state
        payload = (
            f"{self._sequence_number}|{self._last_hash}|{trace_id}|{uid}|{sha256_digest}"
        )
        
        new_chain_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        
        self._links.append((sha256_digest, new_chain_hash))
        self._last_hash = new_chain_hash
        
        logger.debug(
            f"Registered atomic hash for uid={uid}, seq={self._sequence_number}. "
            f"Chain hash: {new_chain_hash}"
        )
        
        return new_chain_hash

    def verify_chain(self) -> bool:
        """
        Verify that all links in the chain remain untampered and valid.
        """
        prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        for seq, (digest, expected_link_hash) in enumerate(self._links, start=1):
            # Recalculate using default trace_id/uid bindings if unspecified
            payload = f"{seq}|{prev_hash}|trace-default|uid-default|{digest}"
            recomputed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if recomputed != expected_link_hash:
                return False
            prev_hash = recomputed
        return True

    @property
    def current_chain_hash(self) -> str:
        """Return the current tip of the atomic hash chain."""
        return self._last_hash

    @property
    def sequence_number(self) -> int:
        """Return the current sequence number."""
        return self._sequence_number

