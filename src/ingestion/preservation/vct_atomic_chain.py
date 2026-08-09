"""
Specula Verifiable Conversation Transcripts (VCT) Atomic Chain & Merkle Tree.

Registers each atomic log-line/record hash into the VCT hash chain.
Reference: specula_ingestion_final_plan.md §3.3
"""

import hashlib
import json
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class MerkleTree:
    """
    Merkle Tree calculation and verification for VCT audit chains.
    """

    def __init__(self, leaves: List[bytes]):
        self.leaves = [
            hashlib.sha256(leaf).digest() if isinstance(leaf, bytes)
            else hashlib.sha256(str(leaf).encode()).digest()
            for leaf in leaves
        ]
        self.tree: List[List[bytes]] = []
        self._build_tree()

    def _build_tree(self):
        if not self.leaves:
            self.root = ""
            return
        current_layer = self.leaves
        self.tree.append(current_layer)
        while len(current_layer) > 1:
            if len(current_layer) % 2 == 1:
                current_layer.append(current_layer[-1])
            next_layer = []
            for i in range(0, len(current_layer), 2):
                combined = current_layer[i] + current_layer[i + 1]
                parent = hashlib.sha256(combined).digest()
                next_layer.append(parent)
            self.tree.append(next_layer)
            current_layer = next_layer
        self.root = self.tree[-1][0].hex() if self.tree[-1] else ""

    def get_proof(self, index: int) -> List[tuple[str, str]]:
        proof = []
        idx = index
        for layer in self.tree[:-1]:
            is_right = idx % 2 == 1
            sibling_idx = idx - 1 if is_right else idx + 1
            if sibling_idx < len(layer):
                sibling_hash = layer[sibling_idx].hex()
                direction = "left" if is_right else "right"
                proof.append((sibling_hash, direction))
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf: bytes, proof: List[tuple[str, str]], root: str) -> bool:
        current = hashlib.sha256(leaf).digest()
        for sibling_hex, direction in proof:
            sibling = bytes.fromhex(sibling_hex)
            if direction == "left":
                combined = sibling + current
            else:
                combined = current + sibling
            current = hashlib.sha256(combined).digest()
        return current.hex() == root


class VCTAtomicChain:
    """
    Manages the atomic-level hash chain for ingested evidence.
    """

    def __init__(self):
        self._last_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"
        self._sequence_number: int = 0
        self._links: list = []

    def register(self, sha256_digest: str, trace_id: str = "trace-default", uid: str = "uid-default") -> str:
        return self.register_hash(sha256_digest=sha256_digest, trace_id=trace_id, uid=uid)

    def register_hash(self, sha256_digest: str, trace_id: str = "trace-default", uid: str = "uid-default") -> str:
        self._sequence_number += 1
        payload = f"{self._sequence_number}|{self._last_hash}|{trace_id}|{uid}|{sha256_digest}"
        new_chain_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._links.append((sha256_digest, new_chain_hash, trace_id, uid))
        self._last_hash = new_chain_hash
        return new_chain_hash

    def verify_chain(self) -> bool:
        prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        for seq, link_data in enumerate(self._links, start=1):
            if len(link_data) == 4:
                digest, expected_link_hash, trace_id, uid = link_data
            else:
                digest, expected_link_hash = link_data
                trace_id, uid = "trace-default", "uid-default"
            payload = f"{seq}|{prev_hash}|{trace_id}|{uid}|{digest}"
            recomputed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if recomputed != expected_link_hash:
                return False
            prev_hash = recomputed
        return True

    @property
    def current_chain_hash(self) -> str:
        return self._last_hash

    @property
    def sequence_number(self) -> int:
        return self._sequence_number
