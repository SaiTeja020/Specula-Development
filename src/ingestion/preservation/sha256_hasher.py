"""
Specula Chunked SHA-256 Hasher.

Computes SHA-256 digests of raw evidence files/streams incrementally.
Uses a fixed 64MB chunk size to support arbitrarily large inputs.

Reference: specula_ingestion_final_plan.md §3.1
"""

import hashlib
import io
import json
import logging
from typing import Any, BinaryIO, Union

logger = logging.getLogger(__name__)

CHUNK_SIZE_BYTES = 64 * 1024 * 1024


def chunked_sha256(data: Union[bytes, BinaryIO], chunk_size: int = CHUNK_SIZE_BYTES) -> str:
    if isinstance(data, bytes):
        file_obj = io.BytesIO(data)
    else:
        file_obj = data
    return compute_sha256_stream(file_obj, chunk_size=chunk_size)


def compute_sha256_stream(file_obj: BinaryIO, chunk_size: int = CHUNK_SIZE_BYTES) -> str:
    hasher = hashlib.sha256()
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def compute_sha256_file(file_path: str, chunk_size: int = CHUNK_SIZE_BYTES) -> str:
    with open(file_path, "rb") as f:
        return compute_sha256_stream(f, chunk_size)


def canonical_json_hash(obj: Any) -> str:
    """
    Compute deterministic SHA-256 hash of a dictionary with sorted keys.
    """
    canonical_bytes = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return compute_sha256_bytes(canonical_bytes)
