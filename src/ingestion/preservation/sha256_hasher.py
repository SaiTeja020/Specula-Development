"""
Specula Chunked SHA-256 Hasher.

Computes SHA-256 digests of raw evidence files/streams incrementally.
Uses a fixed 64MB chunk size to support arbitrarily large inputs
(e.g., memory dumps, disk images) without exhausting memory.

Reference: specula_ingestion_final_plan.md §3.1
"""

import hashlib
import io
import logging
from typing import BinaryIO, Union

logger = logging.getLogger(__name__)

# Recommended chunk size from v6 plan: 64MB
CHUNK_SIZE_BYTES = 64 * 1024 * 1024


def chunked_sha256(data: Union[bytes, BinaryIO], chunk_size: int = CHUNK_SIZE_BYTES) -> str:
    """
    Compute SHA-256 digest of bytes or a binary stream incrementally.

    Args:
        data: Raw bytes or binary file-like object.
        chunk_size: Size of chunks to read into memory at once.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    if isinstance(data, bytes):
        file_obj = io.BytesIO(data)
    else:
        file_obj = data
    return compute_sha256_stream(file_obj, chunk_size=chunk_size)



def compute_sha256_stream(file_obj: BinaryIO, chunk_size: int = CHUNK_SIZE_BYTES) -> str:
    """
    Compute SHA-256 digest of a binary stream incrementally.

    Args:
        file_obj: A binary file-like object (must be open in 'rb' mode).
        chunk_size: Size of chunks to read into memory at once.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    hasher = hashlib.sha256()
    
    # Ensure we read from the current position. If the caller needs
    # the whole file hashed, they should seek(0) before calling.
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
        
    return hasher.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """
    Compute SHA-256 digest of a byte string in memory.
    
    This is a convenience wrapper for small payloads (e.g., single
    syslog messages or API responses) where streaming is overkill.
    
    Args:
        data: The raw bytes to hash.
        
    Returns:
        Hex-encoded SHA-256 digest string.
    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def compute_sha256_file(file_path: str, chunk_size: int = CHUNK_SIZE_BYTES) -> str:
    """
    Compute SHA-256 digest of a file on disk incrementally.

    Args:
        file_path: Path to the file.
        chunk_size: Size of chunks to read into memory at once.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    with open(file_path, "rb") as f:
        return compute_sha256_stream(f, chunk_size)
