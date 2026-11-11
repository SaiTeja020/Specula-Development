"""
Specula Quickwit Append-Only Client.

Commits raw bytes, unmodified, to Quickwit over its REST API.
This is the Tier-1 evidence preservation step. Nothing that lands
here can later be edited or deleted.

Reference: specula_ingestion_final_plan.md §3.2

Mistakes to avoid (from v6):
    Do NOT treat Quickwit commit failure as non-fatal. If preservation
    fails, the event must not proceed further in the pipeline.
"""

import base64
import json
import logging
import time as _time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

QUICKWIT_ENDPOINT = "http://localhost:7280"
EVIDENCE_INDEX_NAME = "specula_raw_evidence"


class QuickwitClientError(Exception):
    """Raised when an append-only commit to Quickwit fails."""
    pass


class QuickwitClient:
    """Client for appending raw evidence to Quickwit."""

    def __init__(self, endpoint: str = QUICKWIT_ENDPOINT, index_name: str = EVIDENCE_INDEX_NAME):
        self.endpoint = endpoint.rstrip("/")
        self.index_name = index_name
        self.ingest_url = f"{self.endpoint}/api/v1/{self.index_name}/ingest"

    # ------------------------------------------------------------------
    # Core write path
    # ------------------------------------------------------------------

    def commit_raw_evidence(
        self,
        uid: str,
        trace_id: str,
        sha256_digest: str,
        raw_bytes: bytes,
        source_type: str,
    ) -> None:
        """
        Commit raw evidence bytes to Quickwit securely.

        Args:
            uid: Deterministic UID of the entity/event.
            trace_id: W3C trace-context identifier.
            sha256_digest: Pre-computed SHA-256 digest of the raw_bytes.
            raw_bytes: The original untouched bytes, NEVER sanitized or extracted.
            source_type: E.g., 'evtx', 'mft', 'cloudtrail'.

        Raises:
            QuickwitClientError: If the commit fails. Preservation failure
                                 MUST halt pipeline progression.
        """
        # Encode raw bytes to base64 for safe transport via JSON API
        b64_data = base64.b64encode(raw_bytes).decode("utf-8")

        payload = {
            "uid": uid,
            "trace_id": trace_id,
            "sha256": sha256_digest,
            "source_type": source_type,
            "raw_data_b64": b64_data,
            "committed_at_ms": int(_time.time() * 1000),
        }

        # Quickwit ingest API expects NDJSON
        ndjson_payload = json.dumps(payload) + "\n"

        try:
            response = requests.post(
                self.ingest_url,
                data=ndjson_payload,
                headers={"Content-Type": "application/x-ndjson"},
                timeout=10.0,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            error_msg = f"Failed to commit raw evidence to Quickwit (uid={uid}): {e}"
            logger.error(error_msg)
            # Fatal error: without preservation, we have no chain of custody.
            raise QuickwitClientError(error_msg) from e
        
        logger.debug(f"Successfully committed raw evidence to Quickwit: uid={uid}")

    # ------------------------------------------------------------------
    # Index lifecycle
    # ------------------------------------------------------------------

    def ensure_index(self) -> None:
        """
        Create the Quickwit index for raw evidence if it does not already exist.

        Idempotent — safe to call on every pipeline startup. A 400 response
        with 'already exists' in the body is silently ignored; any other
        error raises QuickwitClientError.

        Reference: specula_ingestion_final_plan.md §3.2
        """
        index_schema = {
            "version": "0.7",
            "index_id": self.index_name,
            "doc_mapping": {
                "mode": "lenient",
                "field_mappings": [
                    # uid: raw tokenizer so exact-match UID search works correctly
                    {"name": "uid", "type": "text", "tokenizer": "raw",
                     "record": "basic", "fast": True},
                    {"name": "trace_id", "type": "text", "tokenizer": "raw",
                     "record": "basic"},
                    # sha256 stored as raw text for exact-match integrity checks
                    {"name": "sha256", "type": "text", "tokenizer": "raw",
                     "record": "basic", "fast": True},
                    {"name": "source_type", "type": "text", "tokenizer": "raw",
                     "record": "basic", "fast": True},
                    # raw bytes stored as base64 — not indexed (too large / not useful to search)
                    {"name": "raw_data_b64", "type": "text",
                     "indexed": False, "stored": True},
                    # epoch-ms timestamp for ordering and range queries
                    {"name": "committed_at_ms", "type": "i64",
                     "fast": True, "stored": True},
                ],
            },
            "search_settings": {
                "default_search_fields": ["uid"],
            },
            "indexing_settings": {
                # Commit every 5 seconds for near-real-time visibility in dev
                "commit_timeout_secs": 5,
            },
        }

        url = f"{self.endpoint}/api/v1/indexes"
        try:
            response = requests.post(
                url,
                json=index_schema,
                headers={"Content-Type": "application/json"},
                timeout=10.0,
            )
            # 200/201 = created; 400/409 with "already exist" in body = idempotent success
            if response.status_code in (400, 409) and "already exist" in response.text.lower():
                logger.debug(f"Quickwit index '{self.index_name}' already exists — skipping creation.")
                return
            response.raise_for_status()
            logger.info(f"Quickwit index '{self.index_name}' created successfully.")
        except requests.RequestException as e:
            raise QuickwitClientError(
                f"Failed to ensure Quickwit index '{self.index_name}': {e}"
            ) from e

    # ------------------------------------------------------------------
    # Read / integrity path
    # ------------------------------------------------------------------

    def get_evidence(self, uid: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a stored evidence record from Quickwit by its UID.

        Used by integrity_checker.py to verify stored vs. replayed bytes.
        Returns None if no record is found for the given uid.

        Args:
            uid: Deterministic UID of the evidence entity.

        Returns:
            Dict with keys: uid, trace_id, sha256, source_type, raw_bytes,
            committed_at_ms — or None if not found.

        Raises:
            QuickwitClientError: If the Quickwit search request itself fails.
        """
        search_url = f"{self.endpoint}/api/v1/{self.index_name}/search"
        # Escape any special Lucene characters in the uid
        escaped_uid = uid.replace('"', '\\"')
        body = {
            "query": f'uid:"{escaped_uid}"',
            "max_hits": 1,
        }

        try:
            response = requests.post(
                search_url,
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=10.0,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise QuickwitClientError(
                f"Failed to retrieve evidence from Quickwit (uid={uid}): {e}"
            ) from e

        result = response.json()
        hits = result.get("hits", [])
        if not hits:
            return None

        hit = hits[0]
        # Decode base64 raw_data_b64 back to bytes for integrity comparison
        raw_b64 = hit.get("raw_data_b64", "")
        raw_bytes = base64.b64decode(raw_b64) if raw_b64 else b""

        return {
            "uid": hit.get("uid"),
            "trace_id": hit.get("trace_id"),
            "sha256": hit.get("sha256"),
            "source_type": hit.get("source_type"),
            "raw_bytes": raw_bytes,
            "committed_at_ms": hit.get("committed_at_ms"),
        }
