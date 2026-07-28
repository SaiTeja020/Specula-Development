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
from typing import Any, Dict

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
            source_type: E.g., 'evtx', 'syslog', 'pcap'.

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
