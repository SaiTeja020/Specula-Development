"""
FAISS IndexIVFPQ Threat-Intel Corpus Index.

Loads, queries, and hot-reloads the pre-built FAISS index for ATT&CK
techniques/groups and CVE records. This is the in-process, read-only
component consumed by threat_intel_mcp.py.

Key design rules (from the implementation plan §3 & §6):
- IndexIVFPQ MUST be trained before vectors can be added (build script handles
  this; ThreatIntelIndex.load() trusts that the on-disk file is already trained).
- FAISS has no native metadata filter. record_type filtering is done
  post-search by over-fetching (top_k * 3) and filtering, then truncating.
- Hot-reload is atomic: check build_manifest.json hash, reload all three files
  together under a lock so a concurrent query never sees a partial state.

Reference: faiss_threat_intel_implementation_plan.md §3, §4.1 step 9, §6
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default paths (relative to repo root; build script writes here)
# ---------------------------------------------------------------------------
_DEFAULT_INDEX_DIR = os.path.join("data", "threat_intel")
_FAISS_INDEX_FILE = "faiss_index.bin"
_ID_MAP_FILE = "faiss_id_map.json"
_METADATA_FILE = "metadata_store.json"
_MANIFEST_FILE = "build_manifest.json"


class ThreatIntelIndexNotReadyError(Exception):
    """Raised when the index is queried before a valid corpus has been loaded."""


class ThreatIntelIndex:
    """
    In-process FAISS threat-intel corpus index.

    Lifecycle
    ---------
    1. At __init__ time, _load() is called. If the index files don't exist yet
       (e.g. first run before build_threat_intel_index.py has run), the index
       starts in a "not-ready" state and all queries raise
       ThreatIntelIndexNotReadyError.
    2. Call reload_if_stale() periodically (e.g. on each MCP request) to pick
       up a rebuilt corpus without restarting the process.
    """

    def __init__(
        self,
        index_dir: str = _DEFAULT_INDEX_DIR,
        nprobe: int = 8,
    ) -> None:
        self.index_dir = index_dir
        self.default_nprobe = nprobe

        # Guarded by _lock for hot-reload safety
        self._lock = threading.RLock()
        self._faiss_index: Any = None          # faiss.IndexIVFPQ instance
        self._id_map: Dict[int, str] = {}      # faiss int id -> record_id string
        self._metadata: Dict[str, dict] = {}   # record_id -> metadata dict
        self._manifest_hash: Optional[str] = None
        self._corpus_size: int = 0
        self._build_timestamp: Optional[str] = None

        self._load()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def reload_if_stale(self) -> bool:
        """
        Check build_manifest.json content hash. If it has changed since the last
        load (i.e. build_threat_intel_index.py wrote a new corpus), atomically
        reload all three index files.

        Returns True if a reload happened, False if the corpus is still current.
        """
        manifest_path = os.path.join(self.index_dir, _MANIFEST_FILE)
        if not os.path.isfile(manifest_path):
            return False

        current_hash = self._file_hash(manifest_path)
        if current_hash == self._manifest_hash:
            return False

        logger.info(
            "ThreatIntelIndex: manifest changed (old=%s new=%s) — reloading corpus.",
            self._manifest_hash,
            current_hash,
        )
        self._load()
        return True

    def query(
        self,
        query_text: str,
        record_type: Optional[str] = None,
        top_k: int = 5,
        nprobe: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Embed query_text, search FAISS, post-filter by record_type, return
        ranked results with scores.

        Args:
            query_text:  Natural-language query (will be embedded on the fly).
            record_type: Optional filter: "attack_technique" | "attack_group" | "cve".
                         Filtering happens AFTER the FAISS search (FAISS has no
                         native metadata filter).  We over-fetch top_k * 3 to
                         compensate for the loss from filtering.
            top_k:       Max number of results to return after filtering.
            nprobe:      Number of IVFPQ cells to probe. Defaults to self.default_nprobe.
                         Higher = better recall, slower query.

        Returns:
            List of dicts with keys: record_id, record_type, title, score, metadata.

        Raises:
            ThreatIntelIndexNotReadyError: if no corpus has been built yet.
        """
        with self._lock:
            if self._faiss_index is None:
                raise ThreatIntelIndexNotReadyError(
                    "Threat-intel index is not ready. "
                    "Run scripts/build_threat_intel_index.py first."
                )

            try:
                import faiss  # noqa: F401
                import numpy as np
            except ImportError as exc:
                raise RuntimeError(
                    "faiss-cpu is not installed. Add it to requirements.txt."
                ) from exc

            from src.ingestion.indexing.vector_store import EmbeddingGenerator
            gen = EmbeddingGenerator()
            vec = gen.embed(query_text)
            query_vec = np.array([vec], dtype="float32")

            # Over-fetch when filtering by record_type to avoid short results
            fetch_k = top_k * 3 if record_type else top_k

            eff_nprobe = nprobe if nprobe is not None else self.default_nprobe
            if hasattr(self._faiss_index, "nprobe"):
                self._faiss_index.nprobe = eff_nprobe

            distances, indices = self._faiss_index.search(query_vec, fetch_k)

            results: List[Dict[str, Any]] = []
            for dist, idx in zip(distances[0], indices[0]):
                if idx < 0:
                    # FAISS returns -1 for empty slots
                    continue
                record_id = self._id_map.get(int(idx))
                if record_id is None:
                    continue
                meta = self._metadata.get(record_id, {})

                # Post-search filter by record_type
                if record_type and meta.get("record_type") != record_type:
                    continue

                results.append(
                    {
                        "record_id": record_id,
                        "record_type": meta.get("record_type"),
                        "title": meta.get("title", ""),
                        "score": float(dist),
                        "metadata": meta,
                    }
                )

                if len(results) >= top_k:
                    break

            return results

    @property
    def corpus_size(self) -> int:
        """Total number of vectors currently loaded in the index."""
        with self._lock:
            return self._corpus_size

    @property
    def build_timestamp(self) -> Optional[str]:
        """ISO-8601 UTC timestamp of the last successful corpus build."""
        with self._lock:
            return self._build_timestamp

    def is_ready(self) -> bool:
        """Return True if a corpus has been successfully loaded."""
        with self._lock:
            return self._faiss_index is not None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """
        Load (or reload) all three index artifacts from disk atomically.
        Acquires _lock to prevent concurrent queries from seeing a partial state.
        """
        index_path = os.path.join(self.index_dir, _FAISS_INDEX_FILE)
        id_map_path = os.path.join(self.index_dir, _ID_MAP_FILE)
        metadata_path = os.path.join(self.index_dir, _METADATA_FILE)
        manifest_path = os.path.join(self.index_dir, _MANIFEST_FILE)

        # If any required file is missing, stay (or remain) in not-ready state
        missing = [
            p for p in [index_path, id_map_path, metadata_path, manifest_path]
            if not os.path.isfile(p)
        ]
        if missing:
            logger.warning(
                "ThreatIntelIndex: missing files %s — index not ready.", missing
            )
            return

        try:
            import faiss
            new_index = faiss.read_index(index_path)
        except ImportError as exc:
            raise RuntimeError(
                "faiss-cpu is not installed. "
                "Run: pip install faiss-cpu"
            ) from exc
        except Exception as exc:
            logger.error("ThreatIntelIndex: failed to load FAISS index: %s", exc)
            return

        try:
            with open(id_map_path, "r", encoding="utf-8") as f:
                # Keys are stored as strings in JSON; convert back to int
                raw_id_map = json.load(f)
            new_id_map = {int(k): v for k, v in raw_id_map.items()}
        except Exception as exc:
            logger.error("ThreatIntelIndex: failed to load id_map: %s", exc)
            return

        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                new_metadata = json.load(f)
        except Exception as exc:
            logger.error("ThreatIntelIndex: failed to load metadata_store: %s", exc)
            return

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception as exc:
            logger.error("ThreatIntelIndex: failed to load build_manifest: %s", exc)
            return

        # Atomic swap under lock
        with self._lock:
            self._faiss_index = new_index
            self._id_map = new_id_map
            self._metadata = new_metadata
            self._manifest_hash = self._file_hash(manifest_path)
            self._corpus_size = new_index.ntotal
            self._build_timestamp = manifest.get("build_timestamp")

        logger.info(
            "ThreatIntelIndex loaded: %d vectors, build_timestamp=%s",
            self._corpus_size,
            self._build_timestamp,
        )

    @staticmethod
    def _file_hash(path: str) -> str:
        """Return SHA-256 hex digest of a file's contents."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
