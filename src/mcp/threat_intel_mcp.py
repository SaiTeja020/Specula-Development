"""
MCP Server: mcp-threat-intel

Exposes the FAISS threat-intel corpus to the Threat Attribution Agent via
tool-call interface consistent with the existing mcp-vector-retrieval and
mcp-dfkg-cypher servers.

Tools exposed:
    query_attack_techniques(query_text, top_k)
    query_attack_groups(query_text, top_k)
    query_cves(query_text, top_k)
    health_check()

No RBAC on reads — this corpus has no case-sensitive or secret data.
No write interface — corpus is exclusively built offline by
scripts/build_threat_intel_index.py.

Reference: faiss_threat_intel_implementation_plan.md §6.1
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from src.ingestion.indexing.threat_intel_index import (
    ThreatIntelIndex,
    ThreatIntelIndexNotReadyError,
)

logger = logging.getLogger("ThreatIntelMCP")

# Corpus staleness threshold: warn in health_check() if corpus is older than
# this many seconds (default 26 hours — one missed daily build + buffer).
_DEFAULT_STALENESS_THRESHOLD_SECS: float = 26 * 3600


class ThreatIntelMCPServer:
    """
    MCP server for the FAISS threat-intel corpus.

    Usage
    -----
    server = ThreatIntelMCPServer()          # auto-loads from data/threat_intel/
    results = server.query_attack_techniques("powershell credential dumping")
    """

    def __init__(
        self,
        index: Optional[ThreatIntelIndex] = None,
        index_dir: str = "data/threat_intel",
        nprobe: int = 8,
        staleness_threshold_secs: float = _DEFAULT_STALENESS_THRESHOLD_SECS,
    ) -> None:
        self._index = index or ThreatIntelIndex(
            index_dir=index_dir, nprobe=nprobe
        )
        self._staleness_threshold = staleness_threshold_secs

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def query_attack_techniques(
        self,
        query_text: str,
        top_k: int = 5,
        nprobe: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Tool: query_attack_techniques
        Semantic search over MITRE ATT&CK technique records.

        Args:
            query_text: Natural-language behaviour description to match.
            top_k:      Max results to return.
            nprobe:     Optional FAISS nprobe override for recall/latency tradeoff.

        Returns:
            {"status": "ok", "count": N, "results": [...]}
        """
        return self._query(
            query_text=query_text,
            record_type="attack_technique",
            top_k=top_k,
            nprobe=nprobe,
            tool_name="query_attack_techniques",
        )

    def query_attack_groups(
        self,
        query_text: str,
        top_k: int = 5,
        nprobe: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Tool: query_attack_groups
        Semantic search over MITRE ATT&CK threat-group / intrusion-set records.

        Args:
            query_text: Natural-language description of observed threat actor behaviour.
            top_k:      Max results to return.
            nprobe:     Optional FAISS nprobe override.
        """
        return self._query(
            query_text=query_text,
            record_type="attack_group",
            top_k=top_k,
            nprobe=nprobe,
            tool_name="query_attack_groups",
        )

    def query_cves(
        self,
        query_text: str,
        top_k: int = 5,
        nprobe: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Tool: query_cves
        Semantic search over NVD CVE records.

        Args:
            query_text: Vulnerability description or affected product/component.
            top_k:      Max results to return.
            nprobe:     Optional FAISS nprobe override.
        """
        return self._query(
            query_text=query_text,
            record_type="cve",
            top_k=top_k,
            nprobe=nprobe,
            tool_name="query_cves",
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Tool: health_check
        Returns corpus readiness, size, build timestamp, and staleness age.

        The Threat Attribution Agent (or a monitoring hook) should call this to
        detect a stale corpus feeding attribution scores, per Master doc §9.6.
        """
        # Opportunistically check for a fresh corpus before reporting status
        try:
            reloaded = self._index.reload_if_stale()
        except Exception as exc:
            logger.warning("health_check: reload_if_stale raised: %s", exc)
            reloaded = False

        ready = self._index.is_ready()
        corpus_size = self._index.corpus_size
        build_timestamp = self._index.build_timestamp

        # Compute staleness
        corpus_age_secs: Optional[float] = None
        is_stale = False
        if build_timestamp:
            try:
                import datetime
                ts = datetime.datetime.fromisoformat(
                    build_timestamp.replace("Z", "+00:00")
                )
                now = datetime.datetime.now(datetime.timezone.utc)
                corpus_age_secs = (now - ts).total_seconds()
                is_stale = corpus_age_secs > self._staleness_threshold
            except Exception:
                pass

        if is_stale:
            logger.warning(
                "health_check: threat-intel corpus is stale (%.0f s old, "
                "threshold=%.0f s). Attribution scores may be outdated.",
                corpus_age_secs,
                self._staleness_threshold,
            )

        return {
            "status": "ready" if ready else "not_ready",
            "corpus_size": corpus_size,
            "build_timestamp": build_timestamp,
            "corpus_age_secs": corpus_age_secs,
            "is_stale": is_stale,
            "staleness_threshold_secs": self._staleness_threshold,
            "reloaded_on_this_call": reloaded,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _query(
        self,
        query_text: str,
        record_type: str,
        top_k: int,
        nprobe: Optional[int],
        tool_name: str,
    ) -> Dict[str, Any]:
        """Shared query dispatcher with error handling."""
        if not query_text or not query_text.strip():
            return {"status": "ok", "count": 0, "results": []}

        # Reload on every query call (cheap hash check, no I/O if manifest unchanged)
        try:
            self._index.reload_if_stale()
        except Exception as exc:
            logger.warning("%s: reload_if_stale raised: %s", tool_name, exc)

        try:
            results = self._index.query(
                query_text=query_text,
                record_type=record_type,
                top_k=top_k,
                nprobe=nprobe,
            )
        except ThreatIntelIndexNotReadyError as exc:
            return {
                "status": "error",
                "error": str(exc),
                "count": 0,
                "results": [],
            }

        return {
            "status": "ok",
            "count": len(results),
            "results": results,
        }
