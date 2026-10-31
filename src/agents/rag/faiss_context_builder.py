"""
Specula FAISS Threat-Intel Context Builder for RAG Pipeline.

Queries the existing FAISS threat-intel corpus (ATT&CK techniques/groups + CVE
records) and converts results into a structured text block that is appended to
the forensic RAG prompt as a separate, clearly labelled section.

Design rules (per ADR-036):
 - The FAISS corpus is labelled THREAT-INTEL CONTEXT — distinct from the
   FORENSIC EVIDENCE section so the model always knows the provenance.
 - Results are bounded by `top_k` and are presented read-only; no writes.
 - Corpus unavailability is non-fatal: the caller receives an empty string and
   a trace note instead of an exception.
 - No new dependency: reuses ThreatIntelIndex / ThreatIntelMCPServer which are
   already imported elsewhere in the codebase.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("FaissContextBuilder")

# Maximum results fetched per record type when the query is not type-filtered.
_DEFAULT_TECHNIQUE_K = 5
_DEFAULT_GROUP_K = 3
_DEFAULT_CVE_K = 3


def _format_technique(rec: Dict[str, Any]) -> str:
    meta = rec.get("metadata", {})
    tid = meta.get("technique_id", rec.get("record_id", "?"))
    name = rec.get("title", meta.get("name", "Unknown technique"))
    tactic = meta.get("tactic", "")
    tactic_str = f" [{tactic}]" if tactic else ""
    score = rec.get("score", 0.0)
    return f"  ATT&CK {tid}{tactic_str}: {name}  (similarity={score:.3f})"


def _format_group(rec: Dict[str, Any]) -> str:
    meta = rec.get("metadata", {})
    gid = meta.get("group_id", rec.get("record_id", "?"))
    name = rec.get("title", meta.get("name", "Unknown group"))
    aliases = meta.get("aliases", [])
    alias_str = f" (aka {', '.join(aliases)})" if aliases else ""
    score = rec.get("score", 0.0)
    return f"  ATT&CK Group {gid}{alias_str}: {name}  (similarity={score:.3f})"


def _format_cve(rec: Dict[str, Any]) -> str:
    meta = rec.get("metadata", {})
    cve_id = meta.get("cve_id", rec.get("record_id", "?"))
    desc = rec.get("title", meta.get("description", ""))
    cvss = meta.get("cvss_score", "N/A")
    score = rec.get("score", 0.0)
    short_desc = desc[:120] + "…" if len(desc) > 120 else desc
    return f"  {cve_id} (CVSS {cvss}): {short_desc}  (similarity={score:.3f})"


def build_faiss_threat_context(
    query: str,
    threat_intel_server: Any,
    technique_k: int = _DEFAULT_TECHNIQUE_K,
    group_k: int = _DEFAULT_GROUP_K,
    cve_k: int = _DEFAULT_CVE_K,
) -> str:
    """
    Query the FAISS threat-intel corpus for techniques, groups, and CVEs
    relevant to *query* and return a formatted multi-line string.

    Args:
        query:               The analyst's forensic question (same text used
                             for ChromaDB retrieval).
        threat_intel_server: ThreatIntelMCPServer instance (or any object
                             exposing query_attack_techniques / query_attack_groups /
                             query_cves methods).
        technique_k:         Max ATT&CK techniques to return.
        group_k:             Max ATT&CK groups to return.
        cve_k:               Max CVE records to return.

    Returns:
        Formatted string to embed in the RAG prompt, or "" if the corpus is
        unavailable (non-fatal).
    """
    techniques: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    cves: List[Dict[str, Any]] = []
    trace_notes: List[str] = []

    # --- Techniques ---
    try:
        if hasattr(threat_intel_server, "query_attack_techniques"):
            resp = threat_intel_server.query_attack_techniques(query, top_k=technique_k)
            techniques = resp.get("results", []) if isinstance(resp, dict) else resp
        else:
            trace_notes.append("query_attack_techniques_unavailable")
    except Exception as exc:
        logger.debug("FAISS technique query failed: %s", exc)
        trace_notes.append(f"technique_query_error:{type(exc).__name__}")

    # --- Groups ---
    try:
        if hasattr(threat_intel_server, "query_attack_groups"):
            resp = threat_intel_server.query_attack_groups(query, top_k=group_k)
            groups = resp.get("results", []) if isinstance(resp, dict) else resp
        else:
            trace_notes.append("query_attack_groups_unavailable")
    except Exception as exc:
        logger.debug("FAISS group query failed: %s", exc)
        trace_notes.append(f"group_query_error:{type(exc).__name__}")

    # --- CVEs ---
    try:
        if hasattr(threat_intel_server, "query_cves"):
            resp = threat_intel_server.query_cves(query, top_k=cve_k)
            cves = resp.get("results", []) if isinstance(resp, dict) else resp
        else:
            trace_notes.append("query_cves_unavailable")
    except Exception as exc:
        logger.debug("FAISS CVE query failed: %s", exc)
        trace_notes.append(f"cve_query_error:{type(exc).__name__}")

    total = len(techniques) + len(groups) + len(cves)
    logger.info(
        "FAISS threat-intel context: %d techniques, %d groups, %d CVEs for query '%s…'",
        len(techniques), len(groups), len(cves), query[:50],
    )

    if total == 0:
        note = "; ".join(trace_notes) if trace_notes else "corpus_empty_or_not_built"
        logger.info("FAISS threat-intel context empty: %s", note)
        return ""

    lines: List[str] = [
        "=== THREAT-INTEL CONTEXT (FAISS ATT&CK + CVE corpus) ===",
        "(This context comes from the pre-built threat-intelligence index and",
        " is ranked by semantic similarity to your query. It is NOT case evidence.)",
        "",
    ]

    if techniques:
        lines.append("-- Related ATT&CK Techniques --")
        lines.extend(_format_technique(r) for r in techniques)
        lines.append("")

    if groups:
        lines.append("-- Potentially Related Threat Actor Groups --")
        lines.extend(_format_group(r) for r in groups)
        lines.append("")

    if cves:
        lines.append("-- Related CVE Records --")
        lines.extend(_format_cve(r) for r in cves)
        lines.append("")

    lines.append("=== END THREAT-INTEL CONTEXT ===")

    if trace_notes:
        lines.append(f"(Partial corpus availability: {'; '.join(trace_notes)})")

    return "\n".join(lines)

