"""
Specula RAG Output Validator.

Validates Gemini response output against the DFKG graph context that was
actually retrieved from Neo4j. The purpose is to detect hallucinated UID
citations — UIDs that Gemini invented and that do not exist in the
retrieved subgraph.

This is the output-side complement to the input-side injection guard in
forensic_prompt.py.

Validation rule:
    Every uid=<value> citation found in the Gemini response MUST correspond
    to a node UID that is present in the graph_contexts dict returned by
    DFKGRetriever. Any citation not in that set is flagged as UNVERIFIED.

Usage:
    from src.agents.rag.response_validator import validate_response_uids

    report = validate_response_uids(gemini_text, graph_contexts)
    if report["has_unverified_uids"]:
        # Handle / flag / log

The validator never modifies the Gemini response. It only annotates.

Design note — why uid prefix truncation matters:
    GraphContextBuilder emits uids in the context as uid=<first_16_chars>…
    (truncated for readability). Gemini's response may cite the full UID,
    the first 12 chars, or the first 16 chars. The validator handles all
    three by checking prefix membership rather than exact match.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Set

logger = logging.getLogger("RAGResponseValidator")

# Regex to extract UID-like citations from Gemini text.
# Matches: uid=abc123..., (uid=abc123...), uid=abc123def456...
# A Specula UID is a hex string (SHA-256 output, 64 chars when full).
_UID_PATTERN = re.compile(r"uid=([0-9a-f]{8,64})")

# Minimum UID prefix length to consider a match valid
_MIN_PREFIX_LEN = 8


def _collect_known_uids(graph_contexts: List[Dict[str, Any]]) -> Set[str]:
    """
    Build the set of all UIDs present in the retrieved graph contexts.
    Includes both full UIDs and all prefix substrings >= _MIN_PREFIX_LEN.
    """
    known: Set[str] = set()
    for ctx in graph_contexts:
        for uid in ctx.get("nodes", {}).keys():
            known.add(uid)
            # Add all prefix lengths so prefix citations are resolvable
            for length in range(_MIN_PREFIX_LEN, len(uid) + 1):
                known.add(uid[:length])
    return known


def validate_response_uids(
    gemini_response: str,
    graph_contexts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Validate UID citations in a Gemini response against retrieved graph contexts.

    Args:
        gemini_response: The raw text response from GeminiClient.generate().
        graph_contexts:  List of graph subgraph dicts from DFKGRetriever.retrieve()
                         or DFKGRetriever.expand_from_uid(). These are the ONLY
                         nodes Gemini was allowed to reference.

    Returns:
        A validation report dict:
        {
            "cited_uids":          List[str],  # all uid=... values found in response
            "verified_uids":       List[str],  # cited UIDs that match a known node
            "unverified_uids":     List[str],  # cited UIDs NOT in the graph context
            "has_unverified_uids": bool,
            "total_nodes_in_context": int,
            "validation_passed":   bool,       # True iff has_unverified_uids is False
            "warning_message":     str | None, # human-readable warning, or None
        }
    """
    known_uids = _collect_known_uids(graph_contexts)
    total_nodes = sum(len(ctx.get("nodes", {})) for ctx in graph_contexts)

    # Extract all uid=... citations from the Gemini text
    cited = _UID_PATTERN.findall(gemini_response)

    verified: List[str] = []
    unverified: List[str] = []

    for cited_uid in cited:
        if _is_known(cited_uid, known_uids):
            verified.append(cited_uid)
        else:
            unverified.append(cited_uid)

    has_unverified = len(unverified) > 0
    warning_message: str | None = None

    if has_unverified:
        warning_message = (
            f"HALLUCINATION RISK: {len(unverified)} UID citation(s) in the Gemini response "
            f"could NOT be verified against the {total_nodes} nodes in the retrieved graph context.\n"
            f"Unverified UIDs: {unverified}\n"
            "These UIDs may be hallucinated or may belong to a different case/query."
        )
        logger.warning(warning_message)
    else:
        logger.info(
            f"UID validation passed: {len(verified)} citation(s) verified against "
            f"{total_nodes} context nodes."
        )

    return {
        "cited_uids": cited,
        "verified_uids": verified,
        "unverified_uids": unverified,
        "has_unverified_uids": has_unverified,
        "total_nodes_in_context": total_nodes,
        "validation_passed": not has_unverified,
        "warning_message": warning_message,
    }


def _is_known(cited_uid: str, known_uids: Set[str]) -> bool:
    """
    Check if a cited UID string can be matched to a known UID.
    Handles:
      - Exact full-length match (64 hex chars)
      - Prefix match (Gemini may cite first N chars)
      - Suffix ellipsis patterns: uid=d7708536853e7e83...
    """
    # Strip trailing ellipsis or dots
    clean = cited_uid.rstrip(".")

    # Direct membership (covers full or any pre-computed prefix)
    if clean in known_uids:
        return True

    # Check if any known UID starts with the cited prefix
    for known in known_uids:
        if len(clean) >= _MIN_PREFIX_LEN and known.startswith(clean):
            return True

    return False


def format_validation_report(report: Dict[str, Any]) -> str:
    """
    Format the validation report as a human-readable section for logging or
    appending to the forensic investigation notes.
    """
    lines = [
        "=== DFKG UID VALIDATION REPORT ===",
        f"Context nodes available : {report['total_nodes_in_context']}",
        f"UIDs cited by Gemini    : {len(report['cited_uids'])}",
        f"Verified citations      : {len(report['verified_uids'])}",
        f"Unverified citations    : {len(report['unverified_uids'])}",
        f"Validation result       : {'PASSED ✓' if report['validation_passed'] else 'FAILED — HALLUCINATION RISK ✗'}",
    ]
    if report["unverified_uids"]:
        lines.append("")
        lines.append("⚠ Unverified UIDs (may be hallucinated):")
        for uid in report["unverified_uids"]:
            lines.append(f"  uid={uid}")
    lines.append("=== END VALIDATION REPORT ===")
    return "\n".join(lines)
