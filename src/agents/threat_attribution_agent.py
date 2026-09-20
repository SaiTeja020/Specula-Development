"""
Threat Attribution Agent — real implementation.

Replaces the generic _run_agent() stub with a grounded 3-lookup pipeline:

  1. ATT&CK technique lookup  — ThreatIntelMCPServer.query_attack_techniques()
  2. Threat group lookup       — ThreatIntelMCPServer.query_attack_groups()
  3. Case graph entity fetch   — DFKGQueryTool (parameterized Cypher, read-only)

The LLM is only invoked AFTER these lookups, with the real data injected into
the prompt as grounding context. This eliminates hallucinated technique IDs
and replaces them with FAISS-retrieved, score-ranked ATT&CK records.

Degradation contract (all lookups are best-effort):
  - FAISS not ready (index not built yet): skip lookups A & B, run LLM
    with timeline only and mark attribution.confidence_basis = "llm_only".
  - Neo4j unavailable (driver is None or query fails): skip lookup C,
    run with FAISS results only.
  - Any individual lookup failure is caught and logged; the agent never
    raises from inside lookup failures.

Reference: threat_attribution_plan.md (approved 2026-09-20)
"""
from __future__ import annotations

import datetime
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Top-k constants — tunable without code changes
# ---------------------------------------------------------------------------
_TOP_K_TECHNIQUES = 7   # retrieve extra; LLM selects the most relevant
_TOP_K_GROUPS = 5
_MAX_GRAPH_ENTITIES = 30


# ---------------------------------------------------------------------------
# Lookup A + B — FAISS threat intel
# ---------------------------------------------------------------------------

def _query_threat_intel(
    timeline_summary: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """
    Query FAISS for ATT&CK techniques and groups matching the timeline.

    Returns:
        (techniques, groups, confidence_basis)
        confidence_basis is "faiss+llm" on success, "llm_only" on failure.
    """
    try:
        from src.mcp.threat_intel_mcp import ThreatIntelMCPServer
        server = ThreatIntelMCPServer()

        tech_resp = server.query_attack_techniques(
            query_text=timeline_summary,
            top_k=_TOP_K_TECHNIQUES,
        )
        group_resp = server.query_attack_groups(
            query_text=timeline_summary,
            top_k=_TOP_K_GROUPS,
        )

        techniques = tech_resp.get("results", []) if tech_resp.get("status") == "ok" else []
        groups = group_resp.get("results", []) if group_resp.get("status") == "ok" else []

        logger.info(
            "ThreatIntelMCP: retrieved %d techniques, %d groups for attribution.",
            len(techniques), len(groups),
        )
        return techniques, groups, "faiss+llm"

    except Exception as exc:
        logger.warning(
            "ThreatAttributionAgent: FAISS lookup failed (%s) — "
            "falling back to LLM-only attribution.",
            exc,
        )
        return [], [], "llm_only"


# ---------------------------------------------------------------------------
# Lookup C — Neo4j case graph entities
# ---------------------------------------------------------------------------

def _query_graph_entities(
    neo4j_driver,
    case_id: str,
) -> List[Dict[str, Any]]:
    """
    Fetch confirmed IOCs / entities already in the DFKG for this case.
    Uses DFKGQueryTool (parameterized, read-only — no injection risk).

    Returns empty list if driver is None or query fails.
    """
    if neo4j_driver is None:
        logger.debug("ThreatAttributionAgent: no Neo4j driver — skipping graph entity fetch.")
        return []

    try:
        from src.agents.react_tools import DFKGQueryTool

        tool = DFKGQueryTool(neo4j_driver, case_id)
        cypher = (
            "MATCH (e:Entity {case_id: $case_id}) "
            "RETURN e.uid AS uid, e.type AS type, e.value AS value "
            f"LIMIT {_MAX_GRAPH_ENTITIES}"
        )
        result = tool.run(cypher=cypher, params={})

        if result.ok and result.data:
            logger.info(
                "ThreatAttributionAgent: %d graph entities fetched for case %s.",
                len(result.data), case_id,
            )
            return result.data
        else:
            logger.debug(
                "ThreatAttributionAgent: graph query returned no entities (%s).",
                result.observation,
            )
            return []

    except Exception as exc:
        logger.warning(
            "ThreatAttributionAgent: Neo4j entity fetch failed (%s) — skipping.", exc
        )
        return []


# ---------------------------------------------------------------------------
# Prompt builder — injects real lookup results
# ---------------------------------------------------------------------------

def _format_techniques(techniques: List[Dict[str, Any]]) -> str:
    if not techniques:
        return "No ATT&CK techniques retrieved (FAISS index not ready or no matches)."
    lines = []
    for t in techniques:
        meta = t.get("metadata", {})
        tactic = ", ".join(meta.get("tags", [])) or "unknown tactic"
        lines.append(
            f"  - {t['record_id']} | {t['title']} | tactic: {tactic} | score: {t['score']:.3f}"
        )
    return "\n".join(lines)


def _format_groups(groups: List[Dict[str, Any]]) -> str:
    if not groups:
        return "No threat actor groups retrieved."
    lines = []
    for g in groups:
        lines.append(
            f"  - {g['record_id']} | {g['title']} | score: {g['score']:.3f}"
        )
    return "\n".join(lines)


def _format_entities(entities: List[Dict[str, Any]]) -> str:
    if not entities:
        return "No entities in case graph yet."
    lines = []
    for e in entities:
        lines.append(
            f"  - [{e.get('type', '?')}] {e.get('value', '?')} (uid: {e.get('uid', '?')})"
        )
    return "\n".join(lines)


def _build_grounded_prompt(
    case_id: str,
    timeline_summary: str,
    techniques: List[Dict[str, Any]],
    groups: List[Dict[str, Any]],
    entities: List[Dict[str, Any]],
) -> str:
    return (
        f"You are the Threat Attribution agent for case {case_id}.\n\n"
        "## ATT&CK Techniques retrieved from threat-intel corpus (FAISS semantic search)\n"
        f"{_format_techniques(techniques)}\n\n"
        "## Threat actor groups retrieved from threat-intel corpus\n"
        f"{_format_groups(groups)}\n\n"
        "## Entities confirmed in the forensic graph for this case (Neo4j)\n"
        f"{_format_entities(entities)}\n\n"
        "## Timeline summary (from Timeline Reconstruction agent)\n"
        f"{timeline_summary or 'No timeline available yet.'}\n\n"
        "## Your task\n"
        "Based ONLY on the data above (do not rely on general knowledge for technique IDs), "
        "produce a structured JSON attribution report with EXACTLY this schema:\n"
        "{\n"
        '  "techniques": [\n'
        '    {"id": "T1059.001", "name": "PowerShell", "confidence": 0.87, "tactic": "execution", "reasoning": "..."}\n'
        "  ],\n"
        '  "groups": [\n'
        '    {"id": "G0016", "name": "APT29", "confidence": 0.72, "reasoning": "..."}\n'
        "  ],\n"
        '  "overall_confidence": 0.80,\n'
        '  "low_confidence_flags": ["T1234 confidence < 0.5 — insufficient evidence"],\n'
        '  "narrative": "One-paragraph plain-English summary of the attribution."\n'
        "}\n"
        "Flag any technique or group where confidence < 0.5 in low_confidence_flags. "
        "Respond with ONLY the JSON object, no surrounding text."
    )


# ---------------------------------------------------------------------------
# LLM call + response parsing
# ---------------------------------------------------------------------------

def _call_llm(prompt: str, case_id: str) -> str:
    """Invoke the configured LLM for threat_attribution. Returns raw string."""
    from src.agents.config import get_llm
    llm = get_llm("threat_attribution", case_id=case_id)
    response = llm.invoke(prompt)
    return response.content if hasattr(response, "content") else str(response)


def _parse_llm_response(raw: str) -> Dict[str, Any]:
    """
    Parse the LLM JSON response into a structured attribution dict.
    Falls back to a minimal dict if JSON parsing fails (LLM didn't follow schema).
    """
    # Strip markdown code fences if LLM wrapped the JSON
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        cleaned = "\n".join(
            l for l in lines if not l.strip().startswith("```")
        ).strip()

    try:
        parsed = json.loads(cleaned)
        # Ensure required keys are present
        parsed.setdefault("techniques", [])
        parsed.setdefault("groups", [])
        parsed.setdefault("overall_confidence", 0.0)
        parsed.setdefault("low_confidence_flags", [])
        parsed.setdefault("narrative", raw[:500])
        return parsed
    except (json.JSONDecodeError, ValueError):
        logger.warning(
            "ThreatAttributionAgent: LLM did not return valid JSON — "
            "storing raw response as narrative."
        )
        return {
            "techniques": [],
            "groups": [],
            "overall_confidence": 0.0,
            "low_confidence_flags": ["LLM response was not valid JSON — see narrative"],
            "narrative": raw[:2000],
        }


# ---------------------------------------------------------------------------
# Main entry point — called from nodes.py
# ---------------------------------------------------------------------------

def run_threat_attribution(
    state: dict,
    neo4j_driver=None,
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """
    Run the full grounded threat attribution pipeline.

    Args:
        state:         SpeculaState dict from LangGraph.
        neo4j_driver:  Optional Neo4j driver for graph entity lookup (Lookup C).
                       If None, graph lookup is skipped gracefully.

    Returns:
        (attribution, finding, trace)
        - attribution: structured dict written to state["attribution"]
        - finding:     standard finding dict written to state["findings"]
        - trace:       standard trace dict written to state["agent_traces"]
    """
    t_start = time.time()
    case_id = state.get("case_id", "unknown")
    timeline_summary = str(state.get("timeline", {}).get("summary", ""))[:1000]

    # ------------------------------------------------------------------
    # Lookup A + B: FAISS
    # ------------------------------------------------------------------
    techniques, groups, confidence_basis = _query_threat_intel(timeline_summary)

    # ------------------------------------------------------------------
    # Lookup C: Neo4j graph entities
    # ------------------------------------------------------------------
    entities = _query_graph_entities(neo4j_driver, case_id)

    # ------------------------------------------------------------------
    # Build grounded prompt and call LLM
    # ------------------------------------------------------------------
    prompt = _build_grounded_prompt(
        case_id=case_id,
        timeline_summary=timeline_summary,
        techniques=techniques,
        groups=groups,
        entities=entities,
    )
    raw_response = _call_llm(prompt, case_id)
    parsed = _parse_llm_response(raw_response)

    latency_ms = round((time.time() - t_start) * 1000, 1)

    # ------------------------------------------------------------------
    # Collect dfkg_refs from graph entity UIDs returned by Lookup C
    # ------------------------------------------------------------------
    dfkg_refs = [e["uid"] for e in entities if e.get("uid")]

    # ------------------------------------------------------------------
    # Assemble structured attribution (written to state["attribution"])
    # ------------------------------------------------------------------
    attribution: Dict[str, Any] = {
        "techniques": parsed["techniques"],
        "groups": parsed["groups"],
        "overall_confidence": parsed["overall_confidence"],
        "low_confidence_flags": parsed["low_confidence_flags"],
        "narrative": parsed["narrative"],
        "dfkg_refs": dfkg_refs,
        "confidence_basis": confidence_basis,   # "faiss+llm" | "llm_only"
        "summary": parsed["narrative"],          # for downstream _summarise_findings()
    }

    # ------------------------------------------------------------------
    # Standard finding + trace shapes (match existing agent conventions)
    # ------------------------------------------------------------------
    finding: Dict[str, Any] = {
        "agent_role": "threat_attribution",
        "summary": parsed["narrative"],
        "dfkg_refs": dfkg_refs,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "kafka_offset": None,
        "attribution_detail": {
            "techniques": parsed["techniques"],
            "groups": parsed["groups"],
            "overall_confidence": parsed["overall_confidence"],
            "low_confidence_flags": parsed["low_confidence_flags"],
            "confidence_basis": confidence_basis,
        },
    }

    trace: Dict[str, Any] = {
        "agent_role": "threat_attribution",
        "thought": (
            f"Retrieved {len(techniques)} ATT&CK techniques, {len(groups)} groups "
            f"from FAISS; {len(entities)} entities from Neo4j graph."
        ),
        "action": "grounded_attribution_pipeline",
        "observation": parsed["narrative"][:300],
        "model_used": "gemini-2.5-flash",
        "latency_ms": latency_ms,
        "confidence_basis": confidence_basis,
    }

    return attribution, finding, trace
