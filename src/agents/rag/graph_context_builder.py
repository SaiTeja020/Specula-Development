"""
Specula Graph Context Builder.

Converts the raw graph subgraph returned by DFKGRetriever.expand_from_uid()
into a human-readable, LLM-ingestible structured text block suitable for
inclusion in a forensic RAG prompt.

The output is deterministic and inspectable — every step is logged so that
the pipeline can be debugged without reading the LLM response.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger("GraphContextBuilder")

# Label -> human-readable property priorities (what to surface in context)
_LABEL_KEY_PRIORITY: Dict[str, List[str]] = {
    "Host":            ["hostname"],
    "Process":         ["process_name", "pid", "command_line", "start_time"],
    "User":            ["user_name"],
    "NetworkEndpoint": ["ip", "canonical_host_id"],
    "File":            ["file_name", "file_path", "file_hash_sha256"],
}


def _format_node(uid: str, node: Dict[str, Any]) -> str:
    label = node.get("label", "Unknown")
    props = node.get("properties", {})

    priority_keys = _LABEL_KEY_PRIORITY.get(label, [])
    ordered_props = []

    # Priority keys first
    for k in priority_keys:
        if k in props and props[k] is not None:
            ordered_props.append(f"    {k}: {props[k]}")

    # Then any remaining non-system keys
    system_keys = {"case_id", "first_seen", "last_seen", "canonical_host_id", "timestamp"}
    for k, v in props.items():
        if k not in priority_keys and k not in system_keys and v is not None:
            ordered_props.append(f"    {k}: {v}")

    props_str = "\n".join(ordered_props) if ordered_props else "    (no additional properties)"
    return f"[{label}] uid={uid[:16]}…\n{props_str}"


def build_graph_context(graph_contexts: List[Dict[str, Any]], query: str) -> str:
    """
    Convert a list of graph subgraphs into a structured forensic context string.

    Args:
        graph_contexts: List of subgraphs from DFKGRetriever.expand_from_uid()
        query: Original user query (included for reference)

    Returns:
        A formatted multi-line string ready to embed in an LLM prompt.
    """
    if not graph_contexts:
        return "NO FORENSIC GRAPH CONTEXT RETRIEVED. The query returned no relevant DFKG entities."

    lines: List[str] = [
        "=== RETRIEVED FORENSIC GRAPH CONTEXT ===",
        f"Query: {query}",
        "",
    ]

    all_nodes: Dict[str, Dict] = {}
    all_edges: List[Dict] = []

    # Merge all subgraphs (deduplicate nodes by uid)
    for ctx in graph_contexts:
        for uid, node in ctx.get("nodes", {}).items():
            if uid not in all_nodes:
                all_nodes[uid] = node
        all_edges.extend(ctx.get("edges", []))

    # Deduplicate edges
    seen_edges = set()
    unique_edges = []
    for e in all_edges:
        key = (e["from_uid"], e["rel"], e["to_uid"])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(e)

    lines.append(f"Entities retrieved: {len(all_nodes)}")
    lines.append(f"Relationships retrieved: {len(unique_edges)}")
    lines.append("")

    lines.append("--- ENTITIES ---")
    for uid, node in all_nodes.items():
        lines.append(_format_node(uid, node))
        lines.append("")

    lines.append("--- RELATIONSHIPS ---")
    for e in unique_edges:
        from_node = all_nodes.get(e["from_uid"], {})
        to_node   = all_nodes.get(e["to_uid"],   {})
        from_label = from_node.get("label", "?")
        to_label   = to_node.get("label",   "?")
        from_name  = _get_display_name(from_node)
        to_name    = _get_display_name(to_node)
        lines.append(
            f"  [{from_label}] {from_name} (uid={e['from_uid'][:12]}…)"
            f"  --[{e['rel']}]-->"
            f"  [{to_label}] {to_name} (uid={e['to_uid'][:12]}…)"
        )

    lines.append("")
    lines.append("=== END OF FORENSIC CONTEXT ===")

    context = "\n".join(lines)
    logger.info(f"Graph context built: {len(all_nodes)} nodes, {len(unique_edges)} edges")
    logger.debug(f"\n{context}")
    return context


def _get_display_name(node: Dict[str, Any]) -> str:
    """Extract the most human-meaningful name property from a node."""
    props = node.get("properties", {})
    for key in ("process_name", "hostname", "user_name", "ip", "file_name"):
        val = props.get(key)
        if val:
            return str(val)
    return "(unnamed)"
