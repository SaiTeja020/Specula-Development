"""LangGraph node factory for the deterministic Memory Forensics specialist."""
from __future__ import annotations

import time
from typing import Any, Callable

from src.agents.memory_forensics.agent import run_memory_forensics_analysis
from src.agents.memory_forensics.kafka_publisher import publish_findings


def _records_to_artifacts(records: Any) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for record in records or []:
        value = record.get("e") if hasattr(record, "get") else None
        if value is None:
            continue
        artifacts.append(dict(value.items()) if hasattr(value, "items") else dict(value))
    return artifacts


def _load_artifacts(state: dict, neo4j_driver: Any,
                    artifact_provider: Callable[[dict], list[dict]] | None) -> list[dict[str, Any]]:
    if artifact_provider is not None:
        return artifact_provider(state)
    supplied = state.get("memory_artifacts")
    if isinstance(supplied, list):
        return [artifact for artifact in supplied if isinstance(artifact, dict)]
    if neo4j_driver is None:
        return []
    query = """
    MATCH (e {case_id: $case_id})
    WHERE e.source_type = 'memory'
       OR toLower(coalesce(e.plugin, '')) CONTAINS 'scan'
       OR toLower(coalesce(e.plugin, '')) CONTAINS 'malfind'
       OR toLower(coalesce(e.artifact_type, '')) CONTAINS 'memory'
    RETURN e
    """
    records, _, _ = neo4j_driver.execute_query(query, case_id=state.get("case_id"))
    return _records_to_artifacts(records)


def make_memory_forensics_node(neo4j_driver: Any = None, kafka_producer: Any = None,
                               artifact_provider: Callable[[dict], list[dict]] | None = None):
    """Return the single-argument node callable required by LangGraph."""
    def memory_forensics_node(state: dict) -> dict:
        started = time.perf_counter()
        case_id = state.get("case_id", "unknown")
        artifacts = _load_artifacts(state, neo4j_driver, artifact_provider)
        findings = run_memory_forensics_analysis(artifacts, case_id=case_id)
        publish_findings(findings, kafka_producer)
        trace = {
            "agent_role": "memory_forensics",
            "thought": f"Analyzed {len(artifacts)} case-scoped memory artifacts.",
            "action": "deterministic_memory_rules",
            "observation": f"Produced {len(findings)} evidence-cited findings.",
            "model_used": "deterministic_rules",
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        return {
            "findings": findings,
            "agent_traces": [trace],
            "specialists_completed": ["memory"],
        }

    return memory_forensics_node
