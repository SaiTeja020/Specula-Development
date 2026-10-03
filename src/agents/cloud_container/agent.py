"""
Cloud & Container Forensics Agent (F13b) Orchestration Runner.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from .detection_rules import (
    RuleContext,
    SpecialistFinding,
    evaluate_cloud_rules,
    evaluate_container_rules,
)
from .kafka_publisher import publish_findings

logger = logging.getLogger(__name__)


def query_neo4j_dfkg_events(case_id: str) -> List[Dict[str, Any]]:
    """
    Temporary abstraction function for querying OCSF events from Neo4j DFKG.
    Will be replaced by mcp-dfkg-cypher server in Stage 5.
    """
    # Production fallback returns empty list if direct driver not attached
    return []


def run_cloud_container_agent(
    state: Dict[str, Any],
    *,
    event_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
    rule_context: Optional[RuleContext] = None,
    kafka_producer: Any = None,
) -> Dict[str, Any]:
    """
    Main execution entry point for Cloud & Container Forensics Agent.
    Evaluates evidence against 13 detection rules, publishes findings to Kafka,
    and returns explicit status in LangGraph state format.
    """
    case_id = str(state.get("case_id") or "case_unknown")
    ctx = rule_context or RuleContext()
    start_time = time.time()

    # Determine event retrieval mechanism
    retriever = event_provider or query_neo4j_dfkg_events

    try:
        raw_events = retriever(case_id)
    except Exception as exc:
        logger.error(f"Failed to query DFKG events for case {case_id}: {exc}")
        trace = {
            "agent_role": "cloud_container",
            "agent": "cloud_container",
            "timestamp": time.time(),
            "status": "error",
            "error_detail": str(exc),
            "findings_count": 0,
            "duration_ms": round((time.time() - start_time) * 1000, 2),
        }
        return {
            "findings": [],
            "agent_traces": [trace],
            "specialists_completed": ["cloud_container"],
            "specialist_statuses": {"cloud_container": "error"},
        }

    if not raw_events:
        # Case has zero cloud or container events. Return no_events status without false HITL escalation.
        trace = {
            "agent_role": "cloud_container",
            "agent": "cloud_container",
            "timestamp": time.time(),
            "status": "no_events",
            "findings_count": 0,
            "duration_ms": round((time.time() - start_time) * 1000, 2),
        }
        return {
            "findings": [],
            "agent_traces": [trace],
            "specialists_completed": ["cloud_container"],
            "specialist_statuses": {"cloud_container": "no_events"},
        }

    # Partition events by source class/type
    cloud_events: List[Dict[str, Any]] = []
    container_events: List[Dict[str, Any]] = []

    for event in raw_events:
        if not isinstance(event, dict):
            continue
        # Verify case isolation
        evt_case = event.get("case_id")
        if evt_case not in (None, case_id):
            raise ValueError(f"CloudContainerAgent received event belonging to case {evt_case}, expected {case_id}")

        cls_uid = int(event.get("class_uid", 0))
        if cls_uid == 6003 or "cloud_provider" in event or "eventSource" in event or "api_service" in event:
            cloud_events.append(event)
        elif cls_uid in (1007, 4001, 1001) or "container" in event or "k8s_pod" in event:
            container_events.append(event)

    # Evaluate rules
    findings_list: List[SpecialistFinding] = []
    if cloud_events:
        findings_list.extend(evaluate_cloud_rules(cloud_events, case_id, ctx))
    if container_events:
        findings_list.extend(evaluate_container_rules(container_events, case_id, ctx))

    dict_findings = [f.to_dict() for f in findings_list]

    # Publish to Kafka
    if kafka_producer is not None:
        publish_findings(dict_findings, kafka_producer)

    trace = {
        "agent_role": "cloud_container",
        "agent": "cloud_container",
        "timestamp": time.time(),
        "status": "ok",
        "findings_count": len(dict_findings),
        "cloud_events_analyzed": len(cloud_events),
        "container_events_analyzed": len(container_events),
        "duration_ms": round((time.time() - start_time) * 1000, 2),
    }

    return {
        "findings": dict_findings,
        "agent_traces": [trace],
        "specialists_completed": ["cloud_container"],
        "specialist_statuses": {"cloud_container": "ok"},
    }
