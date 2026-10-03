"""
LangGraph node factory for the deterministic Cloud & Container Forensics specialist (F13b).
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from src.agents.cloud_container.agent import run_cloud_container_agent
from src.agents.cloud_container.detection_rules import RuleContext


def make_cloud_container_node(
    neo4j_driver: Any = None,
    kafka_producer: Any = None,
    event_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
    rule_context: Optional[RuleContext] = None,
):
    """Return the single-argument node callable required by LangGraph."""
    def cloud_container_node(state: dict) -> dict:
        result = run_cloud_container_agent(
            state,
            event_provider=event_provider,
            rule_context=rule_context,
            kafka_producer=kafka_producer,
        )
        return result

    return cloud_container_node
