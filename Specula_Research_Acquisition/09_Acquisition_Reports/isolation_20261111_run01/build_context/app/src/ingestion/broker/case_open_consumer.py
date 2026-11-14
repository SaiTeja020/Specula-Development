"""
Specula Case Open Kafka Consumer & Dispatcher — Stage 2 §4.

Subscribes to 'specula.cases.opened' topic and translates case-open events into
minimal LangGraph initial state ({case_id, trace_id, test_control}), triggering
the multi-agent orchestration graph without relying on raw_input in initial state.

Reference: Specula_Stage2_Ingestion_Implementation_Plan.md §4, §5
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

CASE_OPENED_TOPIC = "specula.cases.opened"


@dataclass
class CaseOpenedEvent:
    case_id: str
    trace_id: str
    dfkg_root_uid: Optional[str] = None
    is_synthetic_test: bool = False
    test_control: Optional[dict] = None
    evidence_count: int = 0


def deserialize_case_opened(payload: bytes, headers: Optional[dict] = None) -> CaseOpenedEvent:
    """Deserialize a case.opened message from Kafka."""
    data = json.loads(payload.decode("utf-8"))
    
    # Extract test control from payload or Kafka headers
    test_control = data.get("test_control")
    if not test_control and headers:
        test_control = headers.get("test_control")
        if isinstance(test_control, (bytes, bytearray)):
            try:
                test_control = json.loads(test_control.decode("utf-8"))
            except Exception:
                test_control = {"raw": str(test_control)}

    return CaseOpenedEvent(
        case_id=data["case_id"],
        trace_id=data.get("trace_id", f"trace-{data['case_id']}"),
        dfkg_root_uid=data.get("dfkg_root_uid"),
        is_synthetic_test=data.get("is_synthetic_test", False),
        test_control=test_control,
        evidence_count=data.get("evidence_count", 0),
    )


class CaseOpenConsumer:
    """Kafka consumer that listens for case.opened events and dispatches to LangGraph."""

    def __init__(
        self,
        graph_invoker: Callable[[dict, dict], Any],
        topic: str = CASE_OPENED_TOPIC,
    ):
        self.graph_invoker = graph_invoker
        self.topic = topic

    def handle_message(self, payload: bytes, headers: Optional[dict] = None) -> dict:
        """Process a case.opened message, construct clean initial state, and invoke the graph."""
        event = deserialize_case_opened(payload, headers=headers)
        
        # Ingestion-independent minimal initial state per §4 & §5
        initial_state = {
            "case_id": event.case_id,
            "trace_id": event.trace_id,
            "input_type": "siem_alert",
            "raw_input": "",  # Empty: agents pull from Kafka/DFKG directly per §4
            "case_status": "open",
            "findings": [],
            "agent_traces": [],
            "debate_round": 1,
            "debate_history": [],
            "specialists_completed": [],
            "dead_end_detected": False,
            "dead_end_categories": [],
        }

        # Wire test_control flags if present (per §5)
        config = {"configurable": {"thread_id": event.case_id}}
        if event.test_control:
            config["configurable"]["test_control"] = event.test_control
            if "raw_input" in event.test_control:
                initial_state["raw_input"] = event.test_control["raw_input"]
            if "force_dead_end" in event.test_control:
                initial_state["dead_end_detected"] = True
                initial_state["dead_end_categories"] = event.test_control.get("categories", ["memory"])

        logger.info(f"Dispatched case {event.case_id} to LangGraph orchestrator")
        return self.graph_invoker(initial_state, config)
