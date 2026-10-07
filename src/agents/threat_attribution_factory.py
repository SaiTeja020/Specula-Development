"""LangGraph adapter for case-grounded Threat Attribution."""

import json
import logging
from typing import Any

from src.agents.kafka_utils import ROLE_TOPIC_MAP, _get_producer
from src.agents.threat_attribution_agent import run_threat_attribution

log = logging.getLogger(__name__)


def make_threat_attribution_node(neo4j_driver: Any, kafka_producer: Any,
                                 threat_intel: Any = None, llm_factory: Any = None):
    def threat_attribution_node(state: dict) -> dict:
        attribution, finding, trace = run_threat_attribution(
            state, neo4j_driver=neo4j_driver, threat_intel=threat_intel,
            llm_factory=llm_factory,
        )
        topic = ROLE_TOPIC_MAP["threat_attribution"]
        receipt = {"status": "unavailable"}
        def delivered(error, message):
            receipt["status"] = "failed" if error else "acknowledged"
            if error:
                log.warning("Threat Attribution Kafka delivery failed for %s: %s", finding["uid"], error)
            else:
                log.info("Threat Attribution Kafka delivery acknowledged for %s", finding["uid"])
        try:
            producer = kafka_producer if kafka_producer is not None else _get_producer()
            if producer is not None:
                receipt["status"] = "pending"
                producer.produce(
                    topic=topic,
                    key=str(state["case_id"]).encode("utf-8"),
                    value=json.dumps(finding, sort_keys=True).encode("utf-8"),
                    on_delivery=delivered,
                )
                producer.poll(0)
        except Exception as exc:
            log.warning("Threat Attribution Kafka publication failed: %s", exc)
            receipt["status"] = "failed"
        # Copy the outcome at return. Late callbacks log outcomes but cannot alter checkpointed state.
        trace["kafka_publication"] = dict(receipt)
        finding["kafka_publication"] = dict(receipt)
        flag = {"pending": "kafka_delivery_unconfirmed", "failed": "kafka_publication_failed",
                "unavailable": "kafka_unavailable"}.get(receipt["status"])
        if flag:
            attribution["degraded_flags"] = sorted(set(attribution["degraded_flags"]) | {flag})
            trace["degraded_flags"] = list(attribution["degraded_flags"])
        return {"attribution": attribution, "findings": [finding], "agent_traces": [trace]}

    return threat_attribution_node
