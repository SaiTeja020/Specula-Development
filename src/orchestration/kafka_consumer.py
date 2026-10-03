"""Specula Kafka Orchestration Consumer.

Listens on 'specula.cases.opened' and launches the canonical
23-node LangGraph investigation for each new case.

Uses investigation_runner.run_investigation() — the same path as
scripts/run_investigation.py — so there is ONE canonical investigation
implementation. supervisor_graph.py (the old 6-node stub) is no longer
invoked here.

Duplicate-run protection: an in-process set tracks active case_ids.
If the same case_id arrives twice before its investigation completes,
the second message is skipped with a warning.
"""
import json
import logging
import os
import time
from typing import Any, Dict, Optional

from confluent_kafka import Consumer, KafkaError

from src.ingestion.broker.kafka_consumer import deserialize_event

logger = logging.getLogger(__name__)

# In-process guard against duplicate investigations for the same case_id.
# This is a single-process safeguard; for multi-replica deployments a
# Redis lock would be required.
_active_case_ids: set[str] = set()


class SupervisorKafkaConsumer:
    """Kafka consumer that launches a real LangGraph investigation for each case."""

    def __init__(self, bootstrap_servers: str, group_id: str):
        self.consumer = Consumer({
            "bootstrap.servers": bootstrap_servers,
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "topic.metadata.refresh.interval.ms": 3000,
        })

    def _parse_headers(self, headers: Optional[list]) -> Dict[str, Any]:
        """Extract test-control flags from Kafka message headers."""
        control_flags: Dict[str, Any] = {}
        if not headers:
            return control_flags
        for key, value in headers:
            if key == "test_control":
                try:
                    if isinstance(value, bytes):
                        value = value.decode("utf-8")
                    for flag in value.split(","):
                        flag = flag.strip()
                        if flag == "FORCE_DEAD_END":
                            control_flags["FORCE_DEAD_END"] = True
                        elif flag.startswith("FORCE_GUARDRAIL_FAIL_TIER:"):
                            control_flags["FORCE_GUARDRAIL_FAIL_TIER"] = flag.split(":")[1]
                        elif flag.startswith("DEPLOYED_MODEL_TIER:"):
                            control_flags["DEPLOYED_MODEL_TIER"] = flag.split(":")[1]
                except Exception as e:
                    logger.error(f"Error parsing test_control header: {e}")
        return control_flags

    def _run_investigation(self, case_id: str, query: str, thread_id: str) -> None:
        """Run the canonical investigation and remove the case_id guard on completion."""
        try:
            from src.agents.investigation_runner import run_investigation, HITLPausedResult
            from langgraph.checkpoint.memory import InMemorySaver

            neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
            neo4j_driver = None
            neo4j_enabled = os.environ.get("SPECULA_NEO4J_ENABLED", "false").lower() == "true"
            if neo4j_enabled:
                try:
                    from neo4j import GraphDatabase
                    neo4j_driver = GraphDatabase.driver(neo4j_uri)
                except Exception as e:
                    logger.warning(f"Neo4j unavailable (non-fatal): {e}")

            checkpointer = InMemorySaver()
            result = run_investigation(
                query=query,
                case_id=case_id,
                neo4j_driver=neo4j_driver,
                checkpointer=checkpointer,
                thread_id=thread_id,
            )

            if isinstance(result, HITLPausedResult):
                logger.info(
                    f"Case {case_id} paused at HITL — thread={result.thread_id}. "
                    f"POST to http://localhost:8200/hitl/{result.thread_id} to resume."
                )
                # Keep case_id in active set until human resumes
            else:
                logger.info(f"Case {case_id} completed: status={result.get('status')}")
                _active_case_ids.discard(case_id)

            if neo4j_driver:
                neo4j_driver.close()
        except Exception as exc:
            logger.error(f"Investigation failed for case {case_id}: {exc}", exc_info=True)
            _active_case_ids.discard(case_id)

    def start_listening(self) -> None:
        """Block and process case-open events from Kafka."""
        self.consumer.subscribe(["specula.cases.opened"])
        logger.info("SupervisorKafkaConsumer ready — listening on 'specula.cases.opened'")
        logger.info("Using canonical investigation_runner.run_investigation() (23-node real graph)")

        try:
            while True:
                msg = self.consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error(f"Kafka error: {msg.error()}")
                    time.sleep(1)
                    continue

                try:
                    payload = deserialize_event(msg.value())
                    case_id = payload.get("case_id")
                    trace_id = payload.get("trace_id", "")
                    query = payload.get("query") or (
                        "Investigate the available activity in this case and identify "
                        "anything that may require attention."
                    )

                    if not case_id:
                        logger.warning(f"Missing case_id in payload: {payload}")
                        continue

                    # Duplicate guard
                    if case_id in _active_case_ids:
                        logger.warning(
                            f"Duplicate case-open event for case_id={case_id} — "
                            "investigation already active, skipping."
                        )
                        continue

                    _active_case_ids.add(case_id)
                    thread_id = f"thread-{case_id}"
                    logger.info(f"Launching investigation: case={case_id}, thread={thread_id}")

                    # Run blocking investigation in the same thread.
                    # For high-throughput deployments, use a ThreadPoolExecutor here.
                    self._run_investigation(case_id, query, thread_id)

                except json.JSONDecodeError:
                    logger.error("Failed to decode Kafka message JSON")
                except Exception as exc:
                    logger.error(f"Error processing case-open event: {exc}", exc_info=True)

        except KeyboardInterrupt:
            pass
        finally:
            self.consumer.close()
            logger.info("SupervisorKafkaConsumer stopped.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    consumer = SupervisorKafkaConsumer(bootstrap_servers, "supervisor_group")
    consumer.start_listening()

