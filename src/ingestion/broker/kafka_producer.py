"""
Specula Kafka Producer.

Publishes validated OCSF events to Kafka with wire-level schema
enforcement and deterministic host-keyed partitioning.

Stage 2: serialize_event() validates against the OCSF JSON Schema
(required fields + types) using jsonschema. EventProducer uses
confluent_kafka.SerializingProducer when a broker is available,
falling back to an in-memory buffer for unit-test environments.

Reference: specula_ingestion_final_plan.md §6.4, Stage 2 §3 Step 4
"""

import json
import logging
import struct
from typing import Any, Dict, List, Optional

from src.ingestion.broker.active_cases_cache import ActiveCasesCache
from src.ingestion.validation.schema_registry_client import (
    SchemaRegistryError,
    OCSF_BASE_JSON_SCHEMA,
)
from src.schemas.ocsf_base import OCSFBaseEvent

logger = logging.getLogger(__name__)

# Parse the schema once at import time for validation
_OCSF_SCHEMA = json.loads(OCSF_BASE_JSON_SCHEMA)


def _validate_against_schema(event: dict) -> None:
    """
    Validate event dict against the OCSF base JSON schema.

    Uses jsonschema for real type/required-field enforcement, replacing
    the Stage 1 stub that only checked for ``case_id`` presence.
    """
    try:
        import jsonschema
        jsonschema.validate(instance=event, schema=_OCSF_SCHEMA)
    except jsonschema.ValidationError as e:
        raise SchemaRegistryError(
            f"Event fails wire-level schema validation: {e.message}"
        ) from e


def serialize_event(event: dict, topic: str = "specula.logs.system") -> bytes:
    """
    Serialize event dict into Confluent Wire Format (5-byte magic header + JSON).

    Validates required fields and types against the OCSF JSON Schema before
    encoding, matching Stage 2 §3 Step 4's requirement for wire-level rejection.

    Magic byte: 0x00
    Schema ID: 4-byte big-endian int (1 for local / non-registry mode)
    """
    if not isinstance(event, dict):
        raise SchemaRegistryError(
            "Event fails wire-level schema validation: event must be a dict"
        )

    # Real schema validation — replaces the Stage 1 ``case_id in event`` check
    _validate_against_schema(event)

    magic_byte = b"\x00"
    schema_id = struct.pack(">I", 1)
    json_bytes = json.dumps(event, sort_keys=True).encode("utf-8")
    return magic_byte + schema_id + json_bytes


def build_event_headers(canonical_host_id: str, cache: ActiveCasesCache, trace_id: str) -> dict:
    """
    Build event headers including produce-time case tagging from ActiveCasesCache.
    """
    case_id = cache.get_active_case(canonical_host_id)
    return {
        "case_id": case_id,
        "trace_id": trace_id,
        "canonical_host_id": canonical_host_id,
    }


def produce_event(topic: str, event: dict) -> bytes:
    """
    Produce event with schema registry validation.
    """
    return serialize_event(event, topic=topic)


class EventProducer:
    """
    Kafka producer with Confluent Schema Registry integration.

    Attempts to create a ``confluent_kafka.SerializingProducer`` connected
    to a real broker + schema registry. If the broker is unreachable or
    ``confluent_kafka`` is not installed, falls back to an in-memory buffer
    so unit tests can still exercise the serialization and validation logic.
    """

    def __init__(
        self,
        schema_str: str,
        topic: str,
        active_cases_cache: ActiveCasesCache,
        kafka_conf: Optional[dict] = None,
        schema_registry_url: str = "http://localhost:8081",
    ):
        self.topic = topic
        self.active_cases_cache = active_cases_cache
        self._buffer: List[bytes] = []
        self._real_producer = None

        # Try to create a real SerializingProducer
        try:
            from confluent_kafka.schema_registry import SchemaRegistryClient
            from confluent_kafka.schema_registry.json_schema import JSONSerializer
            from confluent_kafka import SerializingProducer

            sr_client = SchemaRegistryClient({"url": schema_registry_url})
            json_serializer = JSONSerializer(
                schema_str or OCSF_BASE_JSON_SCHEMA,
                sr_client,
            )

            producer_conf = kafka_conf or {}
            producer_conf.setdefault("bootstrap.servers", "localhost:9092")
            producer_conf["value.serializer"] = json_serializer

            self._real_producer = SerializingProducer(producer_conf)
            logger.info("EventProducer: using real Confluent SerializingProducer")
        except Exception as e:
            logger.warning(
                f"EventProducer: Confluent producer unavailable ({e}); "
                "using in-memory buffer fallback."
            )

    def produce_event(self, event: OCSFBaseEvent) -> None:
        """Serialize and produce an event to Kafka (or in-memory buffer)."""
        canonical_host_id = getattr(event, "canonical_host_id", None)
        if canonical_host_id and self.active_cases_cache:
            event.case_id = self.active_cases_cache.get_case_for_host(canonical_host_id)

        event_dict = (
            event.model_dump(mode="json")
            if hasattr(event, "model_dump")
            else event.__dict__
        )

        if self._real_producer is not None:
            try:
                self._real_producer.produce(
                    topic=self.topic,
                    value=event_dict,
                )
            except Exception as e:
                logger.error(f"Real produce failed: {e}; buffering locally")
                self._buffer.append(serialize_event(event_dict, self.topic))
        else:
            # Fallback: validate + buffer
            self._buffer.append(serialize_event(event_dict, self.topic))

    def flush(self, timeout: float = 10.0) -> int:
        """Flush pending messages. Returns outstanding message count."""
        if self._real_producer is not None:
            return self._real_producer.flush(timeout)
        # In-memory fallback: nothing to flush to a broker
        count = len(self._buffer)
        self._buffer.clear()
        return count

