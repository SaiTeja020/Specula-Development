"""
Specula Kafka Producer.

Publishes validated OCSF events to Kafka with wire-level schema
enforcement and deterministic host-keyed partitioning.

Reference: specula_ingestion_final_plan.md §6.4

Mistakes to avoid (from v6):
    Do NOT partition Kafka by case_id or any composite of case_id + host_id.
    Partition strictly by canonical_host_id alone — case reassignment must
    never move a host's event stream to a different partition, or ordering
    guarantees break at the exact moment they matter most.
"""

import hashlib
import json
import logging
from typing import Optional

from confluent_kafka import Producer
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.json_schema import JSONSerializer
from confluent_kafka.serialization import SerializationContext, MessageField

from src.ingestion.broker.active_cases_cache import ActiveCasesCache
from src.schemas.ocsf_base import OCSFBaseEvent

logger = logging.getLogger(__name__)

KAFKA_BROKER = "localhost:9092"
SCHEMA_REGISTRY_URL = "http://localhost:8081"


class EventProducer:
    """
    Kafka Producer for OCSF events with schema registry validation
    and active case tagging.
    """

    def __init__(
        self,
        schema_str: str,
        topic: str,
        active_cases_cache: ActiveCasesCache,
        kafka_conf: Optional[dict] = None,
        schema_registry_url: str = SCHEMA_REGISTRY_URL,
    ):
        self.topic = topic
        self.active_cases_cache = active_cases_cache
        
        # Base config
        conf = {"bootstrap.servers": KAFKA_BROKER}
        if kafka_conf:
            conf.update(kafka_conf)
            
        self.producer = Producer(conf)
        
        # Schema Registry Client & Serializer
        sr_client = SchemaRegistryClient({"url": schema_registry_url})
        
        def to_dict(event: OCSFBaseEvent, ctx: SerializationContext) -> dict:
            return event.model_dump(mode="json")
            
        self.serializer = JSONSerializer(
            schema_str=schema_str,
            schema_registry_client=sr_client,
            to_dict=to_dict,
        )

    def _delivery_report(self, err, msg):
        """Called once for each message produced to indicate delivery result."""
        if err is not None:
            logger.error(f"Message delivery failed: {err}")
        else:
            logger.debug(
                f"Message delivered to {msg.topic()} [{msg.partition()}] "
                f"at offset {msg.offset()}"
            )

    def produce_event(self, event: OCSFBaseEvent) -> None:
        """
        Produce a validated event to Kafka.
        
        Enforces:
        1. Produce-time case tagging via ActiveCasesCache lookup.
        2. Strict canonical_host_id partitioning.
        3. Wire-level JSON serialization with schema registry magic byte.
        """
        
        # 1. Produce-time case tagging
        # Look up the host in the persistent Redis cache. If present, tag the
        # event immediately. If absent, fallback is UNASSIGNED_CONTINUOUS.
        canonical_host_id = getattr(event, "canonical_host_id", None)
        if canonical_host_id:
            assigned_case_id = self.active_cases_cache.get_case_for_host(canonical_host_id)
            event.case_id = assigned_case_id
        
        # 2. Extract headers per v6 §6.4
        headers = [
            ("trace_id", event.trace_id.encode("utf-8")),
            ("case_id", event.case_id.encode("utf-8")),
            ("ocsf_version", event.ocsf_version.encode("utf-8")),
        ]
        
        # 3. Partition strictly by hash(canonical_host_id)
        # Using sha256 to generate a consistent partition key string.
        # If no host ID (e.g. account-level cloud event), use a generic key.
        if canonical_host_id:
            partition_key = hashlib.sha256(canonical_host_id.encode("utf-8")).hexdigest()
        else:
            partition_key = "NO_HOST"

        try:
            # 4. Serialize with wire-level schema enforcement
            ctx = SerializationContext(self.topic, MessageField.VALUE)
            serialized_value = self.serializer(event, ctx)
            
            # 5. Produce
            self.producer.produce(
                topic=self.topic,
                key=partition_key,
                value=serialized_value,
                headers=headers,
                on_delivery=self._delivery_report,
            )
            
            # Typically poll should be called periodically in a background thread,
            # but for a simple synchronous wrapper we call it here to handle callbacks.
            self.producer.poll(0)
            
        except Exception as e:
            logger.error(f"Failed to produce event {event.uid}: {e}")
            raise

    def flush(self, timeout: float = 10.0) -> int:
        """Wait for all messages in the Producer queue to be delivered."""
        return self.producer.flush(timeout)
