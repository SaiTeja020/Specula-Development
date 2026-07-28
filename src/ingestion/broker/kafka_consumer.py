"""
Specula Kafka Consumer.

Consumes validated OCSF events from Kafka, enforcing wire-level schemas,
with explicit degraded fallback handling for checkpointing.

Reference: specula_ingestion_final_plan.md §6.5

Mistakes to avoid (from v6):
    Do NOT implement the serializer without the matching JSONDeserializer
    on the consumer.
    Do NOT treat `checkpoint_degraded: true` as sufficient on its own —
    it must feed into the reconciliation task.
"""

import json
import logging
from pathlib import Path
from typing import Optional, Callable, Any

from confluent_kafka import Consumer, KafkaError
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.json_schema import JSONDeserializer
from confluent_kafka.serialization import SerializationContext, MessageField

import redis

logger = logging.getLogger(__name__)

KAFKA_BROKER = "localhost:9092"
SCHEMA_REGISTRY_URL = "http://localhost:8081"
REDIS_URL = "redis://localhost:6379/0"
QUARANTINE_DIR = Path("quarantine")


class EventConsumer:
    """
    Kafka Consumer for OCSF events with schema registry validation
    and explicit checkpoint degradation handling.
    """

    def __init__(
        self,
        schema_str: str,
        topic: str,
        group_id: str,
        process_func: Callable[[dict, bool], None],
        kafka_conf: Optional[dict] = None,
        schema_registry_url: str = SCHEMA_REGISTRY_URL,
        redis_url: str = REDIS_URL,
    ):
        self.topic = topic
        self.process_func = process_func
        
        # Base config: MUST disable auto-commit
        conf = {
            "bootstrap.servers": KAFKA_BROKER,
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False, # Enforced by v6 §6.5
        }
        if kafka_conf:
            conf.update(kafka_conf)
            
        self.consumer = Consumer(conf)
        self.consumer.subscribe([topic])
        
        # Schema Registry Client & Deserializer
        sr_client = SchemaRegistryClient({"url": schema_registry_url})
        
        def dict_to_obj(dict_obj: dict, ctx: SerializationContext) -> dict:
            # We return the dict for the processing pipeline
            return dict_obj
            
        self.deserializer = JSONDeserializer(
            schema_str=schema_str,
            schema_registry_client=sr_client,
            from_dict=dict_to_obj,
        )
        
        # Redis client for offset checkpointing
        self.redis_client = redis.from_url(redis_url, decode_responses=True)
        self.checkpoint_key = f"specula:kafka_offsets:{group_id}:{topic}"
        
        # DLT Path setup
        self.dlt_producer = None # In a real implementation, a separate producer instance
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    def _route_to_dlt(self, raw_msg: Any, error_msg: str) -> None:
        """
        Route unprocessable poison-pill messages to DLT.
        Must not stall the consumer group.
        """
        logger.error(f"DLT routing: {error_msg}")
        # Simplification for Phase 1: Write to file instead of actual Kafka DLT topic
        dlt_file = QUARANTINE_DIR / "specula.ingestion.dlt.json"
        
        payload = {
            "error": error_msg,
            "topic": raw_msg.topic() if raw_msg else "unknown",
            "partition": raw_msg.partition() if raw_msg else -1,
            "offset": raw_msg.offset() if raw_msg else -1,
        }
        
        with open(dlt_file, "a") as f:
            f.write(json.dumps(payload) + "\n")

    def _record_degraded_window(self, partition: int, offset: int) -> None:
        """Enqueue the degraded window to quarantine for reconciliation."""
        window_file = QUARANTINE_DIR / "degraded_windows.json"
        
        payload = {
            "topic": self.topic,
            "partition": partition,
            "start_offset": offset, # Simplification: tracking single offset
            "end_offset": offset,
            "resolved": False
        }
        
        with open(window_file, "a") as f:
            f.write(json.dumps(payload) + "\n")

    def consume_loop(self) -> None:
        """Run the consumption loop."""
        try:
            while True:
                msg = self.consumer.poll(1.0)
                
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    else:
                        logger.error(f"Consumer error: {msg.error()}")
                        continue

                # 1. Deserialize with wire-level schema enforcement
                try:
                    ctx = SerializationContext(msg.topic(), MessageField.VALUE)
                    event_dict = self.deserializer(msg.value(), ctx)
                except Exception as e:
                    # Poison pill message failed deserialization
                    self._route_to_dlt(msg, f"Deserialization failed: {e}")
                    self.consumer.commit(asynchronous=False)
                    continue

                # 2. Process event & Checkpoint
                checkpoint_degraded = False
                try:
                    # Try to checkpoint to Redis
                    self.redis_client.hset(
                        self.checkpoint_key, 
                        str(msg.partition()), 
                        msg.offset()
                    )
                except redis.RedisError as e:
                    # Degraded fallback (Redis unreachable)
                    logger.warning(f"REDIS_UNREACHABLE_WARNING: {e}")
                    checkpoint_degraded = True
                    self._record_degraded_window(msg.partition(), msg.offset())
                
                try:
                    # Process the event, passing the degraded flag
                    self.process_func(event_dict, checkpoint_degraded)
                    
                    # Primary path / Fallback native commit
                    self.consumer.commit(asynchronous=False)
                    
                except Exception as e:
                    self._route_to_dlt(msg, f"Processing failed: {e}")
                    self.consumer.commit(asynchronous=False)

        except KeyboardInterrupt:
            pass
        finally:
            self.consumer.close()
