import json
import logging
from datetime import datetime, timezone
from confluent_kafka import Consumer, KafkaError
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.entity_resolver import CanonicalEntityResolver
from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
from src.ingestion.preservation.sha256_hasher import compute_sha256_bytes
from src.ingestion.preservation.quickwit_client import QuickwitClient
from src.ingestion.broker.kafka_producer import EventProducer
from src.ingestion.run_pipeline import run_pipeline_on_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("WinlogbeatConsumer")

def adapt_winlogbeat_ecs_to_legacy(ecs_event: dict) -> dict:
    """
    Translates Winlogbeat ECS JSON schema into the dictionary format
    expected by Specula's evtx_normalizer and CanonicalEntityResolver.
    """
    winlog = ecs_event.get("winlog", {})
    event_data = winlog.get("event_data", {})
    host_info = ecs_event.get("host", {})
    
    # Reconstruct raw message body if absent from event_data
    message = ecs_event.get("message", "")
    
    return {
        "Id": int(winlog.get("event_id", 0)),
        "ProviderName": winlog.get("provider_name", winlog.get("channel", "Security")),
        "TimeCreated": ecs_event.get("@timestamp", datetime.now(timezone.utc).isoformat()),
        "Computer": winlog.get("computer_name", host_info.get("name", "LOCAL_HOST")),
        "Message": message,
        # Preserve ECS parsed fields directly for optimal extraction
        "EventData": event_data,
        "ProcessId": event_data.get("ProcessId") or event_data.get("NewProcessId"),
        "ParentProcessId": event_data.get("ParentProcessId"),
        "CommandLine": event_data.get("CommandLine"),
        "Image": event_data.get("Image") or event_data.get("NewProcessName"),
        "SubjectUserName": event_data.get("SubjectUserName") or event_data.get("TargetUserName"),
        "IpAddress": event_data.get("IpAddress") or event_data.get("SourceAddress")
    }

def start_winlogbeat_ingest_consumer():
    conf = {
        'bootstrap.servers': 'localhost:9092',
        'group.id': 'specula-winlogbeat-ingest-group',
        'auto.offset.reset': 'latest',
        'enable.auto.commit': False
    }
    
    consumer = Consumer(conf)
    consumer.subscribe(['specula-winlogbeat-raw'])
    
    from src.ingestion.validation.schema_registry_client import OCSF_BASE_JSON_SCHEMA
    from src.ingestion.broker.active_cases_cache import ActiveCasesCache

    # Initialize shared pipeline dependencies
    time_normalizer = TimeNormalizer()
    resolver = CanonicalEntityResolver()
    vct_chain = VCTAtomicChain()
    
    active_cases_cache = ActiveCasesCache()
    producer = EventProducer(
        schema_str=OCSF_BASE_JSON_SCHEMA, 
        topic="logs.normalized.ocsf",
        active_cases_cache=active_cases_cache
    )
    
    qw_client = None
    if os.environ.get("SPECULA_QUICKWIT_ENABLED", "false").lower() == "true":
        try:
            qw_client = QuickwitClient()
            qw_client.ensure_index()
            logger.info("Quickwit Preservation: ACTIVE")
        except Exception as e:
            logger.error(f"Quickwit init failed: {e}")
    
    logger.info("Winlogbeat Kafka Consumer daemon started. Listening for live events...")
    
    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error(f"Kafka error: {msg.error()}")
                continue
                
            raw_ecs = json.loads(msg.value().decode('utf-8'))
            legacy_event = adapt_winlogbeat_ecs_to_legacy(raw_ecs)
            
            # Execute Preservation -> Gate -> OCSF Normalization
            # Intentionally omit neo4j_client to prevent direct graphing (Invariant 1)
            results = run_pipeline_on_event(
                legacy_event,
                vct_chain=vct_chain,
                resolver=resolver,
                time_normalizer=time_normalizer,
                qw_client=qw_client,
                source_type="evtx"
            )
            
            if results:
                for validated_evt, cypher_q, _ in results:
                    if validated_evt:
                        evt_obj = getattr(validated_evt, "event", validated_evt)
                        evt_dict = evt_obj.model_dump(mode="json") if hasattr(evt_obj, "model_dump") else (evt_obj.__dict__ if hasattr(evt_obj, "__dict__") else evt_obj)
                        producer.produce_event(evt_dict)
                        logger.info(f"Published normalized OCSF event to Kafka: {evt_dict.get('uid')}")
                
            consumer.commit(msg, asynchronous=False)
    except KeyboardInterrupt:
        logger.info("Stopping Winlogbeat consumer.")
    finally:
        consumer.close()

if __name__ == "__main__":
    start_winlogbeat_ingest_consumer()
