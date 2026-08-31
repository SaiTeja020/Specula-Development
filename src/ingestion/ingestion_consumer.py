"""
Specula Ingestion Consumer.

Listens to `logs.normalized.ocsf`, distills events, generates Cypher,
writes to Neo4j, and upserts semantic embeddings into ChromaDB.
"""

import os
import sys
import uuid
import logging
from typing import List, Dict, Any

sys.path.insert(0, os.path.abspath("."))

from src.ingestion.distillation.distillation_layer import DistillationLayer
from src.graph.cypher_builder import CypherBuilder
from src.ingestion.indexing.vector_store import ChromaVectorStore, EmbeddingGenerator
from src.config import CHROMA_EVIDENCE_COLLECTION
from src.ingestion.broker.kafka_consumer import EventConsumer
from src.ingestion.validation.schema_registry_client import OCSF_BASE_JSON_SCHEMA

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IngestionConsumer")

from dotenv import load_dotenv
load_dotenv()

NEO4J_ENABLED: bool = os.environ.get("SPECULA_NEO4J_ENABLED", "false").lower() == "true"

from datetime import datetime, timezone
from src.ingestion.broker.kafka_producer import EventProducer
from src.schemas.ocsf_events import ProcessActivity

class IngestionPipelineConsumer:
    def __init__(self):
        self.distiller = DistillationLayer(entropy_threshold=0.3)
        self.neo4j_client = None
        if NEO4J_ENABLED:
            try:
                from src.graph.neo4j_client import Neo4jClient
                self.neo4j_client = Neo4jClient()
                logger.info("Neo4j connected for Graph writes.")
            except Exception as e:
                logger.warning(f"Neo4j startup failed: {e}")
                
        persist_path = os.path.abspath(os.path.join("data", "Specula_Chroma"))
        os.makedirs(persist_path, exist_ok=True)
        self.v_store = ChromaVectorStore(collection_name=CHROMA_EVIDENCE_COLLECTION, persist_dir=persist_path)
        self.embedder = EmbeddingGenerator()
        
        self.signal_producer = EventProducer(
            schema_str=OCSF_BASE_JSON_SCHEMA, 
            topic="specula.cases.opened", 
            active_cases_cache=None
        )
        
        # Batch buffer for distillation
        self.batch = []
        self.batch_size = 100

    def process_event(self, event: dict, degraded: bool = False):
        self.batch.append(event)
        if len(self.batch) >= self.batch_size:
            self.flush_batch()

    def flush_batch(self):
        if not self.batch:
            return
            
        logger.info(f"Processing batch of {len(self.batch)} events.")
        distilled_batch = self.distiller.process_batch(self.batch)
        
        processed_cases = set()
        
        for dist_evt in distilled_batch:
            # Cypher generation
            cypher_query, cypher_params = None, None
            if "process_pid" in dist_evt:
                cypher_query, cypher_params = CypherBuilder.build_process_creation(dist_evt)
            elif "src_ip" in dist_evt and "auth_protocol" in dist_evt:
                cypher_query, cypher_params = CypherBuilder.build_authentication_activity(dist_evt)
            elif "src_ip" in dist_evt:
                cypher_query, cypher_params = CypherBuilder.build_network_activity(dist_evt)
            elif "file_path" in dist_evt:
                cypher_query, cypher_params = CypherBuilder.build_file_activity(dist_evt)
                
            if cypher_query and self.neo4j_client:
                try:
                    self.neo4j_client.execute(cypher_query, cypher_params)
                except Exception as e:
                    logger.warning(f"Neo4j write failed: {e}")
                    
            # ChromaDB upsert
            case_id = dist_evt.get("case_id", "UNASSIGNED")
            source_type = dist_evt.get("source_type", "evtx")
            trace_id = dist_evt.get("trace_id", f"trace-{uuid.uuid4().hex[:12]}")
            
            if case_id != "UNASSIGNED":
                processed_cases.add((case_id, trace_id))
            
            # Generate structured embedding text
            if "process_pid" in dist_evt:
                text_repr = f"Process {dist_evt.get('process_name')} (PID: {dist_evt.get('process_pid')}) launched on host {dist_evt.get('host_name', '')} with CLI: {dist_evt.get('command_line', '')}"
            elif "auth_protocol" in dist_evt:
                text_repr = f"User {dist_evt.get('user_name')} authenticated via {dist_evt.get('auth_protocol')} from {dist_evt.get('src_ip')} on host {dist_evt.get('host_name', '')}"
            else:
                text_repr = str(dist_evt.get("Message", dist_evt))
                
            vector = self.embedder.embed(text_repr)
            uid = dist_evt.get("uid", str(uuid.uuid4()))
            self.v_store.upsert(
                record_id=uid,
                text=text_repr,
                vector=vector,
                metadata={"case_id": case_id, "source": source_type}
            )
            
        # Emit specula.cases.opened for processed cases
        for case_id, trace_id in processed_cases:
            # We construct a synthetic signal event containing the case_id and trace_id.
            # In a real environment, this should ideally be an Avro payload, but we'll 
            # mimic the structure expected by the downstream Supervisor.
            signal_event = ProcessActivity(
                trace_id=trace_id,
                case_id=case_id,
                activity_id=99,
                severity_id=1,
                time=datetime.now(timezone.utc),
                raw_source_timestamp=datetime.now(timezone.utc).isoformat(),
                clock_skew_offset_ms=0,
                clock_skew_unverified=True,
                security_scan_degraded=False,
                uid=f"sig-{uuid.uuid4().hex}",
                process_name="SupervisorTrigger",
                process_pid=0,
                command_line="TRIGGER_CASE",
                canonical_host_id="UNKNOWN_HOST"
            )
            self.signal_producer.produce_event(signal_event)
            
        if processed_cases:
            self.signal_producer.flush()
            logger.info(f"Emitted {len(processed_cases)} case open signals to specula.cases.opened.")
            
        self.batch.clear()

def run_consumer_loop():
    logger.info("Starting Ingestion Consumer...")
    pipeline = IngestionPipelineConsumer()
    
    consumer = EventConsumer(
        schema_str=OCSF_BASE_JSON_SCHEMA,
        topic="logs.normalized.ocsf",
        group_id="specula-ingestion-distillation-group",
        process_func=pipeline.process_event
    )
    logger.info("Consumer initialized and starting consume loop...")
    
    # Run the consume loop a few times for the sake of the test / background execution
    try:
        while True:
            consumer.consume_loop(timeout=2.0, max_messages=100)
            pipeline.flush_batch()
    except KeyboardInterrupt:
        logger.info("Interrupted. Flushing remaining batch...")
        pipeline.flush_batch()
    
if __name__ == "__main__":
    run_consumer_loop()
