import json
import logging
import os
import sys
import time
from confluent_kafka import Consumer, KafkaError

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.ingestion.distillation.distillation_layer import DistillationLayer
from src.ingestion.indexing.vector_store import ChromaVectorStore, EmbeddingGenerator
from src.graph.cypher_builder import CypherBuilder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IngestionConsumer")

def start_ingestion_consumer():
    conf = {
        'bootstrap.servers': 'localhost:9092',
        'group.id': 'specula-graph-writer-group',
        'auto.offset.reset': 'latest',
        'enable.auto.commit': False
    }
    
    consumer = Consumer(conf)
    consumer.subscribe(['logs.normalized.ocsf'])
    
    distiller = DistillationLayer(entropy_threshold=0.3)
    embedder = EmbeddingGenerator()
    
    # Initialize ChromaDB with Docker HTTP Client
    import chromadb
    host = os.environ.get("CHROMA_HOST", "localhost")
    port = int(os.environ.get("CHROMA_PORT", 8000))
    v_store = ChromaVectorStore(collection_name="specula_dfkg_embeddings")
    # Override client to use HttpClient (ensuring it matches our fix)
    v_store.client = chromadb.HttpClient(host=host, port=port)
    
    # Initialize Neo4j
    neo4j_client = None
    if os.environ.get("SPECULA_NEO4J_ENABLED", "false").lower() == "true":
        try:
            from src.graph.neo4j_client import Neo4jClient
            neo4j_client = Neo4jClient()
            logger.info("Neo4j Connected: Graph writes ACTIVE")
        except Exception as e:
            logger.error(f"Neo4j startup failed: {e}")
            
    logger.info("Ingestion Consumer daemon started. Listening for normalized OCSF events...")
    
    batch = []
    MAX_BATCH_SIZE = 100
    LAST_FLUSH = time.time()
    
    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            
            if msg is not None:
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error(f"Kafka error: {msg.error()}")
                    continue
                    
                evt = json.loads(msg.value().decode('utf-8'))
                batch.append(evt)
                
            now = time.time()
            if len(batch) >= MAX_BATCH_SIZE or (len(batch) > 0 and now - LAST_FLUSH > 5.0):
                logger.info(f"Processing batch of {len(batch)} normalized events...")
                
                # 1. Distillation Layer
                distilled_batch = distiller.process_batch(batch)
                logger.info(f"Distillation reduced {len(batch)} events to {len(distilled_batch)} unique nodes.")
                
                # 2. Graph and Vector Writes (1:1 Parity)
                for dist_evt in distilled_batch:
                    # Neo4j Cypher Builder expects OCSF dictionaries
                    cypher_query, cypher_params = CypherBuilder.dispatch_event(dist_evt)
                    uid = dist_evt.get("uid")
                    case_id = dist_evt.get("case_id", "UNASSIGNED_CONTINUOUS")
                    
                    if not uid:
                        continue
                        
                    # Write to Neo4j
                    if neo4j_client and cypher_query:
                        try:
                            neo4j_client.execute(cypher_query, cypher_params)
                        except Exception as e:
                            logger.warning(f"Neo4j write failed: {e}")
                    
                    # Embed into ChromaDB mapping exactly to the UID
                    text_repr = str(dist_evt.get("Message", dist_evt.get("command_line", dist_evt.get("finding_info", ""))))
                    if not text_repr.strip():
                        text_repr = json.dumps(dist_evt)
                        
                    vector = embedder.embed(text_repr)
                    v_store.upsert(
                        record_id=uid,
                        text=text_repr,
                        vector=vector,
                        metadata={"case_id": case_id}
                    )
                
                logger.info("Batch committed to DFKG and Vector Store.")
                consumer.commit(asynchronous=False)
                batch = []
                LAST_FLUSH = time.time()
                
    except KeyboardInterrupt:
        logger.info("Stopping Ingestion consumer.")
    finally:
        consumer.close()
        if neo4j_client:
            neo4j_client.close()

if __name__ == "__main__":
    start_ingestion_consumer()
