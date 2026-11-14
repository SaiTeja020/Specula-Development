"""Continuous normalized evidence writer using the same durable case index as uploads."""
import logging
import os
import time
from confluent_kafka import Consumer
from src.graph.neo4j_client import Neo4jClient
from src.ingestion.indexing.case_evidence import CaseEvidenceIndex
from .case_stream import TOPIC,decode_normalized_message,index_normalized_batch,ensure_topic

log=logging.getLogger(__name__)

def start_ingestion_consumer():
    ensure_topic()
    consumer=Consumer({'bootstrap.servers':os.getenv('KAFKA_BOOTSTRAP_SERVERS','localhost:9092'),
        'group.id':'specula-normalized-evidence-writer-v2','auto.offset.reset':'earliest','enable.auto.commit':False})
    consumer.subscribe([TOPIC])
    graph=Neo4jClient()
    graph.apply_schema('src/graph/schema_constraints.cypher')
    index=CaseEvidenceIndex()
    batch=[];last_flush=time.monotonic()
    try:
        while True:
            message=consumer.poll(1)
            if message is not None:
                if message.error():raise RuntimeError('Normalized broker read failed')
                batch.append(decode_normalized_message(message.value()))
            if batch and (len(batch)>=100 or time.monotonic()-last_flush>=5):
                receipts=index_normalized_batch(batch,graph,index)
                consumer.commit(asynchronous=False)
                log.info('Verified normalized case index receipts: %s',receipts)
                batch=[];last_flush=time.monotonic()
    finally:
        consumer.close();graph.close()

if __name__=='__main__':
    logging.basicConfig(level=logging.INFO)
    start_ingestion_consumer()
