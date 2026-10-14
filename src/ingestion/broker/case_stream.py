"""Schema-checked normalized case stream with broker delivery receipts."""
import json
import os
from collections import defaultdict
from confluent_kafka import Producer
from .kafka_producer import _validate_against_schema

TOPIC='logs.normalized.ocsf'


def ensure_topic():
    from confluent_kafka.admin import AdminClient,NewTopic
    from confluent_kafka import KafkaException,KafkaError
    client=AdminClient({'bootstrap.servers':os.getenv('KAFKA_BOOTSTRAP_SERVERS','localhost:9092')})
    try:client.create_topics([NewTopic(TOPIC,num_partitions=1,replication_factor=1)])[TOPIC].result(timeout=10)
    except KafkaException as error:
        if error.args[0].code()!=KafkaError.TOPIC_ALREADY_EXISTS:raise


def publish_normalized_case(case_id,events,producer=None):
    if producer is None:ensure_topic()
    producer=producer or Producer({'bootstrap.servers':os.getenv('KAFKA_BOOTSTRAP_SERVERS','localhost:9092')})
    delivered=[];errors=[]
    def receipt(error,message):
        if error:errors.append(str(error))
        else:delivered.append({'partition':message.partition(),'offset':message.offset()})
    unique={e['uid']:e for e in events}
    for event in unique.values():
        row={**event,'case_id':case_id}
        _validate_against_schema(row)
        producer.produce(TOPIC,key=(row.get('canonical_host_id') or row['uid']).encode(),
                         value=json.dumps(row,default=str).encode(),on_delivery=receipt)
        producer.poll(0)
    remaining=producer.flush(30)
    if errors or remaining or len(delivered)!=len(unique):
        raise RuntimeError('Normalized Kafka delivery unconfirmed; preserved evidence remains available')
    return {'status':'verified','topic':TOPIC,'events':len(unique),'acknowledged':len(delivered)}


def decode_normalized_message(data):
    if data[:1]==b'\x00':data=data[5:]  # Existing Confluent JSON wire format.
    event=json.loads(data)
    _validate_against_schema(event)
    return event


def index_normalized_batch(events,graph,index):
    """All event UIDs survive; no compressed summary replaces retained evidence."""
    from src.graph.cypher_builder import CypherBuilder
    by_case=defaultdict(list)
    for event in events:
        case_id=event['case_id'];by_case[case_id].append(event)
        query,params=CypherBuilder.dispatch_event(event)
        if query:graph.execute(query,params)
        properties={k:json.dumps(v,sort_keys=True) if isinstance(v,(dict,list)) else v for k,v in event.items()}
        graph.execute('MERGE (c:Case {uid:$case_id}) MERGE (e:Event {uid:$uid}) '
            'ON CREATE SET e += $properties MERGE (c)-[:HAS_EVENT]->(e)',
            {'case_id':case_id,'uid':event['uid'],'properties':properties})
    return [index.index(case_id,rows) for case_id,rows in by_case.items()]
