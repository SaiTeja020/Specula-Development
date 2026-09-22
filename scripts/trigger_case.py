import json
import uuid
from confluent_kafka import Producer

def delivery_report(err, msg):
    if err is not None:
        print(f"Message delivery failed: {err}")
    else:
        print(f"Message delivered to {msg.topic()} [{msg.partition()}]")

def main():
    producer = Producer({'bootstrap.servers': 'localhost:9092'})
    topic = 'specula.cases.opened'

    payload = {
        "case_id": f"CASE-{str(uuid.uuid4())[:8].upper()}",
        "trace_id": f"trace-{uuid.uuid4()}",
        "dfkg_uri": "bolt://localhost:7687",
        "query": "Investigate suspicious PowerShell commands executing encoded payloads across the network."
    }

    # Add the test_control header to bypass HITL for the demo (so the agents don't block waiting for human approval)
    headers = [("test_control", b"FORCE_DEAD_END")]

    producer.produce(
        topic, 
        value=json.dumps(payload).encode('utf-8'),
        headers=headers,
        callback=delivery_report
    )
    
    producer.flush()
    print(f"Triggered case {payload['case_id']} on topic {topic}!")

if __name__ == '__main__':
    main()
