import json
import logging
from typing import Dict, Any, Optional
from confluent_kafka import Consumer, KafkaError

from src.agents.supervisor_agent import SupervisorState
from src.orchestration.supervisor_graph import build_supervisor_graph

logger = logging.getLogger(__name__)

class SupervisorKafkaConsumer:
    def __init__(self, bootstrap_servers: str, group_id: str):
        self.consumer = Consumer({
            'bootstrap.servers': bootstrap_servers,
            'group.id': group_id,
            'auto.offset.reset': 'earliest'
        })
        self.graph = build_supervisor_graph()

    def _parse_headers(self, headers: Optional[list]) -> Dict[str, Any]:
        control_flags = {}
        if not headers:
            return control_flags
            
        for key, value in headers:
            if key == 'test_control':
                try:
                    # Expecting comma-separated flags or JSON
                    if isinstance(value, bytes):
                        value = value.decode('utf-8')
                    flags = value.split(',')
                    for flag in flags:
                        flag = flag.strip()
                        if flag == 'FORCE_DEAD_END':
                            control_flags['FORCE_DEAD_END'] = True
                        elif flag.startswith('FORCE_GUARDRAIL_FAIL_TIER:'):
                            tier = flag.split(':')[1]
                            control_flags['FORCE_GUARDRAIL_FAIL_TIER'] = tier
                        elif flag.startswith('DEPLOYED_MODEL_TIER:'):
                            tier = flag.split(':')[1]
                            control_flags['DEPLOYED_MODEL_TIER'] = tier
                except Exception as e:

                    logger.error(f"Error parsing test_control header: {e}")
        return control_flags

    def start_listening(self):
        self.consumer.subscribe(['specula.cases.opened'])
        logger.info("SupervisorKafkaConsumer started listening on 'specula.cases.opened'")

        try:
            while True:
                msg = self.consumer.poll(1.0)

                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    else:
                        logger.error(f"Kafka Error: {msg.error()}")
                        break

                try:
                    payload = json.loads(msg.value().decode('utf-8'))
                    case_id = payload.get('case_id')
                    trace_id = payload.get('trace_id')
                    dfkg_uri = payload.get('dfkg_uri')
                    nl_query = payload.get('query')
                    
                    if not case_id or not trace_id or not dfkg_uri:
                        logger.warning(f"Invalid payload format, missing required fields: {payload}")
                        continue

                    # Parse headers for control flags
                    control_flags = self._parse_headers(msg.headers())
                    
                    # Check for trace_id embedded flags if no header
                    if 'FORCE_DEAD_END' in trace_id and 'FORCE_DEAD_END' not in control_flags:
                        control_flags['FORCE_DEAD_END'] = True

                    # Initialize state
                    initial_state: SupervisorState = {
                        "case_id": case_id,
                        "trace_id": trace_id,
                        "control_flags": control_flags,
                        "active_tier": "",
                        "dispatched_agents": [],
                        "completed_agents": [],
                        "dead_end_detected": False,
                        "hitl_attempt_count": 0,
                        "terminal_state": "",
                        "nl_query": nl_query,
                        "query_routing_decision": None,
                        "degraded_capability_mode": False
                    }


                    # Invoke Graph
                    logger.info(f"Invoking Supervisor Graph for case {case_id}")
                    import asyncio
                    final_state = asyncio.run(self.graph.ainvoke(initial_state))
                    logger.info(f"Graph completed for case {case_id} with state {final_state.get('terminal_state', 'RESOLVED')}")

                except json.JSONDecodeError:
                    logger.error("Failed to decode JSON payload")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")

        except KeyboardInterrupt:
            pass
        finally:
            self.consumer.close()

if __name__ == "__main__":
    import os
    logging.basicConfig(level=logging.INFO)
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    consumer = SupervisorKafkaConsumer(bootstrap_servers, "supervisor_group")
    consumer.start_listening()
