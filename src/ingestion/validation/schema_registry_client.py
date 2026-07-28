"""
Specula Schema Registry Client.

Interfaces with Confluent Schema Registry to manage and enforce
versioned OCSF JSON schemas at the wire level.

Reference: specula_ingestion_final_plan.md §6.1
"""

from confluent_kafka.schema_registry import SchemaRegistryClient

# Default Confluent Schema Registry endpoint
SCHEMA_REGISTRY_URL = "http://localhost:8081"

def get_schema_registry_client(url: str = SCHEMA_REGISTRY_URL) -> SchemaRegistryClient:
    """
    Get a configured Confluent Schema Registry Client.
    """
    return SchemaRegistryClient({"url": url})
