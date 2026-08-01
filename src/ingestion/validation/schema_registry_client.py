"""
Specula Schema Registry Client.

Interfaces with Confluent Schema Registry to manage and enforce
versioned OCSF JSON schemas at the wire level.

Reference: specula_ingestion_final_plan.md §6.1
"""

from typing import Any


class SchemaRegistryError(Exception):
    """Raised when wire-level schema registry validation or encoding fails."""
    pass


def get_schema_registry_client(url: str = "http://localhost:8081") -> Any:
    """
    Get a configured Confluent Schema Registry Client.
    """
    try:
        from confluent_kafka.schema_registry import SchemaRegistryClient
        return SchemaRegistryClient({"url": url})
    except Exception as e:
        raise SchemaRegistryError(f"Failed to connect to schema registry at {url}: {e}") from e
