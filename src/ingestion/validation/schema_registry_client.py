"""
Specula Schema Registry Client.

Interfaces with Confluent Schema Registry to manage and enforce
versioned OCSF JSON schemas at the wire level.

Reference: specula_ingestion_final_plan.md §6.1, Stage 2 §3 Step 4
"""

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SchemaRegistryError(Exception):
    """Raised when wire-level schema registry validation or encoding fails."""
    pass


# Minimal OCSF base-event JSON Schema for wire-level validation.
# This is the schema registered in Confluent Schema Registry and used by
# JSONSerializer / JSONDeserializer to enforce required envelope fields.
OCSF_BASE_JSON_SCHEMA = json.dumps({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "OCSFBaseEvent",
    "type": "object",
    "required": ["case_id", "trace_id"],
    "properties": {
        "case_id": {"type": "string"},
        "trace_id": {"type": "string"},
        "class_uid": {"type": "integer"},
        "activity_id": {"type": "integer"},
        "severity_id": {"type": "integer"},
        "uid": {"type": "string"},
        "time": {"type": "string"},
    },
})


def get_schema_registry_client(url: str = "http://localhost:8081") -> Any:
    """
    Get a configured Confluent Schema Registry Client.
    """
    try:
        from confluent_kafka.schema_registry import SchemaRegistryClient
        return SchemaRegistryClient({"url": url})
    except Exception as e:
        raise SchemaRegistryError(f"Failed to connect to schema registry at {url}: {e}") from e


def get_json_serializer(
    schema_str: Optional[str] = None,
    registry_client: Optional[Any] = None,
    schema_registry_url: str = "http://localhost:8081",
) -> Any:
    """
    Return a Confluent JSONSerializer configured with the given schema.

    Falls back to raising SchemaRegistryError if confluent_kafka is not available.
    """
    if schema_str is None:
        schema_str = OCSF_BASE_JSON_SCHEMA

    try:
        from confluent_kafka.schema_registry import SchemaRegistryClient
        from confluent_kafka.schema_registry.json_schema import JSONSerializer

        if registry_client is None:
            registry_client = SchemaRegistryClient({"url": schema_registry_url})

        return JSONSerializer(schema_str, registry_client)
    except ImportError as e:
        raise SchemaRegistryError(
            "confluent-kafka[json] package is required for Schema Registry integration"
        ) from e


def get_json_deserializer(schema_str: Optional[str] = None) -> Any:
    """
    Return a Confluent JSONDeserializer configured with the given schema.

    Falls back to raising SchemaRegistryError if confluent_kafka is not available.
    """
    if schema_str is None:
        schema_str = OCSF_BASE_JSON_SCHEMA

    try:
        from confluent_kafka.schema_registry.json_schema import JSONDeserializer
        return JSONDeserializer(schema_str)
    except ImportError as e:
        raise SchemaRegistryError(
            "confluent-kafka[json] package is required for Schema Registry integration"
        ) from e

