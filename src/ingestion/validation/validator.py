"""
Specula OCSF Validator.

Validates every OCSF event against Pydantic models.
Events that fail validation are routed to quarantine rather than
dropped silently or forced into the graph.

Reference: specula_ingestion_final_plan.md §6.2
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Type

from pydantic import ValidationError

from src.schemas.ocsf_base import OCSFBaseEvent

logger = logging.getLogger(__name__)

QUARANTINE_DIR = Path("quarantine/ingestion_errors")


class IngestionError(Exception):
    """Raised when an event fails schema validation."""
    pass


def validate_event(raw_event: Dict[str, Any], model_class: Type[OCSFBaseEvent]) -> OCSFBaseEvent:
    """
    Validate a raw dictionary against the expected Pydantic model.
    
    Args:
        raw_event: The parsed, pre-normalized event dictionary.
        model_class: The Pydantic model class to validate against.
        
    Returns:
        The validated Pydantic model instance.
        
    Raises:
        IngestionError: If validation fails, triggering quarantine.
    """
    try:
        validated_event = model_class.model_validate(raw_event)
        return validated_event
    except ValidationError as e:
        _quarantine_event(raw_event, str(e), model_class.__name__)
        raise IngestionError(f"Event failed schema validation: {e}") from e


def _quarantine_event(raw_event: Dict[str, Any], error_msg: str, schema_name: str) -> None:
    """
    Route failed events to quarantine with diagnostic metadata.
    """
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    
    # In a real system this might be a DLT topic or S3 bucket,
    # but the plan specifies a quarantine/ directory path.
    trace_id = raw_event.get("trace_id", "UNKNOWN_TRACE")
    uid = raw_event.get("uid", "UNKNOWN_UID")
    
    file_path = QUARANTINE_DIR / f"{schema_name}_{trace_id}_{uid}.json"
    
    quarantine_payload = {
        "error_reason": error_msg,
        "schema": schema_name,
        "raw_payload": raw_event,
    }
    
    try:
        with open(file_path, "w") as f:
            json.dump(quarantine_payload, f, indent=2)
        logger.error(f"INGESTION_ERROR: Quarantined malformed {schema_name} event to {file_path}")
    except IOError as e:
        logger.error(f"Failed to write to quarantine: {e}")
