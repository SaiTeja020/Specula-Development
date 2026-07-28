"""
Specula Drain3 Parametric Log Parser.

Extracts parametric abstractions from unstructured payload strings
to reduce LLM token overhead downstream.

Reference: specula_ingestion_final_plan.md §7.1
"""

import json
from pathlib import Path
from typing import Dict, Any, Tuple

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.file_persistence import FilePersistence

# Initialize Drain3 with basic config
CONFIG_FILE = Path("config/drain3.ini")
PERSISTENCE_FILE = Path("data/drain3_state.bin")

PERSISTENCE_FILE.parent.mkdir(parents=True, exist_ok=True)

# Use default config for Phase 1
config = TemplateMinerConfig()

persistence = FilePersistence(str(PERSISTENCE_FILE))
template_miner = TemplateMiner(persistence, config=config)


def parse_unstructured_message(message: str) -> Tuple[str, Dict[str, Any]]:
    """
    Parse an unstructured message into a template and parameters.
    
    Args:
        message: Unstructured payload string.
        
    Returns:
        Tuple of (template_string, extracted_parameters_dict).
        
    Example:
        parse_unstructured_message("User Admin failed to login from 10.0.0.1")
        -> ("User <*> failed to login from <*>", {"param_0": "Admin", "param_1": "10.0.0.1"})
    """
    if not message:
        return "", {}
        
    result = template_miner.add_log_message(message)
    
    template = result["template_mined"]
    parameters = result.get("extracted_parameters", [])
    
    # Drain3 returns a list of (param_name, param_value) tuples
    param_dict = {
        name: value for name, value in parameters
    } if parameters else {}
    
    return template, param_dict
