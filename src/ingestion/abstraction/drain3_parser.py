"""
Specula Drain3 Parametric Log Parser.

Extracts parametric abstractions from unstructured payload strings
to reduce LLM token overhead downstream.

Reference: specula_ingestion_final_plan.md §7.1
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

PERSISTENCE_FILE = Path("data/drain3_state.bin")
PERSISTENCE_FILE.parent.mkdir(parents=True, exist_ok=True)

config = TemplateMinerConfig()
persistence = FilePersistence(str(PERSISTENCE_FILE))
template_miner = TemplateMiner(persistence, config=config)


def parse_unstructured_message(message: str) -> Tuple[str, Dict[str, Any]]:
    """
    Parse an unstructured message into a template and parameters.
    """
    if not message:
        return "", {}
        
    result = template_miner.add_log_message(message)
    template = result["template_mined"]
    parameters = result.get("extracted_parameters", [])
    
    param_dict = {
        name: value for name, value in parameters
    } if parameters else {}
    
    return template, param_dict


def mine_templates(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Mine templates across a list of events using Drain3.
    """
    templates_seen = {}

    for e in events:
        msg = e.get("raw_text") or e.get("command_line") or e.get("message") or ""
        template, params = parse_unstructured_message(msg)
        
        event_copy = dict(e)
        event_copy["template"] = template
        event_copy["template_mined"] = template
        event_copy["extracted_parameters"] = params

        if template not in templates_seen:
            templates_seen[template] = []
        templates_seen[template].append(event_copy)

    return [
        {
            "template": t,
            "shared_template": t,
            "events_count": len(evs),
            "events": evs,
        }
        for t, evs in templates_seen.items()
    ]
