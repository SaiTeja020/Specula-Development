"""
Specula FastMCP Gateway.

Exposes OCSF Normalization tools over MCP.
Architecturally, these are internal microservices reachable on ports 8100-8113,
each handling a category of source format.

Reference: specula_ingestion_final_plan.md §4 & §5.3
           ocsf_phase2_phase3_implementation_plan_FINAL.md §4

Phase 1 Gateway Ports:
  - 8100: EVTX / Sysmon
  - 8101: MFT / USN Journal
  - 8102: Network (Zeek/Suricata)
  - 8103: AD & Authentication
  - 8104: Cloud Audit (CloudTrail)
  - 8105: System Logs

Phase 2 & Phase 3 Gateway Ports:
  - 8106: EDR Telemetry
  - 8107: Malware Metadata / Sandbox Reports
  - 8108: Email / Messaging Logs
  - 8109: Memory Dumps (Volatility JSON)
  - 8110: Container Logs (Docker / K8s JSON)
  - 8111: Vulnerability Scans
  - 8112: UEBA & Browser Artifacts
  - 8113: Cloud Topology Maps
  - 8114: Vector Retrieval MCP Server
"""

import json
from typing import Any, Dict, List

from src.ingestion.normalization import (
    cloud_topology_normalizer,
    container_normalizer,
    edr_normalizer,
    email_normalizer,
    malware_normalizer,
    memory_dump_normalizer,
    ueba_browser_normalizer,
    vuln_scan_normalizer,
)


PORT_NORMALIZER_MAP = {
    8106: edr_normalizer,
    8107: malware_normalizer,
    8108: email_normalizer,
    8109: memory_dump_normalizer,
    8110: container_normalizer,
    8111: vuln_scan_normalizer,
    8112: ueba_browser_normalizer,
    8113: cloud_topology_normalizer,
}


def normalize_log_batch(port: int, raw_payload: Dict[str, Any], trace_id: str, case_id: str = "UNASSIGNED_CONTINUOUS") -> List[Dict[str, Any]]:
    """
    Route raw event payload to the normalizer registered on the specified port.
    Returns a list of dictionary-serialized OCSF event objects.
    """
    normalizer = PORT_NORMALIZER_MAP.get(port)
    if not normalizer:
        raise ValueError(f"No gateway normalizer registered for port {port}")

    events = normalizer.normalize(raw_payload, trace_id, case_id)
    return [event.model_dump(mode="json") for event in events]


def run_gateway_service(port: int, category: str):
    """
    Start a FastMCP gateway instance on the given port for a specific source category.
    """
    pass
