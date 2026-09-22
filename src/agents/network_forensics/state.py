from typing import TypedDict, List, Dict, Optional, Any

class NetworkForensicsState(TypedDict):
    """
    State payload for the Network Forensics deterministic triage agent.
    Maintains multi-case isolation and tracks UIDs across the batch.
    """
    case_id: str
    trace_id: str
    batch_uids: List[str]
    
    # Internal state tracking
    iteration_count: int
    max_iterations: int
    dead_end: bool
    
    # Outputs
    anomalies_detected: List[Dict[str, Any]]
    status: str
