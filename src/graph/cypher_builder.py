"""
Specula Parameterized Cypher Builder.

Constructs secure, injection-safe Cypher queries for OCSF events,
ensuring explicit locks and supernode protection.

Reference: specula_ingestion_final_plan.md §8.1 & §8.4
"""

from typing import Any, Dict, List, Optional, Tuple


def build_node_merge(
    label: str,
    properties: Optional[dict] = None,
    uid: Optional[str] = None,
    props: Optional[dict] = None,
) -> Tuple[str, dict]:
    effective_props = props if props is not None else (properties or {})
    effective_uid = uid if uid is not None else effective_props.get("uid", "")
    
    query = f"MERGE (n:{label} {{uid: $uid}}) SET n += $props RETURN n"
    params = {"uid": effective_uid, "props": effective_props}
    return query, params


def build_case_backfill_query(
    labels: List[str],
    host_id: Optional[str] = None,
    start_time: Optional[str] = None,
    case_open_time: Optional[str] = None,
    case_id: Optional[str] = None,
    **kwargs: Any,
) -> Tuple[str, dict]:
    """
    Build a parameterized query for tagging historical nodes with a case ID.
    Filters labels using parameter binding `labels(n)[0] IN $labels`
    to prevent Cypher string concatenation vulnerabilities.
    """
    query = (
        "MATCH (n) "
        "WHERE labels(n)[0] IN $labels AND n.canonical_host_id = $host_id "
        "AND n.timestamp >= $start_time AND n.timestamp <= $case_open_time "
        "SET n.case_id = $case_id "
        "RETURN count(n)"
    )
    params = {
        "labels": labels,
        "host_id": host_id,
        "start_time": start_time,
        "case_open_time": case_open_time,
        "case_id": case_id,
    }
    return query, params


class CypherBuilder:
    @staticmethod
    def build_node_merge(
        label: str,
        properties: Optional[dict] = None,
        uid: Optional[str] = None,
        props: Optional[dict] = None,
    ) -> Tuple[str, dict]:
        return build_node_merge(label, properties, uid, props)

    @staticmethod
    def build_case_backfill_query(
        labels: List[str],
        host_id: Optional[str] = None,
        start_time: Optional[str] = None,
        case_open_time: Optional[str] = None,
        case_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[str, dict]:
        return build_case_backfill_query(labels, host_id, start_time, case_open_time, case_id, **kwargs)

    @staticmethod
    def build_process_creation(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = """
        MERGE (h:Host {uid: $canonical_host_id})
        ON CREATE SET 
            h.hostname = $host_name,
            h.case_id = $case_id,
            h.first_seen = $time
        ON MATCH SET
            h.last_seen = $time
            
        MERGE (parent:Process {uid: $parent_process_uid})
        ON CREATE SET
            parent.process_name = $parent_process_name,
            parent.pid = $parent_process_pid,
            parent.host_uid = $canonical_host_id,
            parent.case_id = $case_id
            
        MERGE (child:Process {uid: $process_uid})
        ON CREATE SET
            child.process_name = $process_name,
            child.pid = $process_pid,
            child.command_line = $command_line,
            child.host_uid = $canonical_host_id,
            child.case_id = $case_id,
            child.start_time = $time
            
        MERGE (parent)-[r:SPAWNED]->(child)
        ON CREATE SET 
            r.time = $time,
            r.trace_id = $trace_id,
            r.raw_source_timestamp = $raw_source_timestamp
        """
        params = {
            "canonical_host_id": event.get("canonical_host_id", "UNKNOWN_HOST"),
            "host_name": event.get("host_name", ""),
            "case_id": event.get("case_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
            "raw_source_timestamp": event.get("raw_source_timestamp"),
            "trace_id": event.get("trace_id"),
            "parent_process_uid": event.get("parent_process_uid", "UNKNOWN_PARENT"),
            "parent_process_name": event.get("parent_process_name", ""),
            "parent_process_pid": event.get("parent_process_pid", 0),
            "process_uid": event.get("uid"),
            "process_name": event.get("process_name", ""),
            "process_pid": event.get("process_pid", 0),
            "command_line": event.get("command_line", ""),
        }
        return query, params

    @staticmethod
    def query_with_supernode_protection(
        start_node_uid: str, 
        rel_type: str, 
        direction: str = "OUTGOING",
        max_degree: int = 1000
    ) -> Tuple[str, Dict[str, Any]]:
        dir_marker = "->" if direction == "OUTGOING" else "<-"
        if direction == "BOTH":
            dir_marker = "-"
            
        query = f"""
        MATCH (n:Entity {{uid: $start_node_uid}})
        WHERE apoc.node.degree(n, '{rel_type}') < $max_degree
        MATCH (n)-[r:{rel_type}]{dir_marker}(target)
        RETURN target
        """
        params = {
            "start_node_uid": start_node_uid,
            "max_degree": max_degree
        }
        return query, params
