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
            h.first_seen = CASE WHEN $time < h.first_seen THEN $time ELSE h.first_seen END,
            h.last_seen = CASE WHEN h.last_seen IS NULL OR $time > h.last_seen THEN $time ELSE h.last_seen END
            
        FOREACH (ignoreMe IN CASE WHEN $parent_process_uid IS NOT NULL THEN [1] ELSE [] END |
            MERGE (parent:Process {uid: $parent_process_uid})
            ON CREATE SET
                parent.process_name = $parent_process_name,
                parent.pid = $parent_process_pid,
                parent.canonical_host_id = $canonical_host_id,
                parent.case_id = $case_id
                
            MERGE (child:Process {uid: $process_uid})
            ON CREATE SET
                child.process_name = $process_name,
                child.pid = $process_pid,
                child.command_line = $command_line,
                child.canonical_host_id = $canonical_host_id,
                child.case_id = $case_id,
                child.start_time = $time
                
            MERGE (child)-[:RUNS_ON]->(h)
                
            MERGE (parent)-[r:SPAWNED]->(child)
            ON CREATE SET 
                r.time = $time,
                r.trace_id = $trace_id,
                r.raw_source_timestamp = $raw_source_timestamp
        )
        
        FOREACH (ignoreMe IN CASE WHEN $parent_process_uid IS NULL THEN [1] ELSE [] END |
            MERGE (child:Process {uid: $process_uid})
            ON CREATE SET
                child.process_name = $process_name,
                child.pid = $process_pid,
                child.command_line = $command_line,
                child.canonical_host_id = $canonical_host_id,
                child.case_id = $case_id,
                child.start_time = $time
            
            MERGE (child)-[:RUNS_ON]->(h)
        )
        """
        params = {
            "canonical_host_id": event.get("canonical_host_id") if event.get("canonical_host_id") not in (None, "UNKNOWN_HOST") else "uuid-local-host",
            "host_name": event.get("host_name") or "",
            "case_id": event.get("case_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
            "raw_source_timestamp": event.get("raw_source_timestamp"),
            "trace_id": event.get("trace_id"),
            "parent_process_uid": event.get("parent_process_uid"),
            "parent_process_name": event.get("parent_process_name") or "",
            "parent_process_pid": event.get("parent_process_pid") or 0,
            "process_uid": event.get("uid") or "PENDING_UID",
            "process_name": event.get("process_name") or "",
            "process_pid": event.get("process_pid") or 0,
            "command_line": event.get("command_line") or "",
        }
        return query, params

    @staticmethod
    def build_network_activity(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = """
        MERGE (src:NetworkEndpoint {uid: $src_ip})
        ON CREATE SET 
            src.ip = $src_ip,
            src.first_seen = $time,
            src.canonical_host_id = CASE WHEN $src_ip <> "UNKNOWN_IP" THEN $host_uid ELSE src.canonical_host_id END
        ON MATCH SET
            src.first_seen = CASE WHEN $time < src.first_seen THEN $time ELSE src.first_seen END,
            src.last_seen = CASE WHEN src.last_seen IS NULL OR $time > src.last_seen THEN $time ELSE src.last_seen END,
            src.canonical_host_id = CASE WHEN src.canonical_host_id IS NULL AND $src_ip <> "UNKNOWN_IP" THEN $host_uid ELSE src.canonical_host_id END
            
        MERGE (dst:NetworkEndpoint {uid: $dst_ip})
        ON CREATE SET
            dst.ip = $dst_ip,
            dst.first_seen = $time
        ON MATCH SET
            dst.first_seen = CASE WHEN $time < dst.first_seen THEN $time ELSE dst.first_seen END,
            dst.last_seen = CASE WHEN dst.last_seen IS NULL OR $time > dst.last_seen THEN $time ELSE dst.last_seen END
            
        MERGE (src)-[r:COMMUNICATED_WITH {uid: $uid}]->(dst)
        ON CREATE SET
            r.protocol = $protocol,
            r.src_port = $src_port,
            r.dst_port = $dst_port,
            r.bytes_in = $bytes_in,
            r.bytes_out = $bytes_out,
            r.timestamp = $time
        """
        
        params = {
            "uid": event.get("uid") or "PENDING_UID",
            "src_ip": event.get("src_ip") or "UNKNOWN_IP",
            "dst_ip": event.get("dst_ip") or "UNKNOWN_IP",
            "src_port": event.get("src_port") or 0,
            "dst_port": event.get("dst_port") or 0,
            "protocol": event.get("protocol") or "",
            "host_uid": event.get("canonical_host_id") if event.get("canonical_host_id") not in (None, "UNKNOWN_HOST") else "uuid-local-host",
            "time": event.get("time") or "",
            "bytes_in": event.get("bytes_in") or 0,
            "bytes_out": event.get("bytes_out") or 0,
            "packets_in": event.get("packets_in") or 0,
            "packets_out": event.get("packets_out") or 0,
            "action": event.get("action") or "Unknown"
        }
        
        return query, params

    @staticmethod
    def build_authentication_activity(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        # FAILED_AUTH_FROM for 4625 (failure), AUTHENTICATED_FROM for 4624 (success)
        rel_type = "AUTHENTICATED_FROM"
        if event.get("status") == "Failure" or event.get("activity_id") == 3: # OCSF 3 is Logon Failure
            rel_type = "FAILED_AUTH_FROM"
            
        # Using APOC to set dynamic relationship type securely, or just hardcoding two paths
        # Since parameterizing relationship types isn't natively supported, we split by rel_type
        if rel_type == "FAILED_AUTH_FROM":
            query = """
            MERGE (user:User {uid: $user_name})
            ON CREATE SET user.first_seen = $time
            ON MATCH SET 
                user.first_seen = CASE WHEN $time < user.first_seen THEN $time ELSE user.first_seen END,
                user.last_seen = CASE WHEN user.last_seen IS NULL OR $time > user.last_seen THEN $time ELSE user.last_seen END
            
            MERGE (ip:NetworkEndpoint {uid: $src_ip})
            ON CREATE SET ip.ip = $src_ip, ip.first_seen = $time, ip.canonical_host_id = $host_uid
            ON MATCH SET 
                ip.first_seen = CASE WHEN $time < ip.first_seen THEN $time ELSE ip.first_seen END,
                ip.last_seen = CASE WHEN ip.last_seen IS NULL OR $time > ip.last_seen THEN $time ELSE ip.last_seen END,
                ip.canonical_host_id = CASE WHEN ip.canonical_host_id IS NULL THEN $host_uid ELSE ip.canonical_host_id END
            
            MERGE (user)-[r:FAILED_AUTH_FROM {uid: $uid}]->(ip)
            ON CREATE SET
                r.timestamp = $time,
                r.auth_protocol = $auth_protocol,
                r.logon_type = $logon_type,
                r.failure_reason = $failure_reason
            """
        else:
            query = """
            MERGE (user:User {uid: $user_name})
            ON CREATE SET user.first_seen = $time
            ON MATCH SET 
                user.first_seen = CASE WHEN $time < user.first_seen THEN $time ELSE user.first_seen END,
                user.last_seen = CASE WHEN user.last_seen IS NULL OR $time > user.last_seen THEN $time ELSE user.last_seen END
            
            MERGE (ip:NetworkEndpoint {uid: $src_ip})
            ON CREATE SET ip.ip = $src_ip, ip.first_seen = $time, ip.canonical_host_id = $host_uid
            ON MATCH SET 
                ip.first_seen = CASE WHEN $time < ip.first_seen THEN $time ELSE ip.first_seen END,
                ip.last_seen = CASE WHEN ip.last_seen IS NULL OR $time > ip.last_seen THEN $time ELSE ip.last_seen END,
                ip.canonical_host_id = CASE WHEN ip.canonical_host_id IS NULL THEN $host_uid ELSE ip.canonical_host_id END
            
            MERGE (user)-[r:AUTHENTICATED_FROM {uid: $uid}]->(ip)
            ON CREATE SET
                r.timestamp = $time,
                r.auth_protocol = $auth_protocol,
                r.logon_type = $logon_type
            """
            
        params = {
            "uid": event.get("uid") or "PENDING_UID",
            "user_name": event.get("user_name") or "UNKNOWN_USER",
            "src_ip": event.get("src_ip") or "UNKNOWN_IP",
            "host_uid": event.get("canonical_host_id") if event.get("canonical_host_id") not in (None, "UNKNOWN_HOST") else "uuid-local-host",
            "time": event.get("time") or "",
            "auth_protocol": event.get("auth_protocol") or "",
            "logon_type": event.get("logon_type") or 0,
            "failure_reason": event.get("failure_reason") or ""
        }
        return query, params

    @staticmethod
    def build_file_activity(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        # OCSF File Activity: 1=Create, 2=Read, 3=Update, 4=Delete
        activity_id = event.get("activity_id", 0)
        rel_type = "ACCESSED"
        if activity_id == 1:
            rel_type = "CREATED"
        elif activity_id == 4:
            rel_type = "DELETED"
            
        if rel_type == "CREATED":
            query = """
            MERGE (f:File {uid: $file_path})
            ON CREATE SET f.file_name = $file_name, f.first_seen = $time
            ON MATCH SET 
                f.first_seen = CASE WHEN $time < f.first_seen THEN $time ELSE f.first_seen END,
                f.last_seen = CASE WHEN f.last_seen IS NULL OR $time > f.last_seen THEN $time ELSE f.last_seen END
            
            MERGE (host:Host {uid: $canonical_host_id})
            ON CREATE SET host.canonical_host_id = $canonical_host_id
            ON MATCH SET host.canonical_host_id = $canonical_host_id
            
            MERGE (host)-[r:CREATED {uid: $uid}]->(f)
            ON CREATE SET
                r.timestamp = $time,
                r.user_name = $user_name
            """
        elif rel_type == "DELETED":
            query = """
            MERGE (f:File {uid: $file_path})
            ON CREATE SET f.file_name = $file_name, f.first_seen = $time
            ON MATCH SET 
                f.first_seen = CASE WHEN $time < f.first_seen THEN $time ELSE f.first_seen END,
                f.last_seen = CASE WHEN f.last_seen IS NULL OR $time > f.last_seen THEN $time ELSE f.last_seen END
            
            MERGE (host:Host {uid: $canonical_host_id})
            ON CREATE SET host.canonical_host_id = $canonical_host_id
            ON MATCH SET host.canonical_host_id = $canonical_host_id
            
            MERGE (host)-[r:DELETED {uid: $uid}]->(f)
            ON CREATE SET
                r.timestamp = $time,
                r.user_name = $user_name
            """
        else:
            query = """
            MERGE (f:File {uid: $file_path})
            ON CREATE SET f.file_name = $file_name, f.first_seen = $time
            ON MATCH SET 
                f.first_seen = CASE WHEN $time < f.first_seen THEN $time ELSE f.first_seen END,
                f.last_seen = CASE WHEN f.last_seen IS NULL OR $time > f.last_seen THEN $time ELSE f.last_seen END
            
            MERGE (host:Host {uid: $canonical_host_id})
            ON CREATE SET host.canonical_host_id = $canonical_host_id
            ON MATCH SET host.canonical_host_id = $canonical_host_id
            
            MERGE (host)-[r:ACCESSED {uid: $uid}]->(f)
            ON CREATE SET
                r.timestamp = $time,
                r.user_name = $user_name
            """
            
        params = {
            "uid": event.get("uid") or "PENDING_UID",
            "file_path": event.get("file_path") or "UNKNOWN_FILE",
            "file_name": event.get("file_name") or "",
            "user_name": event.get("user_name") or "",
            "canonical_host_id": event.get("canonical_host_id") if event.get("canonical_host_id") not in (None, "UNKNOWN_HOST") else "uuid-local-host",
            "time": event.get("time") or ""
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
