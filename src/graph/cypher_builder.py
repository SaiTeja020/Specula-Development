"""
Specula Parameterized Cypher Builder.

Constructs secure, injection-safe Cypher queries for OCSF events,
ensuring explicit locks and supernode protection.

Reference: specula_ingestion_final_plan.md §8.1 & §8.4
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from src.schemas.uid_generator import generate_deterministic_uid


_MERGE_TEMPLATES = {
    "Host": "MERGE (n:Host {uid: $uid}) SET n += $props RETURN n",
    "Process": "MERGE (n:Process {uid: $uid}) SET n += $props RETURN n",
    "File": "MERGE (n:File {uid: $uid}) SET n += $props RETURN n",
    "NetworkEndpoint": "MERGE (n:NetworkEndpoint {uid: $uid}) SET n += $props RETURN n",
    "User": "MERGE (n:User {uid: $uid}) SET n += $props RETURN n",
    "Entity": "MERGE (n:Entity {uid: $uid}) SET n += $props RETURN n",
    "DetectionFinding": "MERGE (n:DetectionFinding {uid: $uid}) SET n += $props RETURN n",
}

def build_node_merge(
    label: str,
    properties: Optional[dict] = None,
    uid: Optional[str] = None,
    props: Optional[dict] = None,
) -> Tuple[str, dict]:
    effective_props = props if props is not None else (properties or {})
    effective_uid = uid if uid is not None else effective_props.get("uid", "")
    
    if label not in _MERGE_TEMPLATES:
        raise ValueError(f"Unsupported label for parameterized MERGE: {label}")
        
    query = _MERGE_TEMPLATES[label]
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
            
        MERGE (child:Process {uid: $process_uid})
        ON CREATE SET
            child.process_name = $process_name,
            child.pid = $process_pid,
            child.command_line = $command_line,
            child.host_uid = $canonical_host_id,
            child.case_id = $case_id,
            child.start_time = $time
            
        MERGE (child)-[r1:RUNS_ON]->(h)
        ON CREATE SET
            r1.time = $time,
            r1.trace_id = $trace_id,
            r1.case_id = $case_id
        ON MATCH SET
            r1.last_seen = $time
        
        WITH child, h
        WHERE $parent_process_uid IS NOT NULL
        MERGE (parent:Process {uid: $parent_process_uid})
        ON CREATE SET
            parent.process_name = $parent_process_name,
            parent.pid = $parent_process_pid,
            parent.host_uid = $canonical_host_id,
            parent.case_id = $case_id
            
        MERGE (parent)-[r:SPAWNED]->(child)
        ON CREATE SET 
            r.time = $time,
            r.trace_id = $trace_id,
            r.raw_source_timestamp = $raw_source_timestamp
        """
        params = {
            "canonical_host_id": event.get("canonical_host_id", "UNKNOWN_HOST"),
            "host_name": event.get("host_name"),
            "case_id": event.get("case_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
            "raw_source_timestamp": event.get("raw_source_timestamp"),
            "trace_id": event.get("trace_id"),
            "parent_process_uid": event.get("parent_process_uid"),
            "parent_process_name": event.get("parent_process_name"),
            "parent_process_pid": event.get("parent_process_pid", 0),
            "process_uid": event.get("uid"),
            "process_name": event.get("process_name"),
            "process_pid": event.get("process_pid", 0),
            "command_line": event.get("command_line"),
        }
        return query, params

    @staticmethod
    def build_file_activity(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = """
        MERGE (h:Host {uid: $canonical_host_id})
        ON CREATE SET 
            h.hostname = $host_name,
            h.case_id = $case_id,
            h.first_seen = $time
        ON MATCH SET
            h.last_seen = $time
            
        MERGE (f:File {uid: $file_uid})
        ON CREATE SET
            f.file_name = $file_name,
            f.file_path = $file_path,
            f.si_created = $si_created,
            f.fn_created = $fn_created,
            f.host_uid = $canonical_host_id,
            f.case_id = $case_id,
            f.first_seen = $time
        ON MATCH SET
            f.last_seen = $time,
            f.si_created = coalesce($si_created, f.si_created),
            f.fn_created = coalesce($fn_created, f.fn_created)
            
        MERGE (f)-[r:RUNS_ON]->(h)
        ON CREATE SET
            r.time = $time,
            r.trace_id = $trace_id,
            r.case_id = $case_id
        ON MATCH SET
            r.last_seen = $time
        """
        si_created = event.get("si_created")
        fn_created = event.get("fn_created")
        params = {
            "canonical_host_id": event.get("canonical_host_id", "UNKNOWN_HOST"),
            "host_name": event.get("host_name"),
            "case_id": event.get("case_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
            "trace_id": event.get("trace_id"),
            "file_uid": event.get("uid"),
            "file_name": event.get("file_name"),
            "file_path": event.get("file_path"),
            "si_created": si_created.isoformat() if hasattr(si_created, "isoformat") else si_created,
            "fn_created": fn_created.isoformat() if hasattr(fn_created, "isoformat") else fn_created,
        }
        return query, params

    @staticmethod
    def build_cloud_audit(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = """
        MERGE (c:CloudAudit {uid: $uid})
        ON CREATE SET
            c.cloud_provider = $cloud_provider,
            c.cloud_region = $cloud_region,
            c.cloud_account_id = $cloud_account_id,
            c.api_operation = $api_operation,
            c.api_service = $api_service,
            c.source_ip = $source_ip,
            c.user_identity = $user_identity,
            c.case_id = $case_id,
            c.first_seen = $time
        ON MATCH SET
            c.last_seen = $time
        """
        params = {
            "uid": event.get("uid"),
            "cloud_provider": event.get("cloud_provider"),
            "cloud_region": event.get("cloud_region"),
            "cloud_account_id": event.get("cloud_account_id"),
            "api_operation": event.get("api_operation"),
            "api_service": event.get("api_service"),
            "source_ip": event.get("source_ip"),
            "user_identity": event.get("user_identity"),
            "case_id": event.get("case_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
        }
        
        host_id = event.get("canonical_host_id")
        if host_id:
            query += """
            MERGE (h:Host {uid: $canonical_host_id})
            MERGE (c)-[r:RUNS_ON]->(h)
            ON CREATE SET
                r.time = $time,
                r.trace_id = $trace_id,
                r.case_id = $case_id
            ON MATCH SET
                r.last_seen = $time
            """
            params["canonical_host_id"] = host_id
            params["trace_id"] = event.get("trace_id")
            
        return query, params

    @staticmethod
    def build_detection_finding(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = """
        MERGE (h:Host {uid: $canonical_host_id})
        
        MERGE (d:DetectionFinding {uid: $uid})
        ON CREATE SET
            d.finding_info = $finding_info,
            d.severity_id = $severity_id,
            d.case_id = $case_id,
            d.first_seen = $time
        ON MATCH SET
            d.last_seen = $time
            
        MERGE (d)-[r:TRIGGERED_ON]->(h)
        ON CREATE SET
            r.time = $time,
            r.trace_id = $trace_id,
            r.case_id = $case_id
        ON MATCH SET
            r.last_seen = $time
        """
        params = {
            "uid": event.get("uid"),
            "finding_info": event.get("finding_info"),
            "severity_id": event.get("severity_id"),
            "canonical_host_id": event.get("canonical_host_id", "UNKNOWN_HOST"),
            "case_id": event.get("case_id"),
            "trace_id": event.get("trace_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
        }
        return query, params

    @staticmethod
    def build_defense_evasion(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = """
        MERGE (h:Host {uid: $canonical_host_id})
        
        MERGE (a:AuditActivity {uid: $uid})
        ON CREATE SET
            a.message = $message,
            a.severity_id = $severity_id,
            a.case_id = $case_id,
            a.first_seen = $time
        ON MATCH SET
            a.last_seen = $time
            
        MERGE (a)-[r:CLEARED_LOGS_ON]->(h)
        ON CREATE SET
            r.time = $time,
            r.trace_id = $trace_id,
            r.case_id = $case_id
        ON MATCH SET
            r.last_seen = $time
        """
        params = {
            "uid": event.get("uid"),
            "message": event.get("message"),
            "severity_id": event.get("severity_id"),
            "canonical_host_id": event.get("canonical_host_id", "UNKNOWN_HOST"),
            "case_id": event.get("case_id"),
            "trace_id": event.get("trace_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
        }
        return query, params


    @staticmethod
    def build_incident_finding(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = '''
        MERGE (h:Host {uid: $canonical_host_id})
        MERGE (i:IncidentFinding {uid: $uid})
        ON CREATE SET
            i.title = $title,
            i.severity_id = $severity_id,
            i.case_id = $case_id,
            i.first_seen = $time
        ON MATCH SET
            i.last_seen = $time
            
        MERGE (i)-[r:DETECTED_ON]->(h)
        ON CREATE SET
            r.time = $time,
            r.trace_id = $trace_id,
            r.case_id = $case_id
        ON MATCH SET
            r.last_seen = $time
        '''
        params = {
            "uid": event.get("uid"),
            "title": event.get("title", ""),
            "severity_id": event.get("severity_id"),
            "canonical_host_id": event.get("canonical_host_id", "UNKNOWN_HOST"),
            "case_id": event.get("case_id"),
            "trace_id": event.get("trace_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
        }
        return query, params

    @staticmethod
    def build_vulnerability_finding(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = '''
        MERGE (h:Host {uid: $canonical_host_id})
        MERGE (v:VulnerabilityFinding {uid: $uid})
        ON CREATE SET
            v.cve = $cve,
            v.severity_id = $severity_id,
            v.case_id = $case_id,
            v.first_seen = $time
        ON MATCH SET
            v.last_seen = $time
            
        MERGE (v)-[r:AFFECTS]->(h)
        ON CREATE SET
            r.time = $time,
            r.trace_id = $trace_id,
            r.case_id = $case_id
        ON MATCH SET
            r.last_seen = $time
        '''
        params = {
            "uid": event.get("uid"),
            "cve": event.get("cve", "UNKNOWN_CVE"),
            "severity_id": event.get("severity_id"),
            "canonical_host_id": event.get("canonical_host_id", "UNKNOWN_HOST"),
            "case_id": event.get("case_id"),
            "trace_id": event.get("trace_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
        }
        return query, params

    @staticmethod
    def build_http_activity(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = '''
        MERGE (h:Host {uid: $canonical_host_id})
        MERGE (a:HTTPActivity {uid: $uid})
        ON CREATE SET
            a.http_method = $http_method,
            a.url = $url,
            a.case_id = $case_id,
            a.first_seen = $time
        ON MATCH SET
            a.last_seen = $time
            
        MERGE (a)-[r:ORIGINATED_FROM]->(h)
        ON CREATE SET
            r.time = $time,
            r.trace_id = $trace_id,
            r.case_id = $case_id
        ON MATCH SET
            r.last_seen = $time
        '''
        params = {
            "uid": event.get("uid"),
            "http_method": event.get("http_method"),
            "url": event.get("url"),
            "canonical_host_id": event.get("canonical_host_id", "UNKNOWN_HOST"),
            "case_id": event.get("case_id"),
            "trace_id": event.get("trace_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
        }
        return query, params

    @staticmethod
    def dispatch_event(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        class_uid = event.get("class_uid")
        if class_uid == 1007:
            return CypherBuilder.build_process_creation(event)
        elif class_uid == 1001:
            return CypherBuilder.build_file_activity(event)
        elif class_uid == 6003:
            return CypherBuilder.build_cloud_audit(event)
        elif class_uid == 3002:
            return CypherBuilder.build_auth_activity(event)
        elif class_uid == 4001:
            return CypherBuilder.build_network_activity(event)
        elif class_uid == 2004:
            return CypherBuilder.build_detection_finding(event)
        elif class_uid == 3001:
            return CypherBuilder.build_defense_evasion(event)
        elif class_uid == 2005:
            return CypherBuilder.build_incident_finding(event)
        elif class_uid == 2002:
            return CypherBuilder.build_vulnerability_finding(event)
        elif class_uid == 4002:
            return CypherBuilder.build_http_activity(event)
        else:
            return None, None

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

    @staticmethod
    def build_auth_activity(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = """
        MERGE (u:User {uid: $user_name})
        ON CREATE SET
            u.name = $user_name,
            u.domain = $user_domain,
            u.sid = $user_sid,
            u.case_id = $case_id,
            u.first_seen = $time
        ON MATCH SET
            u.last_seen = $time
            
        MERGE (h:Host {uid: $canonical_host_id})
        ON CREATE SET
            h.case_id = $case_id,
            h.first_seen = $time
        ON MATCH SET
            h.last_seen = $time
            
        MERGE (u)-[r:LOGGED_IN_TO]->(h)
        ON CREATE SET
            r.time = $time,
            r.trace_id = $trace_id,
            r.case_id = $case_id,
            r.auth_protocol = $auth_protocol,
            r.logon_type = $logon_type,
            r.ticket_options = $ticket_options
        ON MATCH SET
            r.last_seen = $time
        """
        
        user_info = event.get("user", {})
        if isinstance(user_info, dict):
            user_name = user_info.get("name")
            user_domain = user_info.get("domain")
            user_sid = user_info.get("sid")
        else:
            user_name = None
            user_domain = None
            user_sid = None
            
        dst_endpoint = event.get("dst_endpoint", {})
        if isinstance(dst_endpoint, dict):
            canonical_host_id = dst_endpoint.get("canonical_host_uid", "UNKNOWN_HOST")
        else:
            canonical_host_id = "UNKNOWN_HOST"
            
        params = {
            "user_name": user_name,
            "user_domain": user_domain,
            "user_sid": user_sid,
            "canonical_host_id": canonical_host_id,
            "case_id": event.get("case_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
            "trace_id": event.get("trace_id"),
            "auth_protocol": event.get("auth_protocol"),
            "logon_type": event.get("logon_type"),
            "ticket_options": event.get("ticket_options")
        }
        return query, params

    @staticmethod
    def build_network_activity(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        query = """
        MERGE (c:Case {uid: $case_id})
        MERGE (e:Event {uid: $uid})
        ON CREATE SET
            e.class_uid = 4001,
            e.case_id = $case_id,
            e.canonical_host_id = $canonical_host_id,
            e.time = $time,
            e.raw_source_timestamp = $raw_source_timestamp,
            e.trace_id = $trace_id,
            e.src_endpoint = $src_endpoint_json,
            e.dst_endpoint = $dst_endpoint_json,
            e.protocol = $protocol,
            e.dns_query = $dns_query,
            e.dns_query_type = $dns_query_type,
            e.bytes_in = $bytes_in,
            e.bytes_out = $bytes_out
        MERGE (c)-[:HAS_EVENT]->(e)

        MERGE (src:NetworkEndpoint {uid: $src_endpoint_uid})
        ON CREATE SET
            src.ip_address = $src_ip,
            src.canonical_host_uid = $src_canonical_host_uid,
            src.canonical_host_id = $src_canonical_host_uid,
            src.case_id = $case_id,
            src.first_seen = $time,
            src.timestamp = $time
        ON MATCH SET
            src.last_seen = $time
            
        MERGE (dst:NetworkEndpoint {uid: $dst_endpoint_uid})
        ON CREATE SET
            dst.ip_address = $dst_ip,
            dst.canonical_host_uid = $dst_canonical_host_uid,
            dst.canonical_host_id = $dst_canonical_host_uid,
            dst.case_id = $case_id,
            dst.first_seen = $time,
            dst.timestamp = $time
        ON MATCH SET
            dst.last_seen = $time
            
        MERGE (src)-[r:CONNECTED_TO {event_uid: $uid}]->(dst)
        ON CREATE SET
            r.time = $time,
            r.trace_id = $trace_id,
            r.case_id = $case_id,
            r.dst_port = $dst_port,
            r.protocol = $protocol,
            r.dns_query = $dns_query,
            r.bytes_out = $bytes_out
        MERGE (e)-[:SOURCE_ENDPOINT]->(src)
        MERGE (e)-[:DEST_ENDPOINT]->(dst)
        """
        
        src_endpoint = event.get("src_endpoint", {})
        dst_endpoint = event.get("dst_endpoint", {})
        
        if isinstance(src_endpoint, dict):
            src_ip = src_endpoint.get("ip_address", "UNKNOWN_IP")
            src_canonical_host_uid = src_endpoint.get("canonical_host_uid")
        else:
            src_ip = "UNKNOWN_IP"
            src_canonical_host_uid = None
            
        if isinstance(dst_endpoint, dict):
            dst_ip = dst_endpoint.get("ip_address", "UNKNOWN_IP")
            dst_port = dst_endpoint.get("port")
            dst_canonical_host_uid = dst_endpoint.get("canonical_host_uid")
        else:
            dst_ip = "UNKNOWN_IP"
            dst_port = None
            dst_canonical_host_uid = None
            
        uid = event["uid"]
        case_id = event.get("case_id", "UNASSIGNED_CONTINUOUS")
        src_endpoint_uid = generate_deterministic_uid("network_endpoint", {
            "case_id": case_id, "ip": src_ip,
            "host": src_canonical_host_uid or uid,
        })
        dst_endpoint_uid = generate_deterministic_uid("network_endpoint", {
            "case_id": case_id, "ip": dst_ip,
            "host": dst_canonical_host_uid or uid,
        })
        params = {
            "uid": uid,
            "src_endpoint_uid": src_endpoint_uid,
            "dst_endpoint_uid": dst_endpoint_uid,
            "src_ip": src_ip,
            "src_canonical_host_uid": src_canonical_host_uid,
            "dst_ip": dst_ip,
            "dst_canonical_host_uid": dst_canonical_host_uid,
            "dst_port": dst_port,
            "case_id": case_id,
            "canonical_host_id": event.get("canonical_host_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
            "raw_source_timestamp": event.get("raw_source_timestamp"),
            "trace_id": event.get("trace_id"),
            "protocol": event.get("protocol"),
            "dns_query": event.get("dns_query"),
            "dns_query_type": event.get("dns_query_type"),
            "bytes_in": event.get("bytes_in", 0),
            "bytes_out": event.get("bytes_out", 0),
            "src_endpoint_json": json.dumps(src_endpoint, sort_keys=True),
            "dst_endpoint_json": json.dumps(dst_endpoint, sort_keys=True),
        }
        return query, params
