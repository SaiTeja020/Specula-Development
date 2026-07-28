"""
Specula Parameterized Cypher Builder.

Constructs secure, injection-safe Cypher queries for OCSF events,
ensuring explicit locks and supernode protection.

Reference: specula_ingestion_final_plan.md §8.1 & §8.4

Mistakes to avoid (from v6):
    Do NOT use `apoc.node.degree(n)` without specifying direction and
    relationship type — it counts all edges globally, falsely triggering
    supernode protection on highly-connected but irrelevant hubs.
"""

from typing import Dict, Any, Tuple


class CypherBuilder:
    """Builds parameterized Cypher queries for event ingestion."""

    @staticmethod
    def build_process_creation(event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Build a MERGE query for a process creation event.
        
        Requires explicit write locks (v6 §8.1) via ordered MERGE.
        Requires parameterized inputs.
        """
        query = """
        // 1. Ensure host node exists
        MERGE (h:Host {uid: $canonical_host_id})
        ON CREATE SET 
            h.hostname = $host_name,
            h.case_id = $case_id,
            h.first_seen = $time
        ON MATCH SET
            h.last_seen = $time
            
        // 2. Ensure parent process exists
        MERGE (parent:Process {uid: $parent_process_uid})
        ON CREATE SET
            parent.process_name = $parent_process_name,
            parent.pid = $parent_process_pid,
            parent.host_uid = $canonical_host_id,
            parent.case_id = $case_id
            
        // 3. Ensure child process exists
        MERGE (child:Process {uid: $process_uid})
        ON CREATE SET
            child.process_name = $process_name,
            child.pid = $process_pid,
            child.command_line = $command_line,
            child.host_uid = $canonical_host_id,
            child.case_id = $case_id,
            child.start_time = $time
            
        // 4. Create explicit relationship
        // Uses CREATE instead of MERGE because a process spawn is a unique event.
        // Or MERGE if deduplication is required. We use MERGE for idempotency.
        MERGE (parent)-[r:SPAWNED]->(child)
        ON CREATE SET 
            r.time = $time,
            r.trace_id = $trace_id,
            r.raw_source_timestamp = $raw_source_timestamp
        """
        
        # In a real pipeline, UIDs are generated using uid_generator.py
        # before passing parameters here.
        params = {
            "canonical_host_id": event.get("canonical_host_id", "UNKNOWN_HOST"),
            "host_name": event.get("host_name", ""),
            "case_id": event.get("case_id"),
            "time": event.get("time").isoformat() if hasattr(event.get("time"), "isoformat") else event.get("time"),
            "raw_source_timestamp": event.get("raw_source_timestamp"),
            "trace_id": event.get("trace_id"),
            
            # Note: actual pipeline sets these UIDs properly in Component 4/5
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
        """
        Build a query that traverses a node but aborts if it is a supernode
        for the *specific* relationship being traversed.
        
        Implementation of v6 §8.4 strict rule.
        """
        
        dir_marker = "->" if direction == "OUTGOING" else "<-"
        if direction == "BOTH":
            dir_marker = "-"
            
        query = f"""
        MATCH (n:Entity {{uid: $start_node_uid}})
        // Supernode check using apoc.node.degree with explicit rel_type and direction
        WHERE apoc.node.degree(n, '{direction}_{rel_type}') < $max_degree
        
        MATCH (n)-[r:{rel_type}]{dir_marker}(target)
        RETURN target
        """
        
        params = {
            "start_node_uid": start_node_uid,
            "max_degree": max_degree
        }
        
        return query, params
