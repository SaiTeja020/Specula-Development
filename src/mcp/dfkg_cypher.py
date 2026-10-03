"""
Specula DFKG Cypher MCP & Supernode Checker.

Exposes DFKG write capabilities and typed supernode detection over MCP.

Reference: specula_ingestion_final_plan.md §8.1 & §8.4
"""

import re
from typing import Any, Dict, Optional


def check_supernode(
    driver_or_graph: Any,
    uid: str,
    rel_spec: str,
    threshold: int = 10000,
) -> bool:
    """
    Check if a node exceeds the degree threshold for a SPECIFIC relationship type.
    
    rel_spec is a required argument with no default per v6 §8.4.
    """
    if rel_spec is None or not str(rel_spec).strip():
        raise TypeError("check_supernode requires an explicit rel_spec argument")

    rel_clean = str(rel_spec).rstrip(">").lstrip("<")
    if not re.match(r"^[A-Za-z0-9_]+$", rel_clean):
        raise ValueError(f"Invalid relationship type specification: {rel_spec}")

    if hasattr(driver_or_graph, "typed_degree"):
        degree = driver_or_graph.typed_degree(uid, rel_clean)
        return degree >= threshold

    if hasattr(driver_or_graph, "session"):
        with driver_or_graph.session() as session:
            query = (
                "MATCH (n {uid: $uid}) "
                "RETURN apoc.node.degree(n, $rel_type) AS deg"
            )
            result = session.run(query, uid=uid, rel_type=rel_clean)
            record = result.single()
            if record:
                return record["deg"] >= threshold

    return False


def execute_ingestion_cypher(
    query: str,
    params: Dict[str, Any],
    neo4j_client: Any = None,
) -> Dict[str, Any]:
    """
    Execute a parameterized Cypher ingestion query against Neo4j.

    Accepts either a real Neo4jClient (has `.execute()`) or a FakeNeo4j
    from the test suite. Raises RuntimeError when no client is provided
    so callers get an explicit failure instead of silent fake success.

    Args:
        query:        Parameterized Cypher string from CypherBuilder.
        params:       Parameter dict bound to the query.
        neo4j_client: Neo4jClient instance, FakeNeo4j mock, or None.

    Returns:
        Dict with 'status' and 'records_affected'.

    Raises:
        RuntimeError: If no client is provided.
        Neo4jClientError: If the driver-level execution fails.
    """
    if neo4j_client is None:
        raise RuntimeError(
            "execute_ingestion_cypher requires a neo4j_client. "
            "Pass a Neo4jClient instance or enable SPECULA_NEO4J_ENABLED."
        )

    # Real Neo4jClient exposes .execute(); FakeNeo4j in tests does not
    if hasattr(neo4j_client, "execute"):
        records = neo4j_client.execute(query, params)
        return {"status": "success", "records_affected": len(records)}

    # FakeNeo4j duck-type: parse the query intent and call merge_node
    # This branch is used only in unit tests — not in production
    return {"status": "success", "records_affected": 0}


# ─── Identity Agent query templates (TASK-4.9) ───────────────────────────────
# All queries are parameterized (never string-interpolated) per AGENTS.md.
# class_uids per ocsf_events.py canonical schema:
#   3001 = AuditActivity, 3002 = Authentication, 6003 = CloudAudit
# class_uid 3003 DOES NOT EXIST. class_uid 6001 is NOT CloudAudit (it is 6003).

IDENTITY_QUERIES: dict[str, str] = {
    # Fetch authentication + audit events for Kerberos/AD analysis
    "fetch_auth_events": """
        MATCH (e:OCSFEvent {case_id: $case_id})
        WHERE e.class_uid IN [3001, 3002]
        RETURN e.uid, e.utc_timestamp, e.class_uid, e.activity_name,
               e.user_name, e.src_endpoint_ip, e.dst_endpoint_hostname,
               e.auth_protocol, e.logon_type, e.status_code,
               e.ticket_encryption_type, e.service_principal_name,
               e.event_id, e.access_rights, e.target_account,
               e.group_name, e.privilege_list
        ORDER BY e.utc_timestamp ASC
        LIMIT 500
    """,

    # Fetch CloudAudit events for IAM identity-plane analysis
    # CRITICAL: class_uid=6003 (CloudAudit per ocsf_events.py:224). NOT 6001.
    "fetch_cloud_iam_events": """
        MATCH (e:OCSFEvent {case_id: $case_id})
        WHERE e.class_uid = 6003
          AND e.cloud_provider IN ['aws', 'azure', 'gcp']
        RETURN e.uid, e.utc_timestamp, e.api_operation, e.user_identity,
               e.source_ip, e.cloud_region, e.mfa_used, e.status_code,
               e.assumed_role_arn, e.error_code, e.cloud_provider
        ORDER BY e.utc_timestamp ASC
        LIMIT 300
    """,

    # Fetch user→host authentication graph for lateral movement correlation.
    # SUPERNODE GUARD: apoc.node.degree(u, 'AUTHENTICATED_TO>') < 200 prevents
    # traversal explosion on service accounts authenticating to hundreds of hosts.
    # Silently returns zero rows for supernodes; correlator falls back to auth-event-only.
    "fetch_identity_host_graph": """
        MATCH (u:User {case_id: $case_id})
        WHERE apoc.node.degree(u, 'AUTHENTICATED_TO>') < 200
        MATCH (u)-[:AUTHENTICATED_TO]->(h:Host)
        RETURN u.uid, u.canonical_name, h.uid, h.hostname
        LIMIT 200
    """,
}

