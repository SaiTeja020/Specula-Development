"""Case graph membership follows immutable evidence, not a first-writer case tag."""
import json

NODE_TYPES = ("Event", "Process", "File", "User", "Host", "NetworkEndpoint",
              "DetectionFinding", "CloudAudit", "VulnerabilityFinding", "AuditActivity",
              "IncidentFinding", "HTTPActivity", "Entity", "AgentRun", "Report",
              "Observation", "TimelineEntry", "AttackStep")


def read_case_graph(session, case_id, limit=300):
    root = session.run("MATCH (c:Case {uid:$case_id}) RETURN c", case_id=case_id).single()["c"]
    events = [dict(row["e"]) for row in session.run(
        "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(e:Event) RETURN e", case_id=case_id)]
    event_uids = [e["uid"] for e in events]
    canonical_processes={row['uid'] for row in session.run(
        'MATCH (p:Process) WHERE p.uid IN $uids RETURN p.uid AS uid',
        uids=[e['process_uid'] for e in events if e.get('process_uid')])}
    process_uids={e['process_uid'] if e.get('process_uid') in canonical_processes else e['uid']
                  for e in events if e.get('class_uid')==1007}
    # Legacy graph events can omit class_uid; preserve their directly referenced Process nodes.
    process_uids.update(e['uid'] for e in events if e.get('class_uid') is None)
    process_uids.update(e['parent_process_uid'] for e in events if e.get('parent_process_uid'))
    member_uids = set(event_uids)
    for e in events:
        member_uids.update(e.get(k) for k in ("process_uid", "parent_process_uid", "canonical_host_id") if e.get(k))
        user = e.get("user") or {}
        if isinstance(user, str):
            try:
                user = json.loads(user)
            except ValueError:
                user = {}
        member_uids.update(v for v in (e.get("user_name"), user.get("name") if isinstance(user, dict) else None) if v)
    for row in session.run(
        "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(:Event)-[:SOURCE_ENDPOINT|DEST_ENDPOINT]->(n) "
        "RETURN DISTINCT n.uid AS uid", case_id=case_id):
        member_uids.add(row["uid"])
    params = {"case_id": case_id, "uids": sorted(member_uids), "process_uids":sorted(process_uids), "event_uids": event_uids,
              "traces": list({e["trace_id"] for e in events if e.get("trace_id")}), "limit": limit}
    membership = (
        "MATCH (n) WHERE $label IN labels(n) AND ((n.uid IN $uids AND ($label <> 'Process' OR n.uid IN $process_uids)) "
        "OR (n:Entity AND n.case_id=$case_id) "
        "OR EXISTS { MATCH (:Case {uid:$case_id})-[:HAS_AGENT_RUN|HAS_REPORT|HAS_ANALYSIS]->(n) }) ")
    nodes = {str(root.element_id): {"id": str(root.element_id), "label": "Case", "properties": dict(root)}}
    counts, edges = {}, []
    for label in NODE_TYPES:
        counts[label] = session.run(membership + "RETURN count(n) AS n", label=label, **params).single()["n"]
        for row in session.run(membership +
            "RETURN n ORDER BY n.severity_id DESC, n.time DESC, n.uid LIMIT $limit", label=label, **params):
            n = row["n"]
            node_id = str(n.element_id)
            nodes[node_id] = {"id": node_id, "label": label, "properties": dict(n)}
            edges.append({"id": "membership-"+node_id, "source": str(root.element_id),
                          "target": node_id, "type": "CASE_EVIDENCE", "derived": True})
    for row in session.run(
        "MATCH (a)-[r]->(b) WHERE elementId(a) IN $ids AND elementId(b) IN $ids "
        "AND (r.case_id=$case_id OR r.event_uid IN $event_uids OR r.trace_id IN $traces "
        "OR r.source_event_uid IN $event_uids OR (a:Case AND a.uid=$case_id)) "
        "RETURN a,r,b LIMIT $edge_limit", ids=list(nodes), edge_limit=limit*len(NODE_TYPES), **params):
        r = row["r"]
        edges.append({"id": str(r.element_id), "source": str(row["a"].element_id),
                      "target": str(row["b"].element_id), "type": r.get('relation_kind') if r.type=='CORRELATED_EVIDENCE' else r.type, "derived": False,
                      "properties": dict(r)})
    return {"nodes": list(nodes.values()), "edges": edges, "totals": {"Case": 1, **counts},
            "per_type_limit": limit,
            "sampled": any(counts[label] > sum(n["label"] == label for n in nodes.values()) for label in counts)}
