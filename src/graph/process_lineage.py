"""Resolve source-reported parents using host and observed process lifetimes."""
from collections import defaultdict
from src.agents.case_analysis import context, instant, decode_record
from src.schemas.uid_generator import generate_deterministic_uid


def process_identity(host, *, guid=None, pid=None, start=None, image=None):
    if not host or (not guid and not start):
        return None
    attrs = {"host": host}
    if guid:
        attrs["guid"] = str(guid).strip().lower()
    else:
        attrs.update(pid=pid, start=str(start), image=str(image or "").lower())
    return generate_deterministic_uid("process-instance-v1", attrs)


def resolve_parent_links(events):
    groups = defaultdict(list)
    for event in events:
        if event.get("class_uid") == 1007 and event.get("canonical_host_id") and instant(event.get("time")):
            groups[event["canonical_host_id"]].append(event)
    links = []
    for rows in groups.values():
        for child in rows:
            raw = context(child)
            guid = child.get("parent_process_guid") or raw.get("parent_process_guid") or (raw.get("EventData") or {}).get("ParentProcessGuid")
            candidates = [p for p in rows if p["uid"] != child["uid"] and p.get("activity_id") == 1
                          and p.get('source_type')!='memory' and instant(p["time"]) < instant(child["time"])]
            if guid:
                candidates = [p for p in candidates if str(p.get("process_guid") or context(p).get("process_guid") or
                              (context(p).get("EventData") or {}).get("ProcessGuid") or "").lower() == str(guid).lower()]
            else:
                pid = child.get("parent_process_pid")
                if not pid:
                    continue
                candidates = [p for p in candidates if p.get("process_pid") == pid]
            if not candidates:
                continue
            latest = max(instant(p["time"]) for p in candidates)
            candidates = [p for p in candidates if instant(p["time"]) == latest]
            if len(candidates) != 1:
                continue
            parent = candidates[0]
            if any(p.get('activity_id')==2 and p.get('process_pid')==parent.get('process_pid') and
                   latest<instant(p['time'])<instant(child['time']) for p in rows):
                continue
            if not guid and (not child.get("parent_process_name") or
                            str(child["parent_process_name"]).lower() != str(parent.get("process_name")).lower()):
                continue  # PID reuse: never search backwards past a different executable.
            links.append({"parent": parent["uid"], "child": child["uid"],
                          "parent_node": parent.get("process_uid") or parent["uid"],
                          "child_node": child.get("process_uid") or child["uid"],
                          "basis": "source_parent_guid" if guid else "source_parent_pid_observed_lifetime",
                          "host": child["canonical_host_id"], "time": child["time"]})
    return links


def persist_lineage(client, case_id):
    execute=(client.execute if hasattr(client,'execute') else lambda query,params:client.execute_query(query,**params)[0])
    events = [decode_record(row["e"]) for row in execute(
        "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(e:Event) WHERE e.class_uid=1007 RETURN e", {"case_id": case_id})]
    links = resolve_parent_links(events)
    if links:
        execute(
            "UNWIND $links AS link "
            "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(pe:Event {uid:link.parent}) "
            "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(ce:Event {uid:link.child}) "
            "MATCH (p:Process),(c:Process) WHERE (p.uid=link.parent_node OR "
            "(p.uid=link.parent AND NOT EXISTS { MATCH (:Process {uid:link.parent_node}) })) "
            "AND (c.uid=link.child_node OR (c.uid=link.child AND NOT EXISTS { MATCH (:Process {uid:link.child_node}) })) "
            "MERGE (p)-[r:SPAWNED {source_event_uid:link.child}]->(c) "
            "SET r.identity_basis=link.basis,r.canonical_host_id=link.host,r.time=link.time,r.source_reported=true",
            {"case_id": case_id, "links": links})
    return {"resolved": len(links), "process_events": len(events)}
