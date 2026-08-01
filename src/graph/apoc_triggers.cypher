// Specula APOC Triggers
//
// Database triggers that emit events to the LangGraph Supervisor
// when specific subgraph milestones are reached.
//
// Reference: specula_ingestion_final_plan.md §8.3

// Trigger: Milestone Pattern Created (e.g. Lateral Movement)
// Fires when a Process on one host communicates with a Process on another host.
CALL apoc.trigger.install('specula', 'lateral_movement_detected',
  "
  UNWIND $createdRelationships AS rel
  WITH rel
  WHERE type(rel) = 'COMMUNICATED_WITH'
  MATCH (src:Process)-[rel]->(dst:Process)
  WHERE src.canonical_host_id <> dst.canonical_host_id
  CALL apoc.util.sleep(0)
  
  WITH src, dst, rel
  CALL apoc.periodic.submit('notify_supervisor_' + id(rel),
    '
    CALL apoc.load.jsonParams(
      \"http://localhost:8200/supervisor/trigger\",
      {`Content-Type`: \"application/json\"},
      apoc.convert.toJson({
        trigger: \"lateral_movement\",
        src_uid: $srcUid,
        dst_uid: $dstUid,
        case_id: $caseId,
        timestamp: timestamp()
      })
    ) YIELD value RETURN value
    ',
    {srcUid: src.uid, dstUid: dst.uid, caseId: src.case_id}
  ) YIELD name
  RETURN count(*)
  ",
  {phase: 'afterAsync', debounceMs: 5000}
);
