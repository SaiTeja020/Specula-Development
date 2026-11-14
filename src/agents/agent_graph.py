"""Project checkpointed agent execution into the case knowledge graph."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from hashlib import sha256
import json


def _uid(kind: str, case_id: str, index: int = 0) -> str:
    return sha256(f"{kind}:{case_id}:{index}".encode("utf-8")).hexdigest()


def persist_case_execution(driver, case_id: str, traces: list[dict],
                           findings: list[dict], report: str | None = None,
                           report_metadata: dict | None = None,
                           start_index: int = 0) -> None:
    """Idempotently save observed outputs, model labels and bounded citations.

    The full checkpoint retains all structured findings and evidence refs. This
    projection gives Neo4j a navigable audit trail without storing private model
    reasoning or claiming a rule-based step invoked Qwen.
    """
    by_role = defaultdict(deque)
    for finding in findings:
        by_role[finding.get("agent_role")].append(finding)
    runs = []
    for index, trace in enumerate(traces, start=start_index):
        role = trace.get("agent_role", "unknown")
        finding = by_role[role].popleft() if by_role[role] else {}
        refs = trace.get("dfkg_refs") or finding.get("dfkg_refs") or []
        runs.append({
            "uid": _uid("agent-run", case_id, index),
            "case_id": case_id,
            "sequence": index,
            "agent_role": role,
            "model_used": trace.get("model_used") or "none",
            "action": trace.get("action") or "",
            "analysis": finding.get("summary") or trace.get("observation") or "",
            "model_output": trace.get('model_output') or '',
            "model_output_validated":bool(trace.get('model_output_validated')),
            "review_json":json.dumps({key:trace[key] for key in ('assessment','investigation_assessments','review_coverage','examination_coverage','grounding_issues','investigation_plan','examination_receipts','planning_attempts','behavioral_baselines','permission_examinations','sandbox_examinations') if key in trace},sort_keys=True),
            "observation": trace.get("observation") or "",
            "timestamp": trace.get("timestamp") or finding.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "latency_ms": float(trace.get("latency_ms") or 0),
            "evidence_refs": [str(ref) for ref in refs[:30]],
            "evidence_ref_count": len(refs),
        })
    if runs:
        driver.execute_query(
            "UNWIND $runs AS run "
            "MATCH (c:Case {uid: $case_id}) "
            "MERGE (a:AgentRun {uid: run.uid}) SET a += run "
            "MERGE (c)-[:HAS_AGENT_RUN]->(a)",
            runs=runs, case_id=case_id)
    if report:
        metadata = report_metadata or {}
        driver.execute_query(
            "MATCH (c:Case {uid: $case_id}) "
            "MERGE (r:Report {uid: $uid}) "
            "SET r.case_id = $case_id, r.content = $content, "
            "r.status = $status, r.generated_at = $generated_at "
            "MERGE (c)-[:HAS_REPORT]->(r)",
            case_id=case_id, uid=_uid("report", case_id), content=report,
            status=metadata.get("status") or "generated",
            generated_at=metadata.get("generated_at") or datetime.now(timezone.utc).isoformat())


def persist_case_analysis(driver,case_id,state):
    """Case-bound projections retain citations; source evidence is never rewritten."""
    timeline=(state.get('timeline') or {}).get('events',[])
    observations=[n for n in (state.get('attack_graph') or {}).get('nodes',[]) if n.get('node_kind')!='evidence']
    topology=state.get('exploit_topology') or {}
    maps={}
    for label,kind,rows in [('TimelineEntry','timeline',timeline),('Observation','observation',observations),
                            ('AttackStep','attack-step',topology.get('nodes',[]))]:
        entries=[];lookup={}
        for row in rows:
            key=str(row.get('id') or row.get('uid'))
            refs=row.get('dfkg_refs') or row.get('evidence_refs') or []
            uid=sha256((case_id+':'+kind+':'+key).encode()).hexdigest()
            lookup[key]=uid
            entries.append({'uid':uid,'case_id':case_id,'source_id':key,'label':row.get('label',kind),
                            'summary':row.get('summary') or row.get('label') or '', 'time':row.get('time'),
                            'canonical_host_id':row.get('canonical_host_id'),'classification':row.get('classification'),
                            'operation_outcome':row.get('operation_outcome'),'effect_scope':row.get('effect_scope'),'dfkg_refs':refs})
        maps[label]=lookup
        # label is a fixed internal allowlist; values remain parameterized.
        query={'TimelineEntry':"MERGE (n:TimelineEntry {uid:row.uid})",
               'Observation':"MERGE (n:Observation {uid:row.uid})",
               'AttackStep':"MERGE (n:AttackStep {uid:row.uid})"}[label]
        if entries:
            driver.execute_query("UNWIND $entries AS row MATCH (c:Case {uid:$case_id}) "+query+
                " SET n += row MERGE (c)-[:HAS_ANALYSIS]->(n) "
                "WITH n,row UNWIND row.dfkg_refs AS ref "
                "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(e:Event {uid:ref}) "
                "MERGE (n)-[:CITES {case_id:$case_id}]->(e)", entries=entries,case_id=case_id)
    edges=[]
    for row in (state.get('attack_graph') or {}).get('edges',[]):
        mapping=maps['Observation']
        if row['source'] in mapping and row['target'] in mapping:
            edges.append({'source':mapping[row['source']],'target':mapping[row['target']],
                          'refs':row.get('dfkg_refs',[])})
    if edges:
        driver.execute_query("UNWIND $edges AS row MATCH (a:Observation {uid:row.source}),(b:Observation {uid:row.target}) "
            "MERGE (a)-[r:PRECEDES {case_id:$case_id}]->(b) SET r.dfkg_refs=row.refs,r.causal=false",edges=edges,case_id=case_id)
    source_relations=(state.get('attack_graph') or {}).get('source_relations',[])
    if source_relations:
        rows=[{**r,'basis_json':json.dumps(r['basis'],sort_keys=True)} for r in source_relations]
        driver.execute_query('UNWIND $relations AS row '
            'MATCH (c:Case {uid:$case_id})-[:HAS_EVENT]->(a:Event {uid:row.source}) '
            'MATCH (c)-[:HAS_EVENT]->(b:Event {uid:row.target}) '
            'MERGE (a)-[r:CORRELATED_EVIDENCE {uid:row.id,case_id:$case_id}]->(b) '
            'SET r.relation_kind=row.type,r.basis_json=row.basis_json,r.causal=false,r.dfkg_refs=row.dfkg_refs,r.source_reported=true',
            relations=rows,case_id=case_id)
    transitions=[]
    for row in topology.get('edges',[]):
        mapping=maps['AttackStep']
        transitions.append({'source':mapping[row['source']],'target':mapping[row['target']],
                            'refs':row['precondition_refs']+row['exploitation_refs'],
                            'probability':row.get('conditional_probability')})
    if transitions:
        driver.execute_query("UNWIND $edges AS row MATCH (a:AttackStep {uid:row.source}),(b:AttackStep {uid:row.target}) "
            "MERGE (a)-[r:REVIEWED_TRANSITION {case_id:$case_id}]->(b) "
            "SET r.dfkg_refs=row.refs,r.conditional_probability=row.probability,r.reviewed_by=$analyst",
            edges=transitions,case_id=case_id,analyst=topology['reviewed_by'])
