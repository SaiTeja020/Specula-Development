"""Second-tier source-correlated network review, distinct from primary detectors."""
from .case_analysis import records, get_llm,current_findings
from .investigative_review import investigate


def network_specialist_node(state):
    from .evidence_correlations import correlate
    events=records(state)
    flows=[r for r in events if r.get('class_uid')==4001]
    facts=[f for f in correlate(state)['findings'] if f['agent_role']=='network_specialist']
    review_facts=list(facts)
    for f in current_findings(state):
        if f.get('agent_role')=='network_forensics':
            review_facts.append({**f,'agent_role':'network_specialist','finding_type':'network_primary_review',
                          'summary':'Primary network observation requiring second-tier interpretation: '+f['summary']})
    trace=investigate('network_forensics',state,review_facts,get_llm('network_forensics',case_id=state.get('case_id','unknown')))
    trace.update(agent_role='network_specialist',action='network_correlation_and_structured_review')
    from .kafka_utils import publish_finding,ROLE_TOPIC_MAP
    for fact in facts:publish_finding(ROLE_TOPIC_MAP['network_specialist'],fact,state.get('trace_id'))
    return {'findings':facts,'agent_traces':[trace],'specialists_completed':['network']}
