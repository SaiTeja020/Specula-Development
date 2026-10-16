"""Second-tier source-correlated network review, distinct from primary detectors."""
from .case_analysis import records, get_llm,current_findings
from .investigative_review import investigate


def network_specialist_node(state):
    from .evidence_correlations import correlate
    events=records(state)
    flows=[r for r in events if r.get('class_uid')==4001]
    facts=[f for f in correlate(state)['findings'] if f['agent_role']=='network_specialist']
    for row in flows:
        examination = (row.get('unmapped') or {}).get('examination') or {}
        if examination.get('analysis_origin') != 'independent_packet_capture_examination':
            continue
        import json
        flow = examination['flow']
        facts.append({'agent_role': 'network_specialist', 'finding_type': 'independent_packet_session',
            'effect_scope':'captured_protocol_bytes',
            'source': 'validated_case_rule', 'classification': 'context', 'operation_outcome': 'unknown',
            'canonical_host_id': row.get('canonical_host_id'), 'event_time': row.get('time'),
            'dfkg_refs': [row['uid']], 'summary': 'Independent capture examination: ' + json.dumps({
                'handshake_observed': flow['tcp_handshake_observed'], 'reset_observed': flow['reset_observed'],
                'streams': flow['streams'], 'dns': flow['dns'], 'packet_count': flow['packet_count'],
                'captured_payload_bytes_out': flow['captured_payload_bytes_out'],
                'captured_payload_bytes_in': flow['captured_payload_bytes_in'],
                'payload_measurement': flow.get('payload_measurement', 'legacy captured packet payload counter'),
                'payload_measurement_status': flow.get('payload_measurement_status', 'legacy_counter'),
                'fragment_set_status_counts': examination.get('fragment_set_status_counts', {}),
                'capture_status': examination['status'], 'coverage': examination['coverage']}, sort_keys=True) +
                '. Captured bytes and headers do not prove malicious intent or successful exfiltration.'})
    review_facts=list(facts)
    for f in current_findings(state):
        if f.get('agent_role')=='network_forensics':
            review_facts.append({**f,'agent_role':'network_specialist','finding_type':'network_primary_review',
                          'summary':'Primary network observation requiring second-tier interpretation: '+f['summary']})
    trace=investigate('network_forensics',state,review_facts,get_llm('network_forensics',case_id=state.get('case_id','unknown')))
    trace.update(agent_role='network_specialist',action='network_correlation_and_structured_review')
    native = [(row.get('unmapped') or {}).get('examination') for row in flows]
    native = [r for r in native if r and r.get('analysis_origin') == 'independent_packet_capture_examination']
    trace['examination_coverage'] = {'native_examinations': len(native), 'imported_records': len(flows)-len(native),
        'unavailable': sum(r.get('status') != 'complete' for r in native),
        'scope': 'Packet-derived sessions when capture bytes exist; log/flow review otherwise.'}
    from .kafka_utils import publish_finding,ROLE_TOPIC_MAP
    for fact in facts:publish_finding(ROLE_TOPIC_MAP['network_specialist'],fact,state.get('trace_id'))
    return {'findings':facts,'agent_traces':[trace],'specialists_completed':['network']}
