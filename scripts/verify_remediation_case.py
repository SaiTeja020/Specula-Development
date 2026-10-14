"""Read-only live oracle for the generated augmented remediation ZIP."""
import argparse
import json
from datetime import datetime
from pathlib import Path

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('case_id')
    parser.add_argument('--completed', action='store_true')
    parser.add_argument('--valid-debate', action='store_true')
    args = parser.parse_args()
    with requests.Session() as session:
        session.trust_env = False
        session.get('http://127.0.0.1:8400/api/local/investigations/history',
                    headers={'Origin': 'http://localhost:5173', 'X-Specula-Local-Boot': '1'},
                    timeout=30).raise_for_status()
        headers = {'Authorization': 'Bearer ' + Path('data/private/verification_token').read_text().strip()}

        def get(path, **params):
            response = session.get('http://127.0.0.1:8300' + path, headers=headers,
                                   params=params, timeout=60)
            response.raise_for_status()
            return response.json()

        path = '/api/investigations/' + requests.utils.quote(args.case_id, safe='')
        saved = get(path)
        records = saved['evidence_collection']['records']
        assert len({event['uid'] for event in records}) == 1235
        assert not saved['failed_nodes'], saved['failed_nodes']
        receipts = saved['ingestion_provenance']
        assert receipts['vector_index']['stored'] == receipts['normalized_stream']['acknowledged'] == 1235
        assert receipts['process_lineage']['resolved'] >= 1
        native = []
        for event in records:
            context = event.get('unmapped') or {}
            if isinstance(context, str):
                context = json.loads(context)
            if context.get('examination'):
                native.append(context['examination'])
        assert len(native) == 4 and all(row['status'] == 'complete' for row in native)
        chroma = get(path + '/stores/chroma')
        analytics = get(path + '/stores/duckdb')
        assert chroma['status'] == analytics['status'] == 'success'
        assert chroma['total_events'] == 1235
        assert dict((row['name'], row['rows']) for row in analytics['tables'])['events'] == 1235
        graph = get('/api/data/neo4j', case_id=args.case_id)
        assert graph['totals']['Event'] == 1235 and graph['totals']['Process'] > 300
        if args.completed:
            roles = {trace['agent_role'] for trace in saved['agent_traces']}
            assert {'network_specialist', 'malware_stylometry', 'memory_forensics',
                    'proponent', 'critic', 'judge'} <= roles, roles
            assert len(saved['timeline']['events']) == 1235
            assert graph['totals']['TimelineEntry'] == 1235 and graph['totals']['Observation'] > 0
            evidence_ids={event['uid'] for event in records}
            nodes={node['id']:node for node in saved['attack_graph']['nodes']}
            for node in nodes.values():
                assert node['dfkg_refs'] and set(node['dfkg_refs']) <= evidence_ids
            for edge in saved['attack_graph']['edges']:
                a,b=nodes[edge['source']],nodes[edge['target']]
                ta=datetime.fromisoformat(a['time'].replace('Z','+00:00'));tb=datetime.fromisoformat(b['time'].replace('Z','+00:00'))
                if edge['type']=='PRECEDES':
                    assert a.get('canonical_host_id') and a['canonical_host_id']==b.get('canonical_host_id') and ta<tb
                else:
                    assert ta<=tb and edge['basis'] and not edge['causal']
                    assert set(edge['dfkg_refs'])==set(a['dfkg_refs']+b['dfkg_refs'])
            for trace in saved['agent_traces']:
                assert set(trace.get('dfkg_refs',[])) <= evidence_ids
                coverage=trace.get('review_coverage')
                if coverage and coverage['complete']:
                    assert coverage['submitted']==coverage['validated']==coverage['total']
                if trace['agent_role']=='log_analysis':
                    retrievals=trace.get('semantic_retrieval',[])
                    assert retrievals and all(row['status']=='verified' and row['count']>0 for row in retrievals)
                    assert all(set(row['uids']) <= evidence_ids for row in retrievals)
        if args.valid_debate:
            for role in ('proponent','critic','judge'):
                trace=next(row for row in saved['agent_traces'] if row['agent_role']==role)
                assert trace['model_output_validated'] and trace['review_coverage']['complete'], role
        print('PASS: preserved evidence, four native examinations, lineage, semantic/analytic stores and broker receipts.')
        print('Case status:', saved['case_status'], '| Pending:', saved['paused_at'])


if __name__ == '__main__':
    main()
