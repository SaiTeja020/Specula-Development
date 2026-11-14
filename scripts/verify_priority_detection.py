"""Separate synthetic-answer-key oracle. Never provided to model prompts."""
import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from src.agents.case_analysis import records,context,detections,instant
from src.agents.evidence_correlations import correlate
from src.agents.timeline_reconstruction import reconstruct
from src.agents.network_forensics_factory import make_network_forensics_node


def evaluate(snapshot,key,saved=False):
    rows=records(snapshot);by_record={}
    for row in rows:by_record.setdefault(context(row).get('record_id'),[]).append(row)
    refs=lambda names:{r['uid'] for n in names for r in by_record[n]}
    correlations=correlate(snapshot)
    if saved:
        facts=[f for f in snapshot['findings'] if f.get('source')=='validated_case_rule']
        timeline=snapshot['timeline'];relations=snapshot['attack_graph']['source_relations']
    else:
        facts=sum((detections(snapshot,role) for role in ('log_analysis','identity','memory_forensics','malware_stylometry','cloud_container','insider_threat')),[])+correlations['findings']
        graph=SimpleNamespace(execute_query=lambda *a,**k:([{'e':r} for r in rows],None,None))
        facts+=make_network_forensics_node(graph,None)({'case_id':snapshot['case_id']})['findings']
        timeline=reconstruct(snapshot);relations=correlations['relations']
    results=[]
    for expectation in key['expectations']:
        name=expectation['name'];wanted=refs(expectation['record_ids'])
        matches=[f for f in facts if wanted & set(f['dfkg_refs'])]
        def finding(kind,classification=None,outcome=None,all_refs=False):
            return any(f['finding_type']==kind and (classification is None or f['classification']==classification)
                and (outcome is None or f['operation_outcome']==outcome) and (not all_refs or wanted<=set(f['dfkg_refs'])) for f in matches)
        if name.startswith('A1 '):assert finding('failed_logons_followed_by_success','suspicious',all_refs=True)
        elif name.startswith('A2 '):
            assert finding('encoded_powershell') and any('Write-Output' in f['summary'] for f in matches)
            assert any(r['type']=='POSSIBLE_PROCESS_ACTIVITY' and wanted & set(r['dfkg_refs']) for r in relations)
        elif name.startswith('A3 '):assert finding('possible_network_fallback','unresolved','confirmed') and finding('network_connection_failed','failed','failed')
        elif name.startswith('A4 '):assert finding('denied_remote_access_branch','failed','failed')
        elif name.startswith('A5 '):assert finding('different_account_after_denial','unresolved','confirmed',True)
        elif name.startswith('A6 '):assert finding('source_credential_access','failed','failed') and finding('source_memory_finding','negative')
        elif name.startswith('A7 '):
            flows=[r for r in rows if r['uid'] in wanted and r.get('class_uid')==4001]
            assert sum(r.get('bytes_out',0) for r in flows)==188743680
            assert any(f.get('agent_role')=='network_forensics' and f['classification']=='suspicious' for f in matches)
        elif name.startswith('A8 '):assert finding('security_log_clear_failed','failed','failed') and not finding('security_log_cleared')
        elif name.startswith('A9 '):assert finding('timestamp_inconsistency','suspicious')
        elif name.startswith('B1 '):assert finding('service_account_key_failed','failed','failed') and finding('service_account_key_creation','suspicious','confirmed') and finding('cloud_principal_activity',all_refs=True)
        elif name.startswith('C1 '):assert finding('source_operation_context','failed')
        elif name.startswith('C2 '):assert finding('security_log_cleared','suspicious','confirmed')
        elif name.startswith('N1 '):assert finding('encoded_powershell','benign')
        elif name.startswith('N2 '):assert finding('timestamp_inconsistency','benign')
        elif name.startswith('N3 '):
            assert finding('authorized_transfer_job','benign')
            assert any(f.get('agent_role')=='network_forensics' and f['classification']=='benign' for f in matches)
            assert not any(f.get('agent_role')=='network_forensics' and f['classification']=='suspicious' for f in matches)
        elif name.startswith('N4 '):assert finding('source_credential_access','benign') and finding('source_memory_finding','benign')
        elif name.startswith('N5 '):assert finding('failed_logons_followed_by_success','benign')
        elif name.startswith('N6 '):assert finding('source_vulnerability_context','benign') and finding('source_vulnerability_context','unresolved')
        elif name.startswith('N7 '):assert finding('specimen_assessment_conflict','unresolved') and finding('source_specimen_assessment','benign')
        elif name.startswith('N8 '):assert all(not r.get('canonical_host_id') for r in by_record[expectation['record_ids'][0]]) and finding('source_memory_finding','unresolved')
        elif name.startswith('Q1 '):
            relevant=[e for e in timeline['events'] if e['uid'] in wanted]
            assert all(not e.get('derived_time') for e in relevant) and any(e.get('clock_uncertainty') for e in relevant)
        elif name.startswith('Q2 '):
            later=by_record[expectation['record_ids'][0]][0]
            prior=[r for r in rows if r.get('canonical_host_id')==later.get('canonical_host_id') and r.get('process_pid')==later.get('process_pid') and instant(r['time'])<instant(later['time'])]
            assert prior and all(r.get('process_guid')!=later.get('process_guid') for r in prior)
        elif name.startswith('Q3 '):assert len(by_record[expectation['record_ids'][0]])==1
        else:raise AssertionError('Unhandled answer-key expectation: '+name)
        results.append({'expectation':name,'status':'passed','source_uids':sorted(wanted)})
    return {'mode':'saved_case_outputs' if saved else 'deterministic_source_replay','checks':results,
        'limitations':['This fixture oracle verifies specified observations and negative controls, not general forensic accuracy, actor attribution or legal admissibility.']}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('snapshot');parser.add_argument('--saved',action='store_true');args=parser.parse_args()
    result=evaluate(json.loads(Path(args.snapshot).read_text()),json.loads(Path('output/fixtures/complex-evidence-answer-key.json').read_text()),args.saved)
    Path('data/private/priority_detection_'+('saved' if args.saved else 'replay')+'.json').write_text(json.dumps(result,indent=2))
    print('PASS:',len(result['checks']),'explicit answer-key expectations;',result['mode'])


if __name__=='__main__':main()
