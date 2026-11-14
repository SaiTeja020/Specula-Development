from copy import deepcopy
from types import SimpleNamespace
import pytest
from src.agents.evidence_correlations import correlate,authorized_job
from src.agents.network_forensics_factory import make_network_forensics_node


def row(uid,minute,host='H',kind=4001,**raw):
    return {'uid':uid,'case_id':'A','canonical_host_id':host,'class_uid':kind,
            'time':f'2026-10-14T00:{minute:02d}:00Z','unmapped':{'source_context':raw}}


def test_account_transition_and_destination_fallback_keep_failed_branches():
    denied=row('denied',1,kind=3002,user='alice',source_ip='10.1.1.1');denied['source_event_id']=4625
    accepted=row('accepted',3,kind=3002,user='svc',source_ip='10.1.1.1',logon_id='B');accepted['source_event_id']=4624
    proc=row('process',4,kind=1007,user='svc',logon_id='B')
    archive=row('archive',5,kind=1001,user='svc',path='C:\\cache\\finance.zip')
    failed=row('failed',6,process='agent.exe',source_ip='10.1.1.1',destination_ip='198.51.100.1',outcome='connection_refused')
    success=row('success',7,process='agent.exe',source_ip='10.1.1.1',destination_ip='198.51.100.2',outcome='established')
    facts=correlate({'case_id':'A','evidence_collection':{'records':[denied,accepted,proc,archive,failed,success]}})
    account=next(f for f in facts['findings'] if f['finding_type']=='different_account_after_denial')
    assert set(account['dfkg_refs'])=={'denied','accepted','process','archive'}
    assert any(r['type']=='POSSIBLE_NETWORK_FALLBACK' for r in facts['relations'])
    assert all(not r['causal'] for r in facts['relations'])
    success['unmapped']['source_context']['process']='other.exe'
    assert not any(r['type']=='POSSIBLE_NETWORK_FALLBACK' for r in correlate({'evidence_collection':{'records':[failed,success]}})['relations'])
    accepted['canonical_host_id']='OTHER'
    assert not any(f['finding_type']=='different_account_after_denial' for f in correlate({'evidence_collection':{'records':[denied,accepted]}})['findings'])


@pytest.mark.parametrize('change',[{'host':'OTHER'},{'job_id':'OTHER'},{'destination_ip':'198.51.100.9'},
                                  {'destination_ip':None},{'minute':20},{'result':'failed'}])
def test_job_authorization_cannot_transfer_to_wrong_context(change):
    flow=row('flow',1,job_id='JOB',destination_ip='198.51.100.2',outcome='established')
    options={'job_id':'JOB','destination_ip':'198.51.100.2','change_ticket':'CHG','detection':'Scheduled backup completed'}
    options.update(change);host=options.pop('host','H');minute=options.pop('minute',2)
    control=row('control',minute,host=host,kind=2004,**options)
    assert not authorized_job(flow,[control])


def test_primary_network_recognizes_actual_authorized_backup_control():
    flow=row('flow',1,job_id='JOB',destination_ip='198.51.100.2',outcome='established')
    flow.update(src_endpoint={'ip_address':'10.0.0.1'},dst_endpoint={'ip_address':'198.51.100.2','port':443},bytes_out=315000000)
    control=row('control',2,kind=2004,job_id='JOB',destination_ip='198.51.100.2',change_ticket='CHG',detection='Scheduled backup completed')
    assert authorized_job(flow,[control])==[control]
    graph=SimpleNamespace(execute_query=lambda *a,**k:([{'e':flow},{'e':control}],None,None))
    producer=SimpleNamespace(produce=lambda *a,**k:None,poll=lambda *a:None)
    result=make_network_forensics_node(graph,producer)({'case_id':'A'})
    assert result['findings'] and all(f['classification']=='benign' for f in result['findings'])
    assert all(f['dfkg_refs']==['control','flow'] and not f['attacks'] for f in result['findings'])


def test_timeline_episodes_and_clock_model_never_rewrite_original_time():
    from src.agents.timeline_reconstruction import reconstruct
    flow=row('flow',1,job_id='JOB',destination_ip='198.51.100.2',outcome='established')
    control=row('control',2,kind=2004,job_id='JOB',destination_ip='198.51.100.2',change_ticket='CHG',detection='Scheduled backup completed')
    clock=row('clock',3,kind=2004,ntp_offset_seconds=95,clock_state='unsynchronized')
    state={'case_id':'A','evidence_collection':{'records':[flow,control,clock]}}
    result=reconstruct(state)
    assert len(result['events'])==3 and result['episodes'] and result['relations']
    assert all(e['derived_time'] is None for e in result['events'])
    clock['unmapped']['source_context'].update(clock_offset_convention='local_minus_utc',clock_measurement_verified=True)
    result=reconstruct(state);e=next(e for e in result['events'] if e['uid']=='flow')
    assert e['time']==e['recorded_time']=='2026-10-14T00:01:00Z'
    assert e['derived_time']=='2026-10-13T23:59:25+00:00' and not e['derived_time_basis']['independently_verified']


def test_relational_graph_has_cited_basis_and_acyclic_candidate_paths():
    from src.agents.relational_graph import enrich
    flow=row('flow',1,job_id='JOB',destination_ip='198.51.100.2',outcome='established')
    control=row('control',2,kind=2004,job_id='JOB',destination_ip='198.51.100.2',change_ticket='CHG',detection='Scheduled backup completed')
    state={'case_id':'A','evidence_collection':{'records':[control,flow]}}
    graph=enrich(state,[],[])
    assert graph['relation_count']==1 and graph['activity_paths'][0]['probability'] is None
    assert graph['edges'][0]['type']=='MATCHING_AUTHORIZED_JOB' and graph['edges'][0]['basis']['job_id']=='JOB'
    assert graph['activity_paths'][0]['nodes']==['evidence-flow','evidence-control']
    assert all(n['dfkg_refs'] for n in graph['nodes'])
