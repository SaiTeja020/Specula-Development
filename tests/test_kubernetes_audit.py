from copy import deepcopy
from io import BytesIO
import json
from zipfile import ZipFile
import pytest

from src.agents.kubernetes_audit import analyze


def raw(audit='A',stage='ResponseComplete',code=201,cluster='cluster-1',namespace='team'):
    return {'apiVersion':'audit.k8s.io/v1','kind':'Event','cluster_id':cluster,'auditID':audit,
        'stage':stage,'verb':'create','stageTimestamp':'2026-10-15T00:00:00Z',
        'user':{'username':'admin'},'objectRef':{'resource':'pods','namespace':namespace,'name':'pod','uid':'P'},
        'responseStatus':{'code':code}}


def event(uid,data,minute=0):
    return {'uid':uid,'source_type':'kubernetes_audit','class_uid':99,
        'time':f'2026-10-15T00:{minute:02d}:00Z','unmapped':{'source_context':data}}


def run(rows):return analyze({'case_id':'C','evidence_collection':{'records':rows}})


def test_denied_stream_started_and_completed_operations_have_distinct_effects():
    rows=[event('denied',raw(code=403)),event('stream',raw('B','ResponseStarted',101)),
          event('received',raw('C','RequestReceived',201)),event('complete',raw('D'))]
    facts=run(rows)['findings'];by={f['dfkg_refs'][0]:f for f in facts}
    assert by['denied']['operation_outcome']=='failed'
    assert by['stream']['operation_outcome']=='unknown' and '"stream_upgrade_observed": true' in by['stream']['summary']
    assert by['received']['operation_outcome']=='unknown' and by['complete']['operation_outcome']=='confirmed'
    assert all('does not prove container execution' in f['summary'] for f in facts)


def test_pod_admitted_configuration_is_not_replaced_by_different_request_proposal():
    data=raw();data['requestObject']={'kind':'Pod','spec':{'hostPID':True}}
    data['responseObject']={'kind':'Pod','metadata':{'uid':'P'},'spec':{
        'hostNetwork':True,'containers':[{'name':'tool','securityContext':{'privileged':True}}]}}
    finding=next(f for f in run([event('p',data)])['findings'] if f['finding_type']=='kubernetes_sensitive_pod_configuration')
    assert 'response_object' in finding['summary'] and '"hostPID": null' in finding['summary']
    denied=deepcopy(data);denied['responseStatus']['code']=403
    finding=next(f for f in run([event('p',denied)])['findings'] if f['finding_type']=='kubernetes_sensitive_pod_configuration')
    assert 'request_proposal' in finding['summary'] and finding['operation_outcome']=='failed'


def binding():
    data=raw();data['objectRef']={'resource':'rolebindings','namespace':'team','name':'binding','uid':'B'}
    data['responseObject']={'kind':'RoleBinding','metadata':{'namespace':'team','uid':'B'},
        'roleRef':{'kind':'ClusterRole','name':'cluster-admin'},
        'subjects':[{'kind':'ServiceAccount','name':'worker','namespace':'team'}]}
    return data


def cluster_role():
    data=raw('role')
    data['verb']='create'
    data['objectRef']={'resource':'clusterroles','name':'cluster-admin'}
    data['responseObject']={'kind':'ClusterRole','metadata':{'name':'cluster-admin'},'rules':[
        {'apiGroups':[''],'resources':['pods'],'verbs':['get','list']}]}
    return data


def bound_request(verb='get',namespace='team',cluster='cluster-1'):
    data=raw('use',cluster=cluster,namespace=namespace)
    data['verb']=verb
    data['user']={'username':'system:serviceaccount:team:worker','groups':[]}
    return data


def test_observed_role_and_binding_rules_produce_cited_scoped_match():
    result=run([event('role',cluster_role(),0),event('binding',binding(),1),
                event('request',bound_request(),2)])
    finding=next(f for f in result['findings'] if f['finding_type']=='kubernetes_observed_rbac_rule_match')
    assert finding['dfkg_refs']==['binding','role','request']
    assert finding['operation_outcome']=='unknown'
    assert 'does not establish a complete policy inventory' in finding['summary']


@pytest.mark.parametrize('change',['verb','namespace','cluster','failed_binding'])
def test_observed_role_match_respects_request_and_binding_scope(change):
    role=cluster_role();grant=binding();request=bound_request()
    if change=='verb':request['verb']='delete'
    elif change=='namespace':request['objectRef']['namespace']='other'
    elif change=='cluster':request['cluster_id']='other'
    else:grant['responseStatus']['code']=403
    findings=run([event('role',role,0),event('binding',grant,1),event('request',request,2)])['findings']
    assert not any(f['finding_type']=='kubernetes_observed_rbac_rule_match' for f in findings)


@pytest.mark.parametrize('change',['cluster','namespace','principal','denied_binding'])
def test_rbac_subject_context_does_not_cross_scope_or_failed_grant(change):
    grant=binding();request=raw('use');request['user']={'username':'system:serviceaccount:team:worker'}
    if change=='cluster':request['cluster_id']='other'
    elif change=='namespace':request['objectRef']['namespace']='other'
    elif change=='principal':request['user']['username']='system:serviceaccount:other:worker'
    else:grant['responseStatus']['code']=403
    assert not any(r['type']=='RECORDED_RBAC_SUBJECT_CONTEXT' for r in run([event('binding',grant),event('request',request,1)])['relations'])


def test_impersonated_subject_and_audit_stage_citations_stay_source_qualified():
    grant=binding();request=raw('use');request['impersonatedUser']={'username':'system:serviceaccount:team:worker'}
    result=run([event('binding',grant),event('request',request,1)])
    relation=next(r for r in result['relations'] if r['type']=='RECORDED_RBAC_SUBJECT_CONTEXT')
    assert relation['dfkg_refs']==['binding','request'] and not relation['causal']
    assert relation['basis']['role_reference']['name']=='cluster-admin'
    start=raw('same','RequestReceived');end=raw('same')
    relations=run([event('start',start),event('end',end,1)])['relations']
    assert relations[0]['type']=='RECORDED_KUBERNETES_AUDIT_STAGE'
    end['user']['username']='other'
    assert not run([event('start',start),event('end',end,1)])['relations']


def test_actual_audit_zip_normalizes_without_invented_host_or_account(tmp_path):
    from src.ingestion.upload_archive import validate_archive,archive_batches
    from src.ingestion.run_pipeline import run_pipeline_on_event
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    from src.schemas.entity_resolver import CanonicalEntityResolver
    from src.agents.investigative_review import plan
    stream=BytesIO()
    with ZipFile(stream,'w') as archive:archive.writestr('kubernetes/audit.json',json.dumps({'kind':'EventList','items':[raw()]}))
    data=stream.getvalue();path=tmp_path/'evidence.zip';path.write_bytes(data)
    source,rows=next(archive_batches(path,validate_archive(data)))
    result=run_pipeline_on_event(rows[0],VCTAtomicChain(),CanonicalEntityResolver(),TimeNormalizer(),
        case_id='C',source_type=source,exported_log_path='kubernetes/audit.json')
    event=result[0][0].event.model_dump(mode='json');event['source_type']=source
    assert event['class_uid']==99 and event['canonical_host_id'] is None
    assert event['raw_source_timestamp']==raw()['stageTimestamp']
    assert 'cloud_container' in plan({'evidence_collection':{'records':[event]}})['required_roles']


def test_malformed_native_security_context_is_rejected_before_agent_execution():
    from src.ingestion.normalization.kubernetes_normalizer import normalize
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    data=raw();data['responseObject']={'kind':'Pod','spec':{'containers':'wrong-shape'}}
    with pytest.raises(ValueError,match='Pod list'):normalize(data,TimeNormalizer(),'t')


def test_successful_removal_or_replacement_ends_prior_binding_subject_context():
    grant=binding();removed=raw('delete',code=200)
    removed['verb']='delete';removed['objectRef']=deepcopy(grant['objectRef'])
    request=raw('use');request['user']={'username':'system:serviceaccount:team:worker'}
    rows=[event('grant',grant),event('deleted',removed,5),event('request',request,10)]
    assert not any(r['type']=='RECORDED_RBAC_SUBJECT_CONTEXT' and r['target']=='request' for r in run(rows)['relations'])
    removed['responseStatus']['code']=403
    assert any(r['type']=='RECORDED_RBAC_SUBJECT_CONTEXT' and r['target']=='request' for r in run(rows)['relations'])
