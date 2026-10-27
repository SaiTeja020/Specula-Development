from copy import deepcopy
from datetime import datetime,timezone
import json
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from scripts import followup_acquisition as collector
from src.agents import investigation_followup as followup

CASE='LOCAL-'+'1'*32


def state():
    event={'uid':'e','canonical_host_id':'H','source_type':'evtx','class_uid':99,
        'time':'2026-10-15T01:00:00+00:00','unmapped':{'source_context':{'MachineName':'HOST'}}}
    return {'case_id':CASE,'case_status':'specialist_tier','followup_cycle':1,
            'ingestion_provenance':{'source':'local_windows','selection':{
                'start_date':'2026-10-15T00:59:00+00:00','end_date':'2026-10-15T01:02:00+00:00'}},
            'evidence_collection':{'records':[event]},
            'findings':[{'agent_role':'identity','source':'validated_case_rule','classification':'unresolved',
                'summary':'Examine authentication context','dfkg_refs':['e']}]}


def test_collection_window_is_clipped_and_cannot_expand_host_or_date_scope():
    snapshot=state();window=collector.selection(CASE,['e'],snapshot,'HOST')
    assert window['start_date']=='2026-10-15T00:59:00+00:00'
    assert window['end_date']=='2026-10-15T01:02:00+00:00'
    assert window['channels']==list(collector.CHANNELS) and window['max_events_per_channel']==100
    for mutate in [lambda s:s.update(case_id='other'),lambda s:s.update(case_status='closed'),
                   lambda s:s['ingestion_provenance'].update(source='uploaded_zip'),
                   lambda s:s['evidence_collection']['records'][0]['unmapped']['source_context'].update(MachineName='FOREIGN'),
                   lambda s:s['evidence_collection']['records'][0].update(time='2026-10-16T00:00:00Z')]:
        changed=state();mutate(changed)
        with pytest.raises(ValueError):collector.selection(CASE,['e'],changed,'HOST')
    with pytest.raises(ValueError):collector.selection(CASE,['foreign'],snapshot,'HOST')


def test_one_case_audit_is_offered_and_does_not_repeat_after_resume():
    snapshot=state();snapshot['findings']*=3
    tasks=followup.candidates(snapshot)
    assert sum(t['tool']=='local_endpoint_audit' for t in tasks)==1
    snapshot['followup_history']=[{'tool':'local_endpoint_audit','cycle':1,'status':'partial'}]
    assert not any(t['tool']=='local_endpoint_audit' for t in followup.candidates(snapshot))
    snapshot=state();snapshot['ingestion_provenance']['source']='uploaded_zip'
    assert not any(t['tool']=='local_endpoint_audit' for t in followup.candidates(snapshot))


class Driver:
    def __init__(self):self.claim=None;self.receipt=None;self.calls=[]
    def execute_query(self,query,**params):
        self.calls.append((query,params))
        if 'RETURN r.claim' in query:
            if self.claim is None:self.claim=params['claim']
            return [{'claim':self.claim,'receipt':self.receipt}],None,None
        if 'receipt_json=$receipt' in query:self.receipt=params['receipt']
        return [],None,None


def test_actual_acquisition_calls_fixed_channels_and_caches_partial_receipt(monkeypatch):
    import scripts.local_case_pipeline as pipeline
    driver=Driver();calls=[]
    monkeypatch.setattr(collector.socket,'gethostname',lambda:'HOST')
    monkeypatch.setattr(collector.sys,'platform','win32')
    def extract(channel,start,end,limit):
        calls.append((channel,start,end,limit))
        if channel=='Security':raise RuntimeError('Access unavailable')
        return []
    monkeypatch.setattr('src.ingestion.run_pipeline.extract_windows_events',extract)
    def ingest(case,batches,ports,provenance,append_only=False):
        assert case==CASE and append_only and not ports
        list(batches)
        return {'accepted':0,'extracted':0,'excluded_records':0}
    monkeypatch.setattr(pipeline,'_ingest_batches',ingest)
    receipt=collector.acquire(CASE,['e'],1,state(),driver)
    assert receipt['status']=='partial' and len(calls)==3 and all(c[3]==100 for c in calls)
    assert collector.acquire(CASE,['e'],1,state(),driver)==receipt and len(calls)==3
    other=state();other['evidence_collection']['records'][0]['uid']='different'
    with pytest.raises(ValueError,match='different source anchors'):
        collector.acquire(CASE,['different'],1,other,driver)
    assert all('SET c.owner' not in q for q,p in driver.calls)
    with pytest.raises(ValueError,match='cycle'):collector.acquire(CASE,['e'],2,state(),driver)


def test_failed_delivery_is_durable_and_not_silently_retried(monkeypatch):
    monkeypatch.setattr(collector.socket,'gethostname',lambda:'HOST')
    monkeypatch.setattr(collector.sys,'platform','win32')
    def fail(*a,**k):raise RuntimeError('Delivery failed')
    monkeypatch.setattr('scripts.local_case_pipeline._ingest_batches',fail)
    driver=Driver();receipt=collector.acquire(CASE,['e'],1,state(),driver)
    assert receipt['status']=='failed' and 'not rolled back' in receipt['limitation']
    assert collector.acquire(CASE,['e'],1,state(),driver)==receipt


def test_internal_collector_requires_bearer_not_dashboard_origin(monkeypatch):
    from scripts import local_boot_api as api
    monkeypatch.setattr(api,'_local_token',lambda:'test-private-token')
    client=TestClient(api.app)
    body={'anchor_refs':['e'],'cycle':1}
    response=client.post('/api/internal/local-cases/'+CASE+'/acquire',json=body,
        headers={'Origin':'http://localhost:5173','X-Specula-Local-Boot':'1'})
    assert response.status_code==401
    response=client.post('/api/internal/local-cases/foreign/acquire',json=body,
        headers={'Authorization':'Bearer test-private-token'})
    assert response.status_code==403
    response=client.post('/api/internal/local-cases/'+CASE+'/acquire',json={**body,'command':'malicious'},
        headers={'Authorization':'Bearer test-private-token'})
    assert response.status_code==422


def test_new_sources_trigger_one_bounded_reanalysis_and_keep_budget(monkeypatch):
    from tests.test_investigation_followup import Driver as Graph, event,llm_for
    monkeypatch.setattr('src.agents.config.get_llm',lambda *a,**k:llm_for())
    snapshot=state();snapshot['followup_round']=1
    driver=Graph([*snapshot['evidence_collection']['records'],event('new')])
    command=followup.make_followup_node(driver)(snapshot)
    assert command.goto=='supervisor' and command.update['acquisition_reanalysis_count']==1
    assert command.update['followup_round']==2 and command.update['followup_reanalysis_pending']
    snapshot['acquisition_reanalysis_count']=1
    command=followup.make_followup_node(driver)(snapshot)
    assert command.goto=='timeline_reconstruction' and command.update['followup_status']=='source_changed_requires_reanalysis'


def test_partial_receipt_never_becomes_complete_when_no_tasks_remain():
    snapshot=state();snapshot['findings']=[]
    snapshot['followup_history']=[{'task_id':'t','cycle':1,'status':'partial'}]
    command=followup.make_followup_node(None)(snapshot)
    assert command.update['followup_status']=='requires_analyst'


def test_append_ingestion_preserves_owner_memberships_and_original_provenance(monkeypatch):
    from scripts import local_case_pipeline as pipeline
    from unittest.mock import MagicMock
    queries=[]
    class Graph:
        def execute(self,query,params):
            queries.append((query,params))
            return [{'owner':'local-validation'}] if 'AS owner' in query else []
        def close(self):pass
    event=SimpleNamespace(uid='new',model_dump=lambda mode:{'uid':'new','time':'2026-10-15T01:00:00Z'})
    monkeypatch.setattr('src.ingestion.run_pipeline.run_pipeline_on_event',lambda *a,**k:
        [(SimpleNamespace(valid=True,event=event),'MERGE',[])])
    monkeypatch.setattr('src.ingestion.preservation.quickwit_client.QuickwitClient',lambda:MagicMock())
    monkeypatch.setattr('src.graph.neo4j_client.Neo4jClient',Graph)
    monkeypatch.setattr('src.graph.process_lineage.persist_lineage',lambda *a:{})
    monkeypatch.setattr('src.ingestion.indexing.case_evidence.CaseEvidenceIndex',lambda:MagicMock(index=lambda *a:{}))
    monkeypatch.setattr('src.agents.case_analytics.write_case_analytics',lambda *a:{})
    monkeypatch.setattr('src.ingestion.broker.case_stream.publish_normalized_case',lambda *a:{})
    provenance={'id':'run-1','source':'local_windows_followup'}
    result=pipeline._ingest_batches(CASE,[('evtx',[{'Id':4688}])],[],provenance,append_only=True)
    assert result['accepted']==1
    assert any('HAS_ACQUISITION' in q for q,p in queries)
    assert not any('SET c.owner' in q or 'c.member_user_ids' in q or 'SET c.ingestion_provenance_json' in q for q,p in queries)


def test_supervisor_reanalysis_preserves_cycle_and_budget(monkeypatch):
    from src.agents.supervisor_factory import make_supervisor_node
    from tests.test_investigation_followup import Driver,event
    monkeypatch.setattr('src.agents.case_analysis.review',lambda *a:{'timestamp':'now'})
    snapshot=state();snapshot.update(followup_reanalysis_pending=True,followup_round=1,acquisition_reanalysis_count=1)
    out=make_supervisor_node(Driver([event('e')]))(snapshot)
    assert out['followup_cycle']==1 and out['followup_round']==1 and out['acquisition_reanalysis_count']==1
    assert out['followup_reanalysis_pending'] is False
    snapshot['followup_reanalysis_pending']=False
    out=make_supervisor_node(Driver([event('e')]))(snapshot)
    assert out['followup_cycle']==2 and out['followup_round']==0 and out['acquisition_reanalysis_count']==0


def test_compiled_followup_cycle_collects_once_and_reloads_new_evidence(monkeypatch):
    from langgraph.graph import StateGraph,START,END
    from src.agents.state import SpeculaState
    from src.agents.supervisor_factory import make_supervisor_node
    from tests.test_investigation_followup import Driver,llm_for
    snapshot=state();driver=Driver(snapshot['evidence_collection']['records'].copy());calls=[]
    monkeypatch.setattr('src.agents.config.get_llm',lambda *a,**k:llm_for())
    monkeypatch.setattr('src.agents.case_analysis.review',lambda *a:{'timestamp':'now'})
    def collect(task,s):
        calls.append(task['id'])
        new=deepcopy(driver.rows[0]);new['uid']='new';driver.rows.append(new)
        return {'status':'complete','dfkg_refs':task['anchor_refs'],'limitation':'Bounded test collection'}
    monkeypatch.setattr(followup,'acquire_local_audit',collect)
    builder=StateGraph(SpeculaState)
    builder.add_node('investigation_followup',followup.make_followup_node(driver))
    builder.add_node('supervisor',make_supervisor_node(driver))
    builder.add_node('evidence_collection',lambda s:{'evidence_collection':{'records':driver.rows}})
    builder.add_node('timeline_reconstruction',lambda s:{})
    builder.add_edge(START,'investigation_followup');builder.add_edge('supervisor','evidence_collection')
    builder.add_edge('evidence_collection','investigation_followup');builder.add_edge('timeline_reconstruction',END)
    result=builder.compile().invoke(snapshot,{'recursion_limit':12})
    assert len(calls)==1 and result['acquisition_reanalysis_count']==1
    assert {r['uid'] for r in result['evidence_collection']['records']}=={'e','new'}
    assert result['followup_cycle']==1 and result['followup_round']==1 and result['followup_status']=='complete'
