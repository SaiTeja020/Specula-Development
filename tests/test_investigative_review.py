import json
from types import SimpleNamespace
from src.agents.investigative_review import investigate,plan
from src.agents.nodes import judge_node


def test_specialist_records_explanation_limits_and_exact_coverage():
    facts=[{'summary':'Operation denied','dfkg_refs':['e'],'classification':'failed','operation_outcome':'failed'}]
    result={'assessments':[{'observation_id':0,'disposition':'supported_observation','explanation':'Denied operation is recorded.','limitations':'Extraction is not established.','next_action':'Review access telemetry.'}]}
    prompts=[]
    def invoke(prompt,schema):
        prompts.append(prompt);return SimpleNamespace(content=json.dumps(result))
    state={'evidence_collection':{'records':[{'uid':'e','time':'2026-10-14T00:00:00Z','canonical_host_id':'H','unmapped':{'source_context':{'result':'access_denied'}}}]}}
    trace=investigate('identity',state,facts,SimpleNamespace(invoke_structured=invoke,model_name='qwen3:8b'))
    assert trace['review_coverage']['complete'] and trace['investigation_assessments'][0]['dfkg_refs']==['e']
    assert 'access_denied' in prompts[0] and 'private reasoning' in prompts[0]
    result['assessments'][0]['observation_id']=99
    assert not investigate('identity',state,facts,SimpleNamespace(invoke_structured=invoke))['model_output_validated']


def test_work_plan_includes_native_and_specialist_roles():
    state={'evidence_collection':{'records':[{'uid':'e','source_type':'malware','class_uid':2004},
        {'uid':'m','source_type':'memory','class_uid':2004},{'uid':'c','source_type':'container','class_uid':6003}]}}
    p=plan(state)
    assert set(p['required_roles'])>={'malware_stylometry','memory_forensics','cloud_container','judge'}
    assert p['imported_only']==2


def test_actual_evidence_debate_revises_once_then_pauses(monkeypatch):
    review={'verdict':'revise','resolutions':[]}
    monkeypatch.setattr('src.agents.nodes._run_agent',lambda *a:({'summary':'revise','assessment':review,'review_valid':True},{}))
    state={'evidence_review_required':True,'proponent_review':{'hypotheses':[{}]},'critic_review':{'challenges':[{}]},'debate_round':1}
    first=judge_node(state)
    assert first.goto=='proponent' and first.update['debate_round']==2 and first.update['debate_feedback']['judge']==review
    second=judge_node({**state,'debate_round':2})
    assert second.goto=='hitl' and second.update['acceptance_status']=='incomplete'


def test_incomplete_required_worker_does_not_burn_more_model_calls(monkeypatch):
    from src.agents.nodes import _run_agent
    monkeypatch.setattr('src.agents.nodes.get_llm',lambda *a,**k:(_ for _ in ()).throw(AssertionError('Model must not run')))
    finding,trace=_run_agent('proponent',{'evidence_review_required':True,'agent_traces':[
        {'agent_role':'network_specialist','review_coverage':{'complete':False}}]})
    assert not finding['review_valid'] and trace['model_used']=='not_invoked_missing_upstream_review'


def test_supervisor_cohorts_retain_every_source_reference(monkeypatch):
    from src.agents import case_analysis
    from src.agents.supervisor_factory import make_supervisor_node
    rows=[{'uid':str(i),'class_uid':1007,'canonical_host_id':'H','source_type':'evtx'} for i in range(3)]
    reviewed=[]
    monkeypatch.setattr(case_analysis,'review',lambda role,state,facts:(reviewed.extend(facts) or {'timestamp':'2026-10-14T00:00:00Z'}))
    result=make_supervisor_node(SimpleNamespace(execute_query=lambda *a,**k:([{'e':r} for r in rows],None,None)))({'case_id':'A'})
    assert len(reviewed)==1 and set(reviewed[0]['dfkg_refs'])=={'0','1','2'}
    assert result['agent_traces'][0]['preserved_event_count']==result['investigation_plan']['source_count']==3


def test_clarification_preserves_history_without_poisoning_new_cycle(monkeypatch):
    from src.agents.case_analysis import current_findings,current_traces,debate_facts
    from src.agents.nodes import _run_agent
    old={'agent_role':'network_specialist','review_coverage':{'complete':False}}
    traces=[{'agent_role':'supervisor'},old,{'agent_role':'supervisor','review_coverage':{'complete':True}}]
    findings=[{'agent_role':'supervisor'},{'source':'validated_case_rule','finding_type':'old','summary':'Old analysis','dfkg_refs':['e']},
        {'agent_role':'supervisor'},{'source':'validated_case_rule','finding_type':'new','summary':'New analysis','dfkg_refs':['e']}]
    s={'evidence_review_required':True,'agent_traces':traces,'findings':findings,'evidence_collection':{'records':[{'uid':'e'}]}}
    assert len(current_traces(s))==1 and len(current_findings(s))==2
    assert [f['finding_type'] for f in debate_facts(s)]==['new']
    monkeypatch.setattr('src.agents.nodes.get_llm',lambda *a,**k:None)
    monkeypatch.setattr('src.agents.evidence_review.debate',lambda *a:(None,{'action':'new_review','model_output_validated':False,'dfkg_refs':[],
        'timestamp':'now','observation':'New review invoked'}))
    _,trace=_run_agent('proponent',s)
    assert trace['action']=='new_review' and len(s['agent_traces'])==3 and old in s['agent_traces']
