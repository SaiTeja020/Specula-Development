import json
from types import SimpleNamespace

from src.agents.grounding import claim_errors,audit


def test_unrelated_unknown_does_not_excuse_confirmed_failed_effect():
    facts=[{'summary':'Source reports denied access.','operation_outcome':'failed','classification':'failed'}]
    assert claim_errors('Credential extraction succeeded; actor identity remains unknown.',facts)
    assert claim_errors('The legitimate service account completed activity and other motives remain unknown.',facts)
    assert not claim_errors('Successful credential extraction was not established.',facts)
    assert not claim_errors('No confirmed compromise is established.',facts)
    assert claim_errors('Exploit success is 99% and the actor is unknown.',facts)
    assert claim_errors('Confirmed timestomping was detected.',facts)
    assert not claim_errors('Confirmed timestomping was not established.',facts)


def test_policy_or_api_success_cannot_be_upgraded_to_runtime_execution():
    facts=[{'summary':'Source policy model grants requested access.','operation_outcome':'unknown',
            'classification':'context','effect_scope':'permission_model'}]
    assert claim_errors('The command was executed.',facts)
    assert not claim_errors('The policy grants the requested right.',facts)
    assert not claim_errors('Command execution remains unverified.',facts)
    facts[0].update(effect_scope='api_audit',operation_outcome='confirmed',summary='API request returned 201.')
    assert claim_errors('The container escaped.',facts)
    assert not claim_errors('The API reports a successful creation request.',facts)


def test_grounding_decoder_limits_each_hypothesis_to_its_source_observations():
    hypotheses=[{'hypothesis':'First operation was denied.','observation_ids':[0]},
                {'hypothesis':'Second operation was denied.','observation_ids':[1]}]
    captured=[]
    def invoke(prompt,schema):
        captured.append(schema)
        return SimpleNamespace(content=json.dumps({'checks':[{'hypothesis_id':i,'status':'grounded',
            'observation_ids':[i],'rationale':'Cited denial supports the bounded statement.'} for i in range(2)]}))
    facts=[{'summary':'Source denied operation.','dfkg_refs':[str(i)],'operation_outcome':'failed'} for i in range(2)]
    trace=audit({'proponent_review':{'hypotheses':hypotheses}},facts,SimpleNamespace(invoke_structured=invoke,model_name='qwen3:8b'))
    assert trace['grounding_passed']
    variants=captured[0]['properties']['checks']['items']['oneOf']
    assert variants[0]['properties']['observation_ids']['items']['enum']==[0]
    assert variants[1]['properties']['observation_ids']['items']['enum']==[1]


def test_graph_keeps_relationship_direction_but_not_reverse_time_candidate_path(monkeypatch):
    from src.agents import relational_graph
    rows=[{'uid':'parent','time':'2026-10-14T00:02:00Z'}, {'uid':'child','time':'2026-10-14T00:01:00Z'}]
    relation={'id':'r','source':'parent','target':'child','type':'SOURCE_PARENT_PROCESS',
        'dfkg_refs':['parent','child'],'basis':{'source_guid':'P'},'limitations':['Source clock uncertainty']}
    monkeypatch.setattr(relational_graph,'correlate',lambda state:{'relations':[relation]})
    graph=relational_graph.enrich({'evidence_collection':{'records':rows}},[],[])
    edge=graph['edges'][0]
    assert edge['source']=='evidence-parent' and edge['target']=='evidence-child'
    assert not edge['chronology_eligible'] and not graph['activity_paths']
