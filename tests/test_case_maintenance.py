from types import SimpleNamespace
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import InMemorySaver
from tests.api_auth_helpers import configure_test_auth
from src.agents import visualizer_api


def test_maintenance_authorization_topology_scope_and_pause(monkeypatch,tmp_path):
    headers=configure_test_auth(monkeypatch,tmp_path,{'test-user':{'role':'analyst','cases':['A']}})
    values={'case_id':'A','evidence_collection':{'records':[{'uid':'e'}]}}
    next_nodes=['hitl'];writes=[]
    graph=SimpleNamespace(checkpointer=InMemorySaver(),
        get_state=lambda config:SimpleNamespace(values=values,next=tuple(next_nodes),tasks=()),
        update_state=lambda config,data:values.update(data))
    monkeypatch.setattr(visualizer_api,'_specula_graph',graph)
    monkeypatch.setattr(visualizer_api,'_neo4j_driver',SimpleNamespace(execute_query=lambda *a,**k:([],None,None)))
    monkeypatch.setattr('src.agents.agent_graph.persist_case_analysis',lambda *a:writes.append(a))
    client=TestClient(visualizer_api.app)
    assert client.post('/api/investigations/A/reindex').status_code==401
    assert client.post('/api/investigations/B/reindex',headers=headers).status_code==403
    body={'nodes':[{'id':n,'label':n,'evidence_refs':['e']} for n in ['start','goal']],
          'edges':[{'source':'start','target':'goal','precondition_refs':['e'],'exploitation_refs':['e']}],
          'start':'start','goal':'goal','rationale':'Source evidence reviewed by the analyst'}
    r=client.post('/api/investigations/A/exploit-topology',headers=headers,json=body)
    assert r.status_code==200 and r.json()['path_conditional_probability'] is None
    assert writes and values['exploit_topology']['reviewed_by']=='test-user' and next_nodes==['hitl']
    body['nodes'][0]['evidence_refs']=['foreign']
    assert client.post('/api/investigations/A/exploit-topology',headers=headers,json=body).status_code==422
    next_nodes[:]=['supervisor']
    assert client.post('/api/investigations/A/exploit-topology',headers=headers,json=body).status_code==409
