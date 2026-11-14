from types import SimpleNamespace
from unittest.mock import patch
import pytest
from src.agents.graph import _dead_end_route
from src.agents.log_analysis_factory import make_log_analysis_node
from src.agents.network_forensics_factory import make_network_forensics_node


def test_native_only_malware_dispatch_and_missing_graph_fail_closed():
    state={'case_id':'A','evidence_review_required':True,'evidence_collection':{'records':[
        {'uid':'pe','source_type':'malware','class_uid':2004}]}}
    assert {send.node for send in _dead_end_route(state)}=={'malware_stylometry'}
    with pytest.raises(RuntimeError):make_log_analysis_node(None,None,None,None)(state)
    with pytest.raises(RuntimeError):make_network_forensics_node(None,None)(state)


def test_real_rule_failure_is_not_replaced_with_model_narration():
    event={'uid':'p','case_id':'A','trace_id':'t','class_uid':1007,'category_uid':1,'activity_id':1,
           'severity_id':1,'time':'2026-10-14T00:00:00Z','raw_source_timestamp':'2026-10-14T00:00:00Z',
           'ocsf_version':'1.2.0','canonical_host_id':'host-A'}
    graph=SimpleNamespace(execute_query=lambda *a,**k:([{'e':event}],None,None))
    with patch('src.agents.log_analysis_factory.LogAnalysisAgent') as agent:
        agent.return_value.run_on_batch.side_effect=ValueError('malformed rule input')
        with pytest.raises(RuntimeError,match='Log analysis failed'):
            make_log_analysis_node(None,None,None,graph)({'case_id':'A','evidence_review_required':True})
    graph.execute_query=lambda *a,**k:(_ for _ in ()).throw(ValueError('read failed'))
    with pytest.raises(RuntimeError,match='read failed'):
        make_network_forensics_node(graph,None)({'case_id':'A'})
