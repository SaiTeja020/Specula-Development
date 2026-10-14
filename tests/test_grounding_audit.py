import json
from types import SimpleNamespace
from src.agents.grounding import claim_errors,audit


def test_source_constraints_distinguish_uncertainty_from_completed_effects():
    failed=[{'summary':'Credential access denied','operation_outcome':'failed'}]
    assert claim_errors('Successful credential extraction occurred.',failed)
    assert not claim_errors('Credential extraction is unproven; access was denied.',failed)
    assert claim_errors('Patch VULN-001 and CVE-2026-9999.',failed)
    assert claim_errors('Exploit success probability 99.8%.',failed)
    assert not claim_errors('Exploit probability unavailable.',failed)
    assert claim_errors('The hypothesis is supported: a legitimate service account performed authorized activity.',failed)
    assert not claim_errors('The account may be legitimate; authorization remains unverified.',failed)


def test_final_semantic_audit_cannot_accept_hard_contradiction():
    facts=[{'summary':'Access denied','dfkg_refs':['e'],'operation_outcome':'failed'}]
    state={'evidence_collection':{'records':[{'uid':'e'}]},'proponent_review':{'hypotheses':[
        {'hypothesis':'Successful credential extraction occurred.','observation_ids':[0]}]}}
    response={'checks':[{'hypothesis_id':0,'status':'grounded','observation_ids':[0],'rationale':'Supported source claim.'}]}
    llm=SimpleNamespace(invoke_structured=lambda *a:SimpleNamespace(content=json.dumps(response)))
    result=audit(state,facts,llm)
    assert not result['grounding_passed'] and not result['model_output_validated']
    response['checks'][0]['status']='contradicted'
    result=audit(state,facts,llm)
    assert result['model_output_validated'] and not result['grounding_passed']
    state['proponent_review']['hypotheses'][0]['hypothesis']='Access failed; extraction is not established.'
    response['checks'][0]['status']='grounded'
    assert audit(state,facts,llm)['grounding_passed']
