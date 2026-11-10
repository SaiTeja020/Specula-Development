import json
from types import SimpleNamespace
from src.agents.grounding import claim_errors,audit


def test_scheduled_backup_association_requires_cited_benign_control():
    claim = 'The high outbound volume is attributed to a scheduled backup job.'
    control = {'summary': 'Source-reported scheduled job has matching authorized completion counter-evidence.',
               'classification': 'benign'}
    assert not claim_errors(claim, [control])
    assert claim_errors(claim, [])
    assert claim_errors(claim, [{**control, 'classification': 'suspicious'}])
    assert claim_errors(claim, [{'summary': 'Approved deployment script.', 'classification': 'benign'}])
    assert claim_errors('The incident is attributed to APT29.', [control])
    assert claim_errors('The volume is attributed to a scheduled backup job, attributed to APT29.', [control])
    assert claim_errors('The volume is attributed to a scheduled backup job operated by APT29.', [control])
    assert claim_errors(claim + ' Successful credential extraction occurred.',
                        [{**control, 'operation_outcome': 'failed'}])


def test_password_reset_association_does_not_license_actor_attribution():
    claim = ('The failed logons followed by a successful logon are attributed to a password reset process, '
             'with matching MFA records confirming its benign nature.')
    control = {'summary': 'Matching reset/MFA records are source-reported authorization counter-evidence.',
               'classification': 'benign'}
    assert not claim_errors(claim, [control])
    assert claim_errors(claim, [])
    assert claim_errors(claim, [{**control, 'classification': 'failed'}])
    assert claim_errors(claim, [{'summary': 'Scheduled backup transfer completed.', 'classification': 'benign'}])
    assert claim_errors('The incident is attributed to APT29.', [control])
    assert claim_errors('The logons are attributed to a password reset process operated by APT29.', [control])


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
