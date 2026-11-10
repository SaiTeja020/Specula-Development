"""Fixture metadata cannot replace evidence of behavior in structured reviews."""
import json
import base64
from copy import deepcopy
from types import SimpleNamespace

import pytest

from src.agents.grounding import claim_errors
from src.agents.investigative_review import investigate
from src.agents.evidence_review import debate


@pytest.mark.parametrize('text', [
    'The synthetic flag indicates it is not a real-world threat.',
    'The synthetic nature of the data and lack of further evidence support the benign classification.',
    'The encoded command is synthetic and does not represent actual malicious activity.',
    'The activity is benign because it is synthetic.',
    'The fixture ID proves that the activity was authorized.',
    'No synthetic flag is present, therefore the activity is malicious.',
    'Synthetic provenance does not prove benignness, but the synthetic flag confirms that it is benign.',
    'This activity is harmless because it is only a simulation.',
])
def test_origin_is_never_verdict_evidence(text):
    assert claim_errors(text, [{'summary': 'Operation observed; intent unresolved.'}])


@pytest.mark.parametrize('classification', ['benign', 'suspicious'])
def test_model_payload_omits_fixture_markers_without_changing_evidence(classification):
    row = {'uid': 'e', 'time': '2026-11-10T00:00:00Z', 'synthetic': True,
           'unmapped': {'source_context': {'synthetic': True, 'fixture_id': 'fixture-secret',
               'details': {'is_synthetic': True, 'operation_result': 'access_denied'},
               'command_line': 'echo SYNTHETIC-CONTENT', 'change_ticket': 'CHANGE-123'}}}
    state = {'evidence_collection': {'records': [row]}}
    original = json.dumps(state, sort_keys=True)
    seen = []
    response = {'assessments': [{'observation_id': 0, 'disposition': 'insufficient_context',
        'explanation': 'Source records denied access; intent remains unresolved.',
        'limitations': 'No completed effect is established.', 'next_action': 'Review the source access log.'}]}
    def invoke(prompt, schema):
        seen.append(prompt)
        return SimpleNamespace(content=json.dumps(response))
    trace = investigate('identity', state,
        [{'summary': 'Source records denied access.', 'dfkg_refs': ['e'], 'classification': classification}],
        SimpleNamespace(invoke_structured=invoke))
    assert trace['model_output_validated']
    payload = json.loads(seen[0].split('Return JSON only.\n', 1)[1].split('\nRequired JSON schema:')[0])
    serialized = json.dumps(payload)
    assert '"synthetic"' not in serialized and '"is_synthetic"' not in serialized
    assert 'fixture-secret' not in serialized
    assert payload[0]['classification'] == classification
    assert 'access_denied' in serialized and 'CHANGE-123' in serialized
    assert 'SYNTHETIC-CONTENT' in serialized
    assert json.dumps(state, sort_keys=True) == original


def test_shortcut_in_limitations_cannot_be_accepted():
    response = {'assessments': [{'observation_id': 0, 'disposition': 'supported_observation',
        'explanation': 'Source records an executable starting.',
        'limitations': 'The synthetic flag confirms that this activity is benign.',
        'next_action': 'Review the preserved executable metadata.'}]}
    trace = investigate('malware_stylometry', {}, [{'summary': 'Unsigned process started.', 'dfkg_refs': ['e']}],
        SimpleNamespace(invoke_structured=lambda *args: SimpleNamespace(content=json.dumps(response))))
    assert not trace['model_output_validated']
    assert trace['review_coverage']['validated'] == 0


def test_proponent_cannot_use_fixture_origin_as_an_alternative_explanation():
    response = {'hypotheses': [{'kind': 'alternative',
        'hypothesis': 'The activity is benign because it is synthetic.', 'observation_ids': [0],
        'limitations': 'Source authorization remains unverified.'}]}
    result, trace = debate('proponent', {}, [{'summary': 'Unsigned process started.', 'dfkg_refs': ['e']}],
        SimpleNamespace(invoke_structured=lambda *args: SimpleNamespace(content=json.dumps(response))))
    assert result is None and not trace['model_output_validated']


@pytest.mark.parametrize('text', [
    'Synthetic provenance does not establish whether activity is benign or malicious.',
    'The source reports Synthetic Lab Operations approved the deployment.',
    'Synthetic records include a denied credential-access attempt.',
    'The approved script prints SYNTHETIC-CONTENT, supporting a benign interpretation.',
    'Source-reported approval by Synthetic Lab Operations supports a benign interpretation.',
    "The synthetic flag doesn't prove benignness.",
    'Synthetic provenance must not be used to infer maliciousness.',
    'The synthetic nature of the findings and the lack of execution environment limit the ability to confirm malicious intent.',
    'The synthetic flag indicates a test environment, and the observation notes this is not a verified malicious campaign.',
    "The synthetic nature of the events and the lack of direct execution logs limit the ability to confirm the data transfer's nature.",
])
def test_neutral_origin_descriptions_are_not_verdicts(text):
    assert not claim_errors(text, [{'summary': 'Source provenance and behavior recorded.'}])


@pytest.mark.parametrize('flag', [True, False, None])
def test_actual_rules_depend_on_behavior_and_controls_not_fixture_flag(flag):
    from src.agents.case_analysis import detections
    command = base64.b64encode("Write-Output 'SYNTHETIC-CONTENT'".encode('utf-16le')).decode()
    rows = [{'uid': uid, 'canonical_host_id': host, 'time': '2026-11-10T00:00:00Z',
             'source_type': 'evtx', 'class_uid': 1007,
             'command_line': 'powershell.exe -EncodedCommand ' + command,
             'unmapped': {'source_context': {}}} for uid, host in [('approved', 'host-A'), ('unapproved', 'host-B')]]
    rows.append({'uid': 'control', 'canonical_host_id': 'host-A', 'time': '2026-11-10T00:00:01Z',
                 'source_type': 'edr', 'class_uid': 2004, 'finding_title': 'Deployment validation',
                 'unmapped': {'source_context': {'change_ticket': 'CHANGE-123', 'result': 'approved'}}})
    for row in rows:
        if flag is not None:
            row['unmapped']['source_context']['synthetic'] = flag
    state = {'evidence_collection': {'records': rows}}
    original = deepcopy(state)
    findings = detections(state, 'log_analysis')
    encoded = [f for f in findings if f['finding_type'] == 'encoded_powershell']
    assert [(f['canonical_host_id'], f['classification']) for f in encoded] == [
        ('host-A', 'benign'), ('host-B', 'suspicious')]
    assert state == original


def test_debate_does_not_reuse_legacy_origin_shortcut_as_worker_support():
    state = {'agent_traces': [{'agent_role': 'log_analysis', 'model_output_validated': True,
        'investigation_assessments': [{'dfkg_refs': ['e'], 'disposition': 'supported_observation',
            'explanation': 'The synthetic flag confirms this activity is benign.',
            'limitations': 'Unverified source.', 'next_action': 'Review evidence.'}]}]}
    original = deepcopy(state)
    seen = []
    def invoke(prompt, schema):
        seen.append(prompt)
        return SimpleNamespace(content=json.dumps({'hypotheses': [{'kind': 'unresolved',
            'hypothesis': 'The source observation requires further corroboration.', 'observation_ids': [0],
            'limitations': 'Source intent remains unverified.'}]}))
    result, trace = debate('proponent', state, [{'summary': 'Unsigned process started.', 'dfkg_refs': ['e']}],
        SimpleNamespace(invoke_structured=invoke))
    payload = json.loads(seen[0].split('Return JSON only.\n', 1)[1].split('\nRequired JSON schema:')[0])
    assert result and trace['model_output_validated']
    assert 'worker_assessment' not in payload['observations'][0]
    assert state == original


def test_final_audit_cannot_ground_a_legacy_origin_based_hypothesis():
    from src.agents.grounding import audit
    facts = [{'summary': 'Unsigned process started.', 'dfkg_refs': ['e']}]
    state = {'evidence_collection': {'records': [{'uid': 'e'}]}, 'proponent_review': {'hypotheses': [
        {'hypothesis': 'This activity is benign because it is synthetic.', 'observation_ids': [0]}]}}
    response = {'checks': [{'hypothesis_id': 0, 'status': 'grounded', 'observation_ids': [0],
                            'rationale': 'The cited source supports the hypothesis.'}]}
    trace = audit(state, facts, SimpleNamespace(invoke_structured=lambda *args: SimpleNamespace(content=json.dumps(response))))
    assert not trace['grounding_passed'] and not trace['model_output_validated']
    assert 'Fixture provenance cannot establish a behavioral verdict' in trace['grounding_issues']
