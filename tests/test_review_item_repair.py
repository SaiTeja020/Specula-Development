"""Coverage repair preserves validated items without relaxing source checks."""
import json
from types import SimpleNamespace
import pytest

from src.agents.evidence_review import debate
from src.agents.investigative_review import investigate


def assessment(index, explanation='The source reports an unresolved observation.'):
    return {'observation_id': index, 'disposition': 'insufficient_context',
            'explanation': explanation, 'limitations': 'Independent examination is unavailable.',
            'next_action': 'Review the preserved source artifact.'}


def hypothesis(ids, text='Source observations require independent corroboration.'):
    return {'kind': 'unresolved', 'hypothesis': text, 'observation_ids': ids,
            'limitations': 'The source does not establish malicious intent.'}


def model(responses):
    pending = iter(responses)
    calls = []
    def invoke(prompt, schema):
        calls.append((prompt, schema))
        return SimpleNamespace(content=json.dumps(next(pending)))
    return SimpleNamespace(invoke_structured=invoke, model_name='repair-test'), calls


def facts(count):
    return [{'summary': f'Source observation {i}', 'dfkg_refs': [f'e{i}'],
             'classification': 'unresolved'} for i in range(count)]


def test_memory_duplicate_ids_repair_only_conflicts_and_preserve_valid_rows():
    # Same ID sequence as the captured memory-review failure.
    llm, calls = model([
        {'assessments': [assessment(i) for i in [0, 1, 2, 3, 0, 1]]},
        {'assessments': [assessment(0), assessment(1)]},
    ])
    trace = investigate('memory_forensics', {}, facts(4), llm)
    assert trace['model_output_validated']
    assert len(calls) == 2
    assert [a['observation_id'] for a in trace['investigation_assessments']] == [0, 1, 2, 3]
    for (_, schema), expected in zip(calls, [[0, 1, 2, 3], [0, 1]]):
        assert schema['$defs']['Assessment']['properties']['observation_id']['enum'] == expected
        assert schema['properties']['assessments']['minItems'] == len(expected)
        assert schema['properties']['assessments']['maxItems'] == len(expected)
    assert trace['review_batches'][0]['attempts'][0]['pending_ids'] == [0, 1]


def test_specialist_exhaustion_retains_partial_coverage_without_completion():
    llm, calls = model([{'assessments': [assessment(0)]}, {'assessments': [assessment(99)]}])
    trace = investigate('memory_forensics', {}, facts(2), llm)
    assert len(calls) == 2 and not trace['model_output_validated']
    assert trace['review_coverage']['validated'] == 1
    assert [a['observation_id'] for a in trace['investigation_assessments']] == [0]


def test_proponent_repairs_omission_without_regenerating_valid_hypothesis():
    kept = hypothesis([0])
    llm, calls = model([{'hypotheses': [kept]}, {'hypotheses': [hypothesis([1])]}])
    result, trace = debate('proponent', {}, facts(2), llm)
    assert trace['model_output_validated'] and result['hypotheses'][0] == kept
    assert len(calls) == 2 and len(result['hypotheses']) == 2
    payload = json.loads(calls[1][0].split('Return JSON only.\n', 1)[1].split('\nRequired JSON schema:')[0])
    assert payload['required_observation_ids'] == [1]
    assert trace['review_coverage']['validated'] == 2


def test_proponent_missing_ids_and_unsafe_claims_cannot_create_complete_review():
    bad = hypothesis([1], 'Confirmed compromise was established.')
    llm, calls = model([{'hypotheses': [hypothesis([0]), bad]}, {'hypotheses': [bad]}])
    result, trace = debate('proponent', {}, facts(2), llm)
    assert result is None and not trace['model_output_validated']
    assert len(calls) == 2 and trace['review_coverage']['validated'] == 1
    assert trace['review_batches'][0]['retained_items'] == [hypothesis([0])]


@pytest.mark.parametrize('bad', [
    {'assessments': [assessment(1), assessment(99)]},
    {'assessments': [assessment(True)]},
    {'assessments': [assessment(1)], 'extra': 'not permitted'},
    {'assessments': [assessment(1, 'Confirmed compromise was established.')]},
])
def test_specialist_bad_repair_never_replaces_validated_output(bad):
    original = assessment(0)
    llm, calls = model([{'assessments': [original]}, bad])
    trace = investigate('memory_forensics', {}, facts(2), llm)
    assert len(calls) == 2 and not trace['model_output_validated']
    assert trace['review_coverage']['validated'] == 1
    assert trace['investigation_assessments'] == [{**original, 'dfkg_refs': ['e0']}]


def test_proponent_competing_explanations_can_share_observations():
    alternatives = [hypothesis([0], 'First possible source explanation needs corroboration.'),
                    hypothesis([0], 'A different source explanation remains plausible.')]
    llm, calls = model([{'hypotheses': alternatives}])
    result, trace = debate('proponent', {}, facts(1), llm)
    assert len(calls) == 1 and trace['model_output_validated']
    assert result['hypotheses'] == alternatives


def test_proponent_duplicate_citations_require_correction():
    llm, calls = model([{'hypotheses': [hypothesis([0, 0])]}, {'hypotheses': [hypothesis([0])]}])
    result, trace = debate('proponent', {}, facts(1), llm)
    assert len(calls) == 2 and trace['model_output_validated']
    assert result['hypotheses'] == [hypothesis([0])]


def test_truncated_model_response_cannot_confer_partial_credit():
    count = 0
    def invoke(*args):
        nonlocal count
        count += 1
        return SimpleNamespace(content=json.dumps({'assessments': [assessment(0)]}),
                               response_metadata={'done_reason': 'length'})
    trace = investigate('memory_forensics', {}, facts(1), SimpleNamespace(invoke_structured=invoke))
    assert count == 2 and not trace['model_output_validated']
    assert trace['review_coverage']['validated'] == 0


def test_repair_cannot_overwrite_an_earlier_validated_assessment():
    kept = assessment(0)
    llm, calls = model([
        {'assessments': [kept]},
        {'assessments': [assessment(0, 'A replacement explanation must never overwrite the first.'), assessment(1)]},
    ])
    trace = investigate('memory_forensics', {}, facts(2), llm)
    assert len(calls) == 2 and not trace['model_output_validated']
    assert trace['investigation_assessments'] == [{**kept, 'dfkg_refs': ['e0']}]


def test_specialist_global_ids_remain_stable_across_original_batches():
    llm, calls = model([
        {'assessments': [assessment(i) for i in range(6)]},
        {'assessments': [assessment(0), assessment(1)]},
        {'assessments': [assessment(6), assessment(7)]},
    ])
    trace = investigate('memory_forensics', {}, facts(8), llm)
    assert len(calls) == 3 and trace['model_output_validated']
    assert trace['review_coverage']['validated'] == 8
    assert calls[-1][1]['$defs']['Assessment']['properties']['observation_id']['enum'] == [6, 7]


def test_aggregate_hypothesis_budget_cannot_be_exceeded_by_repair():
    kept = [hypothesis([0], f'Possible explanation {i} still requires source corroboration.') for i in range(6)]
    llm, calls = model([{'hypotheses': kept}, {'hypotheses': [hypothesis([1])]}])
    result, trace = debate('proponent', {}, facts(2), llm)
    assert len(calls) == 2 and result is None
    assert trace['review_coverage']['validated'] == 1
    assert trace['review_batches'][0]['retained_items'] == kept
    assert 'six-item budget' in trace['review_attempts'][-1]['error']


def test_context_budget_stops_before_any_model_request():
    def forbidden(*args):
        raise AssertionError('Oversized input must not reach the model')
    rows = facts(1)
    rows[0]['summary'] = 'x' * 25000
    trace = investigate('memory_forensics', {}, rows, SimpleNamespace(invoke_structured=forbidden))
    assert not trace['model_output_validated']
    assert trace['review_batches'][0]['attempts'][0]['attempt'] == 0
