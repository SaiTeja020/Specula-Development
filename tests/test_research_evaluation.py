"""Controls for independent denominators, label leakage and CLI receipts."""
from copy import deepcopy
import json
import subprocess
import sys

import pytest

from scripts.evaluate_research import (
    compression_metrics, digest, planted_case, replay, score_claims,
)


def claim_inputs():
    evidence = {'case_id': 'A', 'uids': ['a'],
                'entities': [{'type': 'ip', 'value': '192.0.2.1'}]}
    report = {'case_id': 'A', 'claims': [
        {'id': 'c1', 'text': 'Source observed an address', 'dfkg_refs': ['a'],
         'entities': [{'type': 'ip', 'value': '192.0.2.1'}]},
        {'id': 'c2', 'text': 'Unverified foreign address', 'dfkg_refs': ['foreign'],
         'entities': [{'type': 'ip', 'value': '198.51.100.2'}]},
    ]}
    return evidence, report


def test_case_citations_entities_and_support_are_separate():
    evidence, report = claim_inputs()
    original = deepcopy(report)
    score = score_claims(evidence, report)
    assert score['citation_validity'] == 0.5
    assert score['fabricated_entity_rate'] == 0.5
    assert score['unsupported_claim_rate'] is None
    assert score['annotation_coverage'] == 0
    partial = score_claims(evidence, report, {'case_id': 'A', 'support': {'c1': True}})
    assert partial['unsupported_claim_rate'] is None
    full = score_claims(evidence, report, {'case_id': 'A', 'support': {'c1': True, 'c2': False}})
    assert full['unsupported_claim_rate'] == 0.5
    assert report == original


def test_valid_citation_does_not_imply_entailment():
    evidence, report = claim_inputs()
    report['claims'][1]['dfkg_refs'] = ['a']
    result = score_claims(evidence, report, {'case_id': 'A', 'support': {'c1': False, 'c2': False}})
    assert result['citation_validity'] == 1
    assert result['unsupported_claim_rate'] == 1


def test_empty_denominators_and_uncited_claims():
    evidence, report = claim_inputs()
    report['claims'] = []
    result = score_claims(evidence, report)
    assert all(result[k] is None for k in ('citation_validity', 'fabricated_entity_rate',
                                         'unsupported_claim_rate', 'annotation_coverage'))
    report['claims'] = [{'id': 'c', 'text': 'No citation', 'dfkg_refs': [], 'entities': []}]
    assert score_claims(evidence, report)['uncited_claim_count'] == 1


@pytest.mark.parametrize('mutation', [
    lambda e, r: r.update(case_id='B'),
    lambda e, r: e.update(uids=['a', 'a']),
    lambda e, r: r['claims'].append(deepcopy(r['claims'][0])),
    lambda e, r: r['claims'][0].update(dfkg_refs='a'),
    lambda e, r: r['claims'][0].update(entities=[{'type': 'ip'}]),
    lambda e, r: r['claims'][0].update(text=''),
])
def test_malformed_claim_artifacts_fail_closed(mutation):
    evidence, report = claim_inputs()
    mutation(evidence, report)
    with pytest.raises(ValueError):
        score_claims(evidence, report)


@pytest.mark.parametrize('annotations', [
    {'case_id': 'B', 'support': {}},
    {'case_id': 'A', 'support': {'unknown': False}},
    {'case_id': 'A', 'support': {'c1': 'true'}},
    {'case_id': 'A', 'support': {'c2': True}},
])
def test_invalid_annotations_rejected(annotations):
    with pytest.raises(ValueError):
        score_claims(*claim_inputs(), annotations)


def test_generator_is_repeatable_and_truth_is_not_an_input_flag():
    events, gold = planted_case(7, 100, 6)
    assert (events, gold) == planted_case(7, 100, 6)
    assert digest(events) != digest(planted_case(8, 100, 6)[0])
    assert len({e['uid'] for e in events}) == 106
    assert all('is_anomalous' not in e and 'gold' not in e for e in events)
    assert len(gold) == 6
    with pytest.raises(ValueError):
        planted_case(routine=0)


def test_summary_uid_is_not_content_retention_and_bytes_are_utf8():
    from src.ingestion.abstraction.entropy_clusterer import CompactUIDList
    events = [{'uid': 'a', 'command_line': 'é'}, {'uid': 'b', 'command_line': 'needle'}]
    output = [{'is_summary': True, 'source_uids': CompactUIDList(['a', 'b'])}]
    result = compression_metrics(events, output, [{'uid': 'b', 'entity': 'needle'}])
    assert result['anomaly_retention'] == result['entity_retention'] == 0
    assert result['input_bytes'] == len(json.dumps(events, sort_keys=True, separators=(',', ':'),
                                                 ensure_ascii=False).encode('utf-8'))
    # UID alone still does not retain the entity text.
    result = compression_metrics(events, [{'uid': 'b'}], [{'uid': 'b', 'entity': 'needle'}])
    assert result['anomaly_retention'] == 1 and result['entity_retention'] == 0


def test_real_compressor_replay_is_deterministic_except_elapsed_time():
    first, second = replay(9, 60, 6), replay(9, 60, 6)
    assert first['results']['identity']['anomaly_retention'] == 1
    assert first['results']['identity']['entity_retention'] == 1
    assert first['results']['identity']['byte_reduction'] == 0
    assert first['results']['drain3_template_only']['anomaly_retention'] == 0
    for result in (first, second):
        for metrics in result['results'].values():
            assert metrics.pop('elapsed_seconds') >= 0
    assert first == second


def test_claim_cli_writes_hashed_receipt_and_rejects_bad_input(tmp_path):
    paths = [tmp_path / 'evidence.json', tmp_path / 'report.json']
    for path, value in zip(paths, claim_inputs()):
        path.write_text(json.dumps(value), encoding='utf-8')
    output = tmp_path / 'score.json'
    command = [sys.executable, 'scripts/evaluate_research.py', 'claims',
               *map(str, paths), '--output', str(output)]
    run = subprocess.run(command, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    result = json.loads(output.read_text(encoding='utf-8'))
    assert len(result['input_sha256']['evidence']) == 64
    assert result['provenance']['harness_sha256']
    paths[1].write_text('{broken', encoding='utf-8')
    run = subprocess.run(command, capture_output=True, text=True)
    assert run.returncode == 2 and 'Evaluation input/error' in run.stderr
    collision = command[:-1] + [str(paths[0])]
    run = subprocess.run(collision, capture_output=True, text=True)
    assert run.returncode == 2 and 'must not overwrite' in run.stderr
