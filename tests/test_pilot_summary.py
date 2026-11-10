"""Ensure diagnostic coverage never becomes an invented grounding score."""
import json
import csv

from scripts import summarize_evaluation_pilot as pilot


def test_missing_event_and_foreign_citation_remain_visible(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, 'ROOT', tmp_path)
    live = tmp_path / 'live'
    live.mkdir()
    state = {'case_id': 'LOCAL-test', 'paused_at': ['hitl'], 'failed_nodes': [],
             'evidence_collection': {'records': [
                 {'uid': 'normalized-1', 'unmapped': {'source_context': {'record_id': 'raw-1'}}}]},
             'timeline': {'events': [{'uid': 'normalized-1'}]},
             'agent_traces': [{'agent_role': 'critic', 'dfkg_refs': ['foreign-uid'],
                               'model_output_validated': False}]}
    inputs = {
        live / 'case-001-snapshot.json': state,
        live / 'case-001-run.json': {'job': {'phase': 'complete'}},
        tmp_path / 'case-001-answer-key.json': {
            'events': {'raw-1': {}, 'raw-2': {}},
            'comparable_recorded_time_pairs': [['raw-1', 'raw-2']]},
    }
    for path, value in inputs.items():
        path.write_text(json.dumps(value), encoding='utf-8')
    (tmp_path / 'runs.csv').write_text(
        'case_id,configuration,repeat,status,event_tp\n'
        'case-001,specula,1,not_run,\n'
        'case-001,single-agent-rag,1,not_run,\n', encoding='utf-8')
    pilot.main()
    result = json.loads((live / 'summary.json').read_text())['cases'][0]
    assert result['missing_source_records'] == ['raw-2']
    assert result['timeline_source_record_coverage'] == 0.5
    assert result['recorded_time_pair_accuracy'] == 0
    assert result['invalid_trace_citations'] == ['foreign-uid']
    assert result['unvalidated_model_roles'] == ['critic']
    assert result['independent_unsupported_claim_rate'] is None
    assert result['independent_citation_support_precision'] is None
    with (tmp_path / 'runs.csv').open(newline='', encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]['actual_case_id'] == 'LOCAL-test'
    assert rows[0]['event_tp'] == ''
    assert rows[1]['status'] == 'not_run'
    assert rows[1]['actual_case_id'] == ''
