"""Check saved pilot outputs against source records, without claiming entailment."""
from collections import Counter
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'output' / 'evaluation-pilot'


def main():
    summaries = []
    for path in sorted((ROOT / 'live').glob('case-*-snapshot.json')):
        name = path.name.removesuffix('-snapshot.json')
        state = json.loads(path.read_text(encoding='utf-8'))
        run = json.loads((ROOT / 'live' / f'{name}-run.json').read_text())
        key = json.loads((ROOT / f'{name}-answer-key.json').read_text())
        events = (state.get('evidence_collection') or {}).get('records', [])
        inventory = {}
        for event in events:
            context = event.get('unmapped') or {}
            if isinstance(context, str):
                context = json.loads(context)
            source = context.get('source_context') or {}
            inventory[event['uid']] = source.get('record_id')
        expected = set(key['events'])
        mapped = set(inventory.values()) - {None}
        known = set(inventory)
        traces = state.get('agent_traces') or []
        invalid = sorted({uid for trace in traces for uid in trace.get('dfkg_refs', [])
                          if uid not in known})
        timeline = (state.get('timeline') or {}).get('events', [])
        positions = {inventory.get(event.get('uid')): i for i, event in enumerate(timeline)}
        pairs = key['comparable_recorded_time_pairs']
        correct = sum(a in positions and b in positions and positions[a] < positions[b] for a, b in pairs)
        dispositions = Counter(a.get('disposition') for t in traces
                               for a in t.get('investigation_assessments', []))
        summary = {
            'fixture': name, 'case_id': state.get('case_id'),
            'job_phase': run.get('job', {}).get('phase'),
            'case_status': state.get('case_status'), 'paused_at': state.get('paused_at'),
            'judge_verdict': state.get('judge_verdict'),
            'final_report_present': bool(state.get('report_output')),
            'elapsed_to_job_terminal_seconds': run.get('elapsed_to_job_terminal_seconds'),
            'expected_source_records': len(expected), 'collected_events': len(events),
            'mapped_source_records': len(mapped & expected),
            'missing_source_records': sorted(expected - mapped),
            'unexpected_source_records': sorted(mapped - expected),
            'uid_to_source_record': inventory,
            'timeline_events': len(timeline),
            'timeline_source_record_coverage': len(set(positions) & expected) / len(expected),
            'correct_recorded_time_pairs': correct, 'comparable_recorded_time_pairs': len(pairs),
            'recorded_time_pair_accuracy': correct / len(pairs) if pairs else None,
            'trace_count': len(traces), 'failed_nodes': state.get('failed_nodes'),
            'invalid_trace_citations': invalid,
            'unvalidated_model_roles': [t['agent_role'] for t in traces
                                        if t.get('model_output_validated') is False],
            'review_validation_errors': [
                {'role': t['agent_role'], 'observation_ids': batch.get('observation_ids'),
                 'attempt': attempt.get('attempt'), 'error': attempt['error']}
                for t in traces for batch in t.get('review_batches', [])
                for attempt in batch.get('attempts', []) if attempt.get('error')],
            'model_assessment_dispositions': dict(dispositions),
            'roles': [{'role': t['agent_role'], 'model': t.get('model_used'),
                       'latency_ms': t.get('latency_ms'),
                       'review_coverage': t.get('review_coverage')} for t in traces],
            'independent_unsupported_claim_rate': None,
            'independent_citation_support_precision': None,
            'scope': 'Developer-authored synthetic source mapping and recorded chronology only; '
                     'no semantic event F1, correlation F1, entailment or final-report latency claim.',
        }
        summaries.append(summary)
        print(name, summary['case_status'], 'mapped', summary['mapped_source_records'], '/', len(expected),
              'timeline', len(timeline), 'pairs', f'{correct}/{len(pairs)}',
              'failed', summary['failed_nodes'], 'invalid citations', len(invalid))
    result = {'configurations_run': ['specula'], 'cases': summaries,
              'baseline_comparison': 'not run', 'independent_annotations': 'pending'}
    (ROOT / 'live' / 'summary.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    worksheet = ROOT / 'runs.csv'
    if worksheet.exists():
        with worksheet.open(newline='', encoding='utf-8') as handle:
            reader = csv.DictReader(handle)
            fields, rows = list(reader.fieldnames), list(reader)
        for field in ('actual_case_id', 'observed_to_job_terminal_seconds', 'snapshot_path', 'judge_verdict'):
            if field not in fields:
                fields.append(field)
        for summary in summaries:
            for row in rows:
                if (row['case_id'] == summary['fixture'] and row['configuration'] == 'specula'
                        and row['repeat'] == '1'):
                    row.update(status=summary['case_status'] or summary['job_phase'],
                               actual_case_id=summary['case_id'],
                               observed_to_job_terminal_seconds=summary['elapsed_to_job_terminal_seconds'],
                               snapshot_path=f"live/{summary['fixture']}-snapshot.json",
                               judge_verdict=summary['judge_verdict'])
        with worksheet.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)


if __name__ == '__main__':
    main()
