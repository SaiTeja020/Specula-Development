"""Evaluate saved observations against a separately maintained, held-out answer key."""
import argparse
import json
from pathlib import Path


def _required_text(item, field, context):
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{context} requires non-empty {field}')
    return value.strip()


def _evidence_refs(item, context):
    refs = item.get('evidence_refs')
    if not isinstance(refs, list) or not refs:
        raise ValueError(f'{context} requires a non-empty evidence_refs list')
    if any(not isinstance(ref, str) or not ref.strip() for ref in refs):
        raise ValueError(f'{context} evidence_refs must contain non-empty strings')
    if len(refs) != len(set(refs)):
        raise ValueError(f'{context} evidence_refs must not contain duplicates')
    return set(refs)


def _finding_refs(finding):
    refs = finding.get('dfkg_refs')
    if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref.strip() for ref in refs):
        return None
    return set(refs)


def evaluate(snapshot,answer_key):
    if not isinstance(snapshot, dict) or not isinstance(answer_key, dict):
        raise ValueError('Snapshot and answer key must be JSON objects')
    from src.agents.case_analysis import current_findings
    raw_findings = current_findings(snapshot)
    if not isinstance(raw_findings, list):
        raise ValueError('Snapshot findings must be a list')
    findings=[f for f in raw_findings if isinstance(f, dict) and f.get('source')=='validated_case_rule']
    expected=answer_key.get('observations')
    if not isinstance(expected, list) or not expected:
        raise ValueError('Answer key requires independently labelled observations')
    controls=answer_key.get('negative_controls', [])
    if not isinstance(controls, list):
        raise ValueError('negative_controls must be a list')
    by_role={};results=[]
    seen_labels=set();seen_controls=set()
    for label in expected:
        if not isinstance(label, dict):
            raise ValueError('Every observation label must be an object')
        role=_required_text(label, 'agent_role', 'Observation label')
        kind=_required_text(label, 'finding_type', 'Observation label')
        refs=_evidence_refs(label, 'Observation label')
        label_key=(role, kind, tuple(sorted(refs)))
        if label_key in seen_labels:
            raise ValueError('Duplicate observation label')
        seen_labels.add(label_key)
        allowed=label.get('allowed_classifications',['suspicious','unresolved','context'])
        if not isinstance(allowed, list) or not allowed or any(not isinstance(x,str) or not x.strip() for x in allowed):
            raise ValueError('allowed_classifications must be a non-empty list of strings')
        matching=[f for f in findings if f.get('agent_role')==role and f.get('finding_type')==kind
                  and (finding_refs:=_finding_refs(f)) is not None and refs<=finding_refs]
        passed=any(f.get('classification') in allowed for f in matching)
        metrics=by_role.setdefault(role,{'expected':0,'matched':0,'missed':0,'negative_controls':0,'false_alarms':0})
        metrics['expected']+=1;metrics['matched']+=passed;metrics['missed']+=not passed
        results.append({'agent_role':role,'finding_type':kind,'evidence_refs':sorted(refs),'passed':passed})
    for control in controls:
        if not isinstance(control, dict):
            raise ValueError('Every negative control must be an object')
        role=_required_text(control, 'agent_role', 'Negative control')
        refs=_evidence_refs(control, 'Negative control')
        kind=control.get('finding_type')
        if kind is not None and (not isinstance(kind,str) or not kind.strip()):
            raise ValueError('Negative control finding_type must be a non-empty string when supplied')
        control_key=(role, kind, tuple(sorted(refs)))
        if control_key in seen_controls:
            raise ValueError('Duplicate negative control')
        seen_controls.add(control_key)
        alarms=[f for f in findings if f.get('agent_role')==role and
                f.get('classification')=='suspicious' and
                (finding_refs:=_finding_refs(f)) is not None and refs<=finding_refs and
                (not kind or f.get('finding_type')==kind)]
        metrics=by_role.setdefault(role,{'expected':0,'matched':0,'missed':0,'negative_controls':0,'false_alarms':0})
        metrics['negative_controls']+=1;metrics['false_alarms']+=bool(alarms)
    for metrics in by_role.values():
        metrics['observation_recall']=metrics['matched']/metrics['expected'] if metrics['expected'] else None
        metrics['negative_control_false_alarm_rate']=metrics['false_alarms']/metrics['negative_controls'] if metrics['negative_controls'] else None
    return {'case_id':snapshot.get('case_id'),'roles':by_role,'results':results,
        'passed':all(r['passed'] for r in results) and not any(m['false_alarms'] for m in by_role.values()),
        'scope':'Metrics apply only to these supplied independent labels. They are not general detection accuracy, actor calibration or admissibility validation.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot');parser.add_argument('answer_key');parser.add_argument('--output')
    args=parser.parse_args()
    result=evaluate(json.loads(Path(args.snapshot).read_text(encoding='utf-8')),
                    json.loads(Path(args.answer_key).read_text(encoding='utf-8')))
    text=json.dumps(result,indent=2)
    if args.output:Path(args.output).write_text(text,encoding='utf-8')
    print(text)
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
