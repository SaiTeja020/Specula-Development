from scripts.evaluate_agent_findings import evaluate
import pytest


def test_saved_observation_evaluation_reports_misses_and_false_alarms():
    snapshot={'case_id':'C','findings':[{'agent_role':'supervisor'},
        {'agent_role':'identity','source':'validated_case_rule','finding_type':'session',
         'classification':'context','dfkg_refs':['s','e']},
        {'agent_role':'network_forensics','source':'validated_case_rule','finding_type':'transfer',
         'classification':'suspicious','dfkg_refs':['backup']}]}
    key={'observations':[{'agent_role':'identity','finding_type':'session','evidence_refs':['s','e']},
        {'agent_role':'memory_forensics','finding_type':'region','evidence_refs':['m']}],
        'negative_controls':[{'agent_role':'network_forensics','finding_type':'transfer','evidence_refs':['backup']}]}
    result=evaluate(snapshot,key)
    assert result['roles']['identity']['observation_recall']==1
    assert result['roles']['memory_forensics']['missed']==1
    assert result['roles']['network_forensics']['negative_control_false_alarm_rate']==1
    assert not result['passed']


@pytest.mark.parametrize('key', [
    {'observations': [{'agent_role': 'identity', 'finding_type': 'session', 'evidence_refs': []}]},
    {'observations': [{'agent_role': 'identity', 'finding_type': 'session', 'evidence_refs': ['s', 's']}]},
    {'observations': [{'agent_role': '', 'finding_type': 'session', 'evidence_refs': ['s']}]},
    {'observations': [{'agent_role': 'identity', 'finding_type': 'session', 'evidence_refs': ['s'],
                       'allowed_classifications': []}]},
    {'observations': [
        {'agent_role': 'identity', 'finding_type': 'session', 'evidence_refs': ['s']},
        {'agent_role': 'identity', 'finding_type': 'session', 'evidence_refs': ['s']},
    ]},
])
def test_malformed_or_duplicated_labels_are_rejected(key):
    with pytest.raises(ValueError):
        evaluate({'case_id': 'C', 'findings': []}, key)


@pytest.mark.parametrize('controls', [
    [None],
    [{'agent_role': 'network', 'evidence_refs': []}],
    [{'agent_role': 'network', 'evidence_refs': ['x', None]}],
    [{'agent_role': 'network', 'evidence_refs': ['x'], 'finding_type': ''}],
])
def test_malformed_negative_controls_are_rejected(controls):
    with pytest.raises(ValueError):
        evaluate({'case_id': 'C', 'findings': []}, {
            'observations': [{'agent_role': 'identity', 'finding_type': 'session', 'evidence_refs': ['s']}],
            'negative_controls': controls,
        })


@pytest.mark.parametrize('snapshot,key', [
    ([], {'observations': [{'agent_role': 'a', 'finding_type': 'b', 'evidence_refs': ['x']}]}),
    ({'findings': []}, []),
])
def test_non_object_inputs_are_rejected(snapshot, key):
    with pytest.raises(ValueError):
        evaluate(snapshot, key)


@pytest.mark.parametrize('malformed_refs', [None, 'evidence', [None], [[]]])
def test_malformed_snapshot_finding_refs_are_ignored(malformed_refs):
    snapshot={'case_id':'C','findings':[{'agent_role':'identity','source':'validated_case_rule',
        'finding_type':'session','classification':'context','dfkg_refs':malformed_refs}]}
    key={'observations':[{'agent_role':'identity','finding_type':'session','evidence_refs':['e1']}]}
    assert not evaluate(snapshot,key)['passed']


@pytest.mark.parametrize('controls', [None, {}, 'bad'])
def test_negative_controls_must_be_a_list(controls):
    with pytest.raises(ValueError, match='negative_controls'):
        evaluate({'case_id':'C','findings':[]}, {
            'observations':[{'agent_role':'identity','finding_type':'session','evidence_refs':['e1']}],
            'negative_controls':controls,
        })


def test_duplicate_negative_controls_are_rejected():
    control={'agent_role':'network','finding_type':'transfer','evidence_refs':['e1']}
    with pytest.raises(ValueError, match='Duplicate negative control'):
        evaluate({'case_id':'C','findings':[]}, {
            'observations':[{'agent_role':'identity','finding_type':'session','evidence_refs':['e1']}],
            'negative_controls':[control,control],
        })
