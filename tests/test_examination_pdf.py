"""Report content, pagination, evidence boundaries and binary delivery contracts."""
from copy import deepcopy
from hashlib import sha256
from io import BytesIO
from types import SimpleNamespace

from fastapi.testclient import TestClient
from pypdf import PdfReader
import pytest

from src.agents.examination_reports import render_examination_pdf
from src.agents.report_document import report_content
from tests.api_auth_helpers import configure_test_auth


def case():
    return {'case_id': 'C1', 'report_output': 'Original saved report',
            'report_generated_at': '2026-10-27T08:00:00Z',
            'execution_manifest': {'packages': {'example-tool': '1.0'}},
            'ingestion_provenance': {'source': 'uploaded_zip', 'declared_metadata': {
                'synthetic': True, 'expected_attack_story': 'DO-NOT-TREAT-THIS-AS-EVIDENCE'}},
            'evidence_collection': {'case_id': 'C1', 'status': 'complete', 'records': [
                {'uid': 'original-evidence', 'time': '2026-10-20T09:00:00Z', 'class_uid': 1007,
                 'host_name': 'host-a', 'command_line': 'recorded-command',
                 'process_name': '<script>untrusted & quoted</script>'}]},
            'findings': [{'agent_role': 'log_analysis', 'source': 'validated_case_rule',
                          'summary': 'Recorded rule observation', 'dfkg_refs': ['original-evidence']},
                         {'agent_role': 'supervisor_followup', 'source': 'validated_case_rule',
                          'summary': 'FOLLOWUP-IS-NOT-A-DETECTION', 'dfkg_refs': ['original-evidence']},
                         {'agent_role': 'log_analysis', 'summary': 'MODEL-CLAIM', 'dfkg_refs': ['original-evidence']},
                         {'agent_role': 'identity', 'source': 'validated_case_rule',
                          'summary': 'FOREIGN-CLAIM', 'dfkg_refs': ['another-case-event']}],
            'agent_traces': [{'agent_role': 'log_analysis', 'model_used': 'recorded-model',
                              'model_output': 'INTERNAL-MODEL-DUMP'}]}


def extract(document):
    return '\n'.join(p.extract_text() for p in PdfReader(BytesIO(document)).pages)


def test_audiences_differ_and_only_cited_rules_become_observations():
    data = case()
    original = deepcopy(data)
    court, cm = render_examination_pdf(data, 'court')
    technical, tm = render_examination_pdf(data, 'technical')
    ctext, ttext = extract(court), extract(technical)
    assert court.startswith(b'%PDF-') and technical.startswith(b'%PDF-')
    assert cm['document_sha256'] == sha256(court).hexdigest()
    assert tm['document_sha256'] == sha256(technical).hexdigest()
    assert cm['observation_count'] == tm['observation_count'] == 1
    assert 'Examiner declaration' in ctext and 'Examiner declaration' not in ttext
    assert 'Evidence received and integrity' in ctext and 'Evidence received and integrity' not in ttext
    assert 'Detection analysis' in ttext and 'Detection analysis' not in ctext
    assert 'Execution and reproducibility' in ttext and 'Execution and reproducibility' not in ctext
    assert 'recorded-command' in ttext and 'recorded-command' not in ctext
    for value in (ctext, ttext):
        assert 'TEST DATA' in value and 'synthetic validation fixture' in value
        assert 'Recorded rule observation' in value and 'original-evidence' in value
        assert 'E-0001' in value and 'End of report' in value
        for excluded in ['MODEL-CLAIM', 'FOREIGN-CLAIM', 'FOLLOWUP-IS-NOT-A-DETECTION',
                         'INTERNAL-MODEL-DUMP', 'DO-NOT-TREAT-THIS-AS-EVIDENCE']:
            assert excluded not in value
    assert 'UNSIGNED' in ctext and 'NOT CERTIFIED' in ctext
    assert data == original


def test_conflicts_foreign_records_missing_times_and_empty_evidence():
    data = case()
    data['evidence_collection']['case_id'] = None
    data['evidence_collection']['records'] += [
        {'uid': 'foreign', 'case_id': 'C2', 'command_line': 'FOREIGN-COMMAND'},
        {'uid': 'conflict', 'time': 1}, {'uid': 'conflict', 'time': 2},
        {'uid': 'undated', 'command_line': 'undated-command'},
    ]
    pdf, meta = render_examination_pdf(data, 'technical')
    value = extract(pdf)
    assert 'FOREIGN-COMMAND' not in value and 'conflict /' not in value
    assert meta['dfkg_refs'] == ['original-evidence', 'undated']
    assert value.index('recorded-command') < value.index('undated-command')
    assert 'event_time_unavailable' in meta['degraded_flags']
    empty, meta = render_examination_pdf({'case_id': 'empty'}, 'court')
    assert meta['status'] == 'incomplete'
    assert 'No verified case-linked records' in extract(empty)


def test_duplicates_not_counted_and_original_hashes_separate_from_derived():
    data = case()
    data['findings'].append(deepcopy(data['findings'][0]))
    data['ingestion_provenance']['files'] = [{'path': 'original.json', 'sha256': 'a' * 64, 'records': 1}]
    content, meta = report_content(data, 'court')
    assert meta['observation_count'] == 1
    inventory = next(s for s in content['sections'] if s['title'] == 'Original evidence inventory')
    register = next(s for s in content['sections'] if s['title'] == 'Evidence reference register')
    assert inventory['rows'][0][1] == 'a' * 64
    assert register['rows'][0][1] != 'a' * 64


def test_technical_profile_comparisons_require_case_refs_and_verified_corpus():
    data = case()
    data['attribution'] = {'dfkg_refs': ['original-evidence'], 'threat_intel_refs': ['profile:abc'],
                           'candidate_actors': [{'actor_id': 'G-TEST', 'combined_score': .25},
                                                {'actor_id': 'INVALID-SCORE', 'combined_score': float('nan')}]}
    technical, meta = render_examination_pdf(data, 'technical')
    assert 'G-TEST' in extract(technical) and 'INVALID-SCORE' not in extract(technical)
    assert meta['threat_intel_refs'] == ['profile:abc']
    assert 'G-TEST' not in extract(render_examination_pdf(data, 'court')[0])
    data['attribution']['dfkg_refs'].append('foreign')
    assert 'G-TEST' not in extract(render_examination_pdf(data, 'technical')[0])
    data['attribution']['dfkg_refs'] = ['original-evidence']
    data['attribution']['degraded_flags'] = ['corpus_artifacts_unverified']
    assert 'G-TEST' not in extract(render_examination_pdf(data, 'technical')[0])


def test_long_unicode_and_many_events_paginate_without_losing_records():
    data = case()
    data['evidence_collection']['records'] = [
        {'uid': f'uid-{i:03d}', 'time': f'2026-10-20T09:{i % 60:02d}:00Z',
         'host_name': 'café-host', 'command_line': '<tag>&' + 'x' * (4500 if i == 0 else 10)}
        for i in range(80)]
    pdf, meta = render_examination_pdf(data, 'technical')
    reader = PdfReader(BytesIO(pdf))
    value = extract(pdf)
    assert len(reader.pages) > 2 and len(meta['dfkg_refs']) == 80
    assert 'uid-079' in value and 'café-host' in value and '<tag>&' in value
    assert 'End of report' in value
    for i, page in enumerate(reader.pages, 1):
        assert f'Page {i}' in page.extract_text()
        assert float(page.mediabox.width) == pytest.approx(595.276, abs=.01)
    with pytest.raises(ValueError, match='Unknown report type'):
        render_examination_pdf(data, 'other')


def test_api_regenerates_legacy_reports_as_pdf_and_preserves_access_and_finalization(monkeypatch, tmp_path):
    from src.agents import visualizer_api
    data = case()
    data['court_report_output'] = '<html>STALE-LEGACY-REPORT</html>'
    headers = configure_test_auth(monkeypatch, tmp_path, {'test-user': {'role': 'analyst', 'cases': ['C1']}})
    graph = SimpleNamespace(get_state=lambda config: SimpleNamespace(values=data))
    monkeypatch.setattr(visualizer_api, '_specula_graph', graph)
    monkeypatch.setattr(visualizer_api, '_neo4j_driver', None)
    client = TestClient(visualizer_api.app)
    response = client.get('/api/investigations/C1/reports/court', headers=headers)
    assert response.status_code == 200
    assert response.headers['content-type'] == 'application/pdf'
    assert response.headers['content-disposition'].endswith('.pdf"')
    assert response.headers['X-Report-SHA256'] == sha256(response.content).hexdigest()
    assert 'STALE-LEGACY-REPORT' not in extract(response.content)
    assert 'Examiner declaration' in extract(response.content)
    assert client.get('/api/investigations/C1/reports/court').status_code == 401
    assert client.get('/api/investigations/C2/reports/court', headers=headers).status_code == 403
    data['report_output'] = None
    assert client.get('/api/investigations/C1/reports/court', headers=headers).status_code == 409


def test_local_pdf_proxies_container_renderer_and_preserves_binary_and_errors(monkeypatch, tmp_path):
    from scripts import local_boot_api as local
    document, _ = render_examination_pdf(case(), 'court')
    upstream = SimpleNamespace(status_code=200, content=document,
                               headers={'X-Report-Generated-At': '2026-10-27T10:00:00Z', 'X-Report-Status': 'incomplete'})
    calls = []
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, *args, **kwargs):
            calls.append(args[0])
            return upstream
    monkeypatch.setattr(local.requests, 'Session', Session)
    monkeypatch.setattr(local, '_local_token', lambda: 'isolated-test-token')
    monkeypatch.setattr(local, 'ROOT', tmp_path)
    headers = {'Origin': 'http://localhost:5173', 'X-Specula-Local-Boot': '1'}
    client = TestClient(local.app, client=('127.0.0.1', 12345))
    response = client.get('/api/local/cases/LOCAL-example/reports/court', headers=headers)
    assert response.status_code == 200 and response.content == document
    assert calls == ['http://127.0.0.1:8300/api/investigations/LOCAL-example/reports/court']
    assert response.headers['content-type'] == 'application/pdf'
    assert response.headers['X-Report-SHA256'] == sha256(document).hexdigest()
    assert response.headers['X-Report-Generated-At'] == upstream.headers['X-Report-Generated-At']
    assert list((tmp_path / 'data' / 'reports').rglob('*.pdf'))[0].read_bytes() == document
    upstream.status_code = 409
    assert client.get('/api/local/cases/LOCAL-example/reports/court', headers=headers).status_code == 409
    upstream.status_code = 403
    assert client.get('/api/local/cases/LOCAL-example/reports/court', headers=headers).status_code == 403
    upstream.status_code = 200
    upstream.content = b'<html>Not a PDF</html>'
    assert client.get('/api/local/cases/LOCAL-example/reports/court', headers=headers).status_code == 502
