"""CAPE protocol emulator tests: actual HTTP; no guest and no sample execution."""
from copy import deepcopy
from dataclasses import replace
from email import policy
from email.parser import BytesParser
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Thread
from types import SimpleNamespace
from zipfile import ZipFile

import pytest
import requests
from fastapi.testclient import TestClient

from src.agents import cape_sandbox as cape
from tests.test_independent_forensic_tools import sample_pe


@pytest.fixture
def endpoint():
    lab = SimpleNamespace(posts=0, gets=[], status='reported', changes={}, form={}, sample=None,
                          token='test_cape_token_0123456789', submit_ids=[7], response_status=200,
                          report_changes={}, report_bytes=None)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, body, status=200):
            raw = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            assert self.path == '/apiv2/tasks/create/file/'
            assert self.headers['Authorization'] == 'Token ' + lab.token
            lab.posts += 1
            data = self.rfile.read(int(self.headers['Content-Length']))
            message = BytesParser(policy=policy.default).parsebytes(
                ('Content-Type: ' + self.headers['Content-Type'] + '\r\nMIME-Version: 1.0\r\n\r\n').encode() + data)
            for part in message.iter_parts():
                name = part.get_param('name', header='content-disposition')
                content = part.get_payload(decode=True)
                if name == 'file':
                    lab.sample = content
                    lab.filename = part.get_filename()
                else:
                    lab.form[name] = content.decode()
            self.send({'error': [], 'errors': [], 'data': {'task_ids': lab.submit_ids}}, lab.response_status)

        def do_GET(self):
            assert self.headers['Authorization'] == 'Token ' + lab.token
            lab.gets.append(self.path)
            if self.path == '/apiv2/tasks/view/7/':
                self.send({'error': False, 'data': {'id': 7, 'category': 'file', 'status': lab.status,
                    'custom': lab.form['custom'], 'machine': 'win-lab', 'route': 'drop',
                    'sample': {'sha256': sha256(lab.sample).hexdigest()}, **lab.changes}})
            elif self.path == '/apiv2/tasks/get/report/7/json/':
                self.send(lab.report_bytes or report(lab), lab.response_status)
            else:
                self.send({'error': True}, 404)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    lab.config = cape.CapeConfig(f'http://127.0.0.1:{server.server_port}/apiv2', lab.token, 'win-lab', wait_seconds=0)
    yield lab
    server.shutdown()
    server.server_close()
    thread.join(2)


def report(lab):
    result = {'info': {'id': 7, 'custom': lab.form['custom'], 'machine': {'name': 'win-lab'},
                       'category': 'file', 'route': 'drop', 'version': 'emulated-contract',
                       'CAPE_current_commit': 'not-a-real-cape-runtime', 'package': 'exe', 'timeout': True,
                       'started': '2026-10-15 10:00:00', 'ended': '2026-10-15 10:02:00'},
              'target': {'file': {'sha256': sha256(lab.sample).hexdigest()}},
              'behavior': {'processes': [{'process_id': 42, 'parent_id': 1, 'process_path': 'C:\\sample.exe'}],
                           'summary': {key: [] for key in ('file_created', 'file_written', 'file_deleted', 'regkey_written', 'mutex')}},
              'network': {key: [] for key in ('dns', 'tcp', 'udp', 'http')}, 'signatures': [], 'dropped': [], 'debug': {'errors': []}}
    result.update(deepcopy(lab.report_changes))
    return result


def execute(endpoint, tmp_path, **kwargs):
    return cape.run_sample(endpoint.config, cape.CapeStore(tmp_path / 'cape.sqlite3'), sample_pe(), 'C1', ['e'], **kwargs)


def test_real_http_v2_submission_poll_report_hash_and_cached_replay(endpoint, tmp_path):
    receipt = execute(endpoint, tmp_path)
    assert receipt['status'] == 'complete' and receipt['cape_task_id'] == 7
    assert endpoint.posts == 1 and endpoint.sample == sample_pe()
    assert endpoint.form == {'machine': 'win-lab', 'platform': 'windows', 'timeout': '120',
        'custom': 'specula:' + receipt['uid'], 'memory': '0', 'route': 'drop', 'options': '', 'priority': '1'}
    assert endpoint.filename == sha256(sample_pe()).hexdigest() + '.exe'
    store = cape.CapeStore(tmp_path / 'cape.sqlite3')
    raw = store.report('C1', receipt['uid'])
    assert sha256(raw).hexdigest() == receipt['report_sha256']
    assert json.loads(raw)['info']['id'] == 7
    assert receipt['observations']['processes'][0]['process_id'] == '42'
    assert receipt['cape_version'] == 'emulated-contract' and receipt['analysis_timeout_reached'] is True
    count = len(endpoint.gets)
    assert execute(endpoint, tmp_path)['report_sha256'] == receipt['report_sha256']
    assert endpoint.posts == 1 and len(endpoint.gets) == count
    assert endpoint.token not in json.dumps(receipt) and endpoint.token not in repr(endpoint.config)


def test_pending_resume_reuses_task_after_new_store_instance(endpoint, tmp_path):
    endpoint.status = 'running'
    receipt = execute(endpoint, tmp_path)
    assert receipt['status'] == 'pending' and 'observations' not in receipt
    endpoint.status = 'reported'
    assert execute(endpoint, tmp_path)['status'] == 'complete'
    assert endpoint.posts == 1


@pytest.mark.parametrize('changes', [
    {'id': 8}, {'sample': {'sha256': 'a' * 64}}, {'custom': 'other-case'},
    {'machine': 'other-guest'}, {'category': 'url'}, {'route': 'internet'}])
def test_wrong_task_sample_case_machine_category_or_route_never_yields_facts(endpoint, tmp_path, changes):
    endpoint.changes = changes
    receipt = execute(endpoint, tmp_path)
    assert receipt['status'] == 'pending' and 'report_sha256' not in receipt
    assert not any('get/report' in path for path in endpoint.gets)


@pytest.mark.parametrize('changes', [
    {'target': {'file': {'sha256': 'a' * 64}}},
    {'info': {'id': 8, 'custom': 'other'}}, {'info': {'id': 7}}, {'target': []}])
def test_wrong_report_identity_is_not_accepted(endpoint, tmp_path, changes):
    endpoint.report_changes = changes
    receipt = execute(endpoint, tmp_path)
    assert receipt['status'] == 'pending' and 'observations' not in receipt


def test_failed_analysis_is_durable_and_not_benign(endpoint, tmp_path):
    endpoint.status = 'failed_analysis'
    receipt = execute(endpoint, tmp_path)
    assert receipt['status'] == 'failed'
    assert 'not a benign' in receipt['limitation']
    assert execute(endpoint, tmp_path)['status'] == 'failed' and endpoint.posts == 1


@pytest.mark.parametrize('ids', [[], [7, 8], [True], ['7']])
def test_ambiguous_submission_is_not_repeated(endpoint, tmp_path, ids):
    endpoint.submit_ids = ids
    receipt = execute(endpoint, tmp_path)
    assert receipt['status'] == 'submission_unknown'
    assert execute(endpoint, tmp_path)['status'] == 'submission_unknown'
    assert endpoint.posts == 1


def test_network_exception_never_leaks_token_or_resubmits(tmp_path):
    class Client:
        def submit(self, *args):
            raise requests.Timeout('secret_api_token and arbitrary source text')
    config = cape.CapeConfig('https://lab.invalid/apiv2', 'secret_api_token', 'win-lab')
    store = cape.CapeStore(tmp_path / 'cape.sqlite3')
    receipt = cape.run_sample(config, store, sample_pe(), 'C1', ['e'], client=Client())
    assert 'secret_api_token' not in json.dumps(receipt)
    assert cape.run_sample(config, store, sample_pe(), 'C1', ['e'], client=object())['status'] == 'submission_unknown'


def test_per_case_and_machine_configuration_do_not_share_submissions(endpoint, tmp_path):
    one = execute(endpoint, tmp_path)
    two = cape.run_sample(endpoint.config, cape.CapeStore(tmp_path / 'cape.sqlite3'), sample_pe(), 'C2', ['e2'])
    assert one['uid'] != two['uid'] and endpoint.posts == 2
    with pytest.raises(FileNotFoundError):
        cape.CapeStore(tmp_path / 'cape.sqlite3').report('C2', one['uid'])


def test_projection_bounds_missing_coverage_errors_and_no_benign_inference(endpoint, tmp_path):
    endpoint.report_changes = {'behavior': {'processes': [], 'summary': {}},
        'network': {'dns': [{'request': 'test.invalid'}] * 21}, 'debug': {'errors': ['monitor failed']}}
    receipt = execute(endpoint, tmp_path)
    assert receipt['status'] == 'partial' and receipt['analysis_errors_present']
    assert receipt['coverage']['dns'] == {'status': 'partial', 'total': 21, 'returned': 20}
    assert receipt['coverage']['tcp']['status'] == 'unavailable'
    fact = cape.findings([receipt])[0]
    assert fact['classification'] == 'unresolved' and fact['canonical_host_id'] is None
    assert fact['event_time'] is None and fact['effect_scope'] == 'sandbox_execution'


def test_unknown_or_clipped_projection_fields_never_hide_partial_coverage(endpoint, tmp_path):
    endpoint.report_changes = {'network': {'dns': [{'unknown': 'not parsed'}], 'http': [{'uri': 'x'*501}],
                                           'tcp': [], 'udp': []}}
    receipt = execute(endpoint, tmp_path)
    assert receipt['status'] == 'partial'
    assert receipt['coverage']['dns']['status'] == receipt['coverage']['http']['status'] == 'partial'
    assert not receipt['observations']['dns'] and len(receipt['observations']['http'][0]['uri']) == 500


def test_report_size_and_error_envelopes_fail_closed(endpoint, tmp_path, monkeypatch):
    monkeypatch.setattr(cape, 'MAX_REPORT_BYTES', 1200)
    endpoint.report_bytes = b' ' * 1201
    assert execute(endpoint, tmp_path)['status'] == 'pending'
    endpoint.report_bytes = b'{"error":true,"error_value":"secret"}'
    assert execute(endpoint, tmp_path)['status'] == 'pending'
    assert endpoint.posts == 1


def test_redirects_are_not_followed(endpoint, tmp_path):
    endpoint.response_status = 302
    assert execute(endpoint, tmp_path)['status'] == 'submission_unknown'
    assert not endpoint.gets


def test_poll_budget_does_not_resubmit_or_sleep_past_deadline(endpoint, tmp_path):
    endpoint.status = 'running'
    endpoint.config = replace(endpoint.config, wait_seconds=6)
    elapsed = [0]
    waits = []
    def sleep(seconds):
        waits.append(seconds)
        elapsed[0] += seconds
    receipt = execute(endpoint, tmp_path, clock=lambda: elapsed[0], sleep=sleep)
    assert receipt['status'] == 'pending' and waits == [5, 1] and len(endpoint.gets) == 3


def test_configuration_disabled_needs_no_files_and_bad_config_refused(tmp_path):
    assert cape.CapeConfig.from_env({}) is None
    token = tmp_path / 'token'
    token.write_text('test_cape_token_0123456789')
    env = {'SPECULA_CAPE_ENABLED': 'true', 'SPECULA_CAPE_URL': 'https://lab.invalid/apiv2',
           'SPECULA_CAPE_MACHINE': 'win-lab', 'SPECULA_CAPE_TOKEN_FILE': str(token)}
    assert cape.CapeConfig.from_env(env).machine == 'win-lab'
    for key, value in [('SPECULA_CAPE_URL', 'http://lab.invalid/apiv2'),
                        ('SPECULA_CAPE_URL', 'https://user:secret@lab.invalid/apiv2'),
                        ('SPECULA_CAPE_URL', 'https://lab.invalid/apiv2?sample=http://injected'),
                        ('SPECULA_CAPE_MACHINE', 'all'), ('SPECULA_CAPE_MAX_SAMPLES', '999'),
                        ('SPECULA_CAPE_WAIT_SECONDS', '-1')]:
        with pytest.raises(ValueError):
            cape.CapeConfig.from_env({**env, key: value})


def native_case(tmp_path, payload=None):
    payload = sample_pe() if payload is None else payload
    digest = sha256(payload).hexdigest()
    directory = tmp_path / 'data' / 'uploads' / 'C1'
    directory.mkdir(parents=True)
    archive = directory / 'evidence.zip'
    with ZipFile(archive, 'w') as z:
        z.writestr('malware/samples/test.exe', payload)
    return {'case_id': 'C1', 'evidence_collection': {'records': [{'uid': 'e', 'source_type': 'malware',
        'unmapped': {'examination': {'analysis_origin': 'independent_static_examination', 'sha256': digest}}}]},
        'ingestion_provenance': {'archive_sha256': sha256(archive.read_bytes()).hexdigest(),
            'files': [{'path': 'malware/samples/test.exe', 'sha256': digest, 'native_artifact': True}]}}


def test_native_archive_case_selection_and_validation(endpoint, tmp_path, monkeypatch):
    state = native_case(tmp_path)
    monkeypatch.setattr(cape.CapeConfig, 'from_env', lambda: endpoint.config)
    monkeypatch.setattr(cape, 'store_path', lambda: tmp_path / 'cape.sqlite3')
    receipt = cape.examine_case(state, tmp_path)[0]
    assert receipt['status'] == 'complete' and endpoint.posts == 1
    state['ingestion_provenance']['archive_sha256'] = 'wrong'
    assert cape.examine_case(state, tmp_path)[0]['status'] == 'unavailable'
    assert endpoint.posts == 1
    state['evidence_collection']['records'][0]['unmapped'] = {'source_context': {'sha256': 'fake'}}
    assert cape.examine_case(state, tmp_path) == []  # Imported claims cannot submit samples.


def test_disabled_and_missing_native_bytes_are_explicit(endpoint, tmp_path, monkeypatch):
    state = native_case(tmp_path)
    monkeypatch.setattr(cape.CapeConfig, 'from_env', lambda: None)
    assert cape.examine_case(state, tmp_path)[0]['status'] == 'deferred'
    monkeypatch.setattr(cape.CapeConfig, 'from_env', lambda: endpoint.config)
    monkeypatch.setattr(cape, 'store_path', lambda: tmp_path / 'cape.sqlite3')
    state['ingestion_provenance']['files'] = []
    assert cape.examine_case(state, tmp_path)[0]['status'] == 'unavailable' and endpoint.posts == 0


def test_api_download_requires_case_authorization_and_report_digest(endpoint, tmp_path, monkeypatch):
    from src.agents import visualizer_api
    from tests.api_auth_helpers import configure_test_auth
    receipt = execute(endpoint, tmp_path)
    monkeypatch.setattr(cape, 'store_path', lambda: tmp_path / 'cape.sqlite3')
    monkeypatch.setattr(visualizer_api, '_get_neo4j_driver', lambda: None)
    headers = configure_test_auth(monkeypatch, tmp_path, {'test-user': {'role': 'viewer', 'cases': ['C1']}})
    client = TestClient(visualizer_api.app)
    path = '/api/investigations/C1/sandbox/' + receipt['uid'] + '/report'
    assert client.get(path).status_code == 401
    assert client.get(path.replace('/C1/', '/C2/'), headers=headers).status_code == 403
    response = client.get(path, headers=headers)
    assert response.status_code == 200 and response.json()['info']['id'] == 7
    assert response.headers['X-Report-SHA256'] == receipt['report_sha256']
    assert 'attachment' in response.headers['Content-Disposition']
    with cape.CapeStore(tmp_path / 'cape.sqlite3').connect() as conn:
        conn.execute('UPDATE cape_runs SET report=?', (b'corrupted',))
    assert client.get(path, headers=headers).status_code == 409


def test_malware_agent_saves_receipt_and_review_sees_lab_scope(endpoint, tmp_path, monkeypatch):
    from src.agents import case_analysis
    from src.agents.grounding import claim_errors
    from src.agents.grounded_report import _prepared
    receipt = execute(endpoint, tmp_path)
    state = native_case(tmp_path)
    state['evidence_collection']['records'][0]['canonical_host_id'] = 'original-host'
    monkeypatch.setattr(cape, 'examine_case', lambda state: [receipt])
    seen = []
    def review(role, state, facts, llm):
        seen.extend(facts)
        return {'agent_role': role, 'model_output_validated': True}
    monkeypatch.setattr('src.agents.investigative_review.investigate', review)
    monkeypatch.setattr(case_analysis, 'get_llm', lambda *a, **k: None)
    monkeypatch.setattr('src.agents.kafka_utils.publish_finding', lambda *a, **k: None)
    result = case_analysis.specialist('malware_stylometry', 'malware', state)
    assert result['sandbox_runs'] == [receipt]
    assert result['agent_traces'][0]['sandbox_examinations'] == [receipt]
    fact = next(f for f in seen if f['finding_type'] == 'sandbox_examination')
    assert claim_errors('Malware executed on the investigated host.', [fact])
    assert not claim_errors('CAPE recorded a process inside the sandbox.', [fact])
    assert not claim_errors('Execution on the investigated host is unverified.', [fact])
    state['findings'] = result['findings']
    assert next(f for f in case_analysis.debate_facts(state) if f['finding_type']=='sandbox_examination')['canonical_host_id'] is None
    graph = case_analysis.activity_graph(state)['attack_graph']
    lab_nodes = [n for n in graph['nodes'] if n.get('effect_scope')=='sandbox_execution']
    assert lab_nodes and all(n['canonical_host_id'] is None and n['time'] is None for n in lab_nodes)
    _, metadata = _prepared({**state, 'sandbox_runs': [{**receipt, 'status': 'pending'}]})
    assert 'sandbox_examination_incomplete' in metadata['degraded_flags']


def test_local_download_proxy_checks_origin_identifiers_hash_and_redirects(tmp_path, monkeypatch):
    import asyncio
    from fastapi import HTTPException
    from scripts import local_boot_api as local
    request = SimpleNamespace(client=SimpleNamespace(host='127.0.0.1'),
        headers={'origin': 'http://localhost:5173', 'x-specula-local-boot': '1'})
    raw = b'{"info":{"id":7}}'
    digest = sha256(raw).hexdigest()
    calls = []
    response = SimpleNamespace(status_code=200, headers={'X-Report-SHA256': digest}, iter_content=lambda size: [raw])
    class Response:
        def __enter__(self): return response
        def __exit__(self, *args): pass
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return Response()
    monkeypatch.setattr(local.requests, 'Session', Session)
    monkeypatch.setattr(local, '_local_token', lambda: 'private_backend_token')
    case_id, uid = 'LOCAL-' + 'a'*32, 'b'*64
    result = asyncio.run(local.local_sandbox_report(case_id, uid, request))
    assert result.body == raw and result.headers['X-Report-SHA256'] == digest
    assert calls[0][0] == f'http://127.0.0.1:8300/api/investigations/{case_id}/sandbox/{uid}/report'
    assert calls[0][1]['allow_redirects'] is False
    for invalid_case, invalid_uid, code in [('CASE-other', uid, 403), (case_id, '../other', 422)]:
        with pytest.raises(HTTPException) as error:
            asyncio.run(local.local_sandbox_report(invalid_case, invalid_uid, request))
        assert error.value.status_code == code
    response.headers['X-Report-SHA256'] = 'wrong'
    with pytest.raises(HTTPException) as error:
        asyncio.run(local.local_sandbox_report(case_id, uid, request))
    assert error.value.status_code == 503
    request.client.host = '192.0.2.5'
    with pytest.raises(HTTPException) as error:
        asyncio.run(local.local_sandbox_report(case_id, uid, request))
    assert error.value.status_code == 403


def test_durable_claim_prevents_concurrent_submission_and_cached_tamper(endpoint, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    endpoint.status = 'running'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: execute(endpoint, tmp_path), range(2)))
    assert endpoint.posts == 1 and {r['uid'] for r in results} == {results[0]['uid']}
    endpoint.status = 'reported'
    receipt = execute(endpoint, tmp_path)
    with cape.CapeStore(tmp_path / 'cape.sqlite3').connect() as conn:
        conn.execute('UPDATE cape_runs SET report=?', (b'tampered',))
    with pytest.raises(ValueError, match='digest mismatch'):
        execute(endpoint, tmp_path)
    assert endpoint.posts == 1 and receipt['report_sha256']


def test_case_sample_budget_retains_explicit_omissions(endpoint, tmp_path, monkeypatch):
    state = native_case(tmp_path)
    another = deepcopy(state['evidence_collection']['records'][0])
    another['uid'] = 'e2'
    another['unmapped']['examination']['sha256'] = 'f'*64
    state['evidence_collection']['records'].append(another)
    monkeypatch.setattr(cape.CapeConfig, 'from_env', lambda: replace(endpoint.config, max_samples=1))
    monkeypatch.setattr(cape, 'store_path', lambda: tmp_path / 'cape.sqlite3')
    receipts = cape.examine_case(state, tmp_path)
    assert len(receipts) == 2 and receipts[-1]['status'] == 'unavailable'
    assert receipts[-1]['dfkg_refs'] == ['e2'] and endpoint.posts == 1


def test_actual_graph_checkpoint_projection_and_both_reports_retain_lab_receipts(endpoint, tmp_path):
    from langgraph.graph import StateGraph, START, END
    from src.agents.state import SpeculaState
    from src.agents.checkpointer import SQLiteCheckpointSaver
    from src.agents.agent_graph import persist_case_execution
    from src.agents.examination_reports import render_examination_report
    receipt = execute(endpoint, tmp_path)
    state = native_case(tmp_path)
    state['evidence_collection'].update(status='complete', case_id='C1')
    state['evidence_collection']['records'][0].update(time='2026-10-14T00:00:00Z', class_uid=2004)
    trace = {'agent_role': 'malware_stylometry', 'sandbox_examinations': [receipt],
             'dfkg_refs': ['e'], 'examination_coverage': {'unavailable': 0}}
    builder = StateGraph(SpeculaState)
    builder.add_node('malware', lambda s: {'sandbox_runs': [receipt], 'agent_traces': [trace], 'loop_count': 1})
    builder.add_edge(START, 'malware')
    builder.add_edge('malware', END)
    path = tmp_path / 'checkpoint.sqlite3'
    saver = SQLiteCheckpointSaver(path)
    config = {'configurable': {'thread_id': 'C1'}}
    graph = builder.compile(checkpointer=saver)
    graph.invoke(state, config)
    saver.close()
    saver = SQLiteCheckpointSaver(path)
    saved = builder.compile(checkpointer=saver).get_state(config).values
    assert saved['sandbox_runs'][0]['report_sha256'] == receipt['report_sha256']
    queries = []
    driver = SimpleNamespace(execute_query=lambda query, **params: queries.append((query, params)))
    persist_case_execution(driver, 'C1', saved['agent_traces'], cape.findings([receipt]))
    review = json.loads(queries[0][1]['runs'][0]['review_json'])
    assert review['sandbox_examinations'][0]['uid'] == receipt['uid']
    for kind in ('court', 'technical'):
        html, _ = render_examination_report(saved, kind)
        assert 'Isolated laboratory dynamic examination' in html and receipt['report_sha256'] in html
        assert 'separate guest experiment' in html
    saver.close()
