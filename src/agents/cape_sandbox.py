"""CAPE v2 remote execution receipts. No sample is executed on this host."""
from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import urlsplit

import requests

MAX_REPORT_BYTES = 16 * 1024 * 1024
LIMITATION = ('Observed in an isolated CAPE guest only; behavior is not proof of activity on the '
              'investigated host, malicious intent, family/actor identity or absence of undetected behavior.')


def _integer(env, name, default, low, high):
    value = int(env.get(name, default))
    if not low <= value <= high:
        raise ValueError('CAPE setting outside supported bounds: ' + name)
    return value


@dataclass(frozen=True)
class CapeConfig:
    base_url: str
    token: str = field(repr=False)
    machine: str
    timeout: int = 120
    wait_seconds: int = 30
    max_samples: int = 3

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        if env.get('SPECULA_CAPE_ENABLED', 'false').lower() != 'true':
            return None
        base = env.get('SPECULA_CAPE_URL', '').rstrip('/')
        parsed = urlsplit(base)
        if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or
                parsed.password or parsed.query or parsed.fragment or parsed.path != '/apiv2'):
            raise ValueError('CAPE URL must identify an authenticated /apiv2 endpoint')
        # Unencrypted tokens are restricted to an operator-configured local/private endpoint.
        if parsed.scheme == 'http' and parsed.hostname not in {'localhost', 'host.docker.internal'}:
            try:
                address = ipaddress.ip_address(parsed.hostname)
            except ValueError:
                raise ValueError('Use HTTPS for a named CAPE host') from None
            if not (address.is_loopback or address.is_private) or address.is_unspecified or address.is_multicast:
                raise ValueError('Use HTTPS for a non-private CAPE host')
        parsed.port  # Validate malformed/out-of-range ports before sending credentials.
        machine = env.get('SPECULA_CAPE_MACHINE', '')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', machine) or machine.lower() == 'all':
            raise ValueError('Configure exactly one CAPE machine')
        token = Path(env.get('SPECULA_CAPE_TOKEN_FILE', 'data/private/cape_token')).read_text().strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{16,256}', token):
            raise ValueError('Invalid CAPE API token file')
        return cls(base, token, machine,
                   _integer(env, 'SPECULA_CAPE_TIMEOUT', 120, 10, 600),
                   _integer(env, 'SPECULA_CAPE_WAIT_SECONDS', 30, 0, 120),
                   _integer(env, 'SPECULA_CAPE_MAX_SAMPLES', 3, 1, 10))


def store_path():
    checkpoint = Path(os.environ.get('SPECULA_CHECKPOINT_PATH', 'data/checkpoints/specula.sqlite3'))
    return checkpoint.parent / 'cape.sqlite3'


class CapeStore:
    """Single-host durable claims; ambiguous submissions are never blindly retried."""
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS cape_runs '
                         '(uid TEXT PRIMARY KEY, case_id TEXT NOT NULL, receipt TEXT NOT NULL, report BLOB)')

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def claim(self, receipt):
        with self.connect() as conn:
            inserted = conn.execute('INSERT OR IGNORE INTO cape_runs(uid,case_id,receipt) VALUES(?,?,?)',
                                   (receipt['uid'], receipt['case_id'], json.dumps(receipt))).rowcount == 1
            row = conn.execute('SELECT receipt FROM cape_runs WHERE uid=?', (receipt['uid'],)).fetchone()
        return json.loads(row[0]), inserted

    def save(self, receipt, report=None):
        with self.connect() as conn:
            conn.execute('UPDATE cape_runs SET receipt=?,report=coalesce(?,report) WHERE uid=? AND case_id=?',
                         (json.dumps(receipt), report, receipt['uid'], receipt['case_id']))

    def report(self, case_id, uid):
        if not re.fullmatch(r'[a-f0-9]{64}', uid):
            raise ValueError('Invalid sandbox receipt identity')
        with self.connect() as conn:
            row = conn.execute('SELECT receipt,report FROM cape_runs WHERE uid=? AND case_id=?',
                               (uid, case_id)).fetchone()
        if not row or row[1] is None:
            raise FileNotFoundError('Preserved CAPE report unavailable')
        receipt, raw = json.loads(row[0]), bytes(row[1])
        if sha256(raw).hexdigest() != receipt.get('report_sha256'):
            raise ValueError('Preserved CAPE report digest mismatch')
        return raw


class CapeClient:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers['Authorization'] = 'Token ' + config.token

    def close(self):
        self.session.close()

    def request(self, method, path, **kwargs):
        # Only internally constructed relative routes reach this method. Never follow server URLs.
        with self.session.request(method, self.config.base_url + '/' + path,
                                  timeout=(3, 10), allow_redirects=False, stream=True, **kwargs) as response:
            if response.status_code != 200:
                raise ValueError('CAPE HTTP status ' + str(response.status_code))
            content = bytearray()
            for chunk in response.iter_content(65536):
                content.extend(chunk)
                if len(content) > MAX_REPORT_BYTES:
                    raise ValueError('CAPE response exceeds bounded report size')
            raw = bytes(content)
        body = json.loads(raw)
        if not isinstance(body, dict) or body.get('error') or body.get('errors'):
            raise ValueError('CAPE returned an error or invalid object')
        return body, raw

    def submit(self, payload, digest, uid):
        body, _ = self.request('POST', 'tasks/create/file/',
            files={'file': (digest + '.exe', payload, 'application/octet-stream')},
            data={'machine': self.config.machine, 'platform': 'windows', 'timeout': str(self.config.timeout),
                  'custom': 'specula:' + uid, 'memory': '0', 'route': 'drop', 'options': '', 'priority': '1'})
        ids = (body.get('data') or {}).get('task_ids')
        if not isinstance(ids, list) or len(ids) != 1 or type(ids[0]) is not int or ids[0] <= 0:
            raise ValueError('CAPE did not return exactly one task ID; reconcile submission manually')
        return ids[0]

    def view(self, task_id):
        body, _ = self.request('GET', f'tasks/view/{task_id}/')
        entry = body.get('data')
        if not isinstance(entry, dict) or type(entry.get('id')) is not int or entry['id'] != task_id:
            raise ValueError('CAPE task view identity mismatch')
        return entry

    def report(self, task_id):
        return self.request('GET', f'tasks/get/report/{task_id}/json/')


def summarize(report, receipt):
    """Project bounded laboratory observations, not verdicts or original-host times."""
    info, target = report.get('info'), report.get('target')
    if (not isinstance(info, dict) or type(info.get('id')) is not int or info['id'] != receipt['cape_task_id'] or
            info.get('custom') != 'specula:' + receipt['uid'] or not isinstance(target, dict) or
            (target.get('file') or {}).get('sha256', '').lower() != receipt['sample_sha256']):
        raise ValueError('CAPE report is not bound to the submitted case/sample/task')
    if not isinstance(info.get('machine'), dict) or info['machine'].get('name') != receipt['machine']:
        raise ValueError('CAPE report machine differs from configured guest')
    if info.get('route') != 'drop' or info.get('category') != 'file':
        raise ValueError('CAPE report experiment parameters differ from submitted task')
    groups = {}
    coverage = {}
    partial = False

    def retain(name, value, keys):
        nonlocal partial
        if not isinstance(value, list):
            coverage[name] = {'status': 'unavailable', 'returned': 0}
            partial = True
            return
        selected = []
        malformed = False
        clipped = False
        for item in value[:20]:
            if isinstance(item, dict) and keys:
                fields = {key: str(item[key]) for key in keys if key in item}
                if fields:
                    clipped |= any(len(value) > 500 for value in fields.values())
                    selected.append({key: value[:500] for key, value in fields.items()})
                else:
                    malformed = True
            elif isinstance(item, str):
                clipped |= len(item) > 500
                selected.append(item[:500])
            else:
                malformed = True
        coverage[name] = {'status': 'partial' if len(value) > 20 or malformed or clipped else 'complete',
                          'total': len(value), 'returned': len(selected)}
        groups[name] = selected
        partial |= coverage[name]['status'] != 'complete'

    behavior = report.get('behavior')
    if not isinstance(behavior, dict):
        behavior = {}
        partial = True
    retain('processes', behavior.get('processes'), ('process_id', 'parent_id', 'process_path', 'first_seen'))
    summary = behavior.get('summary')
    summary = summary if isinstance(summary, dict) else {}
    for key in ('file_created', 'file_written', 'file_deleted', 'regkey_written', 'mutex'):
        retain(key, summary.get(key), ())
    network = report.get('network')
    network = network if isinstance(network, dict) else {}
    for key, keys in {'dns': ('request', 'type'), 'tcp': ('src', 'sport', 'dst', 'dport'),
                      'udp': ('src', 'sport', 'dst', 'dport'),
                      'http': ('host', 'port', 'method', 'uri', 'status')}.items():
        retain(key, network.get(key), keys)
    retain('signatures', report.get('signatures'), ('name', 'description', 'severity'))
    retain('dropped', report.get('dropped'), ('name', 'sha256', 'size'))
    debug = report.get('debug')
    errors = debug.get('errors', []) if isinstance(debug, dict) else []
    partial |= bool(errors)
    return {'status': 'partial' if partial else 'complete', 'observations': groups, 'coverage': coverage,
            'analysis_errors_present': bool(errors),
            'cape_version': str(info.get('version', 'unavailable'))[:100],
            'cape_commit': str(info.get('CAPE_current_commit', 'unavailable'))[:100],
            'analysis_package': str(info.get('package', 'unavailable'))[:100],
            'analysis_timeout_reached': info.get('timeout') if type(info.get('timeout')) is bool else None,
            'sandbox_started': str(info.get('started', ''))[:100],
            'sandbox_ended': str(info.get('ended', ''))[:100],
            'limitation': LIMITATION}


def run_sample(config, store, payload, case_id, refs, client=None, clock=time.monotonic, sleep=time.sleep):
    if not 0 < len(payload) <= 25 * 1024 * 1024 or not payload.startswith(b'MZ') or not refs:
        raise ValueError('A bounded preserved PE sample and case citations are required')
    digest = sha256(payload).hexdigest()
    # A changed host/guest/time configuration is a distinct experiment; never deduplicate across cases.
    uid = sha256(json.dumps([case_id, digest, config.base_url, config.machine, config.timeout,
                             'windows', 'drop'], separators=(',', ':')).encode()).hexdigest()
    receipt = {'uid': uid, 'case_id': case_id, 'sample_sha256': digest, 'dfkg_refs': sorted(refs),
               'analysis_origin': 'cape_remote_execution', 'environment': 'isolated_lab',
               'machine': config.machine, 'timeout': config.timeout, 'route': 'drop',
               'status': 'submission_unknown', 'created_at': datetime.now(timezone.utc).isoformat(),
               'limitation': 'Submission interrupted or uncertain; reconcile CAPE before retrying. ' + LIMITATION}
    receipt, claimed = store.claim(receipt)
    receipt['dfkg_refs'] = sorted(refs)
    if receipt['status'] in {'complete', 'partial'}:
        store.report(case_id, uid)  # Cached observations remain bound to preserved report bytes.
        return {**receipt, 'dfkg_refs': sorted(refs)}
    if receipt['status'] == 'failed' or (not claimed and not receipt.get('cape_task_id')):
        return {**receipt, 'dfkg_refs': sorted(refs)}
    owned_client = client is None
    client = client or CapeClient(config)
    try:
        if claimed:
            receipt['last_operation'] = 'submit'
            receipt['cape_task_id'] = client.submit(payload, digest, uid)
            receipt.update(status='pending', limitation='CAPE task submitted; analysis is not yet available. ' + LIMITATION)
            store.save(receipt)  # Persist immediately, before polling or graph checkpointing.
        deadline = clock() + config.wait_seconds
        for _ in range(25):
            receipt['last_operation'] = 'task_view'
            entry = client.view(receipt['cape_task_id'])
            if (entry.get('custom') != 'specula:' + uid or entry.get('category') != 'file' or
                    (entry.get('sample') or {}).get('sha256', '').lower() != digest or
                    entry.get('machine') != config.machine or entry.get('route') != 'drop'):
                raise ValueError('CAPE task metadata does not match the case-bound submission')
            status = entry.get('status')
            receipt['cape_status'] = status
            if status == 'reported':
                receipt['last_operation'] = 'report_validation'
                report, raw = client.report(receipt['cape_task_id'])
                projection = summarize(report, receipt)
                receipt.update(projection, report_sha256=sha256(raw).hexdigest(), report_bytes=len(raw),
                               artifact_ref='cape:' + uid + ':report')
                receipt.pop('last_error_code', None)
                store.save(receipt, raw)
                break
            if status in {'failed_analysis', 'failed_processing', 'failed_reporting'}:
                receipt.update(status='failed', limitation='CAPE analysis failed; not a benign result. ' + LIMITATION)
                store.save(receipt)
                break
            if status not in {'pending', 'running', 'completed', 'processing', 'distributed'}:
                raise ValueError('Unsupported CAPE task state')
            store.save(receipt)
            remaining = deadline - clock()
            if remaining <= 0:
                break
            sleep(min(5, remaining))
    except (requests.RequestException, ValueError, TypeError, KeyError, AttributeError):
        # Never expose server text, endpoint secrets, raw headers or credential-bearing exceptions.
        receipt.update(status='pending' if receipt.get('cape_task_id') else 'submission_unknown',
                       last_error_code='transport_response_or_binding_rejected',
                       limitation='CAPE response unavailable or failed identity/format checks; '
                                  'no behavioral conclusion accepted. ' + LIMITATION)
        store.save(receipt)
    finally:
        if owned_client:
            client.close()
    return receipt


def examine_case(state, root=None):
    """Malware specialist tool; sample selection is derived from preserved evidence."""
    from .case_analysis import records
    from .investigation_followup import preserved_artifacts, ROOT
    source = {e['uid']: e for e in records(state)}
    refs_by_hash = {}
    for uid, event in source.items():
        examination = (event.get('unmapped') or {}).get('examination') or {}
        if event.get('source_type') == 'malware' and examination.get('analysis_origin') == 'independent_static_examination':
            refs_by_hash.setdefault(examination['sha256'], []).append(uid)
    refs = sorted(u for group in refs_by_hash.values() for u in group)
    if not refs:
        return []
    try:
        config = CapeConfig.from_env()
        if config is None:
            return [{'status': 'deferred', 'dfkg_refs': refs, 'environment': 'isolated_lab',
                     'limitation': 'CAPE execution disabled; static examination only. ' + LIMITATION}]
        artifacts = preserved_artifacts({'anchor_refs': refs}, state, source, root or ROOT)
        by_hash = {a['sha256']: a for a in artifacts if a['sha256'] in refs_by_hash}
        store = CapeStore(store_path())
        receipts = []
        for digest in sorted(by_hash)[:config.max_samples]:
            payload = by_hash[digest]['payload']
            if not 0 < len(payload) <= 25 * 1024 * 1024 or not payload.startswith(b'MZ'):
                raise ValueError('Only preserved native PE samples may be submitted')
            receipts.append(run_sample(config, store, payload, state['case_id'], refs_by_hash[digest]))
        omitted = set(refs_by_hash) - {r['sample_sha256'] for r in receipts}
        if omitted:
            receipts.append({'status': 'unavailable', 'environment': 'isolated_lab',
                             'dfkg_refs': sorted(u for digest in omitted for u in refs_by_hash[digest]),
                             'limitation': 'Preserved sample unavailable or per-case submission budget reached. ' + LIMITATION})
        return receipts
    except (ValueError, OSError, KeyError, sqlite3.Error):
        return [{'status': 'unavailable', 'dfkg_refs': refs, 'environment': 'isolated_lab',
                 'limitation': 'CAPE configuration, durable storage or preserved sample validation unavailable. ' + LIMITATION}]


def findings(receipts):
    result = []
    for receipt in receipts:
        common = {'agent_role': 'malware_stylometry',
            'source': 'validated_case_rule', 'classification': 'context' if receipt['status'] == 'complete' else 'unresolved',
            'operation_outcome': 'unknown', 'effect_scope': 'sandbox_execution',
            'canonical_host_id': None, 'event_time': None, 'attacks': [], 'dfkg_refs': receipt['dfkg_refs']}
        summary = {key: value for key, value in receipt.items() if key not in {'observations', 'coverage'}}
        summary['coverage'] = receipt.get('coverage', {})
        result.append({**common, 'finding_type': 'sandbox_examination',
                       'summary': 'CAPE isolated laboratory examination: ' + json.dumps(summary, sort_keys=True)})
        # Keep model batches small. All retained observations and the full raw report remain in receipts/storage.
        for group, rows in receipt.get('observations', {}).items():
            if rows:
                sample = [{key: str(value)[:150] for key, value in row.items()} if isinstance(row, dict)
                          else str(row)[:150] for row in rows[:2]]
                result.append({**common, 'finding_type': 'sandbox_' + group,
                    'summary': 'CAPE isolated laboratory ' + group + ': ' + json.dumps(sample, sort_keys=True) +
                    '; model projection=' + str(len(sample)) + '/' + str(len(rows)) + ' retained entries; '
                    'report_sha256=' + receipt.get('report_sha256', 'unavailable') + '; ' + LIMITATION})
    return result
