"""Run three prepared synthetic ZIPs through local Specula, stopping at HITL."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output' / 'evaluation-pilot'
LIVE = OUT / 'live'
BASE = 'http://127.0.0.1:8400'
HEADERS = {'Origin': 'http://localhost:5173', 'X-Specula-Local-Boot': '1'}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def main():
    LIVE.mkdir(parents=True, exist_ok=True)
    with requests.Session() as session:
        session.trust_env = False
        session.headers.update(HEADERS)
        session.mount('http://', HTTPAdapter(max_retries=Retry(
            total=3, backoff_factor=1, allowed_methods={'GET'})))
        response = session.get(BASE + '/api/system/readiness', timeout=30)
        response.raise_for_status()
        save(LIVE / 'readiness.json', response.json())
        current = session.get(BASE + '/api/local/investigations/current', timeout=15)
        current.raise_for_status()
        if current.json().get('phase') in {'queued', 'ingesting', 'investigating'}:
            owned_jobs = {json.loads(path.read_text())['submission']['id']
                          for path in LIVE.glob('case-*-run.json')}
            if current.json()['id'] not in owned_jobs:
                raise RuntimeError('Unrelated local job is active; do not interfere')
        for number in range(1, 4):
            name = f'case-{number:03}'
            receipt_path = LIVE / f'{name}-run.json'
            # Re-entry inspects/resumes polling the original submission, never
            # silently duplicates a case or overwrites an earlier run.
            if receipt_path.exists():
                receipt = json.loads(receipt_path.read_text())
                if receipt.get('terminal'):
                    print(name, 'already recorded', flush=True)
                    continue
            else:
                archive = (OUT / f'{name}.zip').read_bytes()
                started = datetime.now(timezone.utc).isoformat()
                response = session.post(BASE + '/api/local/investigations/upload',
                                        params={'max_events': 2000, 'exclude_ports': ''},
                                        data=archive, timeout=60)
                response.raise_for_status()
                receipt = {'fixture': name, 'configuration': 'specula',
                           'archive_sha256': hashlib.sha256(archive).hexdigest(),
                           'started_utc': started, 'submission': response.json()}
                save(receipt_path, receipt)
                print(name, 'submitted', receipt['submission']['case_id'], flush=True)
            deadline = time.monotonic() + 1800
            previous = None
            while time.monotonic() < deadline:
                job_id = receipt['submission']['id']
                response = session.get(BASE + f'/api/local/investigations/{job_id}', timeout=30)
                response.raise_for_status()
                job = response.json()
                receipt['job'] = job
                receipt['last_checked_utc'] = datetime.now(timezone.utc).isoformat()
                phase = job['phase']
                if phase != previous:
                    print(name, phase, job.get('message', ''), flush=True)
                    previous = phase
                if phase in {'complete', 'error'}:
                    receipt['terminal'] = True
                    receipt['elapsed_to_job_terminal_seconds'] = (
                        datetime.now(timezone.utc) - datetime.fromisoformat(receipt['started_utc'])).total_seconds()
                    snapshot = session.get(BASE + '/api/local/cases/' + job['case_id'], timeout=40)
                    receipt['snapshot_http_status'] = snapshot.status_code
                    save(LIVE / f'{name}-snapshot.json', snapshot.json())
                    save(receipt_path, receipt)
                    print(name, 'saved terminal job/snapshot', flush=True)
                    break
                save(receipt_path, receipt)
                time.sleep(5)
            else:
                save(receipt_path, receipt)
                raise TimeoutError(f'{name}: still running; re-run to poll the existing case')


if __name__ == '__main__':
    main()
