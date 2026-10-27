"""Structured WinEvent collection and lossless unsupported-record preservation."""
import base64
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.ingestion import run_pipeline as pipeline
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
from src.schemas.entity_resolver import CanonicalEntityResolver


def test_windows_collection_preserves_structured_fields_and_uses_data_parameters(monkeypatch):
    calls = []
    row = {'Id': 4698, 'TimeCreated': '2026-10-14T00:00:00Z', 'MachineName': 'H',
           'EventData': {'TaskName': 'Backup', 'SubjectLogonId': '0x1'}, 'SourceXml': '<Event/>'}
    def run(command, **options):
        calls.append((command, options))
        return SimpleNamespace(returncode=0, stdout=json.dumps([row]))
    monkeypatch.setattr(pipeline.subprocess, 'run', run)
    channel = "Security'; Write-Output secret; #"
    assert pipeline.extract_windows_events(channel, max_events=5) == [row]
    command, options = calls[0]
    assert command[:4] == ['powershell', '-NoProfile', '-NonInteractive', '-EncodedCommand']
    script = base64.b64decode(command[4]).decode('utf-16le')
    assert 'EventData=$data' in script and 'SourceXml=$record.ToXml()' in script and channel not in script
    assert options['timeout'] == 120


@pytest.mark.parametrize('response', [SimpleNamespace(returncode=1, stdout='', stderr='sensitive detail'),
    SimpleNamespace(returncode=0, stdout='not JSON'), SimpleNamespace(returncode=0, stdout='[42]')])
def test_windows_collection_failure_is_not_empty_success(monkeypatch, response):
    monkeypatch.setattr(pipeline.subprocess, 'run', lambda *a, **k: response)
    with pytest.raises(RuntimeError) as error:
        pipeline.extract_windows_events('Security')
    assert 'sensitive detail' not in str(error.value)


def test_windows_empty_interval_and_limits(monkeypatch):
    monkeypatch.setattr(pipeline.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout='[]'))
    assert pipeline.extract_windows_events('Security') == []
    for limit in (0, 100001, True):
        with pytest.raises(ValueError):
            pipeline.extract_windows_events('Security', max_events=limit)
    with pytest.raises(ValueError):
        pipeline.extract_windows_events('Security', start_time='2026-10-14T00:00:00Z')


def test_unsupported_windows_event_is_preserved_case_linkable_and_cited():
    raw = {'Id': 4697, 'TimeCreated': '2026-10-14T00:00:00Z', 'ProviderName': 'Microsoft-Windows-Security-Auditing',
           'MachineName': 'H', 'EventData': {'ServiceName': 'BackupService', 'ServiceFileName': 'C:/svc.exe'}}
    graph = Mock()
    result = pipeline.run_pipeline_on_event(raw, VCTAtomicChain(), CanonicalEntityResolver(), TimeNormalizer(),
        neo4j_client=graph, case_id='C')
    assert len(result) == 1 and result[0][0].valid
    event = result[0][0].event
    assert event.class_uid == 99 and event.case_id == 'C' and event.canonical_host_id
    assert event.unmapped['source_context'] == raw
    query, params = graph.execute.call_args.args
    assert '$uid' in query and params['uid'] == event.uid and params['properties']['class_uid'] == 99


def test_channel_failure_is_recorded_and_other_channels_continue(monkeypatch):
    from scripts import local_case_pipeline as local
    def extract(channel, *args):
        if channel == 'Security':
            raise RuntimeError('access unavailable')
        return [{'Id': 4698}] if channel == 'System' else []
    monkeypatch.setattr(pipeline, 'extract_windows_events', extract)
    captured = {}
    def ingest(case, batches, ports, provenance):
        captured.update(rows=list(batches), provenance=provenance)
        return {'accepted': 1}
    monkeypatch.setattr(local, '_ingest_batches', ingest)
    assert local.ingest_case('C', None, None, 50, []) == {'accepted': 1}
    receipts = captured['provenance']['channel_receipts']
    assert next(r for r in receipts if r['channel'] == 'Security')['status'] == 'unavailable'
    assert next(r for r in receipts if r['channel'] == 'System')['records'] == 1
