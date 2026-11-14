"""Prepare three inert, reproducible pilot uploads; never run an investigation."""
from contextlib import redirect_stdout
import csv
from datetime import datetime
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from uuid import NAMESPACE_URL, uuid5
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
import generate_complex_evidence as generator
from src.ingestion.export_aliases import adapt_export
from src.ingestion.upload_archive import SOURCE_FOLDERS, records_from_bytes, validate_archive

OUT = ROOT / 'output' / 'evaluation-pilot'
CASES = {
    'case-001': ('benign', ('N1 ', 'N3 ', 'N5 ')),
    'case-002': ('suspicious_activity', ('A1 ', 'A2 ', 'A3 ', 'A8 ')),
    'case-003': ('incomplete_contradictory', ('A6 ', 'N6 ', 'N7 ', 'N8 ', 'Q1 ')),
}


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')


def archive_bytes(path, blobs):
    with ZipFile(path, 'w') as archive:
        for name, blob in sorted(blobs.items()):
            info = ZipInfo(name, date_time=(2026, 11, 10, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, blob)


def prepare():
    OUT.mkdir(parents=True, exist_ok=True)
    # Keep the source generator's normal output and any existing user artifacts intact.
    previous = generator.OUT
    try:
        with TemporaryDirectory(prefix='specula-pilot-') as temporary:
            generator.OUT = Path(temporary)
            with redirect_stdout(StringIO()):
                generator.main()
            source_key = json.loads((generator.OUT / 'complex-evidence-answer-key.json').read_text())
            with ZipFile(generator.OUT / 'complex-evidence.zip') as archive:
                source = {name: records_from_bytes(archive.read(name), name)
                          for name in archive.namelist() if name != 'manifest.json'}
    finally:
        generator.OUT = previous

    receipts = []
    for case_id, (kind, prefixes) in CASES.items():
        expectations = [e for e in source_key['expectations'] if e['name'].startswith(prefixes)]
        assert len(expectations) == len(prefixes), 'missing source scenario'
        wanted = {uid for e in expectations for uid in e['record_ids']}
        # The source includes an exact and timezone-equivalent re-export for a
        # separate deduplication scenario. This pilot selects unique occurrences.
        selected = {name: [row for row in rows if row['record_id'] in wanted]
                    for name, rows in source.items() if name != 'windows/Sysmon_reexport.jsonl'}
        selected = {name: rows for name, rows in selected.items() if rows}
        blobs = {}
        inventory = {}
        for name, rows in selected.items():
            for row in rows:
                uid = row['record_id']
                assert uid not in inventory, 'duplicate source occurrence'
                row = dict(row)
                row['uid'] = str(uuid5(NAMESPACE_URL, f'specula-pilot-v1/{case_id}/{uid}'))
                row['trace_id'] = row['uid']
                inventory[uid] = {'source_file': name, 'record': row}
                adapt_export(row, SOURCE_FOLDERS[name.split('/')[0]], name)
            records = [inventory[row['record_id']]['record'] for row in rows]
            blobs[name] = (''.join(json.dumps(row, sort_keys=True) + '\n' for row in records).encode()
                           if name.endswith('.jsonl') else encoded(records))
        assert set(inventory) == wanted
        manifest = {'fixture_id': case_id, 'synthetic': True,
                    'description': 'Inert synthetic development pilot; no acquired incident evidence.',
                    'files': {name: {'sha256': sha256(blob).hexdigest(), 'size_bytes': len(blob)}
                              for name, blob in blobs.items()}}
        blobs['manifest.json'] = encoded(manifest)
        path = OUT / f'{case_id}.zip'
        archive_bytes(path, blobs)
        first = path.read_bytes()
        archive_bytes(path, blobs)
        assert path.read_bytes() == first, 'non-deterministic ZIP serialization'
        receipt = validate_archive(first)
        assert sum(f['records'] for f in receipt['files']) == len(wanted)
        # Source times are comparable only on the same known host, excluding the
        # explicitly unsynchronized FS-02 clock in case-003. These are ordering
        # observations, never causal labels.
        pairs = []
        for left, a in inventory.items():
            for right, b in inventory.items():
                ar, br = a['record'], b['record']
                if (ar.get('host') and ar.get('host') == br.get('host')
                        and not (case_id == 'case-003' and ar['host'] == 'FS-02')
                        and datetime.fromisoformat(ar['timestamp'].replace('Z', '+00:00'))
                        < datetime.fromisoformat(br['timestamp'].replace('Z', '+00:00'))):
                    pairs.append([left, right])
        key = {'case_id': case_id, 'synthetic': True, 'scenario': kind,
               'annotation_status': 'developer-authored; independent review pending',
               'archive_sha256': sha256(first).hexdigest(), 'events': inventory,
               'required_observations': expectations, 'comparable_recorded_time_pairs': sorted(pairs),
               'ordering_scope': 'Same-host source chronology; not independently established causal order.',
               'entity_relationship_labels': None,
               'causal_labels': None,
               'independent_claim_annotations': None,
               'limitations': source_key['required_caveats']}
        (OUT / f'{case_id}-answer-key.json').write_bytes(encoded(key))
        with ZipFile(path) as archive:
            assert set(archive.namelist()) == set(blobs)
            assert all('answer-key' not in name for name in archive.namelist())
            for item in receipt['files']:
                assert item['sha256'] == manifest['files'][item['path']]['sha256']
        receipts.append({'case_id': case_id, 'records': len(wanted),
                         'source_files': len(selected), 'observations': len(expectations),
                         'comparable_time_pairs': len(pairs), 'sha256': sha256(first).hexdigest()})

    worksheet = OUT / 'runs.csv'
    # Preserve any measurements entered after preparation.
    if not worksheet.exists():
        fields = ['case_id', 'configuration', 'repeat', 'status', 'model', 'hardware',
                  'prompt_sha256', 'retrieval_budget', 'start_utc', 'end_utc',
                  'compute_seconds', 'human_wait_seconds', 'report_path', 'reviewer',
                  'event_tp', 'event_fp', 'event_fn', 'ordered_correct', 'ordered_total',
                  'relationship_tp', 'relationship_fp', 'relationship_fn',
                  'critical_retained', 'critical_total', 'unsupported', 'contradicted',
                  'factual_claims', 'supported_cited_claims', 'evaluated_cited_claims']
        with worksheet.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for case_id in CASES:
                for configuration in ('single-agent-rag', 'multi-agent-rag', 'specula'):
                    for repeat in range(1, 4):
                        writer.writerow(dict(case_id=case_id, configuration=configuration,
                                             repeat=repeat, status='not_run'))
    result = {'scope': 'Synthetic pilot preparation only; no model accuracy results',
              'checks': 'ZIP preflight, aliases, references, hashes, deterministic bytes, separate keys',
              'cases': receipts, 'runs_executed': 0,
              'source_generator_sha256': sha256(Path(generator.__file__).read_bytes()).hexdigest()}
    (OUT / 'preparation-validation.json').write_bytes(encoded(result))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    prepare()
