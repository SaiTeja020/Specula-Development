"""Offline synthetic compression replay and structured, case-local claim scoring."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import random
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def text(value, context):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{context} must be non-empty text')
    return value


def string_list(value, context):
    if not isinstance(value, list):
        raise ValueError(f'{context} must be a list')
    return [text(item, context) for item in value]


def entity_set(value):
    if not isinstance(value, list):
        raise ValueError('entities must be a list of typed values')
    result = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError('entity must be an object')
        result.add((text(item.get('type'), 'entity type'),
                    text(item.get('value'), 'entity value')))
    return result


def score_claims(evidence, report, annotations=None):
    """Score explicit atomic claims; never infer entailment from UID existence."""
    if not isinstance(evidence, dict) or not isinstance(report, dict):
        raise ValueError('evidence and report must be objects')
    case_id = text(evidence.get('case_id'), 'case_id')
    if report.get('case_id') != case_id:
        raise ValueError('report/evidence case mismatch')
    uids = string_list(evidence.get('uids'), 'uids')
    if len(uids) != len(set(uids)):
        raise ValueError('duplicate evidence UID')
    known_uids = set(uids)
    inventory = entity_set(evidence.get('entities'))
    claims = report.get('claims')
    if not isinstance(claims, list):
        raise ValueError('claims must be a list')
    labels = {}
    if annotations is not None:
        if not isinstance(annotations, dict) or annotations.get('case_id') != case_id:
            raise ValueError('annotation case mismatch')
        labels = annotations.get('support')
        if not isinstance(labels, dict) or any(type(v) is not bool for v in labels.values()):
            raise ValueError('support must map claim IDs to adjudicated booleans')
    seen = set()
    citations = []
    entities = set()
    uncited = 0
    for claim in claims:
        if not isinstance(claim, dict):
            raise ValueError('claim must be an object')
        uid = text(claim.get('id'), 'claim id')
        text(claim.get('text'), 'claim text')
        if uid in seen:
            raise ValueError('duplicate claim id')
        seen.add(uid)
        refs = string_list(claim.get('dfkg_refs'), 'dfkg_refs')
        citations.extend(refs)
        uncited += not refs
        entities.update(entity_set(claim.get('entities')))
        if labels.get(uid) is True and (not refs or not set(refs) <= known_uids):
            raise ValueError('supported annotation requires valid case citations')
    if labels.keys() - seen:
        raise ValueError('annotations reference unknown claims')
    fabricated = entities - inventory
    invalid = [ref for ref in citations if ref not in known_uids]
    unsupported = sum(not label for label in labels.values())
    return {
        'case_id': case_id, 'claim_count': len(claims),
        'citation_count': len(citations), 'invalid_citations': invalid,
        'citation_validity': ratio(len(citations) - len(invalid), len(citations)),
        'uncited_claim_count': uncited, 'entity_count': len(entities),
        'fabricated_entities': [dict(type=t, value=v) for t, v in sorted(fabricated)],
        'fabricated_entity_rate': ratio(len(fabricated), len(entities)),
        'adjudicated_claim_count': len(labels),
        'annotation_coverage': ratio(len(labels), len(claims)),
        'adjudicated_unsupported_rate': ratio(unsupported, len(labels)),
        'unsupported_claim_rate': ratio(unsupported, len(claims))
        if len(labels) == len(claims) else None,
        'scope': 'Structured inventories only; UID validity is not entailment. '
                 'Support labels must come from independent adjudication, never the producer.',
    }


def planted_case(seed=1337, routine=1000, needles=12):
    """Return OCSF-shaped synthetic records and an out-of-band answer key."""
    if routine < 1 or needles < 1:
        raise ValueError('routine and needles must be positive')
    rng = random.Random(seed)
    events, gold = [], []
    for index in range(routine + needles):
        planted = index >= routine
        sequence = index - routine
        command = 'C:\\Windows\\System32\\svchost.exe -k netsvcs'
        if planted:
            # Include low-entropy near-template needles, not only obvious random strings.
            command = ('powershell.exe -EncodedCommand ' +
                       ''.join(rng.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=80))) \
                if sequence % 2 else f'C:\\Windows\\System32\\svchost.exe -k needle-{sequence}'
        event = {
            'uid': digest({'seed': seed, 'index': index}),
            'class_uid': 1007, 'category_uid': 1, 'activity_id': 1,
            'host': 'SYNTHETIC-HOST', 'event_id': 4688,
            'process_name': 'powershell.exe' if planted and sequence % 2 else 'svchost.exe',
            'command_line': command, 'message': command,
            'time': 1790812800000 + index * 1000,
            'metadata': {'version': '1.3.0', 'product': {'name': 'Specula synthetic replay'}},
        }
        events.append(event)
        if planted:
            gold.append({'uid': event['uid'], 'entity': command})
    rng.shuffle(events)
    return events, gold


def compression_metrics(events, output, gold):
    # Round-trip is intentional: hidden CompactUIDList.all_uids is not evidence on wire.
    wire = json.loads(encoded(output))
    def strings(value):
        if isinstance(value, str):
            return {value}
        if isinstance(value, dict):
            return set().union(set(), *(strings(v) for v in value.values()))
        if isinstance(value, list):
            return set().union(set(), *(strings(v) for v in value))
        return set()
    values = strings(wire)
    record_uids = {row.get('uid') for row in wire if not
                   (row.get('is_summary') or row.get('summary') or row.get('_distillation_summary'))}
    retained = [item['uid'] for item in gold if item['uid'] in record_uids]
    entities = {item['entity'] for item in gold}
    raw_size, output_size = len(encoded(events)), len(encoded(output))
    return {'input_bytes': raw_size, 'output_bytes': output_size,
            'byte_reduction': 1 - output_size / raw_size,
            'gold_anomalies': len(gold), 'retained_anomalies': len(retained),
            'anomaly_retention': ratio(len(retained), len(gold)),
            'gold_entities': len(entities), 'retained_entities': len(entities & values),
            'entity_retention': ratio(len(entities & values), len(entities)),
            'missing_anomaly_uids': sorted({item['uid'] for item in gold} - set(retained)),
            'output_sha256': digest(output)}


def replay(seed=1337, routine=1000, needles=12):
    from src.ingestion.abstraction.entropy_clusterer import compress_batch
    from src.ingestion.distillation.distillation_layer import DistillationLayer
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig

    def template_only(rows):
        miner = TemplateMiner(config=TemplateMinerConfig())
        counts = {}
        for row in rows:
            cluster_id = miner.add_log_message(row['message'])['cluster_id']
            counts[cluster_id] = counts.get(cluster_id, 0) + 1
        return [{'template': cluster.get_template(), 'count': counts[cluster.cluster_id]}
                for cluster in miner.drain.clusters]

    events, gold = planted_case(seed, routine, needles)
    original_hash = digest(events)
    sample_size = max(1, len(events) // 10)
    methods = {
        'identity': lambda rows: rows,
        'random_10_percent': lambda rows: random.Random(seed).sample(rows, sample_size),
        'drain3_template_only': template_only,
        'entropy_compressor': compress_batch,
        'pipeline_distillation': lambda rows: DistillationLayer(entropy_threshold=0.3).process_batch(rows),
    }
    results = {}
    for name, method in methods.items():
        start = time.perf_counter()
        output = method(deepcopy(events))
        elapsed = time.perf_counter() - start
        results[name] = compression_metrics(events, output, gold)
        results[name]['elapsed_seconds'] = elapsed
    assert digest(events) == original_hash
    return {'schema_version': 1, 'kind': 'synthetic_component_replay',
            'seed': seed, 'routine': routine, 'needles': needles,
            'input_sha256': original_hash, 'gold_sha256': digest(gold),
            'gold_excluded_from_inputs': True, 'results': results,
            'parameters': {'random_fraction': 0.1, 'distillation_entropy_threshold': 0.3,
                           'template_only': 'fresh Drain3 default miner; final templates and counts'},
            'scope': 'Synthetic component observations only; no system accuracy, '
                     'model hallucination, entailment or production performance claim.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    planted = sub.add_parser('planted')
    planted.add_argument('--seed', type=int, default=1337)
    planted.add_argument('--routine', type=int, default=1000)
    planted.add_argument('--needles', type=int, default=12)
    claims = sub.add_parser('claims')
    claims.add_argument('evidence', type=Path)
    claims.add_argument('report', type=Path)
    claims.add_argument('--annotations', type=Path)
    for child in (planted, claims):
        child.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'planted':
            result = replay(args.seed, args.routine, args.needles)
        else:
            inputs = [args.evidence, args.report]
            if args.annotations:
                inputs.append(args.annotations)
            if args.output.resolve() in {path.resolve() for path in inputs}:
                raise ValueError('output must not overwrite an input artifact')
            payloads = [path.read_bytes() for path in inputs]
            result = score_claims(*(json.loads(data.decode('utf-8-sig')) for data in payloads))
            result['input_sha256'] = {
                name: hashlib.sha256(data).hexdigest()
                for name, data in zip(('evidence', 'report', 'annotations'), payloads)}
        revision = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True)
        status = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True)
        result['provenance'] = {'git_revision': revision.stdout.strip() or None,
                                'working_tree_dirty': bool(status.stdout) if status.returncode == 0 else None,
                                'python': sys.version.split()[0],
                                'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        if args.command == 'planted':
            result['provenance']['packages'] = {name: version(name) for name in
                                                ('drain3', 'datasketch', 'numpy', 'scikit-learn')}
            root = Path(__file__).resolve().parent.parent
            result['provenance']['compressor_sha256'] = {
                str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (root / 'src/ingestion/abstraction/entropy_clusterer.py',
                             root / 'src/ingestion/distillation/distillation_layer.py')}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(encoded(result) + b'\n')
    except (ValueError, OSError, TypeError, KeyError) as exc:
        parser.exit(2, f'Evaluation input/error: {exc}\n')
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
