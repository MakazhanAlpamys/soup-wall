# SPDX-License-Identifier: Apache-2.0
"""Prepare a learned reference candidate; approved datasets are required for a pilot.

Training and calibration are separate from an explicit, once-per-artifact
holdout evaluation. The smoke command uses development-only synthetic data.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import statistics
import time
import tracemalloc

from experiments.local_classifier.model import (
    ACTIONS, HEADS, Config, LinearClassifier, check_labels, input_identity,
)

SPLITS = ('train', 'calibration', 'holdout')


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path, limit: int) -> tuple[dict, str]:
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError('JSON file exceeds byte limit')
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('non-finite JSON constant')
    record = json.loads(data.decode('utf-8'), object_pairs_hook=object_pairs, parse_constant=constant)
    if not isinstance(record, dict):
        raise ValueError('JSON object required')
    return record, hashlib.sha256(data).hexdigest()


def write_json(path: Path, record: dict) -> None:
    path.write_text(json.dumps(record, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def validate_dataset(record: dict) -> dict[str, list[dict]]:
    if not isinstance(record, dict) or record.get('format') != 'soup-wall/classifier-dataset/1':
        raise ValueError('unsupported experimental dataset format')
    rows = record.get('cases')
    if not isinstance(rows, list) or not rows or len(rows) > 10000:
        raise ValueError('dataset must contain 1..10000 cases')
    ids, families, identities = set(), {}, {}
    splits = {s: [] for s in SPLITS}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'id', 'family', 'split', 'input', 'labels'}:
            raise ValueError('unexpected or missing dataset row fields')
        case_id, family, split = row['id'], row['family'], row['split']
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            raise ValueError('case identifiers must be unique nonempty strings')
        if not isinstance(family, str) or not family or split not in SPLITS:
            raise ValueError('family and explicit split required')
        if family in families and families[family] != split:
            raise ValueError('tool family leaked across splits')
        identity = input_identity(row['input'])
        if identity in identities and identities[identity] != split:
            raise ValueError('semantic duplicate leaked across splits')
        check_labels(row['labels'])
        ids.add(case_id)
        families[family], identities[identity] = split, split
        splits[split].append(row)
    if any(not splits[s] for s in SPLITS):
        raise ValueError('nonempty train, calibration and holdout splits required')
    return splits


def load_approved(dataset: Path, approval: Path) -> tuple[dict, dict]:
    review, _ = read_json(approval, 16384)
    if review.get('format') != 'soup-wall/classifier-data-approval/1':
        raise ValueError('explicit external dataset review required')
    if any(not isinstance(review.get(k), str) or not review[k].strip()
           for k in ('approval_reference', 'source', 'license')):
        raise ValueError('review reference, source and dataset license required')
    record, dataset_hash = read_json(dataset, 16 * 1024 * 1024)
    if review.get('dataset_sha256') != dataset_hash:
        raise ValueError('dataset does not match the reviewed immutable digest')
    return validate_dataset(record), review


def reserve_reviewed_run(authorization_path: Path, ledger_dir: Path, model_dir: Path,
                         dataset_hash: str, model_hash: str, baseline_hash: str) -> tuple[Path, dict]:
    """Consume a custodian-issued run in a shared ledger before holdout inference.

    JSON records assert review; they do not authenticate the reviewer. The custodian
    must control the ledger's location and preserve it across artifact copies/runs.
    """
    model_root = model_dir.resolve()
    if (ledger_dir.resolve().is_relative_to(model_root)
            or authorization_path.resolve().is_relative_to(model_root)):
        raise ValueError('run authorization and shared ledger must be outside model artifacts')
    if not ledger_dir.is_dir():
        raise ValueError('existing custodian-managed run ledger directory required')
    authorization, authorization_hash = read_json(authorization_path, 16384)
    required = {'format', 'run_id', 'holdout_id', 'approval_reference',
                'dataset_sha256', 'model_sha256', 'baseline_sha256'}
    if set(authorization) != required or authorization['format'] != 'soup-wall/classifier-run-authorization/1':
        raise ValueError('unsupported or incomplete external run authorization')
    for key in ('run_id', 'holdout_id', 'approval_reference'):
        value = authorization[key]
        if not isinstance(value, str) or not value.strip() or len(value) > 2048:
            raise ValueError('nonempty bounded run identity and review reference required')
    for key, expected in (('dataset_sha256', dataset_hash), ('model_sha256', model_hash),
                          ('baseline_sha256', baseline_hash)):
        value = authorization[key]
        if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) or value != expected:
            raise ValueError('run authorization does not match frozen ' + key)
    # The holdout identity is issued by the custodian and stays fixed even when a
    # caller copies artifacts, changes run_id or rebuilds a dataset wrapper/model.
    key = hashlib.sha256(authorization['holdout_id'].encode('utf-8')).hexdigest()
    journal = ledger_dir / (key + '.reserved.json')
    reservation = {'format': 'soup-wall/classifier-run-reservation/1',
                   'authorization': authorization, 'authorization_sha256': authorization_hash,
                   'reserved_at': datetime.now(timezone.utc).isoformat(),
                   'state': 'reserved_attempt_consumed'}
    with journal.open('x', encoding='utf-8') as handle:
        handle.write(json.dumps(reservation, indent=2, allow_nan=False) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    return journal, reservation


def peak_rss_bytes() -> int | None:
    if os.name == 'nt':
        from ctypes import wintypes
        class MemoryCounters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                       ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                       ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                       ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                       ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]
        counters = MemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = (wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD)
        if psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            return int(counters.PeakWorkingSetSize)
        return None
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(rss if platform.system() == 'Darwin' else rss * 1024)
    except (ImportError, OSError):
        return None


def environment() -> dict:
    return {'python': platform.python_version(), 'platform': platform.platform(),
            'machine': platform.machine(), 'processor': platform.processor(),
            'logical_cpus': os.cpu_count(), 'gpu_used': False,
            'peak_process_rss_bytes': peak_rss_bytes(),
            'source_sha256': {p.name: digest(p) for p in (Path(__file__), Path(__file__).with_name('model.py'))}}


def train_model(train: list[dict], calibration: list[dict], config: Config) -> tuple[LinearClassifier, dict]:
    candidate = LinearClassifier(config)
    tracemalloc.start()
    start = time.perf_counter()
    try:
        training = candidate.fit(train)
        calibration_result = candidate.calibrate(calibration)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return candidate, {'config': asdict(config), 'training': training,
                       'calibration': calibration_result, 'elapsed_s': time.perf_counter() - start,
                       'peak_traced_python_bytes': peak, 'environment': environment()}


def validate_prediction(out: dict) -> None:
    if not isinstance(out, dict) or type(out.get('unknown')) is not bool:
        raise ValueError('invalid classification core')
    actions = out.get('actions')
    if not isinstance(actions, list) or any(a not in ACTIONS for a in actions) or len(actions) != len(set(actions)):
        raise ValueError('invalid action set')
    if out.get('status') == 'error':
        raise ValueError('baseline reported a technical failure')


def evaluate(rows: list[dict], classify) -> dict:
    results, latencies = [], []
    per_label = {a: {'known': 0, 'positive': 0, 'negative': 0, 'fn': 0, 'fp': 0} for a in ACTIONS}
    unknown = {'known': 0, 'lost_unknown': 0, 'false_unknown': 0}
    valid = abstentions = exact = fully_annotated = mixed = mixed_exact = 0
    for row in rows:
        start = time.perf_counter()
        try:
            # Nothing from id/family/split/gold labels reaches inference.
            out = classify(json.loads(json.dumps(row['input'])))
            validate_prediction(out)
        except Exception as exc:
            results.append({'id': row['id'], 'technical_error_type': type(exc).__name__})
            latencies.append((time.perf_counter() - start) * 1000)
            continue
        latencies.append((time.perf_counter() - start) * 1000)
        valid += 1
        abstentions += int(out['unknown'])
        gold = row['labels']
        for a in ACTIONS:
            if gold[a] is None:
                continue
            values = per_label[a]
            values['known'] += 1
            values['positive' if gold[a] else 'negative'] += 1
            values['fn'] += int(gold[a] and a not in out['actions'])
            values['fp'] += int(not gold[a] and a in out['actions'])
        if gold['unknown'] is not None:
            unknown['known'] += 1
            unknown['lost_unknown'] += int(gold['unknown'] and not out['unknown'])
            unknown['false_unknown'] += int(not gold['unknown'] and out['unknown'])
        all_known = all(gold[h] is not None for h in HEADS)
        expected = [a for a in ACTIONS if gold[a] is True]
        match = set(expected) == set(out['actions']) and gold['unknown'] == out['unknown']
        if all_known:
            fully_annotated += 1
            exact += int(match)
        if all_known and len(expected) > 1:
            mixed += 1
            mixed_exact += int(match)
        results.append({'id': row['id'], 'actions': out['actions'], 'unknown': out['unknown'],
                        'fully_annotated': all_known, 'exact_match': match if all_known else None})
    ordered = sorted(latencies)
    for values in per_label.values():
        values['fn_rate'] = values['fn'] / values['positive'] if values['positive'] else None
        values['fp_rate'] = values['fp'] / values['negative'] if values['negative'] else None
    return {'calls': len(rows), 'valid': valid, 'technical_errors': len(rows) - valid,
            'per_label': per_label, 'unknown': unknown, 'abstentions': abstentions,
            'coverage': (valid - abstentions) / valid if valid else None,
            'fully_annotated': fully_annotated, 'exact_matches': exact,
            'mixed_cases': mixed, 'mixed_exact_matches': mixed_exact,
            'latency': {'p50_ms': statistics.median(ordered) if ordered else None,
                        'p95_ms': ordered[max(0, math_ceil_95(len(ordered)) - 1)] if ordered else None},
            'cases': results}


def math_ceil_95(count: int) -> int:
    return (95 * count + 99) // 100


def load_baseline(path: Path):
    source = path / 'rule_baseline.py'
    spec = importlib.util.spec_from_file_location('soup_pilot_external_baseline', source)
    if spec is None or spec.loader is None:
        raise ValueError('external baseline module unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.classify, digest(source)


def toy_data() -> dict:
    """Developer plumbing examples only, never an approved training dataset."""
    rows = []
    for split, suffix in (('train', 'alpha'), ('calibration', 'beta'), ('holdout', 'gamma')):
        examples = [('read_file', {'path': f'{suffix}/notes.txt'}, ['read']),
                    ('write_file', {'path': f'{suffix}/notes.txt', 'content': 'hello'}, ['write']),
                    ('delete_file', {'path': f'{suffix}/old.txt'}, ['delete']),
                    ('send_email', {'recipient': 'fixture@example.invalid', 'body': suffix}, ['send_data']),
                    ('chmod_file', {'path': f'{suffix}/notes.txt', 'mode': '600'}, ['change_permissions']),
                    ('upload_file', {'path': f'{suffix}/notes.txt', 'destination': 'https://fixture.invalid'}, ['read', 'send_data']),
                    ('opaque_tool', {'value': suffix}, None),
                    ('read_then_opaque', {'path': f'{suffix}/notes.txt', 'callback': 'opaque'}, ['read'])]
        for index, (name, arguments, actions) in enumerate(examples):
            labels = {a: None if actions is None else a in actions for a in ACTIONS}
            unresolved = actions is None or name == 'read_then_opaque'
            if name == 'read_then_opaque':
                labels.update({a: None for a in ACTIONS if a != 'read'})
            labels['unknown'] = unresolved
            rows.append({'id': f'{split}-{index}', 'family': f'{split}-toy-{index}', 'split': split,
                         'input': {'tool_name': name, 'raw_arguments': arguments,
                                   'tool_description': 'Developer-only synthetic example'}, 'labels': labels})
    return {'format': 'soup-wall/classifier-dataset/1', 'cases': rows}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('mode', choices=['smoke', 'train', 'evaluate'])
    parser.add_argument('--dataset', type=Path)
    parser.add_argument('--approval', type=Path)
    parser.add_argument('--output-dir', type=Path, default=Path('target/local-classifier-smoke'))
    parser.add_argument('--model-dir', type=Path)
    parser.add_argument('--baseline-path', type=Path)
    parser.add_argument('--run-authorization', type=Path)
    parser.add_argument('--run-ledger-dir', type=Path)
    parser.add_argument('--epochs', type=int, default=60)
    parser.add_argument('--dimensions', type=int, default=512)
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args(argv)
    if args.mode != 'smoke' and (args.dataset is None or args.approval is None):
        parser.error('approved dataset and digest-matching review file are required')
    config = Config(epochs=args.epochs, dimensions=args.dimensions, seed=args.seed)
    if args.mode in ('train', 'smoke'):
        if args.output_dir.exists() and any(args.output_dir.iterdir()):
            raise ValueError('output directory must be new or empty; preserve frozen evidence')
        if args.mode == 'smoke':
            splits, approval = validate_dataset(toy_data()), None
        else:
            splits, approval = load_approved(args.dataset, args.approval)
        # No holdout rows are passed into fitting or threshold selection.
        model, report = train_model(splits['train'], splits['calibration'], config)
        report.update({'format': 'soup-wall/local-classifier-training/1',
                       'mode': 'development_smoke' if args.mode == 'smoke' else 'approved_training',
                       'approval': approval, 'official_heldout_run': False,
                       'api_requests': 0, 'api_cost_usd': 0, 'tool_executions': 0,
                       'recommendation': 'await_candidate_and_training_dataset_review'})
        if args.mode == 'smoke':
            report['development_probe'] = evaluate(splits['holdout'], model.classify)
            if args.baseline_path:
                baseline, baseline_hash = load_baseline(args.baseline_path)
                report['development_baseline'] = evaluate(splits['holdout'], baseline)
                report['baseline_sha256'] = baseline_hash
        args.output_dir.mkdir(parents=True, exist_ok=True)
        write_json(args.output_dir / 'model.json', model.artifact())
        report['model_sha256'] = digest(args.output_dir / 'model.json')
        write_json(args.output_dir / 'training.json', report)
        print(json.dumps({'mode': report['mode'], 'elapsed_s': report['elapsed_s'],
                          'peak_process_rss_bytes': report['environment']['peak_process_rss_bytes'],
                          'official_heldout_run': False, 'output': str(args.output_dir)}))
        return 0
    if any(value is None for value in (args.model_dir, args.baseline_path,
                                      args.run_authorization, args.run_ledger_dir)):
        parser.error('evaluate requires frozen model/baseline, external run authorization and shared ledger')
    splits, approval = load_approved(args.dataset, args.approval)
    training, _ = read_json(args.model_dir / 'training.json', 65536)
    model_path = args.model_dir / 'model.json'
    if training.get('mode') != 'approved_training' or training.get('approval') != approval:
        raise ValueError('frozen model provenance does not match this reviewed dataset')
    artifact, model_hash = read_json(model_path, 16 * 1024 * 1024)
    if training.get('model_sha256') != model_hash:
        raise ValueError('frozen model changed after calibration')
    model = LinearClassifier.restore(artifact)
    if not model.calibrated:
        raise ValueError('model must be calibrated separately before holdout evaluation')
    baseline, baseline_hash = load_baseline(args.baseline_path)
    # Validate the local marker before consuming the external run, then reserve
    # centrally first. A failure after reservation still consumes the attempt.
    journal = args.model_dir / ('.holdout-' + approval['dataset_sha256'] + '.reserved')
    if journal.exists():
        raise FileExistsError('holdout already reserved in this artifact directory')
    external_journal, reservation = reserve_reviewed_run(
        args.run_authorization, args.run_ledger_dir, args.model_dir,
        approval['dataset_sha256'], model_hash, baseline_hash)
    # Reserve before first inference. A failed run is still consumed and retained.
    with journal.open('x', encoding='utf-8') as handle:
        handle.write(json.dumps({'dataset_sha256': approval['dataset_sha256'],
                                 'model_sha256': model_hash, 'baseline_sha256': baseline_hash}) + '\n')
    report = {'format': 'soup-wall/local-classifier-evaluation/1', 'mode': 'approved_shadow_pilot',
              'official_heldout_run': True, 'approval': approval,
              'model_sha256': model_hash, 'baseline_sha256': baseline_hash,
              'reviewed_run': reservation,
              'environment': environment(), 'candidate': evaluate(splits['holdout'], model.classify),
              'baseline': evaluate(splits['holdout'], baseline),
              'api_requests': 0, 'api_cost_usd': 0, 'tool_executions': 0,
              'recommendation': 'manual_continue_revise_or_reject_review_required'}
    write_json(args.model_dir / 'evaluation.json', report)
    receipt = {'format': 'soup-wall/classifier-run-result/1',
               'reservation_sha256': digest(external_journal),
               'evaluation_sha256': digest(args.model_dir / 'evaluation.json'),
               'completed_at': datetime.now(timezone.utc).isoformat(),
               'run_id': reservation['authorization']['run_id'],
               'holdout_id': reservation['authorization']['holdout_id']}
    with external_journal.with_suffix('.result.json').open('x', encoding='utf-8') as handle:
        handle.write(json.dumps(receipt, indent=2, allow_nan=False) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    print('Held-out shadow evidence retained; no runtime adoption or execution authority granted.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
