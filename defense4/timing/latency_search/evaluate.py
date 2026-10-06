#!/usr/bin/env python3
"""Grouped development attacks on the new latency campaign, with per-policy caching."""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
import hashlib
import json
import os
from pathlib import Path

import numpy as np
import sklearn
from sklearn.metrics import balanced_accuracy_score
from sklearn.model_selection import GridSearchCV, LeaveOneGroupOut

import analysis as a

HERE = Path(__file__).resolve().parent
SEED = 20260926
PARAMS = {
    'rf': {'randomforestclassifier__min_samples_leaf': [1, 3, 10]},
    'logistic': {'logisticregression__C': [0.1, 1.0, 10.0]},
    'rbf_svm': {'svc__C': [0.1, 1.0, 10.0]},
}


def read_rows(path):
    with path.open() as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        for key in ('ack_ms', 'clrt_ms', 'rt_ms', 'request_gap_ms'):
            row[key] = float(row[key]) if row.get(key) else None
        row['txn_index'] = int(row.get('txn_index') or 0)
    return rows


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')
    temporary.replace(path)


def train(model, rows, features, tune):
    x = a._pooled_feature_matrix(rows, features)
    y = np.asarray([r['txn_class'] for r in rows])
    groups = np.asarray([r['session'] for r in rows])
    estimator = a._model(model)
    # Avoid hundreds of threads per small forest; this does not change its model.
    if model == 'rf':
        estimator.set_params(randomforestclassifier__n_jobs=1)
    chosen = {}
    if tune:
        estimator = GridSearchCV(estimator, PARAMS[model], scoring='balanced_accuracy',
                                 cv=LeaveOneGroupOut(), n_jobs=1, refit=True, error_score='raise')
        estimator.fit(x, y, groups=groups)
        chosen = estimator.best_params_
    else:
        estimator.fit(x, y)
    return estimator, chosen


def score(estimator, rows, features):
    return float(balanced_accuracy_score([r['txn_class'] for r in rows],
                                        estimator.predict(a._pooled_feature_matrix(rows, features))))


def bounds(records, family, confidence=0.975):
    selected = [r for r in records if r['scenario'] != 'fixed_on_native' and
                (family == 'all_timing' or r['feature'] in ('clrt', 'ack_clrt'))]
    matrix = np.asarray([r['fold_scores'] for r in selected])
    means = matrix.mean(axis=1)
    rng = np.random.default_rng(SEED)
    # The SAME replicate resample is used for every attack, preserving covariance.
    draws = rng.integers(matrix.shape[1], size=(5000, matrix.shape[1]))
    delta = (matrix[:, draws].mean(axis=2) - means[:, None]).max(axis=0)
    margin = max(0.0, float(np.quantile(delta, confidence)))
    best = int(means.argmax())
    upper = min(1.0, float(means[best] + margin))
    return {'max_accuracy': float(means[best]), 'upper_bound': upper,
            'confidence_per_task': confidence, 'n_groups': matrix.shape[1],
            'margin': margin, 'strongest_attack': {k: selected[best][k] for k in
                ('model', 'feature', 'pool', 'scenario')},
            'method': 'centered paired-group bootstrap, maximum deviation over protected attacks',
            'scope': 'development screening; approximate uncertainty from acquisition repetitions'}


def evaluate(rows, name, quick=False):
    native = [r for r in rows if r['arm'] == 'native']
    protected = [r for r in rows if r['policy_name'] == name]
    groups = sorted({r['session'] for r in native} & {r['session'] for r in protected})
    if len(groups) < (2 if quick else 5):
        raise ValueError('Not enough paired repetitions for ' + name)
    native = [r for r in native if r['session'] in groups]
    protected = [r for r in protected if r['session'] in groups]
    for group in groups:
        for arm in (native, protected):
            counts = [sum(r['session']==group and r['txn_class']==c for r in arm) for c in a.CLASSES]
            if counts != [100, 100, 100]:
                raise ValueError('Incomplete paired group: %s %s' % (group, counts))
    result = {'policy': name, 'groups': groups, 'quick': quick,
              'complete_attack_coverage': not quick, 'tasks': {}}
    for task, classes in [('three_class', a.CLASSES), ('read_select', a.BINARY_CLASSES)]:
        records = []
        for pool in ((1,) if quick else (1, 5, 20)):
            pooled = a.pooled_rows([r for r in native+protected if r['txn_class'] in classes], pool)
            for features in (('ack_clrt',) if quick else a.FEATURE_SETS):
                for model in (('rf',) if quick else PARAMS):
                    scores = {s: [] for s in ('fixed_on_native', 'fixed_on_obfuscated', 'adaptive_on_obfuscated')}
                    settings = []
                    for group in groups:
                        split = {(arm, train_set): [r for r in pooled if r['arm']==arm and
                            ((r['session'] != group) if train_set else (r['session'] == group))]
                            for arm in ('native', 'obfuscated') for train_set in (False, True)}
                        fixed, fp = train(model, split['native', True], features, not quick)
                        adaptive, ap = train(model, split['obfuscated', True], features, not quick)
                        scores['fixed_on_native'].append(score(fixed, split['native', False], features))
                        scores['fixed_on_obfuscated'].append(score(fixed, split['obfuscated', False], features))
                        scores['adaptive_on_obfuscated'].append(score(adaptive, split['obfuscated', False], features))
                        settings.append({'held_out': group, 'fixed_params': fp, 'adaptive_params': ap})
                    for scenario, values in scores.items():
                        records.append({'model': model, 'feature': features, 'pool': pool,
                            'scenario': scenario, 'fold_scores': values, 'groups': groups,
                            'mean_accuracy': float(np.mean(values)), 'tuning': settings})
        envelopes = {family: bounds(records, family) for family in ('ack_response', 'all_timing')}
        chance = 1.0/len(classes)
        for envelope in envelopes.values():
            envelope['within_tested_subset_threshold'] = envelope['upper_bound'] <= chance+0.05
            envelope['passes_screen'] = not quick and envelope['within_tested_subset_threshold']
        result['tasks'][task] = {'chance': chance, 'threshold': chance+0.05,
                                'records': records, 'envelopes': envelopes}
    result['qualifies_for_selection'] = not quick and all(
        task['envelopes']['all_timing']['passes_screen'] for task in result['tasks'].values())
    return result


def cached_evaluate(rows, name, quick, cache_key, cache_dir):
    rows = [row for row in rows if row['arm'] == 'native' or row['policy_name'] == name]
    # Adding other policies to a growing campaign cannot change this paired dataset.
    # The aggregate output still records the SHA of the complete input CSV.
    cache_key = dict(cache_key)
    cache_key.pop('source_sha256')
    cache_key['paired_rows_sha256'] = hashlib.sha256(
        json.dumps(rows, sort_keys=True, allow_nan=False).encode()).hexdigest()
    cache = cache_dir/(name+'.json')
    old = json.loads(cache.read_text()) if cache.exists() else {}
    if old.get('cache_key') == cache_key:
        return old['result']
    entry = evaluate(rows, name, quick)
    save(cache, {'cache_key': cache_key, 'result': entry})
    return entry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--quick', action='store_true')
    parser.add_argument('--names', nargs='*')
    parser.add_argument('--jobs', type=int, default=1, help='Independent policy processes; each estimator uses one thread')
    args = parser.parse_args()
    rows = read_rows(args.input)
    source_sha = hashlib.sha256(args.input.read_bytes()).hexdigest()
    code_sha = hashlib.sha256(Path(__file__).read_bytes()+(HERE/'analysis.py').read_bytes()).hexdigest()
    names = sorted({r['policy_name'] for r in rows if r['arm']=='obfuscated'})
    if args.names:
        missing = sorted(set(args.names)-set(names))
        if missing:
            parser.error('Unknown policies: '+', '.join(missing))
        names = [name for name in names if name in args.names]
    if not names or args.jobs < 1:
        parser.error('At least one policy and one job are required')
    cache_key = {'source_sha256': source_sha, 'code_sha256': code_sha,
                 'quick': args.quick, 'sklearn_version': sklearn.__version__}
    result = dict(cache_key, tuning_grid=PARAMS, per_policy={})
    cache_dir = args.out.parent/('attack_cache_quick' if args.quick else 'attack_cache')
    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        pending = {executor.submit(cached_evaluate, rows, name, args.quick, cache_key, cache_dir): name
                   for name in names}
        print('EVALUATING', len(names), 'policies with', args.jobs, 'processes', flush=True)
        for future in as_completed(pending):
            name = pending[future]
            result['per_policy'][name] = future.result()
            save(args.out, result)
            print('DONE', name, {k:round(v['envelopes']['ack_response']['max_accuracy'],3)
                                for k,v in result['per_policy'][name]['tasks'].items()}, flush=True)


if __name__ == '__main__':
    main()
