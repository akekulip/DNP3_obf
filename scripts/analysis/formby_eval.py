#!/usr/bin/env python3
"""Formby et al. (NDSS 2016) transaction-class classifiers over the c72 evaluation rows.

Ported, not imported, from the archived paper estimator (Archive/.../seg61_02/analysis/publication_analysis.py:
histogram, make_windows, MultinomialNB, paired block bootstrap) and the archived Formby replication
(Archive/.../latency_search/formby_evaluation.py: one-hidden-layer FF-ANN). Added here: Formby's unsupervised GMM
on window [mean, variance] and his per-class accuracy/precision/recall as mean and minimum across classes.

Design: results/analysis/evaluation/DESIGN.json. Per D and arm: same-operation windows of K transactions inside one
block and arm; each window becomes Formby Eq. 1, a 200-bin count vector (199 equal bins on [0, H) plus an overflow
bin; x == H overflows, where Formby's Eq. 1 drops it) with H = 1.05 x the largest training value.
  * NB (alpha 1): train on repetitions 1-8, test on 9-16 (Formby's early/late split and the paper's protocol).
  * FF-ANN: Formby's random 75/25 split over all windows; hidden size from GroupKFold on the training part.
  * GMM: full covariance, 3 components, fitted without labels on training windows; Hungarian label matching.
Attackers: pre-deployment (trained on off at the same D, tested on each arm) and retrained per arm.

  $RESEARCH_PYTHON scripts/analysis/formby_eval.py ROWS_CSV --output OUT_DIR
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np
from scipy.optimize import linear_sum_assignment
from sklearn.mixture import GaussianMixture
from sklearn.model_selection import GroupKFold, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.neural_network import MLPClassifier

CLASSES = ('READ', 'SELECT', 'OPERATE')
ARMS = ('off', 'timing_only', 'size_only', 'combined')
FEATURES = {'clrt': ('clrt_ms',), 'size': ('resp_len',), 'joint': ('clrt_ms', 'resp_len')}
WINDOWS_K = (8, 32, 64)
TEST_REPETITIONS = tuple(range(9, 17))
HIDDEN_SIZES = (32, 100)
SEED = 20261027
BOOTSTRAP_RESAMPLES = 10000


def histogram(values, high):
    """Formby Eq. 1: 199 equal half-open bins on [0, H) and one overflow bin for x >= H."""
    if not np.isfinite(high) or high <= 0:
        raise ValueError('histogram H must be finite and positive')
    values = np.asarray(values, dtype=float)
    if not np.isfinite(values).all() or np.any(values < 0):
        raise ValueError('histogram values must be finite and non-negative')
    indices = np.minimum(np.floor(values / high * 199), 199).astype(int)
    return np.bincount(indices, minlength=200)


def make_windows(rows, feature, k):
    """Consecutive same-operation windows of k transactions, never crossing a block, arm or operation."""
    fields = FEATURES[feature]
    groups = {}
    for row in rows:
        if row['piggyback']:
            continue
        groups.setdefault((row['block_id'], row['arm'], row['operation']), []).append(row)
    windows = []
    for (block_id, arm, operation), members in sorted(groups.items()):
        members.sort(key=lambda r: r['seq'])
        for start in range(0, len(members) - k + 1, k):
            chunk = members[start:start + k]
            values = {field: [r[field] for r in chunk] for field in fields}
            windows.append(dict(block_id=block_id, arm=arm, operation=operation,
                                repetition=chunk[0]['repetition'], split=chunk[0]['split'],
                                values=values if len(fields) > 1 else values[fields[0]]))
    return windows


def fit_high(rows, feature):
    """H per field: 1.05 x the largest training value (training rows only; piggybacked rows excluded)."""
    fields = FEATURES[feature]
    train = [r for r in rows if r['split'] == 'train' and not r['piggyback']]
    highs = {field: max(1e-3, 1.05 * max(r[field] for r in train)) for field in fields}
    return highs if len(fields) > 1 else highs[fields[0]]


def signatures(windows, feature, high):
    fields = FEATURES[feature]
    if len(fields) == 1:
        return np.array([histogram(w['values'], high) for w in windows])
    return np.array([np.concatenate([histogram(w['values'][f], high[f]) for f in fields]) for w in windows])


def moments(windows, feature):
    """Formby's [mean, variance] per window, for every field of the feature (joint: CLRT and size)."""
    def per_field(window):
        values = window['values'] if isinstance(window['values'], dict) else {None: window['values']}
        return [stat for v in values.values() for stat in (np.mean(v), np.var(v, ddof=1))]
    return np.array([per_field(w) for w in windows])


def metrics(truth, prediction):
    """Formby's per-class accuracy, precision and recall (mean and minimum across classes), BA and confusion."""
    truth, prediction = list(truth), list(prediction)
    confusion = np.zeros((3, 3), dtype=int)
    for t, p in zip(truth, prediction):
        confusion[CLASSES.index(t), CLASSES.index(p)] += 1
    n = confusion.sum()
    result = dict(n=int(n), confusion=confusion.tolist(), accuracy={}, precision={}, recall={})
    for i, name in enumerate(CLASSES):
        tp = confusion[i, i]
        fn, fp = confusion[i].sum() - tp, confusion[:, i].sum() - tp
        tn = n - tp - fn - fp
        result['accuracy'][name] = float((tp + tn) / n) if n else None
        result['precision'][name] = float(tp / (tp + fp)) if tp + fp else 0.0
        result['recall'][name] = float(tp / (tp + fn)) if tp + fn else None
    for metric in ('accuracy', 'precision', 'recall'):
        values = [v for v in result[metric].values() if v is not None]
        result['mean_' + metric] = float(np.mean(values)) if values else None
        result['min_' + metric] = float(np.min(values)) if values else None
    recalls = [result['recall'][c] for c in CLASSES]
    result['balanced_accuracy'] = float(np.mean(recalls)) if None not in recalls else None
    return result


def block_bootstrap(per_block, seed=SEED, resamples=BOOTSTRAP_RESAMPLES):
    """95% interval of the mean over test blocks, resampling blocks with replacement."""
    keys = sorted(per_block)
    values = np.array([per_block[k] for k in keys], dtype=float)
    rng = np.random.default_rng(seed)
    sampled = values[rng.integers(0, len(values), size=(resamples, len(values)))].mean(axis=1)
    low, high = np.quantile(sampled, [0.025, 0.975])
    return dict(estimate=float(values.mean()), lower=float(low), upper=float(high), blocks=len(values),
                resamples=resamples, seed=seed)


def block_interval(per_block, test_repetitions, seed):
    """Bootstrap interval over test blocks, only when every test block has a balanced accuracy."""
    if not test_repetitions or sorted(per_block) != sorted(test_repetitions):
        return None, 'per-block BA available for test blocks %s of %s' % (sorted(per_block), sorted(test_repetitions))
    return block_bootstrap(per_block, seed), None


def per_block_ba(windows, prediction):
    result = {}
    for repetition in sorted({w['repetition'] for w in windows}):
        idx = [i for i, w in enumerate(windows) if w['repetition'] == repetition]
        truth = [windows[i]['operation'] for i in idx]
        if set(truth) == set(CLASSES):
            result[repetition] = metrics(truth, [prediction[i] for i in idx])['balanced_accuracy']
    return result


def nb_predict(train_windows, test_windows, feature, high):
    model = MultinomialNB(alpha=1.0).fit(signatures(train_windows, feature, high),
                                         [w['operation'] for w in train_windows])
    return list(model.predict(signatures(test_windows, feature, high)))


def gmm_predict(train_windows, test_windows, feature, seed):
    # Formby's raw [mean, variance] (no standardisation: it would inflate the narrow variance axis)
    train_x, test_x = moments(train_windows, feature), moments(test_windows, feature)
    model = GaussianMixture(3, covariance_type='full', random_state=seed, reg_covar=1e-6, n_init=10).fit(train_x)
    train_component = model.predict(train_x)
    cost = np.zeros((3, 3))
    for component, window in zip(train_component, train_windows):
        cost[component, CLASSES.index(window['operation'])] -= 1
    rows, cols = linear_sum_assignment(cost)
    mapping = {r: CLASSES[c] for r, c in zip(rows, cols)}
    return [mapping[c] for c in model.predict(test_x)]


def ann_evaluate(windows, feature, seed):
    """Formby's protocol: random 75/25 split of all windows; hidden size chosen on the training part only."""
    labels = [w['operation'] for w in windows]
    index = np.arange(len(windows))
    train_idx, test_idx = train_test_split(index, test_size=0.25, random_state=seed, stratify=labels)
    high = fit_high_from_windows([windows[i] for i in train_idx], feature)
    x = signatures(windows, feature, high) / float(len(windows[0]['values'] if not isinstance(
        windows[0]['values'], dict) else next(iter(windows[0]['values'].values()))))
    y = np.array(labels)
    groups = np.array([w['block_id'] for w in windows])
    best, best_score = HIDDEN_SIZES[0], -1.0
    folds = min(5, len(set(groups[train_idx])))
    for hidden in HIDDEN_SIZES:
        scores = []
        for fit_i, val_i in GroupKFold(n_splits=folds).split(x[train_idx], y[train_idx], groups[train_idx]):
            model = MLPClassifier(hidden_layer_sizes=(hidden,), max_iter=2000, random_state=seed)
            model.fit(x[train_idx][fit_i], y[train_idx][fit_i])
            truth = y[train_idx][val_i]
            scores.append(np.mean([np.mean(model.predict(x[train_idx][val_i])[truth == c] == c)
                                   for c in CLASSES if (truth == c).any()]))
        if np.mean(scores) > best_score:
            best, best_score = hidden, float(np.mean(scores))
    model = MLPClassifier(hidden_layer_sizes=(best,), max_iter=2000, random_state=seed).fit(x[train_idx], y[train_idx])
    result = metrics(y[test_idx], model.predict(x[test_idx]))
    result.update(hidden=best, validation_ba=best_score, train_windows=len(train_idx), test_windows=len(test_idx),
                  split='random 75/25 (Formby)')
    return result


def fit_high_from_windows(windows, feature):
    fields = FEATURES[feature]
    if len(fields) == 1:
        return max(1e-3, 1.05 * max(max(w['values']) for w in windows))
    return {f: max(1e-3, 1.05 * max(max(w['values'][f]) for w in windows)) for f in fields}


def evaluate_arm(train_rows, test_rows, feature, k, seed=SEED, ann=True):
    """NB and GMM trained on train_rows' training split, tested on test_rows' test split; FF-ANN on test_rows."""
    train_windows = [w for w in make_windows(train_rows, feature, k) if w['split'] == 'train']
    test_windows = [w for w in make_windows(test_rows, feature, k) if w['split'] == 'test']
    if {w['operation'] for w in train_windows} != set(CLASSES) or {w['operation'] for w in test_windows} != set(CLASSES):
        return dict(unavailable='a class has no complete window', train_windows=len(train_windows),
                    test_windows=len(test_windows))
    high = fit_high(train_rows, feature)
    truth = [w['operation'] for w in test_windows]
    nb = nb_predict(train_windows, test_windows, feature, high)
    gmm = gmm_predict(train_windows, test_windows, feature, seed)
    result = dict(train_windows=len(train_windows), test_windows=len(test_windows), high=high,
                  nb=metrics(truth, nb), gmm=metrics(truth, gmm))
    test_repetitions = sorted({r['repetition'] for r in test_rows if r['split'] == 'test'})
    for model, prediction in (('nb', nb), ('gmm', gmm)):
        result[model]['per_block_ba'] = per_block_ba(test_windows, prediction)
        result[model]['ci'], reason = block_interval(result[model]['per_block_ba'], test_repetitions, seed)
        if reason:
            result[model]['ci_unavailable'] = reason
    if ann:
        all_windows = make_windows(test_rows, feature, k)
        result['ff_ann'] = (ann_evaluate(all_windows, feature, seed) if len(all_windows) >= 8
                            else dict(unavailable='fewer than 8 windows'))
    return result


def load_rows(path):
    rows = []
    with Path(path).open() as stream:
        for row in csv.DictReader(stream):
            for field in ('clrt_ms', 'ack_ms', 'rt_ms'):
                row[field] = float(row[field])
            for field in ('d_ms', 'seq', 'req_len', 'resp_len', 'piggyback', 'block_index'):
                row[field] = int(row[field])
            row['repetition'] = int(row['repetition']) if row['repetition'] else None
            rows.append(row)
    return rows


def run(rows, seed=SEED):
    results = []
    for d_ms in sorted({r['d_ms'] for r in rows}):
        at_d = [r for r in rows if r['d_ms'] == d_ms]
        off = [r for r in at_d if r['arm'] == 'off']
        for arm in ARMS:
            arm_rows = [r for r in at_d if r['arm'] == arm]
            if not arm_rows:
                continue
            for feature in FEATURES:
                for k in WINDOWS_K:
                    for attacker, train_rows in (('retrained', arm_rows), ('pre_deployment', off)):
                        value = evaluate_arm(train_rows, arm_rows, feature, k, seed, ann=attacker == 'retrained')
                        if attacker == 'pre_deployment':
                            value['ff_ann_unavailable'] = ("Formby's FF-ANN protocol is a random 75/25 split within "
                                                           "one arm, so it has no pre-deployment form")
                        results.append(dict(d_ms=d_ms, arm=arm, feature=feature, k=k, attacker=attacker, **value))
    comparisons = []
    keyed = {(r['d_ms'], r['feature'], r['k'], r['attacker'], r['arm']): r for r in results}
    for (d_ms, feature, k, attacker, arm), value in keyed.items():
        native = keyed.get((d_ms, feature, k, attacker, 'off'))
        if arm == 'off' or not native:
            continue
        for model in ('nb', 'gmm'):
            record = dict(d_ms=d_ms, feature=feature, k=k, attacker=attacker, arm=arm, model=model)
            if model not in value or model not in native:
                comparisons.append(dict(record, unavailable='no fit for this arm or for off'))
                continue
            a, b = native[model]['per_block_ba'], value[model]['per_block_ba']
            if not a or sorted(a) != sorted(b) or not (native[model].get('ci') and value[model].get('ci')):
                comparisons.append(dict(record, unavailable='paired test blocks incomplete: off %s, arm %s' % (
                    sorted(a), sorted(b))))
                continue
            comparisons.append(dict(record, off_minus_arm=block_bootstrap({r: a[r] - b[r] for r in a}, seed)))
    return results, comparisons


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('rows', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    rows = load_rows(args.rows)
    results, comparisons = run(rows)
    args.output.mkdir(parents=True, exist_ok=True)
    record = dict(schema='c72-formby-eval-v1', rows=str(args.rows),
                  rows_sha256=hashlib.sha256(args.rows.read_bytes()).hexdigest(),
                  analysis_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), seed=SEED,
                  results=results, comparisons=comparisons)
    (args.output / 'formby_results.json').write_text(json.dumps(record, indent=1, default=float) + '\n')
    print('results', len(results), 'comparisons', len(comparisons))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
