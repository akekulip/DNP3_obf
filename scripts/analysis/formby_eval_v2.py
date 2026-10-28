#!/usr/bin/env python3
"""Corrected Formby-style operation classifiers over the c72 evaluation rows (schema c72-formby-eval-v2).

A corrected analysis of already-examined data (audit 2026-10-28, sections 3, 4.3, 4.5 and 5), not a new untouched
test set. v1 (formby_eval.py, final/formby/formby_results.json) is left exactly as it is.
  * One grouped chronological split for NB, GMM and FF-ANN: repetitions 1-8 train, 9-16 test, per D. FF-ANN hidden
    size by GroupKFold over training blocks with H refitted inside every inner fold (formby_v2_models.fit_ann).
  * Observers: retrained (trained on the arm) and pre-deployment (trained on off at the same D), all three models.
  * Features: preregistered clrt (primary), size, joint; exploratory ack (request->ACK) and rt (request->complete
    response). K in (8, 32, 64).
  * Uncertainty: bootstrap over test blocks for each BA and for the paired change off minus arm (matched blocks).
  * Retained: window membership, per-window predictions and scores (formby_fits_v2.json, bound by sha256),
    fitted-parameter summaries, convergence per fit, environment; declared tie rule with near-ties counted per cell.

  $RESEARCH_PYTHON scripts/analysis/formby_eval_v2.py ROWS_CSV --output OUT_DIR
"""
import argparse
import csv
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import scipy
import sklearn
import threadpoolctl
from scipy.stats import binomtest

import formby_v2_models as models
from formby_eval import (ARMS, BOOTSTRAP_RESAMPLES, CLASSES, HIDDEN_SIZES, SEED, TEST_REPETITIONS, WINDOWS_K,
                         block_bootstrap, block_interval, load_rows, metrics, per_block_ba)

SCHEMA = 'c72-formby-eval-v2'
FEATURES = {'clrt': ('clrt_ms',), 'size': ('resp_len',), 'joint': ('clrt_ms', 'resp_len'),
            'ack': ('ack_ms',), 'rt': ('rt_ms',)}
EXPLORATORY = ('ack', 'rt')
FIELDS = ('clrt_ms', 'resp_len', 'ack_ms', 'rt_ms')
CLASSIFIERS = ('nb', 'gmm', 'ff_ann')
OBSERVERS = ('retrained', 'pre_deployment')
RESULTS_NAME, FITS_NAME, CSV_NAME = 'formby_results_v2.json', 'formby_fits_v2.json', 'T2v2_classifier_metrics.csv'
CSV_COLUMNS = ('d', 'arm', 'feature', 'exploratory', 'K', 'classifier', 'observer', 'test_blocks', 'test_windows', 'ba',
               'ci_lower', 'ci_upper', 'paired_delta', 'delta_lower', 'delta_upper', 'near_ties', 'converged_fraction')
TASK = 'operation classification (READ/SELECT/OPERATE), one SEL-751; not device identification'
HISTORICAL_V1_NOTE = ('v1 (schema c72-formby-eval-v1, final/formby/formby_results.json) is unchanged. Its NB and GMM '
                      'used early/late blocks (repetitions 1-8 train, 9-16 test); its FF-ANN used Formby\'s random '
                      '75/25 window split, so FF-ANN test windows came from blocks that also supplied training '
                      'windows. v1 predictions used scikit-learn predict() (sorted class order for exact ties) and '
                      'are not rewritten here.')
V1_SELECT_OPERATE = dict(arm='combined', k=64, feature='joint', classifier='nb', observer='retrained', correct=45, n=64,
                         binomial_p_one_sided=0.0008, source='results/analysis/evaluation/REPORT.md',
                         assumption='windows treated as independent trials')


def make_windows_v2(rows, k):
    """v1 make_windows rule (same operation, non-overlapping, inside one block and arm, from the first row), keeping
    every numeric field and the window's seq range."""
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
            windows.append(dict(block_id=block_id, arm=arm, operation=operation, repetition=chunk[0]['repetition'],
                                split=chunk[0]['split'], seq_first=chunk[0]['seq'], seq_last=chunk[-1]['seq'],
                                values={f: [r[f] for r in chunk] for f in FIELDS}))
    return windows


def member(window):
    return {key: window[key] for key in ('block_id', 'arm', 'operation', 'repetition', 'split', 'seq_first',
                                         'seq_last')}


def view(windows, fields):
    """Windows restricted to one feature's fields (v1 moments() uses every field it is given)."""
    return [dict(w, values={f: w['values'][f] for f in fields}) for w in windows]


def rows_high(rows, fields):
    """NB H per field, v1 rule: 1.05 x the largest training-row value (piggybacked rows excluded)."""
    train = [r for r in rows if r['split'] == 'train' and not r['piggyback']]
    return {f: max(1e-3, 1.05 * max(r[f] for r in train)) for f in fields}


def counts(windows, block_ids=False):
    blocks = sorted({w['block_id'] for w in windows})
    result = dict(blocks=len(blocks), windows=len(windows),
                  per_class={c: sum(w['operation'] == c for w in windows) for c in CLASSES})
    if block_ids:
        result['block_ids'] = blocks
    return result


def fit_one(classifier, train, train_rows, fields, k, seed):
    if classifier == 'nb':
        return models.fit_nb(train, fields, rows_high(train_rows, fields))
    if classifier == 'gmm':
        return models.fit_gmm(train, seed)
    return models.fit_ann(train, fields, k, seed)


def converged_fraction(state):
    fits = state.get('inner_fits', 0) + 1
    return (state.get('inner_converged', 0) + int(state['converged'])) / fits


def fit_cells(d_ms, k, feature, train_arm, classifier, windows, by_arm, seed, detail):
    """Fit one model on train_arm's training windows; score the test windows of every arm this fit observes."""
    fields = FEATURES[feature]
    fit_id = 'd%d/k%d/%s/%s/%s' % (d_ms, k, feature, train_arm, classifier)
    train_ids = [i for i, w in enumerate(windows[train_arm]) if w['split'] == 'train']
    train = view([windows[train_arm][i] for i in train_ids], fields)
    record = dict(id=fit_id, d_ms=d_ms, k=k, feature=feature, train_arm=train_arm, classifier=classifier,
                  train=counts(train, block_ids=True))
    detail['fits'][fit_id] = dict(train_window_ids=train_ids)
    observed = [(train_arm, 'retrained')] + ([(arm, 'pre_deployment') for arm in windows] if train_arm == 'off' else [])
    if {w['operation'] for w in train} != set(CLASSES):
        record['unavailable'] = 'a class has no complete training window'
    else:
        score, params, state = fit_one(classifier, train, by_arm[train_arm], fields, k, seed)
        record.update(params=params, convergence=state)
    cells = []
    for arm, observer in observed:
        test_ids = [i for i, w in enumerate(windows[arm]) if w['split'] == 'test']
        test = view([windows[arm][i] for i in test_ids], fields)
        cell = dict(id='d%d/k%d/%s/%s/%s/%s' % (d_ms, k, feature, classifier, observer, arm), d_ms=d_ms, k=k,
                    feature=feature, exploratory=feature in EXPLORATORY, classifier=classifier, observer=observer,
                    arm=arm, fit=fit_id, train=counts(train), test=counts(test), paired_delta=None)
        cells.append(cell)
        if 'unavailable' in record or {w['operation'] for w in test} != set(CLASSES):
            cell['unavailable'] = record.get('unavailable', 'a class has no complete test window')
            continue
        scores = score(test)
        prediction, margin = models.decide(scores)
        block_ba = per_block_ba(test, prediction)
        test_repetitions = sorted({r['repetition'] for r in by_arm[arm] if r['split'] == 'test'})
        ci, reason = block_interval(block_ba, test_repetitions, seed)
        cell.update(metrics=metrics([w['operation'] for w in test], prediction), per_block_ba=block_ba,
                    ba=float(np.mean(list(block_ba.values()))) if block_ba else None, ci=ci,
                    near_ties=int(np.sum(margin < models.TIE_TOLERANCE)), exact_ties=int(np.sum(margin == 0)),
                    final_converged=state['converged'], converged_fraction=converged_fraction(state))
        if reason:
            cell['ci_unavailable'] = reason
        detail['predictions'][cell['id']] = dict(fit=fit_id, test_arm=arm, test_window_ids=test_ids,
                                                 prediction=prediction, scores=scores.tolist(), score=params['score'])
    return record, cells


def add_paired_deltas(cells, seed):
    """Off minus arm per matched test repetition, bootstrapped over those repetitions (positive: the arm lowered BA)."""
    keyed = {(c['d_ms'], c['k'], c['feature'], c['classifier'], c['observer'], c['arm']): c for c in cells}
    for c in cells:
        if c['arm'] == 'off':
            continue
        off = keyed.get((c['d_ms'], c['k'], c['feature'], c['classifier'], c['observer'], 'off')) or {}
        a, b = off.get('per_block_ba') or {}, c.get('per_block_ba') or {}
        if not a or sorted(a) != sorted(b) or not (off.get('ci') and c.get('ci')):
            reason = 'paired test blocks incomplete: off %s, arm %s' % (sorted(a), sorted(b))
            c['paired_delta'] = dict(unavailable=reason)
            continue
        c['paired_delta'] = block_bootstrap({r: a[r] - b[r] for r in a}, seed)


def select_operate_summary(per_d, seed, resamples=BOOTSTRAP_RESAMPLES):
    """Share of SELECT/OPERATE test windows labelled correctly; test blocks resampled with replacement within each D."""
    rng = np.random.default_rng(seed)
    correct, total = np.zeros(resamples), np.zeros(resamples)
    for d in sorted(per_d):
        hits = np.array([block[0] for block in per_d[d]], dtype=float)
        sizes = np.array([block[1] for block in per_d[d]], dtype=float)
        pick = rng.integers(0, len(hits), size=(resamples, len(hits)))
        correct += hits[pick].sum(axis=1)
        total += sizes[pick].sum(axis=1)
    share = correct / total
    low, high = np.quantile(share, [0.025, 0.975])
    k = int(sum(block[0] for d in per_d for block in per_d[d]))
    n = int(sum(block[1] for d in per_d for block in per_d[d]))
    return dict(correct=k, n=n, blocks=sum(len(per_d[d]) for d in per_d), estimate=k / n, lower=float(low),
                upper=float(high), bootstrap_share_at_or_below_half=float(np.mean(share <= 0.5)),
                binomial_p_one_sided=float(binomtest(k, n, 0.5, alternative='greater').pvalue),
                resamples=resamples, seed=seed)


def select_operate_counts(per_d, seed=SEED):
    """Per D (blocks resampled) and pooled over D (blocks resampled within each D, i.e. stratified by D)."""
    return dict(per_d={str(d): select_operate_summary({d: per_d[d]}, seed) for d in sorted(per_d)},
                pooled=select_operate_summary(per_d, seed))


def select_operate(cells, detail, k, seed):
    """Recompute the v1 exploratory SELECT/OPERATE joint-feature count from v2 predictions, with block clustering."""
    per_arm = {}
    for c in cells:
        if (c['feature'], c['k'], c['classifier'], c['observer']) != ('joint', k, 'nb', 'retrained') or 'ba' not in c:
            continue
        prediction = detail['predictions'][c['id']]
        members = detail['windows']['d%d/k%d' % (c['d_ms'], k)][c['arm']]
        per_block = {}
        for i, label in zip(prediction['test_window_ids'], prediction['prediction']):
            w = members[i]
            if w['operation'] in ('SELECT', 'OPERATE'):
                hit, n = per_block.get(w['repetition'], (0, 0))
                per_block[w['repetition']] = (hit + int(label == w['operation']), n + 1)
        per_arm.setdefault(c['arm'], {})[c['d_ms']] = [per_block[r] for r in sorted(per_block)]
    result = {arm: dict(select_operate_counts(per_d, seed), k=k, feature='joint', classifier='nb',
                        observer='retrained') for arm, per_d in per_arm.items()}
    result['v1_reported'] = V1_SELECT_OPERATE
    return result


def run(rows, seed=SEED, ks=WINDOWS_K, features=tuple(FEATURES)):
    """Every (D, K, feature, training arm, classifier) fit and the cells it scores; returns (result, detail)."""
    fits, cells = [], []
    detail = dict(windows={}, fits={}, predictions={})
    for d_ms in sorted({r['d_ms'] for r in rows}):
        at_d = [r for r in rows if r['d_ms'] == d_ms]
        by_arm = {arm: [r for r in at_d if r['arm'] == arm] for arm in ARMS if any(r['arm'] == arm for r in at_d)}
        for k in ks:
            windows = {arm: make_windows_v2(arm_rows, k) for arm, arm_rows in by_arm.items()}
            detail['windows']['d%d/k%d' % (d_ms, k)] = {arm: [member(w) for w in ws] for arm, ws in windows.items()}
            for feature in features:
                for train_arm in by_arm:
                    for classifier in CLASSIFIERS:
                        record, scored = fit_cells(d_ms, k, feature, train_arm, classifier, windows, by_arm, seed,
                                                   detail)
                        fits.append(record)
                        cells.extend(scored)
    order = lambda c: (c['d_ms'], list(FEATURES).index(c['feature']), c['k'], CLASSIFIERS.index(c['classifier']),
                       OBSERVERS.index(c['observer']), ARMS.index(c['arm']))
    cells.sort(key=order)
    add_paired_deltas(cells, seed)
    result = dict(fits=fits, cells=cells)
    if 'joint' in features:
        result['select_operate'] = select_operate(cells, detail, max(ks), seed)
    return result, detail


def protocol(seed, ks, features):
    return dict(
        split='grouped chronological, per D: repetitions 1-8 train, 9-16 test; shared by NB, GMM and FF-ANN',
        test_repetitions=list(TEST_REPETITIONS), classes=list(CLASSES), windows_k=list(ks), seed=seed,
        features={f: dict(fields=list(FEATURES[f]), exploratory=f in EXPLORATORY,
                          status='exploratory, not preregistered' if f in EXPLORATORY else
                          'preregistered' + (' (primary)' if f == 'clrt' else '')) for f in features},
        observers=dict(retrained='trained on the arm\'s own training blocks',
                       pre_deployment='trained on off at the same D, tested on each arm (off included)'),
        windows='same-operation, non-overlapping, inside one block and arm, from the first row (v1 rule)',
        histogram='Formby Eq. 1: 199 equal bins on [0, H) plus one overflow bin for x >= H',
        high=dict(nb='1.05 x the largest training-row value of the training arm (v1 rule)',
                  ff_ann='1.05 x the largest value in the training windows; refitted inside every inner fold',
                  gmm='not used: raw window [mean, variance], no standardisation'),
        nb='MultinomialNB(alpha=1); score = joint log-likelihood',
        gmm='GaussianMixture(3, full, reg_covar=1e-6, n_init=10, random_state=seed); Hungarian map from training '
            'labels; score = posterior probability of the mapped component',
        ff_ann=dict(hidden_sizes=list(HIDDEN_SIZES), max_iter=models.ANN_MAX_ITER, input='histogram counts / K',
                    selection='GroupKFold(min(5, training blocks)) over training blocks; highest mean validation BA; '
                              'a tie keeps the smaller size', score='predicted probability'),
        tie_rule=models.TIE_RULE, tie_tolerance=models.TIE_TOLERANCE,
        convergence='NB closed form (converged); GMM converged_ and no ConvergenceWarning; FF-ANN n_iter_ < max_iter '
                    'and no ConvergenceWarning, captured per fit',
        converged_fraction='converged fits / fits behind the cell: NB 1, GMM 1, FF-ANN inner-CV fits + 1 final',
        ba='mean over test blocks of per-block balanced accuracy',
        bootstrap=dict(unit='test block (repetition)', resamples=BOOTSTRAP_RESAMPLES, seed=seed, interval='95% '
                       'percentile'),
        paired_delta='off minus arm per matched test repetition, bootstrapped over repetitions; positive means the '
                     'arm lowered BA')


def first_byte_note(rows):
    single = sum(1 for r in rows if str(r['resp_segments']) == '1')
    if single == len(rows):
        return ('not a separate feature: resp_segments == 1 for %d of %d rows, so every response arrived in one '
                'captured TCP segment and request->first response byte equals rt_ms (request->complete response)'
                % (single, len(rows)))
    return ('resp_segments > 1 for %d of %d rows: rt_ms is request->complete response only; first-byte timing is not '
            'in the rows' % (len(rows) - single, len(rows)))


def environment():
    pools = [{key: (os.path.basename(value) if key == 'filepath' else value) for key, value in pool.items()}
             for pool in threadpoolctl.threadpool_info()]
    return dict(python=sys.version, numpy=np.__version__, scipy=scipy.__version__, sklearn=sklearn.__version__,
                threadpoolctl=threadpoolctl.__version__, threadpools=pools,
                thread_env={name: os.environ.get(name) for name in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS',
                                                                    'MKL_NUM_THREADS')})


def totals(result):
    out = {}
    for classifier in CLASSIFIERS:
        fits = [f for f in result['fits'] if f['classifier'] == classifier and 'convergence' in f]
        cells = [c for c in result['cells'] if c['classifier'] == classifier and 'near_ties' in c]
        out[classifier] = dict(
            fits=len(fits), final_converged=sum(f['convergence']['converged'] for f in fits),
            inner_fits=sum(f['convergence'].get('inner_fits', 0) for f in fits),
            inner_converged=sum(f['convergence'].get('inner_converged', 0) for f in fits),
            cells=len(cells), near_ties=sum(c['near_ties'] for c in cells),
            cells_with_near_ties=sum(c['near_ties'] > 0 for c in cells), exact_ties=sum(c['exact_ties'] for c in cells))
    return out


def plain(value):
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    raise TypeError('not JSON serialisable: %r' % type(value))


def dumps(record, compact=False):
    text = json.dumps(record, sort_keys=True, default=plain, indent=None if compact else 1,
                      separators=(',', ':') if compact else None)
    return (text + '\n').encode()


def write_csv(cells, path):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for c in cells:
            ci, delta = c.get('ci') or {}, c.get('paired_delta') or {}
            values = (c['d_ms'], c['arm'], c['feature'], c['exploratory'], c['k'], c['classifier'], c['observer'],
                      c['test']['blocks'], c['test']['windows'], c.get('ba'), ci.get('lower'), ci.get('upper'),
                      delta.get('estimate'), delta.get('lower'), delta.get('upper'), c.get('near_ties'),
                      c.get('converged_fraction'))
            writer.writerow({name: ('' if v is None else '%.6f' % v if isinstance(v, float) else v)
                             for name, v in zip(CSV_COLUMNS, values)})


def write_outputs(rows_path, output, seed=SEED, ks=WINDOWS_K, features=tuple(FEATURES)):
    rows_path, output = Path(rows_path), Path(output)
    rows = load_rows(rows_path)
    result, detail = run(rows, seed, ks, features)
    output.mkdir(parents=True, exist_ok=True)
    rows_sha256 = hashlib.sha256(rows_path.read_bytes()).hexdigest()
    fits_bytes = dumps(dict(detail, schema=SCHEMA + '-fits', rows_sha256=rows_sha256), compact=True)
    (output / FITS_NAME).write_bytes(fits_bytes)
    here = Path(__file__).resolve().parent
    record = dict(result, schema=SCHEMA, task=TASK, historical_v1_note=HISTORICAL_V1_NOTE, rows=str(rows_path),
                  rows_sha256=rows_sha256, fits_file=FITS_NAME, fits_sha256=hashlib.sha256(fits_bytes).hexdigest(),
                  analysis_sha256={name: hashlib.sha256((here / name).read_bytes()).hexdigest() for name in
                                   ('formby_eval_v2.py', 'formby_v2_models.py', 'formby_eval.py')},
                  corrected_analysis_note='corrected analysis of already-examined data, not a new untouched test set',
                  protocol=protocol(seed, ks, features), request_to_first_response_byte=first_byte_note(rows),
                  environment=environment(), totals=totals(result))
    (output / RESULTS_NAME).write_bytes(dumps(record))
    write_csv(result['cells'], output / CSV_NAME)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('rows', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    start = time.monotonic()
    record = write_outputs(args.rows, args.output)
    print('cells', len(record['cells']), 'fits', len(record['fits']), 'seconds %.0f' % (time.monotonic() - start))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
