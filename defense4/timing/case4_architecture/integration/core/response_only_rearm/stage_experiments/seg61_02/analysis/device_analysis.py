#!/usr/bin/env python3
"""Locked analysis of the device-classification study (DEVICE_STUDY_PROTOCOL.md, 2026-10-19).

Formby et al.'s multinomial naive Bayes on 200-bin CLRT histograms of K-exchange windows, with the
label being the emulated device. The histogram, threshold H and windows are publication_analysis's.

    device_analysis.py fit      rows_training.csv lock.json
    device_analysis.py evaluate rows_training.csv rows_testing.csv lock.json OUT_DIR
    device_analysis.py baseline campaign_rows.csv sel_dir OUT_DIR     (offline SEL-751 baseline)

`fit` runs after round 8 and before any testing block exists; `evaluate` refuses a lock whose
training fingerprint differs from the training rows it is given.
"""
import csv
import json
import statistics
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import balanced_accuracy_score, recall_score
from sklearn.naive_bayes import MultinomialNB

sys.path.insert(0, str(Path(__file__).resolve().parent))
from publication_analysis import histogram, load_rows, make_windows, paired_bootstrap, training_fingerprint  # noqa: E402

KS = (8, 32, 64)
SEED = 20261019
PRIMARY_K = 32


def windows(rows, k, shift=0.0):
    """[(histogram-ready values, device, round)] of valid K-windows, never crossing a block."""
    device = {r['block_id']: r['device'] for r in rows}
    shifted = [dict(r, clrt_ms=r['clrt_ms'] + shift) if r['clrt_ms'] is not None else r for r in rows]
    found, _ = make_windows(shifted, k)
    return [(w['values'], device[w['block_id']], w['round']) for w in found]


def threshold(rows, shift=0.0):
    return max(.001, 1.05 * max(r['clrt_ms'] + shift for r in rows if r['clrt_ms'] is not None))


def train(rows, k, shift=0.0):
    high = threshold(rows, shift)
    found = windows(rows, k, shift)
    model = MultinomialNB(alpha=1.).fit(np.array([histogram(v, high) for v, _, _ in found]), [d for _, d, _ in found])
    return dict(k=k, shift_ms=shift, H_ms=high, n_windows=len(found), classes=model.classes_.tolist(),
                class_log_prior=model.class_log_prior_.tolist(), feature_log_prob=model.feature_log_prob_.tolist())


def predict(model, found):
    x = np.array([histogram(v, model['H_ms']) for v, _, _ in found])
    scores = x @ np.array(model['feature_log_prob']).T + np.array(model['class_log_prior'])
    return [model['classes'][i] for i in scores.argmax(axis=1)]


def arm_rows(rows, arm):
    return [r for r in rows if r['arm'] == arm]


def constant_shift(training):
    """The constant-delay control: one constant for every device, from training rounds only."""
    med = lambda arm: statistics.median(r['clrt_ms'] for r in arm_rows(training, arm) if r['clrt_ms'] is not None)
    return med('combined') - med('off')


def fit(training_csv, lock_path):
    training = load_device_rows(training_csv)
    if {r['split'] for r in training} != {'training'}:
        raise ValueError('fit takes training rows only')
    c = constant_shift(training)
    models = {}
    for k in KS:
        models['retrained/off/%d' % k] = train(arm_rows(training, 'off'), k)
        models['retrained/combined/%d' % k] = train(arm_rows(training, 'combined'), k)
        models['constant_delay/off+c/%d' % k] = train(arm_rows(training, 'off'), k, c)
    lock = dict(schema_version=1, protocol='DEVICE_STUDY_PROTOCOL.md', seed=SEED, constant_shift_ms=c,
                training_fingerprint=training_fingerprint(training), models=models)
    with open(lock_path, 'x') as stream:
        json.dump(lock, stream, sort_keys=True, indent=1, allow_nan=False)


def load_device_rows(path):
    rows = load_rows(path)
    for r in rows:
        r['clrt_ms'] = None if r.get('clrt_ms') in (None, '') else float(r['clrt_ms'])
        r['observed_at_ms'] = None if r.get('observed_at_ms') in (None, '') else float(r['observed_at_ms'])
    return rows


def score(model, found):
    truth = [d for _, d, _ in found]
    predicted = predict(model, found)
    by_round = {}
    for rnd in sorted({r for _, _, r in found}):
        idx = [i for i, (_, _, r) in enumerate(found) if r == rnd]
        by_round[rnd] = balanced_accuracy_score([truth[i] for i in idx], [predicted[i] for i in idx])
    recall = dict(zip(model['classes'], recall_score(truth, predicted, labels=model['classes'], average=None).tolist()))
    return balanced_accuracy_score(truth, predicted), by_round, recall, truth, predicted


def evaluate(training_csv, testing_csv, lock_path, out_dir):
    training, testing = load_device_rows(training_csv), load_device_rows(testing_csv)
    lock = json.loads(Path(lock_path).read_text())
    if lock['training_fingerprint'] != training_fingerprint(training):
        raise ValueError('training rows differ from the locked fit')
    if {r['split'] for r in testing} != {'testing'}:
        raise ValueError('evaluate takes testing rows only')
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=False)
    c = lock['constant_shift_ms']
    cases = (('retrained', 'off', 'retrained/off/%d', 0.0), ('retrained', 'combined', 'retrained/combined/%d', 0.0),
             ('pre_deployment', 'combined', 'retrained/off/%d', 0.0),
             ('constant_delay', 'off+c', 'constant_delay/off+c/%d', c))
    summary, rounds, predictions = [], {}, []
    for k in KS:
        for attacker, arm, key, shift in cases:
            found = windows(arm_rows(testing, 'off' if arm == 'off+c' else arm), k, shift)
            ba, by_round, recall, truth, predicted = score(lock['models'][key % k], found)
            rounds[(attacker, arm, k)] = by_round
            summary.append(dict(attacker=attacker, arm=arm, k=k, balanced_accuracy=ba, n_windows=len(found),
                                recall=json.dumps(recall, sort_keys=True), H_ms=lock['models'][key % k]['H_ms']))
            predictions += [dict(attacker=attacker, arm=arm, k=k, truth=t, predicted=p) for t, p in zip(truth, predicted)]
    for name, rows in (('device_attacks.csv', summary), ('device_predictions.csv', predictions)):
        with open(out / name, 'x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    primary = paired_bootstrap(rounds[('constant_delay', 'off+c', PRIMARY_K)], rounds[('retrained', 'combined', PRIMARY_K)],
                               seed=SEED)
    secondary = {'%s %s-minus-combined K=%d' % (a, base, k): paired_bootstrap(rounds[(a, base, k)],
                 rounds[('retrained', 'combined', k)], seed=SEED)
                 for k in KS for a, base in (('retrained', 'off'), ('constant_delay', 'off+c'))}
    with open(out / 'device_primary.json', 'x') as stream:
        json.dump(dict(primary=dict(statistic='retrained balanced accuracy, constant delay minus Timing+Size, K=32',
                                    **primary), secondary=secondary, constant_shift_ms=c,
                       per_round={'%s/%s/%d' % key: value for key, value in rounds.items()}),
                  stream, sort_keys=True, indent=1, allow_nan=False)


def baseline(campaign_rows, sel_dir, out_dir):
    """Descriptive only: physical SEL-751 READ CLRT (2026-08-03, captures r1-r4) against the campaign's
    dev_const5 outstation without obfuscation. Train on SEL r1-r2 and campaign rounds 1-8; test on SEL
    r3-r4 and rounds 9-16; K = 8."""
    rows = []
    for r in load_rows(campaign_rows):
        if r['arm'] == 'off' and r['operation'] == 'READ' and r['condition_id'] == 'D10_J2p4':
            rows.append(dict(r, device='dev_const5', split='training' if r['round'] <= 8 else 'testing'))
    for n in (1, 2, 3, 4):
        text = (Path(sel_dir) / ('sel751_r%d.json' % n)).read_text().split(' ', 1)[1]
        for i, x in enumerate(json.loads(text)['rows']):
            rows.append(dict(example_id='sel751_r%d_%d' % (n, i), block_id='sel751_r%d' % n, device='sel751',
                             condition_id='D10_J2p4', arm='off', operation='READ', round=n, connection_id='r%d' % n,
                             session_id='r%d' % n, split='training' if n <= 2 else 'testing', sequence=i,
                             observed_at_ms=float(i), clrt_ms=x['clrt_ms']))
    training = [r for r in rows if r['split'] == 'training']
    testing = [r for r in rows if r['split'] == 'testing']
    model = train(training, 8)
    ba, _, recall, truth, _ = score(model, windows(testing, 8))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / 'device_baseline_sel751.json', 'x') as stream:
        json.dump(dict(scope='descriptive; physical SEL-751 (n=100) vs software outstation, no obfuscation',
                       k=8, balanced_accuracy=ba, recall=recall,
                       test_windows={d: truth.count(d) for d in sorted(set(truth))}, H_ms=model['H_ms']),
                  stream, sort_keys=True, indent=1, allow_nan=False)


if __name__ == '__main__':
    command, args = sys.argv[1], sys.argv[2:]
    {'fit': fit, 'evaluate': evaluate, 'baseline': baseline}[command](*args)
