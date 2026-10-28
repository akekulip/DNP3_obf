import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
sklearn = pytest.importorskip('sklearn')
import formby_eval  # noqa: E402


def synthetic(separable, d_ms=10, arm='off', blocks=16, seed=0):
    """65 READ / 64 SELECT / 64 OPERATE per block; separable classes have distinct CLRT and size."""
    rng = np.random.default_rng(seed)
    centre = {'READ': 2.0, 'SELECT': 6.0, 'OPERATE': 12.0} if separable else dict.fromkeys(('READ', 'SELECT', 'OPERATE'), d_ms)
    size = {'READ': 141, 'SELECT': 60, 'OPERATE': 49} if separable else dict.fromkeys(('READ', 'SELECT', 'OPERATE'), 60)
    rows = []
    for repetition in range(1, blocks + 1):
        seq = 0
        for operation, count in (('READ', 65), ('SELECT', 64), ('OPERATE', 64)):
            for _ in range(count):
                rows.append(dict(d_ms=d_ms, arm=arm, block_id='e%02d' % repetition, repetition=repetition,
                                 split='train' if repetition <= 8 else 'test', operation=operation, seq=seq,
                                 clrt_ms=float(abs(rng.normal(centre[operation], 0.3))),
                                 resp_len=size[operation], piggyback=0))
                seq += 1
    return rows


def test_histogram_is_formby_eq1_with_overflow_including_h():
    counts = formby_eval.histogram([0.0, 0.4999, 0.5, 1.0, 7.0], high=1.0)
    assert counts.shape == (200,) and counts.sum() == 5
    assert counts[0] == 1 and counts[99] == 2    # floor(0.4999*199) = floor(0.5*199) = 99
    assert counts[199] == 2                      # x == H and x > H both overflow
    with pytest.raises(ValueError):
        formby_eval.histogram([-0.1], high=1.0)


def test_windows_never_cross_block_or_operation_and_respect_k():
    rows = synthetic(True, blocks=2)
    windows = formby_eval.make_windows(rows, 'clrt', 32)
    assert {w['operation'] for w in windows} == {'READ', 'SELECT', 'OPERATE'}
    assert all(len(w['values']) == 32 for w in windows)
    assert len(windows) == 2 * (2 + 2 + 2)       # 65//32, 64//32, 64//32 per block
    assert all(len({w['block_id']}) == 1 for w in windows)


def test_h_is_fitted_on_training_rows_only():
    rows = synthetic(True)
    for row in rows:
        if row['split'] == 'test':
            row['clrt_ms'] += 1000.0
    assert formby_eval.fit_high(rows, 'clrt') < 20


def test_separable_classes_score_near_one_and_identical_classes_near_chance():
    good = formby_eval.evaluate_arm(synthetic(True), synthetic(True), 'clrt', 8, seed=1)
    bad = formby_eval.evaluate_arm(synthetic(False), synthetic(False), 'clrt', 8, seed=1)
    assert good['nb']['balanced_accuracy'] > 0.95 and good['ff_ann']['balanced_accuracy'] > 0.95
    assert abs(bad['nb']['balanced_accuracy'] - 1 / 3) < 0.15
    assert abs(bad['ff_ann']['balanced_accuracy'] - 1 / 3) < 0.2
    assert good['gmm']['balanced_accuracy'] > 0.9


def test_formby_metrics_report_mean_and_minimum_class():
    truth = ['READ'] * 4 + ['SELECT'] * 4 + ['OPERATE'] * 4
    prediction = ['READ'] * 4 + ['SELECT'] * 2 + ['OPERATE'] * 2 + ['OPERATE'] * 4
    m = formby_eval.metrics(truth, prediction)
    assert m['recall']['SELECT'] == 0.5 and m['min_recall'] == 0.5
    assert m['balanced_accuracy'] == pytest.approx((1 + 0.5 + 1) / 3)
    assert m['precision']['OPERATE'] == pytest.approx(4 / 6)
    assert m['min_precision'] == pytest.approx(4 / 6)


def test_block_bootstrap_is_deterministic_and_brackets_the_estimate():
    values = {r: 0.5 + 0.01 * r for r in range(9, 17)}
    a = formby_eval.block_bootstrap(values, seed=3)
    b = formby_eval.block_bootstrap(values, seed=3)
    assert a == b and a['lower'] <= a['estimate'] <= a['upper']


def size_only_separable(arm='size_only'):
    """CLRT identical across classes, response size separates them."""
    rows = synthetic(False, arm=arm)
    size = {'READ': 141, 'SELECT': 60, 'OPERATE': 49}
    for row in rows:
        row['resp_len'] = size[row['operation']]
    return rows


def test_joint_gmm_uses_size_as_well_as_clrt():
    rows = size_only_separable()
    joint = formby_eval.evaluate_arm(rows, rows, 'joint', 8, seed=1)
    clrt = formby_eval.evaluate_arm(rows, rows, 'clrt', 8, seed=1)
    assert joint['gmm']['balanced_accuracy'] > 0.95
    assert clrt['gmm']['balanced_accuracy'] < 0.6


def test_piggybacked_rows_do_not_set_h():
    rows = synthetic(True)
    rows[0].update(piggyback=1, clrt_ms=999.0)
    assert formby_eval.fit_high(rows, 'clrt') < 20


def test_block_interval_requires_every_test_block_and_says_why_not():
    rows = synthetic(True)
    full = formby_eval.evaluate_arm(rows, rows, 'clrt', 64, seed=1)
    assert full['nb']['ci']['blocks'] == 8 and full['gmm']['ci']['blocks'] == 8
    partial = [r for r in rows if not (r['repetition'] == 12 and r['operation'] == 'SELECT')]
    result = formby_eval.evaluate_arm(partial, partial, 'clrt', 64, seed=1)
    assert result['nb']['ci'] is None and 'test blocks' in result['nb']['ci_unavailable']


def test_pre_deployment_attacker_has_no_ff_ann_and_says_so():
    rows = synthetic(True)
    results, _ = formby_eval.run(rows)
    pre = [r for r in results if r['attacker'] == 'pre_deployment' and r['k'] == 64 and r['feature'] == 'clrt']
    assert pre and all('ff_ann' not in r and r['ff_ann_unavailable'] for r in pre)
