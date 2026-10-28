import csv
import hashlib
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
sklearn = pytest.importorskip('sklearn')
import formby_eval  # noqa: E402
import formby_eval_v2 as v2  # noqa: E402
import formby_v2_models as models  # noqa: E402

TEST_BLOCKS = {'e%02d' % r for r in range(9, 17)}


def synthetic(separable, d_ms=10, arm='off', blocks=16, seed=0):
    """test_formby_eval.synthetic() extended with ack_ms and rt_ms (rt = ack + CLRT, as in the c72 rows)."""
    rng = np.random.default_rng(seed)
    classes = ('READ', 'SELECT', 'OPERATE')
    centre = {'READ': 2.0, 'SELECT': 6.0, 'OPERATE': 12.0} if separable else dict.fromkeys(classes, d_ms)
    ack = {'READ': 3.0, 'SELECT': 1.0, 'OPERATE': 7.0} if separable else dict.fromkeys(classes, 2.0)
    size = {'READ': 141, 'SELECT': 60, 'OPERATE': 49} if separable else dict.fromkeys(classes, 60)
    rows = []
    for repetition in range(1, blocks + 1):
        seq = 0
        for operation, count in (('READ', 65), ('SELECT', 64), ('OPERATE', 64)):
            for _ in range(count):
                clrt = float(abs(rng.normal(centre[operation], 0.3)))
                ack_ms = float(abs(rng.normal(ack[operation], 0.3)))
                rows.append(dict(d_ms=d_ms, arm=arm, block_id='e%02d' % repetition, block_index=repetition - 1,
                                 repetition=repetition, split='train' if repetition <= 8 else 'test',
                                 operation=operation, seq=seq, clrt_ms=clrt, ack_ms=ack_ms, rt_ms=ack_ms + clrt,
                                 req_len=25, resp_len=size[operation], resp_segments=1, piggyback=0))
                seq += 1
    return rows


def cell(record, **match):
    found = [c for c in record['cells'] if all(c[k] == v for k, v in match.items())]
    assert len(found) == 1, (match, len(found))
    return found[0]


def fit(record, **match):
    found = [f for f in record['fits'] if all(f[k] == v for k, v in match.items())]
    assert len(found) == 1, (match, len(found))
    return found[0]


def test_windows_follow_the_v1_rule_and_carry_their_seq_range():
    rows = synthetic(True, blocks=2)
    for k in (8, 32):
        old = formby_eval.make_windows(rows, 'clrt', k)
        new = v2.make_windows_v2(rows, k)
        assert [(w['block_id'], w['arm'], w['operation'], w['repetition'], w['split'], w['values']) for w in old] == \
            [(w['block_id'], w['arm'], w['operation'], w['repetition'], w['split'], w['values']['clrt_ms'])
             for w in new]
    first_read = [w for w in v2.make_windows_v2(rows, 8) if w['operation'] == 'READ'][0]
    assert (first_read['seq_first'], first_read['seq_last']) == (0, 7)


def test_ties_go_to_the_declared_class_order_and_near_ties_are_counted():
    scores = np.array([[0.0, 0.0, 0.0],               # exact three-way tie -> READ
                       [-1.0, 0.0, 0.0],              # SELECT/OPERATE tie -> SELECT
                       [0.0, -1.0, 5e-10],            # within 1e-9 of the maximum -> READ
                       [-3.0, -2.0, -1.0],            # clear OPERATE
                       [-1.0, -1.0 + 1e-6, -5.0]])    # 1e-6 margin is a decision, not a tie
    prediction, margin = models.decide(scores)
    assert prediction == ['READ', 'SELECT', 'READ', 'OPERATE', 'SELECT']
    assert list(margin < models.TIE_TOLERANCE) == [True, True, True, False, False]
    assert models.decide(scores)[0] == prediction
    assert models.reorder(['OPERATE', 'READ', 'SELECT'], [[1.0, 2.0, 3.0]]).tolist() == [[2.0, 3.0, 1.0]]


def test_no_classifier_or_ann_fold_sees_a_test_block():
    rows = synthetic(True) + synthetic(False, arm='combined', seed=1)
    record, detail = v2.run(rows, ks=(64,), features=('clrt',))
    assert {f['classifier'] for f in record['fits']} == {'nb', 'gmm', 'ff_ann'}
    windows = detail['windows']['d10/k64']
    for f in record['fits']:
        members = [windows[f['train_arm']][i] for i in detail['fits'][f['id']]['train_window_ids']]
        assert members and all(m['split'] == 'train' for m in members)
        assert not {m['block_id'] for m in members} & TEST_BLOCKS
        assert set(f['train']['block_ids']) == {m['block_id'] for m in members}
        if f['classifier'] == 'ff_ann':
            for fold in f['params']['cv']:
                assert not (set(fold['fit_blocks']) | set(fold['validation_blocks'])) & TEST_BLOCKS
                assert not set(fold['fit_blocks']) & set(fold['validation_blocks'])
    for c in record['cells']:
        prediction = detail['predictions'][c['id']]
        members = [windows[c['arm']][i] for i in prediction['test_window_ids']]
        assert all(m['split'] == 'test' for m in members) and {m['block_id'] for m in members} == TEST_BLOCKS
        assert c['test']['blocks'] == 8 and c['train']['blocks'] == 8
    assert {(c['observer'], c['arm']) for c in record['cells']} == {
        ('retrained', 'off'), ('retrained', 'combined'), ('pre_deployment', 'off'), ('pre_deployment', 'combined')}


def test_h_is_fitted_on_training_data_only_and_fold_local_inside_the_ann_cv():
    rows = synthetic(True)
    for row in rows:
        if row['split'] == 'test':
            row['clrt_ms'] += 1000.0
    next(r for r in rows if r['repetition'] == 3 and r['operation'] == 'READ')['clrt_ms'] = 500.0
    record, _ = v2.run(rows, ks=(64,), features=('clrt',))
    assert fit(record, classifier='nb')['params']['high']['clrt_ms'] == pytest.approx(525.0)
    ann = fit(record, classifier='ff_ann')['params']
    assert ann['high']['clrt_ms'] == pytest.approx(525.0)
    assert len(ann['cv']) == 2 * 5
    for fold in ann['cv']:
        if 'e03' in fold['fit_blocks']:
            assert fold['high']['clrt_ms'] == pytest.approx(525.0)
        else:
            assert 'e03' in fold['validation_blocks'] and fold['high']['clrt_ms'] < 20


def test_paired_delta_is_off_minus_arm_over_matched_test_blocks():
    rows = synthetic(True) + synthetic(False, arm='combined', seed=1)
    record, _ = v2.run(rows, ks=(64,), features=('clrt',))
    off = cell(record, arm='off', classifier='nb', observer='retrained')
    arm = cell(record, arm='combined', classifier='nb', observer='retrained')
    assert off['paired_delta'] is None
    expected = np.mean([off['per_block_ba'][r] - arm['per_block_ba'][r] for r in off['per_block_ba']])
    assert arm['paired_delta']['estimate'] == pytest.approx(expected)
    assert arm['paired_delta']['estimate'] > 0.4 and arm['paired_delta']['lower'] > 0
    assert arm['paired_delta']['blocks'] == 8 and arm['paired_delta']['resamples'] == 10000


def test_separable_classes_score_near_one_and_identical_classes_near_chance():
    good, _ = v2.run(synthetic(True), ks=(8,), features=('clrt',))
    bad, _ = v2.run(synthetic(False), ks=(8,), features=('clrt',))
    for classifier in ('nb', 'gmm', 'ff_ann'):
        assert cell(good, classifier=classifier, observer='retrained')['ba'] > 0.9
        assert abs(cell(bad, classifier=classifier, observer='retrained')['ba'] - 1 / 3) < 0.2
    assert cell(good, classifier='nb', observer='retrained')['ba'] > 0.95
    assert abs(cell(bad, classifier='nb', observer='retrained')['ba'] - 1 / 3) < 0.15


def test_nb_reproduces_v1_when_no_near_tie_occurs():
    rows = synthetic(False)
    record, _ = v2.run(rows, ks=(8,), features=('clrt',))
    new = cell(record, classifier='nb', observer='retrained')
    assert new['near_ties'] == 0
    assert new['metrics']['confusion'] == formby_eval.evaluate_arm(rows, rows, 'clrt', 8, ann=False)['nb']['confusion']


def test_every_fit_records_its_convergence_state():
    record, _ = v2.run(synthetic(True), ks=(64,), features=('clrt',))
    for f in record['fits']:
        state = f['convergence']
        assert {'converged', 'n_iter', 'max_iter', 'warnings'} <= set(state)
        if f['classifier'] == 'ff_ann':
            assert state['converged'] == (state['n_iter'] < state['max_iter'] and not state['warnings'])
            assert state['inner_fits'] == 10 and 0 <= state['inner_converged'] <= 10
    assert all(0 <= c['converged_fraction'] <= 1 for c in record['cells'])
    x = np.eye(3).repeat(4, axis=0)
    _, state = models.ann_fit_once(x, np.array(['READ', 'SELECT', 'OPERATE']).repeat(4), 8, seed=1, max_iter=1)
    assert state['converged'] is False and state['n_iter'] == 1 and state['warnings']


def test_select_operate_reports_window_binomial_and_block_clustered_interval():
    per_d = {5: [(1, 2)] * 8, 10: [(2, 2)] * 4 + [(1, 2)] * 4, 15: [(2, 2)] * 4 + [(1, 2)] * 4,
             20: [(2, 2)] * 5 + [(1, 2)] * 3}
    result = v2.select_operate_counts(per_d, seed=3)
    pooled = result['pooled']
    assert (pooled['correct'], pooled['n'], pooled['blocks']) == (45, 64, 32)
    assert pooled['binomial_p_one_sided'] == pytest.approx(0.00078, rel=0.01)
    assert pooled['lower'] <= pooled['estimate'] <= pooled['upper']
    assert result['per_d']['5']['lower'] == result['per_d']['5']['upper'] == 0.5
    assert v2.select_operate_counts(per_d, seed=3) == result


def write_csv(rows, path):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def test_outputs_are_labelled_and_byte_identical_across_two_runs(tmp_path):
    rows_path = tmp_path / 'rows.csv'
    write_csv(synthetic(True) + synthetic(False, arm='combined', seed=1), rows_path)
    names = ('formby_results_v2.json', 'formby_fits_v2.json', 'T2v2_classifier_metrics.csv')
    for run in ('a', 'b'):
        v2.write_outputs(rows_path, tmp_path / run, ks=(64,), features=('clrt', 'joint', 'ack'))
    for name in names:
        assert (tmp_path / 'a' / name).read_bytes() == (tmp_path / 'b' / name).read_bytes(), name
    import json
    record = json.loads((tmp_path / 'a/formby_results_v2.json').read_text())
    assert record['schema'] == 'c72-formby-eval-v2'
    assert 'not device identification' in record['task'] and 'random 75/25' in record['historical_v1_note']
    assert record['rows_sha256'] == hashlib.sha256(rows_path.read_bytes()).hexdigest()
    assert record['fits_sha256'] == hashlib.sha256((tmp_path / 'a/formby_fits_v2.json').read_bytes()).hexdigest()
    assert 'resp_segments' in record['request_to_first_response_byte']
    assert {'python', 'numpy', 'scipy', 'sklearn', 'threadpools', 'thread_env'} <= set(record['environment'])
    assert {c['feature']: c['exploratory'] for c in record['cells']} == {'clrt': False, 'joint': False, 'ack': True}
    assert record['select_operate']['combined']['pooled']['n'] == 16
    header = (tmp_path / 'a/T2v2_classifier_metrics.csv').read_text().splitlines()[0]
    assert header == ('d,arm,feature,exploratory,K,classifier,observer,test_blocks,test_windows,ba,ci_lower,ci_upper,'
                      'paired_delta,delta_lower,delta_upper,near_ties,converged_fraction')
