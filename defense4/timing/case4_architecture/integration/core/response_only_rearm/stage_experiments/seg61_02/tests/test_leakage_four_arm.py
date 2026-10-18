"""leakage_four_arm.py: campaign_v2's estimators extended to four arms (Part 2, 2026-10-17)."""
import csv
import importlib.util
import json
import os
import sys
from pathlib import Path

import numpy as np
import pytest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('leakage_four_arm', HERE / 'analysis' / 'leakage_four_arm.py')
lfa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lfa)
CANON = lfa.REPO / 'defense4/timing/framework/build/repro_20261006/transactions_canonical.csv'


def synthetic(rng, runs=6, per=60):
    """baseline and size_only leak (class-dependent CLRT); timing_only and combined carry a constant CLRT."""
    rows = []
    centre = {'READ': 1.0, 'SELECT': 2.0, 'OPERATE': 3.0}
    for r in range(runs):
        for arm in lfa.ARMS:
            for i in range(per):
                k = ('READ', 'SELECT', 'OPERATE')[i % 3]
                leaky = arm in ('baseline', 'size_only')
                clrt = centre[k] + rng.normal(0, 0.05) if leaky else 0.95 + rng.normal(0, 0.05)
                ack = 2.0 + rng.normal(0, 0.05)
                rows.append(('s%02d' % r, arm, k, ack, clrt))
    a = np.array(rows, dtype=object)
    return a[:, 0].astype(str), a[:, 1].astype(str), a[:, 2].astype(str), a[:, 3:].astype(float)


@pytest.fixture(autouse=True)
def few_permutations(monkeypatch):
    monkeypatch.setattr(lfa.lc, 'N_PERM', 30)


def test_four_arms_fixed_attacker_separates_leaky_from_defended_arms():
    res = lfa.analyse(*synthetic(np.random.default_rng(1)))
    a = res['classifiers']['clrt']['A_fixed_baseline_trained']
    assert a['tested_on_baseline']['mean'] > 0.95 and a['tested_on_size_only']['mean'] > 0.95
    assert a['tested_on_timing_only']['mean'] < 0.5 and a['tested_on_combined']['mean'] < 0.5
    assert set(res['classifiers']['clrt']['B_adaptive_arm_trained']) == {
        'tested_on_size_only', 'tested_on_timing_only', 'tested_on_combined'}
    assert res['mutual_information']['baseline']['exceeds_null_p99']
    assert res['mutual_information']['combined']['inside_null']
    assert res['classifiers']['clrt']['folds_per_arm'] == {arm: 6 for arm in lfa.ARMS}


def test_an_arm_missing_from_a_run_is_skipped_for_that_fold_and_counted():
    runs, arms, cls, X = synthetic(np.random.default_rng(2))
    keep = ~((runs == 's00') & (arms == 'combined'))
    res = lfa.analyse(runs[keep], arms[keep], cls[keep], X[keep])
    assert res['classifiers']['clrt']['folds_per_arm']['combined'] == 5


def test_campaign_v2_aliases_and_unknown_arms(tmp_path):
    p = tmp_path / 't.csv'
    with open(p, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['run', 'arm', 'txn_class', 'ack_ms', 'clrt_ms'])
        w.writerow(['s01', 'native', 'READ', '1', '2'])
        w.writerow(['s01', 'obfuscated', 'READ', '1', '2'])
    assert list(lfa.load(p)[1]) == ['baseline', 'timing_only']
    with open(p, 'a') as f:
        f.write('s01,defended,READ,1,2\n')
    with pytest.raises(ValueError):
        lfa.load(p)


def test_no_baseline_is_refused():
    runs, arms, cls, X = synthetic(np.random.default_rng(3))
    keep = arms != 'baseline'
    with pytest.raises(ValueError):
        lfa.analyse(runs[keep], arms[keep], cls[keep], X[keep])


@pytest.mark.skipif(not os.environ.get('LEAKAGE_REPRO') or not CANON.exists(),
                    reason='opt-in (LEAKAGE_REPRO=1) and needs the git-ignored campaign_v2 canonical table')
def test_two_arm_restriction_equals_campaign_v2(tmp_path):
    """Restricted to baseline and timing_only, the four-arm output equals leakage_campaign.py's, number for number."""
    lc = lfa.lc
    runs, arms, cls, X = lc.load(str(CANON))
    ref_path = tmp_path / 'ref.json'
    lc.main(str(CANON), str(ref_path))
    ref = json.loads(ref_path.read_text())
    new = lfa.analyse(*lfa.load(CANON))
    for old, arm in (('native', 'baseline'), ('obfuscated', 'timing_only')):
        assert new['mutual_information'][arm] == ref['mutual_information'][old]
    strip = lambda d: {k: v for k, v in d.items() if k != 'interpretation'}      # the run count is stated, not 22
    for name in ('clrt', 'ack_clrt'):
        r, n = ref['classifiers'][name], new['classifiers'][name]
        for who in ('A_fixed_baseline_trained', 'B_adaptive_arm_trained'):
            n[who] = {k: strip(v) for k, v in n[who].items()}
        for who in ('A_fixed_native_trained', 'B_adaptive_obfuscated_trained'):
            r[who] = {k: strip(v) for k, v in r[who].items()}
        assert n['A_fixed_baseline_trained']['tested_on_baseline'] == r['A_fixed_native_trained']['tested_on_timing_off']
        assert n['A_fixed_baseline_trained']['tested_on_timing_only'] == r['A_fixed_native_trained']['tested_on_obfuscated']
        assert n['B_adaptive_arm_trained']['tested_on_timing_only'] == r['B_adaptive_obfuscated_trained']['tested_on_obfuscated']
        for tag, new_tag in (('A_off', 'A_baseline'), ('A_obf', 'A_timing_only'), ('B_obf', 'B_timing_only')):
            assert new['confusion_all_folds']['%s/%s' % (name, new_tag)] == ref['confusion_all_folds']['%s/%s' % (name, tag)]


def test_a_block_level_shift_makes_the_comparison_uninformative():
    """Code review C1/M2: when each block carries its own offset (e.g. a fixture delay of 5/3/8 ms by block), the fixed
    attacker cannot see even the undefended baseline's leak; defended arms at chance must not read as success."""
    runs, arms, cls, X = synthetic(np.random.default_rng(4), runs=3)
    offset = {'s00': 0.0, 's01': -2.0, 's02': 3.0}
    X = X.copy()
    X[:, 1] += np.array([offset[r] for r in runs])
    res = lfa.analyse(runs, arms, cls, X)
    c = res['classifiers']['clrt']['competence']
    assert c['competent'] is False and c['comparison'].startswith('UNINFORMATIVE')
    good = lfa.analyse(*synthetic(np.random.default_rng(5)))['classifiers']['clrt']['competence']
    assert good['competent'] is True and good['comparison'] == 'informative'


def test_mixed_label_vocabularies_are_refused(tmp_path):
    p = tmp_path / 't.csv'
    p.write_text('run,arm,txn_class,ack_ms,clrt_ms\ns01,native,READ,1,2\ns01,baseline,READ,1,2\n')
    with pytest.raises(ValueError):
        lfa.load(p)


def test_spread_states_the_tables_own_run_count():
    d = lfa.spread([0.3, 0.4, 0.5])
    assert d['n_runs'] == 3 and 'across the 3 grouped runs' in d['interpretation']
