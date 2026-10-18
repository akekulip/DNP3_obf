"""four_arm_transactions.py: the attacker's table from four-arm block outputs (Part 2, 2026-10-18)."""
import csv
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fat', HERE / 'analysis' / 'four_arm_transactions.py')
fat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fat)


def block(root, name, exchanges_by_arm):
    for arm, ex in exchanges_by_arm.items():
        t = root / name / 'separate_ack' / arm / ('%s_separate_ack_%s_t0' % (name, arm))
        t.mkdir(parents=True)
        (t / 'timing.json').write_text(json.dumps({'exchanges': ex}))
    return root / name


def ex(kind='READ', ack=200, clrt=950, complete=True):
    return dict(kind=kind, complete=complete, ack_lat_us=ack, clrt_us=clrt, rt_us=None if clrt is None else ack + clrt, resp_len=61,
                retransmitted=False, piggyback=False)


def test_rows_counts_and_arm_names(tmp_path):
    b = block(tmp_path, 'blk_b1_01', {'off': [ex(), ex('SELECT'), ex(complete=False)], 'combined': [ex(clrt=None)],
                                      'size_only': [ex('OPERATE')], 'timing_only': [ex(kind='NULL')]})
    out = tmp_path / 't.csv'
    assert fat.main(['x', str(out), str(b)]) == 0
    rows = list(csv.DictReader(open(out)))
    assert {r['arm'] for r in rows} == {'baseline', 'size_only'} and len(rows) == 3
    assert rows[0]['run'] == 'blk_b1_01' and float(rows[0]['clrt_ms']) == 0.95
    counts = json.loads(Path(str(out) + '.counts.json').read_text())['blk_b1_01']
    assert counts['baseline'] == dict(written=2, incomplete=1, missing_interval=0, other_kind=0)
    assert counts['combined']['missing_interval'] == 1 and counts['timing_only']['other_kind'] == 1


def test_an_unknown_arm_directory_or_empty_block_is_refused(tmp_path):
    with pytest.raises(ValueError):
        fat.block_rows(block(tmp_path, 'b1', {'defended': [ex()]}))
    (tmp_path / 'empty').mkdir()
    with pytest.raises(ValueError):
        fat.block_rows(tmp_path / 'empty')


def test_output_feeds_the_four_arm_attacker(tmp_path):
    spec2 = importlib.util.spec_from_file_location('lfa', HERE / 'analysis' / 'leakage_four_arm.py')
    lfa = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(lfa)
    b = block(tmp_path, 'b1', {a: [ex()] for a in ('off', 'size_only', 'timing_only', 'combined')})
    out = tmp_path / 't.csv'
    fat.main(['x', str(out), str(b)])
    runs, arms, cls, X = lfa.load(out)
    assert sorted(set(arms)) == sorted(lfa.ARMS) and X.shape == (4, 2)
