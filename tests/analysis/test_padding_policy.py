import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
pytest.importorskip('sklearn')
import padding_policy as pp  # noqa: E402

NATIVE = {'mixed': 91, 'integrity': 134, 'SELECT': 49, 'OPERATE': 49}
CURRENT = {'mixed': 141, 'integrity': 158, 'SELECT': 60, 'OPERATE': 60}


def formula(u):
    return 10 + u + 2 * (-(-u // 16))


def synthetic(blocks=4, mixed=33, integrity=32, sbo=64, arm='off', d_ms=5, sizes=None):
    """Per block: alternating mixed/integrity READs, each followed by SELECT and OPERATE (the c72 schedule)."""
    sizes = sizes or NATIVE
    rows = []
    for repetition in range(1, blocks + 1):
        seq, counts = 0, dict(mixed=0, integrity=0, SELECT=0, OPERATE=0)
        limits = dict(mixed=mixed, integrity=integrity, SELECT=sbo, OPERATE=sbo)
        for cycle in range(max(mixed + integrity, sbo)):
            workload = 'mixed' if cycle % 2 == 0 else 'integrity'
            for key, operation in ((workload, 'READ'), ('SELECT', 'SELECT'), ('OPERATE', 'OPERATE')):
                if counts[key] >= limits[key]:
                    continue
                counts[key] += 1
                rows.append(dict(block_id='e%02d_d%d_r%02d' % (repetition, d_ms, repetition), arm=arm, d_ms=d_ms,
                                 repetition=repetition, split='train' if repetition <= blocks // 2 else 'test',
                                 operation=operation, read_class=key if operation == 'READ' else '', seq=seq,
                                 clrt_ms=1.0 + 0.01 * (seq % 7), resp_len=sizes[key],
                                 req_len={'mixed': 25, 'integrity': 27}.get(key, 45), piggyback=0))
                seq += 1
    return rows


def test_read_prefix_totals_follow_the_frame_formula_and_reproduce_the_repo_constants():
    totals = pp.reachable_read(91)
    assert totals[91] is None                                   # the unpadded native is attainable
    expected = {91 + formula(u): u for u in range(12, 251)}
    assert {t: u for t, u in totals.items() if u is not None} == expected
    assert totals[141] == 34 and formula(34) == 50              # current mixed: 50-octet prefix of 34 user octets
    assert totals[158] == 49 and formula(49) == 67              # merged READ: 67-octet prefix
    assert 91 + 29 not in totals and 91 + 30 not in totals      # u=16 -> 28, u=17 -> 31: CRC step skips 29, 30
    integrity = pp.reachable_read(134)
    assert min(t for t, u in integrity.items() if u is not None) == 158   # 134 + 24: the prefix floor
    assert 141 not in integrity
    assert max(totals) == 91 + formula(250)


def test_sbo_reframing_totals_are_partitions_of_the_32_application_octets():
    totals = pp.reachable_sbo(32)
    assert totals[49] == [32]                                   # one segment = the native frame
    two = {t for t, parts in totals.items() if len(parts) == 2}
    assert two == {60, 62}
    assert sorted(t for t in totals if 49 < t < 75) == [60, 62, 71, 73]
    assert max(totals) == 32 * formula(2)
    for total, parts in totals.items():
        assert sum(parts) == 32 and all(1 <= a <= 249 for a in parts)
        assert sum(formula(1 + a) for a in parts) == total
    assert sum(formula(1 + a) for a in (15, 17)) == 60          # the implemented 15+17 partition


def test_assignment_maps_by_class_and_refuses_an_undeclared_native():
    rows = synthetic(blocks=2)
    mapped = pp.apply_assignment(rows, CURRENT, NATIVE)
    assert {(r['operation'], r['read_class'], r['resp_len']) for r in mapped} == {
        ('READ', 'mixed', 141), ('READ', 'integrity', 158), ('SELECT', '', 60), ('OPERATE', '', 60)}
    assert rows[0]['resp_len'] == 91                            # inputs are not mutated
    rows[0]['resp_len'] = 92
    with pytest.raises(ValueError):
        pp.apply_assignment(rows, CURRENT, NATIVE)


def test_workload_windows_stay_inside_one_block_and_unfit_sizes_are_unavailable():
    rows = synthetic(blocks=4)
    windows = pp.workload_windows(rows, 'size', 8)
    assert windows and all(len(w['values']) == 8 for w in windows)
    for w in windows:
        members = [r for r in rows if r['block_id'] == w['block_id'] and r['read_class'] == w['operation']]
        assert len(members) >= 8
    assert {w['operation'] for w in windows} == {'mixed', 'integrity'}
    assert pp.window_fits(rows, 32) and not pp.window_fits(rows, 33)
    assert len(pp.workload_windows(rows, 'size', 32)) == 4 * 2
    short = [r for r in rows if not (r['block_id'].startswith('e03') and r['read_class'] == 'integrity'
                                      and r['seq'] > 40)]
    assert not pp.window_fits(short, 32)                        # never completed by borrowing another block
    assert pp.evaluate_workload(short, 'size', 32)['unavailable']


def test_ceiling_counts_groups_of_identical_class_distributions():
    rows = synthetic(blocks=2)
    assert pp.ceiling(rows, CURRENT, NATIVE, pp.OPERATIONS) == pytest.approx(2 / 3)
    merged = dict(CURRENT, mixed=158)
    assert pp.ceiling(rows, merged, NATIVE, pp.OPERATIONS) == pytest.approx(2 / 3)
    assert pp.ceiling(rows, merged, NATIVE, pp.WORKLOADS) == pytest.approx(1 / 2)
    assert pp.ceiling(rows, CURRENT, NATIVE, pp.WORKLOADS) == pytest.approx(1.0)
    everything = dict.fromkeys(NATIVE, 175)
    assert pp.ceiling(rows, everything, NATIVE, pp.OPERATIONS) == pytest.approx(1 / 3)


def test_size_only_classifiers_reach_the_ceiling_on_deterministic_sizes():
    rows = pp.apply_assignment(synthetic(blocks=4), CURRENT, NATIVE)
    operation = pp.evaluate_operation(rows, 'size', 8)
    assert operation['balanced_accuracy'] == pytest.approx(2 / 3)
    assert operation['test_blocks'] == 2 and operation['ci'] is not None
    assert pp.evaluate_workload(rows, 'size', 8)['balanced_accuracy'] == pytest.approx(1.0)
    merged = pp.apply_assignment(synthetic(blocks=4), dict(CURRENT, mixed=158), NATIVE)
    assert pp.evaluate_workload(merged, 'size', 8)['balanced_accuracy'] == pytest.approx(0.5)
    flat = pp.apply_assignment(synthetic(blocks=4), dict.fromkeys(NATIVE, 175), NATIVE)
    assert pp.evaluate_operation(flat, 'size', 8)['balanced_accuracy'] == pytest.approx(1 / 3)


def test_added_bytes_per_class_and_per_transaction():
    rows = synthetic(blocks=2)
    cost = pp.added_bytes(rows, CURRENT, NATIVE)
    assert cost['per_class'] == {'mixed': 50, 'integrity': 24, 'SELECT': 11, 'OPERATE': 11}
    n = len(rows)
    added = 2 * (33 * 50 + 32 * 24 + 64 * 11 * 2)
    assert cost['exchanges'] == n and cost['added_response_octets'] == added
    assert cost['added_per_transaction'] == pytest.approx(added / n)
    native_resp = sum(r['resp_len'] for r in rows)
    native_all = native_resp + sum(r['req_len'] for r in rows)
    assert cost['response_payload_pct'] == pytest.approx(100 * added / native_resp)
    assert cost['request_response_payload_pct'] == pytest.approx(100 * added / native_all)
