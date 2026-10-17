"""Isolation acceptance version 3 (review of 7637390c1, findings 1 and 2)."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from token_window import (full_run_rejections_v2, full_run_rejections_v3, drain_timing_v3,  # noqa: E402
                          V3_PASS, V3_FAIL, V3_INDETERMINATE)
import test_isolation_acceptance_v2 as v2fx  # noqa: E402

POP = v2fx.POP


# ---- finding 1: one old blocker can retire only once --------------------------------------------------------------
def test_v2_spent_the_same_old_blocker_twice_and_v3_does_not():
    """Review counterexample: 8 old READ tokens, 7 raw-rejected, all 4 OPERATE raw-rejected, no fresh tokens, so at
    most one blocker; one stale retirement before the permit and one after. v2 accepted it (kept as the record)."""
    before, after, end = v2fx.snap(), v2fx.snap(blocker=2, op=4, read=7, read_pkts=8, op_pkts=4), v2fx.quiet(blocker=1)
    assert full_run_rejections_v2(before, after, end, POP)['post_permit_stale_blockers'] == 1
    with pytest.raises(ValueError, match='not already retired'):
        full_run_rejections_v3(before, after, end, POP)


def test_v3_accepts_the_retained_isolation_shape_with_the_joint_allowance():
    proof = full_run_rejections_v3(v2fx.snap(), v2fx.snap(blocker=2, op=4, read=7, read_pkts=24, op_pkts=12),
                                   v2fx.quiet(), POP)
    assert proof['post_permit_allowance'] == 24 + 1 - 0 and proof['acceptance'].startswith('isolation-v3')


def test_v3_one_old_retirement_before_the_permit_leaves_only_the_fresh_allowance_after():
    end = v2fx.quiet(blocker=1)
    ok = full_run_rejections_v3(v2fx.snap(), v2fx.snap(blocker=1 + 24, op=4, read=7, read_pkts=24, op_pkts=12), end, POP)
    assert ok['post_permit_allowance'] == 24
    with pytest.raises(ValueError, match='not already retired'):
        full_run_rejections_v3(v2fx.snap(), v2fx.snap(blocker=1 + 25, op=4, read=7, read_pkts=24, op_pkts=12), end, POP)


# ---- finding 2: three-state drain with full read-window brackets --------------------------------------------------
def poll(trigger_at, rejections_at, period=100_000_000, window=50_000_000, n=200, op_at=None):
    """Samples every `period` ns, each reading for `window` ns. READ triggered from sample trigger_at; raw READ
    rejections (cell 24) appear at the listed samples; the 4 raw OPERATE rejections (cell 23) at sample op_at."""
    op_at = trigger_at + 5 if op_at is None else op_at
    out = []
    for i in range(n):
        cells = [0] * 25
        cells[24] = sum(1 for r in rejections_at if r <= i)
        cells[23] = 4 if i >= op_at else 0
        out.append(dict(t_start_ns=i * period, t_end_ns=i * period + window, outcomes=cells, errors={},
                        pktgen={'READ': dict(trigger_counter=1 if i >= trigger_at else 0, pkt_counter=0),
                                'OPERATE': dict(trigger_counter=0, pkt_counter=0)}))
    return out


SEVEN = (20, 30, 40, 50, 60, 70)


def test_an_interval_overlapping_the_deadline_is_indeterminate_not_a_pass():
    """Review counterexample shape: the drain bracket straddles 15.001 s."""
    r = drain_timing_v3(poll(10, SEVEN + (160,)), POP, 15_000_000_000, 1_000_000)
    lo, hi = r['drain_ns_interval']
    assert lo <= 15_001_000_000 < hi and r['verdict'] == V3_INDETERMINATE


def test_a_bracket_wholly_inside_the_deadline_passes_and_wholly_outside_fails():
    early = drain_timing_v3(poll(10, SEVEN + (150,)), POP, 15_000_000_000, 1_000_000)
    assert early['verdict'] == V3_PASS and early['drain_ns_interval'][1] <= 15_001_000_000
    late = drain_timing_v3(poll(10, SEVEN + (170,)), POP, 15_000_000_000, 1_000_000)
    assert late['verdict'] == V3_FAIL and late['drain_ns_interval'][0] > 15_001_000_000


def test_brackets_use_whole_read_windows():
    r = drain_timing_v3(poll(10, SEVEN + (150,)), POP, 15_000_000_000, 1_000_000)
    # start in [t_start(9), t_end(10)] = [0.9, 1.05] s; drain in [t_start(149), t_end(150)] = [14.9, 15.05] s
    assert r['drain_ns_interval'] == [14_900_000_000 - 1_050_000_000, 15_050_000_000 - 900_000_000]


@pytest.mark.parametrize('broken', ('incomplete_cohort', 'exceeded_cohort', 'overlap', 'decrease', 'errors',
                                    'no_pre_trigger', 'missing_cells'))
def test_invalid_or_incomplete_series_are_indeterminate(broken):
    rej = SEVEN + (150,)
    if broken == 'incomplete_cohort':
        rej = SEVEN
    elif broken == 'exceeded_cohort':
        rej = SEVEN + (150, 180)
    data = poll(0 if broken == 'no_pre_trigger' else 10, rej)
    if broken == 'overlap':
        data[50]['t_start_ns'] = data[49]['t_end_ns'] - 1
    elif broken == 'decrease':
        data[100]['outcomes'][24] = 0
    elif broken == 'errors':
        data[100]['errors'] = {'outcomes[3]': 'timeout'}
    elif broken == 'missing_cells':
        data[100]['outcomes'] = data[100]['outcomes'][:20]
    r = drain_timing_v3(data, POP, 15_000_000_000, 1_000_000)
    assert r['verdict'] == V3_INDETERMINATE and r['reasons']
