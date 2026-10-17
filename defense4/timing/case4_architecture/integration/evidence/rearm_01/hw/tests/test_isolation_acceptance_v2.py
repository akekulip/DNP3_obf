"""Isolation acceptance version 2 (token_window.full_run_rejections_v2, drain_timing_v2)."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from token_window import full_run_rejections_v2, drain_timing_v2, LEGACY_POPULATION  # noqa: E402

POP = dict(LEGACY_POPULATION)
POP['READ'] = dict(POP['READ'], expected_raw_stale=7)
POP['OPERATE'] = dict(POP['OPERATE'], expected_raw_stale=4)


def app(packets):
    return dict(trigger_counter=1, batch_counter=1, pkt_counter=packets)


def snap(blocker=0, op=0, read=0, read_pkts=0, op_pkts=0):
    return {'pktgen': {'READ': dict(trigger_counter=0, batch_counter=0, pkt_counter=read_pkts),
                       'OPERATE': dict(trigger_counter=0, batch_counter=0, pkt_counter=op_pkts)},
            'outcomes': dict(STALE_BLOCKER=blocker, RAW_OPERATE_TIMER_STALE=op, RAW_READ_TIMER_STALE=read,
                             OUT_TOKEN_STALE=blocker + op + read)}


def quiet(blocker=0, op=4, read=7, read_pkts=8, op_pkts=4):
    return {'read_app_after': app(read_pkts), 'operate_app_after': app(op_pkts),
            'timer_rejection_layout': 'split_raw_timer_23_24',
            'old_reject_after': {str(i): {'outcomes.f1': [v]} for i, v in zip((6, 14, 23, 24), (blocker, 0, op, read))}}


def test_the_retained_isolation_shape_passes_with_fresh_cleanup_after_the_permit():
    """ctl_m5_stale_iso20_950_01 / D1: 7 + 4 raw before the permit, 2 stale blockers after, 24 fresh tokens."""
    proof = full_run_rejections_v2(snap(), snap(blocker=2, op=4, read=7, read_pkts=24, op_pkts=12), quiet(), POP)
    assert proof['post_permit_stale_blockers'] == 2 and proof['pre_permit_stale_blockers'] == 0
    assert proof['fresh_tokens_after_permit'] == {'READ': 16, 'OPERATE': 8}
    assert proof['old_tokens_not_rejected_raw'] == 1 and proof['post_permit_allowance'] == 25


def test_post_permit_retirements_beyond_every_token_that_could_seed_them_fail():
    with pytest.raises(ValueError, match='after the permit'):
        full_run_rejections_v2(snap(), snap(blocker=26, op=4, read=7, read_pkts=24, op_pkts=12), quiet(), POP)


def test_pre_permit_retirements_beyond_the_old_tokens_not_rejected_raw_fail():
    with pytest.raises(ValueError, match='before the permit'):
        full_run_rejections_v2(snap(), snap(blocker=2, op=4, read=7, read_pkts=24, op_pkts=12), quiet(blocker=2), POP)


@pytest.mark.parametrize('cell', ('op', 'read'))
def test_a_raw_rejection_after_drain_still_fails(cell):
    after = snap(blocker=2, op=5 if cell == 'op' else 4, read=8 if cell == 'read' else 7, read_pkts=24, op_pkts=12)
    with pytest.raises(ValueError, match='after old batches drained'):
        full_run_rejections_v2(snap(), after, quiet(), POP)


def test_the_delayed_cohort_equalities_still_apply_outside_control():
    with pytest.raises(ValueError, match='READ timer rejection count'):
        full_run_rejections_v2(snap(), snap(op=4, read=6, read_pkts=24, op_pkts=12), quiet(read=6), POP)
    proof = full_run_rejections_v2(snap(), snap(blocker=4, read_pkts=24, op_pkts=12),
                                   quiet(blocker=2, op=0, read=0), POP, control=True)
    assert proof['control'] and proof['post_permit_stale_blockers'] == 2


@pytest.mark.parametrize('broken', ('dirty_baseline', 'nonmonotonic', 'aggregate', 'generator'))
def test_unreadable_or_inconsistent_counters_fail_closed(broken):
    before, after, end = snap(), snap(blocker=2, op=4, read=7, read_pkts=24, op_pkts=12), quiet()
    if broken == 'dirty_baseline':
        before['outcomes']['STALE_BLOCKER'] = 1
    elif broken == 'nonmonotonic':
        after['outcomes']['RAW_READ_TIMER_STALE'] = None
    elif broken == 'aggregate':
        after['outcomes']['OUT_TOKEN_STALE'] += 1
    else:
        after['pktgen']['READ']['pkt_counter'] = 3
    with pytest.raises(ValueError):
        full_run_rejections_v2(before, after, end, POP)


def samples(trigger_at, rejections_at, period=100_000_000, n=200):
    """Poller samples every `period` ns; READ triggered from sample trigger_at, raw READ rejections at the listed
    sample indices."""
    out = []
    for i in range(n):
        out.append(dict(t_start_ns=i * period, t_end_ns=i * period + 50_000_000,
                        outcomes=[0] * 24 + [sum(1 for r in rejections_at if r <= i)],
                        pktgen={'READ': dict(trigger_counter=1 if i >= trigger_at else 0)}))
    return out


def test_drain_is_bracketed_on_the_switch_clock_and_judged_on_its_lower_edge():
    result = drain_timing_v2(samples(10, (60, 110, 160)), 15_000_000_000, 1_000_000, 18_597_019_124)
    assert result['drain_ns_interval'] == [15_000_000_000 - 50_000_000, 15_100_000_000]
    assert result['verdict'] == 'consistent' and result['detection_elapsed_ns'] == 18_597_019_124
    late = drain_timing_v2(samples(10, (60, 110, 170)), 15_000_000_000, 1_000_000)
    assert late['verdict'] == 'slower_than_derived'


@pytest.mark.parametrize('case', ('none', 'no_trigger', 'no_rejection', 'trigger_first_sample'))
def test_drain_without_a_bracketable_window_is_unobserved(case):
    data = {'none': [], 'no_trigger': samples(10**6, (60,)), 'no_rejection': samples(10, ()),
            'trigger_first_sample': samples(0, (60,))}[case]
    assert drain_timing_v2(data, 15_000_000_000, 1_000_000)['verdict'] == 'unobserved'
