"""Regression tests for the Phase 02 bounded-PRNG fix (per-repetition unique seed).

Proves the defect is gone: a transaction position no longer maps to a fixed target across
repetitions; the target sequence is deterministic from one top-level run seed; a different
seed changes it; and the target is independent of response size and drawn uniformly.
"""

from __future__ import annotations

import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import phase02_normalize_experiment as EXP  # noqa: E402
import timing_policy as TP                   # noqa: E402


def _draw(run_seed, cfg_idx, rep_idx, position):
    """Return the `position`-th bounded target (ms) for a per-rep seed (1-indexed)."""
    prof = TP.TimingProfile(mode="bounded", target_min_ms=20.0, target_max_ms=30.0,
                            seed=EXP.rep_seed(run_seed, cfg_idx, rep_idx))
    t_ns = 0
    for _ in range(position):
        t_ns, _ = prof.sample_target_delay_ns()
    return t_ns * TP.NS_TO_MS


def test_rep_seed_is_deterministic():
    assert EXP.rep_seed(20260716, 2, 7) == EXP.rep_seed(20260716, 2, 7)


def test_rep_seed_varies_by_repetition_and_config():
    assert EXP.rep_seed(20260716, 2, 0) != EXP.rep_seed(20260716, 2, 1)
    assert EXP.rep_seed(20260716, 0, 5) != EXP.rep_seed(20260716, 1, 5)


def test_position_target_not_fixed_across_repetitions():
    # THE defect: before the fix, position 4 got the same target every repetition.
    targets = [_draw(20260716, 2, rep, position=4) for rep in range(30)]
    assert len(set(round(t, 6) for t in targets)) > 1        # not all identical
    assert len(set(round(t, 6) for t in targets)) >= 20      # broadly varied


def test_same_run_seed_reproduces_full_sequence():
    seq_a = [_draw(999, 2, rep, position=(rep % 5) + 1) for rep in range(50)]
    seq_b = [_draw(999, 2, rep, position=(rep % 5) + 1) for rep in range(50)]
    assert seq_a == seq_b


def test_different_run_seed_changes_sequence():
    seq_a = [_draw(111, 2, rep, position=1) for rep in range(50)]
    seq_b = [_draw(222, 2, rep, position=1) for rep in range(50)]
    assert seq_a != seq_b


def test_target_independent_of_response_size():
    # position 4 carries the 2407 B READ, position 1 a 17 B response; their target
    # distributions across repetitions must be statistically indistinguishable (the target
    # is drawn from the seed, never from size).
    big = [_draw(20260716, 2, rep, position=4) for rep in range(400)]
    small = [_draw(20260716, 2, rep, position=1) for rep in range(400)]
    assert abs(statistics.mean(big) - statistics.mean(small)) < 0.6   # both ~25 ms


def test_bounded_targets_are_uniform_over_the_interval():
    draws = [_draw(20260716, 2, rep, position=1) for rep in range(2000)]
    assert all(20.0 <= t <= 30.0 for t in draws)
    assert abs(statistics.mean(draws) - 25.0) < 0.4          # uniform mean ~25 ms
    assert abs(statistics.pstdev(draws) - 2.887) < 0.4       # uniform std ~ (30-20)/sqrt(12)
    assert min(draws) < 20.6 and max(draws) > 29.4           # covers the interval


def test_projected_tail_metrics_are_separated():
    """deadline-miss (native>selected) must be distinguished from native>lower/upper bound."""
    import types
    import phase02_projected_leakage as PL

    def txn(native_ms, i):
        return types.SimpleNamespace(
            req_to_resp_ms=native_ms, req_time_epoch=1000.0 + i * 0.1,
            req_tcp_len=35, resp_tcp_len=37, device_label="AB1400", is_reference=False)

    natives = [16.0] * 90 + [22.0] * 5 + [26.0] * 3 + [35.0] * 2
    txns = [txn(v, i) for i, v in enumerate(natives)]
    by_mode = PL.project(txns)

    b = by_mode["bounded20-30"]
    # native>lower(20) = {22,26,35} = 10/100; native>upper(30) = {35} = 2/100
    assert b["native_above_lower_bound_rate"] == 0.10
    assert b["native_above_upper_bound_rate"] == 0.02
    # deadline-miss (native>selected in [20,30]) sits between the two bounds
    assert b["native_above_upper_bound_rate"] <= b["actual_deadline_miss_rate"] <= b["native_above_lower_bound_rate"]
    # the scheduler flag (#1) and the direct native>selected computation (#2) agree
    assert b["actual_deadline_miss_rate"] == b["native_above_selected_target_rate"]

    f = by_mode["fixed25"]
    # fixed: lower==upper==selected==25 -> all four rates identical (native>25 = {26,35} = 5/100)
    assert f["native_above_lower_bound_rate"] == f["native_above_upper_bound_rate"] == 0.05
    assert f["actual_deadline_miss_rate"] == f["native_above_selected_target_rate"] == 0.05
