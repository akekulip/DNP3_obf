"""Phase 02 property tests for the combined-response timing normalization.

Complements tests/test_timing_policy.py with the specific Phase 02 guarantees:
class-independent target, visible-time decorrelation, deadline accounting, and the
absolute-deadline wait actually blocking to the release time. Pure functions; no rig,
no capture. Python 3.8.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import timing_policy as TP  # noqa: E402

MS = TP.MS_TO_NS


def test_fixed_pins_visible_regardless_of_native_and_size():
    sched = TP.ReleaseScheduler(TP.TimingProfile(mode="fixed", target_delay_ms=25.0))
    d_small = sched.decide("a", 1, 0, int(1 * MS), request_size=10, response_size=17)
    d_large = sched.decide("b", 2, 0, int(15 * MS), request_size=99, response_size=2407)
    # both below the 25 ms target -> visible pinned to the target, independent of native/size
    assert abs(d_small.visible_delay_ns - 25 * MS) < 2000
    assert abs(d_large.visible_delay_ns - 25 * MS) < 2000


def test_deadline_missed_when_native_exceeds_target():
    sched = TP.ReleaseScheduler(TP.TimingProfile(mode="fixed", target_delay_ms=10.0))
    d = sched.decide("f", 1, 0, int(50 * MS), request_size=10, response_size=10)
    assert d.deadline_missed is True
    # never send before the response is ready
    assert d.visible_delay_ns >= 50 * MS
    assert d.hold_delay_ns == 0


def test_bounded_targets_stay_in_range_over_many_samples():
    prof = TP.TimingProfile(mode="bounded", target_min_ms=20.0, target_max_ms=30.0, seed=99)
    for _ in range(500):
        target_ns, _ = prof.sample_target_delay_ns()
        assert 20 * MS <= target_ns <= 30 * MS


def test_target_is_class_independent():
    # the sampled target uses only the configured distribution, never a transaction feature
    a = TP.TimingProfile(mode="bounded", target_min_ms=20.0, target_max_ms=30.0, seed=7)
    b = TP.TimingProfile(mode="bounded", target_min_ms=20.0, target_max_ms=30.0, seed=7)
    seq_a = [a.sample_target_delay_ns()[0] for _ in range(20)]
    seq_b = [b.sample_target_delay_ns()[0] for _ in range(20)]
    assert seq_a == seq_b   # deterministic on the seed alone -> independent of any transaction


def test_wait_until_blocks_to_the_deadline():
    now = [1_000_000_000]
    slept = []

    def clock():
        return now[0]

    def sleep(seconds):
        slept.append(seconds)
        now[0] += int(seconds * 1e9)          # advance the fake clock by what we slept

    deadline = now[0] + 40 * MS               # 40 ms out
    TP.wait_until(deadline, clock=clock, sleep=sleep)
    assert now[0] >= deadline                 # returned only after reaching the deadline
    assert sum(slept) > 0                      # it actually waited


def test_wait_until_returns_immediately_if_deadline_passed():
    calls = []
    TP.wait_until(500, clock=lambda: 1000, sleep=lambda s: calls.append(s))
    assert calls == []                         # already past -> no sleep


def test_native_mode_visible_equals_native():
    sched = TP.ReleaseScheduler(TP.TimingProfile(mode="native"))
    d = sched.decide("n", 1, 0, int(16 * MS), request_size=35, response_size=37)
    assert d.visible_delay_ns == 16 * MS
    assert d.bypassed is False and d.hold_delay_ns == 0
