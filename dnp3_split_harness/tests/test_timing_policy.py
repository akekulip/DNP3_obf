"""
Unit tests for timing_policy.py (plan section 10).

Runnable two ways:
    python3 -m pytest tests/test_timing_policy.py       # if pytest present
    python3 tests/test_timing_policy.py                 # standalone runner

All tests are pure (no real clock, no sockets): the scheduler is a deterministic
decision function, so timing behavior is verified against exact nanosecond math.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import timing_policy as tp

MS = tp.MS_TO_NS


def _sched(**profile_kwargs):
    return tp.ReleaseScheduler(tp.TimingProfile(**profile_kwargs))


# --- fixed target release ------------------------------------------------- #

def test_fixed_target_release():
    s = _sched(mode=tp.FIXED, target_delay_ms=12)
    d = s.decide("f", 1, request_received_ns=0, response_ready_ns=1 * MS,
                 request_size=20, response_size=100)
    assert d.target_release_ns == 12 * MS
    assert d.actual_release_ns == 12 * MS         # held to target, ready earlier
    assert d.hold_delay_ns == 11 * MS
    assert d.visible_delay_ns == 12 * MS
    assert not d.deadline_missed and not d.bypassed


def test_response_ready_before_target_is_held():
    s = _sched(mode=tp.FIXED, target_delay_ms=15)
    d = s.decide("f", 1, 0, 2 * MS, 20, 100)
    assert d.actual_release_ns == 15 * MS
    assert d.hold_delay_ns == 13 * MS
    assert not d.deadline_missed


# --- response ready after target => deadline miss, send when ready -------- #

def test_response_ready_after_target_misses_deadline():
    s = _sched(mode=tp.FIXED, target_delay_ms=12)
    d = s.decide("f", 1, 0, 20 * MS, 20, 100)     # response not ready until 20 ms
    assert d.deadline_missed is True
    assert d.actual_release_ns == 20 * MS         # never send early: send when ready
    assert d.hold_delay_ns == 0
    assert not d.bypassed


# --- bounded target + deterministic seeded output ------------------------- #

def test_bounded_target_within_range():
    s = _sched(mode=tp.BOUNDED, target_min_ms=10, target_max_ms=15, seed=42)
    for i in range(50):
        d = s.decide("f", i, 0, 0, 20, 100)
        assert 10 * MS <= d.selected_target_delay_ns <= 15 * MS


def test_deterministic_seeded_output():
    a = _sched(mode=tp.BOUNDED, target_min_ms=10, target_max_ms=15, seed=777)
    b = _sched(mode=tp.BOUNDED, target_min_ms=10, target_max_ms=15, seed=777)
    seq_a = [a.decide("f", i, 0, 0, 20, 100).selected_target_delay_ns for i in range(20)]
    seq_b = [b.decide("f", i, 0, 0, 20, 100).selected_target_delay_ns for i in range(20)]
    assert seq_a == seq_b
    # a different seed should (almost surely) differ
    c = _sched(mode=tp.BOUNDED, target_min_ms=10, target_max_ms=15, seed=778)
    seq_c = [c.decide("f", i, 0, 0, 20, 100).selected_target_delay_ns for i in range(20)]
    assert seq_a != seq_c


def test_target_independent_of_response_size():
    # normalization, not jitter: identical seed sequence regardless of payload size.
    a = _sched(mode=tp.BOUNDED, target_min_ms=10, target_max_ms=15, seed=5)
    b = _sched(mode=tp.BOUNDED, target_min_ms=10, target_max_ms=15, seed=5)
    seq_small = [a.decide("f", i, 0, 0, 20, 40).selected_target_delay_ns for i in range(20)]
    seq_large = [b.decide("f", i, 0, 0, 20, 4000).selected_target_delay_ns for i in range(20)]
    assert seq_small == seq_large


# --- per-flow FIFO + multi-flow independence ------------------------------ #

def test_per_flow_fifo_clamps_release_monotonic():
    s = _sched(mode=tp.FIXED, target_delay_ms=10)
    d1 = s.decide("f", 1, request_received_ns=5 * MS, response_ready_ns=5 * MS,
                  request_size=20, response_size=100)
    # second transaction "arrives" earlier (out of order); release must not precede d1.
    d2 = s.decide("f", 2, request_received_ns=0, response_ready_ns=0,
                  request_size=20, response_size=100)
    assert d1.actual_release_ns == 15 * MS
    assert d2.actual_release_ns >= d1.actual_release_ns    # FIFO monotonic


def test_multiple_flows_are_independent():
    s = _sched(mode=tp.FIXED, target_delay_ms=10)
    a = s.decide("A", 1, 5 * MS, 5 * MS, 20, 100)          # release 15 ms
    b = s.decide("B", 1, 0, 0, 20, 100)                    # own flow, release 10 ms
    assert a.actual_release_ns == 15 * MS
    assert b.actual_release_ns == 10 * MS                  # not clamped by flow A


# --- fail-open bypasses --------------------------------------------------- #

def test_critical_flow_bypass():
    s = _sched(mode=tp.FIXED, target_delay_ms=12, critical_function_bypass=True)
    d = s.decide("f", 1, 0, 1 * MS, 20, 100, is_critical=True)
    assert d.bypassed and d.bypass_reason == tp.BypassReason.CRITICAL_TRANSACTION.value
    assert d.actual_release_ns == 1 * MS and d.hold_delay_ns == 0


def test_unknown_traffic_bypass():
    s = _sched(mode=tp.FIXED, target_delay_ms=12, unknown_traffic_bypass=True)
    d = s.decide("f", 1, 0, 1 * MS, 20, 100, is_supported=False)
    assert d.bypassed and d.bypass_reason == tp.BypassReason.UNSUPPORTED_TRAFFIC.value


def test_queue_limit_bypass():
    s = _sched(mode=tp.FIXED, target_delay_ms=12, max_queue_depth=2)
    s.flow("f").queue_depth = 3
    d = s.decide("f", 1, 0, 1 * MS, 20, 100)
    assert d.bypassed and d.bypass_reason == tp.BypassReason.QUEUE_LIMIT.value


def test_strict_safety_bypass_without_rto():
    s = _sched(mode=tp.FIXED, target_delay_ms=12, strict_safety=True)
    d = s.decide("f", 1, 0, 1 * MS, 20, 100, rto_safe_ms=None)
    assert d.bypassed and d.bypass_reason == tp.BypassReason.RTO_UNKNOWN_STRICT.value
    # with a known safe bound, it holds normally
    d2 = s.decide("f", 2, 0, 1 * MS, 20, 100, rto_safe_ms=100.0)
    assert not d2.bypassed and d2.actual_release_ns == 12 * MS


def test_max_hold_backstop_bypass():
    s = _sched(mode=tp.FIXED, target_delay_ms=500, max_hold_ms=100)
    d = s.decide("f", 1, 0, 1 * MS, 20, 100)
    assert d.bypassed and d.bypass_reason == tp.BypassReason.UNSAFE_TARGET.value
    assert d.actual_release_ns == 1 * MS          # sent when ready, not held 500 ms


def test_rto_safe_bound_bypass():
    s = _sched(mode=tp.FIXED, target_delay_ms=300)
    d = s.decide("f", 1, 0, 1 * MS, 20, 100, rto_safe_ms=150.0)
    assert d.bypassed and d.bypass_reason == tp.BypassReason.UNSAFE_TARGET.value


# --- native mode ---------------------------------------------------------- #

def test_native_mode_no_hold():
    s = _sched(mode=tp.NATIVE)
    d = s.decide("f", 1, 0, 3 * MS, 20, 100)
    assert d.actual_release_ns == 3 * MS and d.hold_delay_ns == 0
    assert not d.bypassed and not d.deadline_missed
    assert d.visible_delay_ns == 3 * MS           # native ready time is the visible time


# --- invalid config ------------------------------------------------------- #

def test_invalid_target_range_raises():
    try:
        tp.TimingProfile(mode=tp.BOUNDED, target_min_ms=15, target_max_ms=10)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for min>max")


def test_invalid_mode_raises():
    try:
        tp.TimingProfile(mode="bogus")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad mode")


# --- Phase 2: ACK-before-response ordering (no ACK after response) -------- #

def test_ack_never_released_after_response():
    # a huge ACK delay must be clamped so the ACK is not sent after the response.
    plan = tp.plan_ack_response_release(
        request_received_ns=0, ack_ready_ns=4 * MS, response_ready_ns=17 * MS,
        ack_mode="ack-delay-only", ack_delay_ns=100 * MS)
    assert plan.ack_release_ns <= plan.response_release_ns
    assert plan.clamped is True


def test_ack_delay_only_shrinks_gap():
    # native gap = 17-4 = 13 ms; delaying the ACK by 5 ms shrinks the visible gap to 8 ms.
    native = tp.plan_ack_response_release(0, 4 * MS, 17 * MS, ack_mode=tp.NATIVE)
    delayed = tp.plan_ack_response_release(0, 4 * MS, 17 * MS,
                                           ack_mode="ack-delay-only", ack_delay_ns=5 * MS)
    assert native.gap_ns == 13 * MS
    assert delayed.gap_ns == 8 * MS
    assert delayed.ack_release_ns <= delayed.response_release_ns


def test_response_delay_only_grows_gap():
    grown = tp.plan_ack_response_release(0, 4 * MS, 17 * MS,
                                         ack_mode="response-delay-only", response_delay_ns=5 * MS)
    assert grown.gap_ns == 18 * MS
    assert grown.ack_release_ns <= grown.response_release_ns


def test_gap_normalized_sets_exact_gap():
    plan = tp.plan_ack_response_release(0, 4 * MS, 17 * MS,
                                        ack_mode="gap-normalized", gap_target_ns=6 * MS)
    assert plan.gap_ns == 6 * MS
    assert plan.ack_release_ns <= plan.response_release_ns


# --- no packet synthesis in Phase 1 (structural) -------------------------- #

def test_decision_carries_no_payload_bytes():
    # the scheduler decides *timing* only; it holds no packet bytes and can neither
    # create nor mutate a packet.  A byte-for-byte guarantee is thus structural.
    fields = tp.TimingDecision.__dataclass_fields__
    assert not any("byte" in name.lower() or "payload" in name.lower() for name in fields)


def _all_tests():
    g = globals()
    return [g[n] for n in sorted(g) if n.startswith("test_") and callable(g[n])]


if __name__ == "__main__":
    failures = 0
    for fn in _all_tests():
        try:
            fn()
            print("PASS", fn.__name__)
        except Exception as exc:                  # report every test's result
            failures += 1
            print("FAIL", fn.__name__, "->", repr(exc))
    print("\n{} passed, {} failed".format(len(_all_tests()) - failures, failures))
    sys.exit(1 if failures else 0)
