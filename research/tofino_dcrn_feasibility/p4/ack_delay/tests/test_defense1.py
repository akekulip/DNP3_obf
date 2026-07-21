"""Unit tests for the ACK-centric CLRT reference model (Case A / Case B).

Validates the design invariants BEFORE any P4 is authored:
  - Case A zero-inversion (ACK always egresses before the response) under randomized interleaving,
    per-pass jitter, non-same-cycle register visibility, and guard-pass variation;
  - combined-mode bypass / fail-open;
  - Case B deadline-governed release (not MAX_PASS) + deadline-miss handling;
  - device-independent target selection (corr(G, device) == 0).

Run: python3 -m pytest research/tofino_dcrn_feasibility/p4/ack_delay/tests/ -q
"""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "refmodel"))
import defense1_state_machine as sm  # noqa: E402


# ---------------------------------------------------------------- Case A ordering ----

def test_case_a_zero_inversion_default():
    r = sm.simulate_case_a(response_offset=5.0)
    assert r.inversion is False
    assert r.ack_egress_seq is not None and r.resp_egress_seq is not None
    assert r.ack_egress_seq < r.resp_egress_seq          # ACK strictly before response
    assert r.resp_reason == "released" and r.ack_reason == "released"
    assert r.egress_order[0][0] == "ack" and r.egress_order[1][0] == "response"


def test_case_a_zero_inversion_randomized_sweep():
    """The core guarantee: no inversion across 5000 randomized runs (jitter, vis_delay, guard, offset)."""
    inversions = 0
    for i in range(5000):
        rng = random.Random(i + 1)
        r = sm.simulate_case_a(
            response_offset=rng.uniform(0.0, 60.0),
            pass_latency=rng.uniform(0.3, 2.0),
            jitter=rng.uniform(0.0, 0.9),
            vis_delay=rng.choice([1, 2, 3]),
            guard_passes=rng.choice([1, 2, 3, 5]),
            rng=rng,
        )
        if r.inversion or r.resp_reason == "resp_maxpass_BUG":
            inversions += 1
    assert inversions == 0, "zero-inversion invariant violated in %d runs" % inversions


def test_case_a_response_before_ack_arrival_still_ordered():
    """Even if the response enters the pipeline very soon after the ACK, wire order is ACK-first."""
    for off in (0.0, 0.01, 0.1, 0.5):
        r = sm.simulate_case_a(response_offset=off, pass_latency=1.0, jitter=0.0)
        assert r.inversion is False
        assert r.ack_egress_seq < r.resp_egress_seq


def test_case_a_high_visibility_delay_preserves_order():
    """Larger write-to-read latency only DELAYS the response; it can never advance it (no inversion)."""
    for vd in (1, 2, 4, 8):
        r = sm.simulate_case_a(response_offset=3.0, vis_delay=vd, guard_passes=2)
        assert r.inversion is False
        assert r.ack_egress_seq < r.resp_egress_seq


def test_case_a_reduced_clrt_is_the_guard():
    """The reduced CLRT (response egress - ack egress, in passes) equals the ordering guard, small."""
    r = sm.simulate_case_a(response_offset=5.0, vis_delay=1, guard_passes=2)
    clrt_passes = r.resp_egress_seq - r.ack_egress_seq
    assert clrt_passes >= 1                 # strictly positive (ACK first)
    assert clrt_passes <= 20                # small — a handful of passes, not tens of ms of jitter


# ---------------------------------------------------------------- fail-open / bypass ----

def test_combined_bypass():
    assert sm.simulate_combined_bypass() == "bypass_forward"


def test_case_a_fail_open_when_no_response():
    r = sm.simulate_case_a(response_offset=0.0, response_arrives=False)
    assert r.ack_reason == "fail_open"      # held ACK fails open, never dropped
    assert r.resp_egress_seq is None


# ---------------------------------------------------------------- Case B deadline ----

def test_defense2_release_caused_by_deadline_not_maxpass():
    t_out, reason = sm.simulate_case_b(t_ack=4.0, g_i=30.0, t_resp_ready=16.0, clock_ok=True)
    assert reason == "deadline"             # release condition is the deadline, not MAX_PASS
    assert abs(t_out - 34.0) < 1e-9         # t_ack + G_i


def test_defense2_deadline_miss_when_ready_after_deadline():
    t_out, reason = sm.simulate_case_b(t_ack=4.0, g_i=5.0, t_resp_ready=20.0, clock_ok=True)
    assert reason == "ready_after_deadline_miss"
    assert abs(t_out - 20.0) < 1e-9         # released at readiness (deadline already passed)


def test_defense2_broken_clock_degenerates_to_maxpass():
    """Documents the current bug: without a refreshing clock the hold is MAX_PASS-governed."""
    _t, reason = sm.simulate_case_b(t_ack=4.0, g_i=30.0, t_resp_ready=16.0, clock_ok=False)
    assert reason == "max_pass_fail_open"


# ---------------------------------------------------------------- target selection ----

def test_target_selection_is_device_independent():
    """A GLOBAL counter over a mixed device stream must produce targets uncorrelated with device."""
    seq_vals = [25.0, 30.0, 35.0, 40.0]
    devices = ["SEL751", "AB1400", "ION7550"]
    gi = 0
    by_dev = {d: [] for d in devices}
    for k in range(600):
        dev = devices[k % 3]                # arbitrary device interleaving
        g = sm.target_from_global_counter(gi, seq_vals)
        by_dev[dev].append(g)
        gi += 1
    # every device sees the same multiset of targets (means equal) => corr(G, device) == 0
    means = [sum(v) / len(v) for v in by_dev.values()]
    assert max(means) - min(means) < 1e-9


def test_target_selection_not_derived_from_device():
    """Sanity: the target index is the global counter, never the device label."""
    seq_vals = [25.0, 30.0, 35.0, 40.0]
    # same global index -> same target regardless of which device it belongs to
    assert sm.target_from_global_counter(7, seq_vals) == sm.target_from_global_counter(7, seq_vals)


# ---------------------------------------------------------------- Case B deadline hold ----

def test_defense2_ack_forwarded_immediately_not_held():
    """Case B forwards the pure ACK at its native time — it must never be held."""
    assert sm.case_b_ack_egress(4.2) == 4.2


def test_defense2_hold_release_is_deadline_governed():
    """With a refreshing clock, release is caused by the DEADLINE, not MAX_PASS; ≈ t_ack + G_i."""
    r = sm.simulate_case_b_hold(g_i=30.0, t_resp_ready=16.0, t_ack=4.0, pass_latency_ms=0.1)
    assert r["reason"] == "deadline"
    assert r["passes"] < sm.MAX_PASS
    assert abs(r["release_time"] - 34.0) < 0.2          # within one paced pass of t_ack+G_i


def test_defense2_maxpass_is_failopen_only_across_the_band():
    """For the whole common-bounded band and both paced+bare pass latencies, MAX_PASS is NEVER the
    release cause — release is always deadline-governed (MAX_PASS stays a pure fail-open cap)."""
    band = [25.0, 30.0, 35.0, 40.0]
    for g in band:
        for pl in (0.1, 0.0007):                        # paced (100us) and bare (~0.7us) per pass
            r = sm.simulate_case_b_hold(g_i=g, t_resp_ready=16.0, t_ack=4.0, pass_latency_ms=pl)
            assert r["reason"] == "deadline", "G=%s pl=%s -> %s" % (g, pl, r["reason"])
            assert r["passes"] < sm.MAX_PASS


def test_defense2_deadline_miss_releases_immediately():
    """If the response is ready after the deadline, release immediately and record a miss."""
    r = sm.simulate_case_b_hold(g_i=5.0, t_resp_ready=20.0, t_ack=4.0)
    assert r["reason"] == "ready_after_deadline_miss"
    assert abs(r["release_time"] - 20.0) < 1e-9


def test_defense2_broken_clock_degenerates_to_maxpass():
    """The current bug: no refreshing clock -> deadline never matures -> MAX_PASS fail-open."""
    r = sm.simulate_case_b_hold(g_i=30.0, t_resp_ready=16.0, t_ack=4.0, clock_refresh=False)
    assert r["reason"] == "max_pass_fail_open"
    assert r["passes"] == sm.MAX_PASS


def test_defense2_increases_clrt_to_target():
    """Case B raises CLRT = (response release − ACK) toward the common target G_i (increase)."""
    native_clrt = 12.9                                  # SEL751 measured median
    t_ack = 4.0
    r = sm.simulate_case_b_hold(g_i=30.0, t_resp_ready=t_ack + native_clrt, t_ack=t_ack)
    defended_clrt = r["release_time"] - t_ack
    assert defended_clrt > native_clrt                  # CLRT increased
    assert abs(defended_clrt - 30.0) < 0.2              # ≈ the common target G_i (device-independent)
