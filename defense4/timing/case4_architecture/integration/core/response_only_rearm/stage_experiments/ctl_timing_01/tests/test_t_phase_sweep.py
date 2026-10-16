"""No early timing decision and a declared clock lifetime for T's time base (directive ba50eac69, C1; Philip
2026-10-16).

T decides a deadline by the sign bit of the 32-bit value now_u - D_u - t0_u, where now_u and the anchor t0_u are the
clock sampled on a grid and D_u is the duration in T units. Quantizing the anchor and `now` can make the quantized
elapsed time exceed the true one by almost a grid. The exact decision is modelled here over all 1,024 anchor phases
against the unquantized reference (true elapsed time), for:
  ns_256    every T before m7: ns units on a 256 ns grid, durations written in ns (early by up to 255 ns);
  naive_512 the first m7 draft: 512 ns units on a 1,024 ns grid, durations floor(D / 512) (early by up to 767 ns at
            J = 2.4 ms, Philip's counterexample);
  m7        256 ns units on a 512 ns grid, durations from t_config.t_units = ceil((D + 512) / 256): never early.
The end-to-end sample runs the real m7 P4 on the source pipeline with fine laps: T's release of a held OPERATE minus
its exact admission time is at least J. The rollover tests cover the m7 clock's 2^40 ns wrap and declare its lifetime:
a passed deadline reads as passed until D + 2^31 x 256 ns after its anchor, so T must resolve every held packet
within about 9.16 minutes of its anchor.
"""
import copy
import importlib.util
import sys
from pathlib import Path

import pytest

import contention_source as cs
import test_t_time_base as tb

t_config = cs.t_config
PHASES = range(1024)
DURATIONS = (2_400_000, 599_808, 950_000, 1_000_000, 2_000_000_000, 1, 256, 511, 512, 1023, 1024)
MASK32 = (1 << 32) - 1


def decision_time(anchor_ns, duration_ns, unit_ns, grid_ns, duration_units):
    """First instant at which T's sign test passes: the first grid sample g >= anchor with g_u - t0_u >= D_u."""
    a_q = anchor_ns // grid_ns * grid_ns
    need = duration_units * unit_ns                               # quantized elapsed time required, in ns
    g = a_q + -(-need // grid_ns) * grid_ns
    return max(g, anchor_ns)


BUILDS = {
    'ns_256': (1, 256, lambda d: d),
    'naive_512': (512, 1024, lambda d: d >> 9),
    'm7': (256, 512, lambda d: t_config.t_units(dict(op_j=d), 256, 512)['op_j']),
}


def earliest_margin(build, duration_ns, base=10_000_000_000):
    unit, grid, convert = BUILDS[build]
    du = convert(duration_ns)
    return min(decision_time(base + phase, duration_ns, unit, grid, du) - (base + phase) - duration_ns
               for phase in PHASES)


@pytest.mark.parametrize('duration_ns', DURATIONS)
def test_m7_never_decides_before_the_ns_duration_in_any_of_1024_anchor_phases(duration_ns):
    assert earliest_margin('m7', duration_ns) >= 0


def test_the_quantization_counterexamples_are_reproduced():
    """The reference model is sensitive: the pre-m7 T is early by up to 255 ns, the naive conversion by 767 ns at
    J = 2,400,000 ns (decision after 2,399,233 ns), as Philip computed."""
    assert earliest_margin('ns_256', 2_400_000) == -255
    assert earliest_margin('naive_512', 2_400_000) == -767


def test_m7_margin_is_bounded_and_the_writer_rounds_up():
    """The conservative bound costs at most two grids of lateness, and t_units never rounds down."""
    for d in DURATIONS:
        unit, grid, convert = BUILDS['m7']
        du = convert(d)
        assert du * unit >= d + grid
        late = max(decision_time(10**10 + ph, d, unit, grid, du) - (10**10 + ph) - d for ph in PHASES)
        assert late <= 2 * grid + unit


# ---- the real m7 P4, end to end on the source pipeline ------------------------------------------------------
FINE = dict(loop_ns=64, service_ns=64)        # held packets re-evaluated every few tens of ns
END_TO_END_PHASES = sorted(set(range(0, 1024, 32)) | {255, 511, 767, 1023})   # incl. the worst phases (511 mod 512)


def _prepared(source):
    p = cs.LapPipeline(source, **FINE).handshake()
    rq, ak, rp = cs.transaction('SELECT')
    t = p.now + 100_000
    p.at(t, rq, master=True)
    p.at(t + 200_000, ak)
    p.at(t + 400_000, rp)
    p.now = t
    p.settle()
    return p


def operate_hold(prepared, phase):
    """T's release of the OPERATE toward the relay minus T's exact admission time of it (TEV kind 12)."""
    p = copy.deepcopy(prepared)
    admitted = []
    original = p.t.handoff

    def handoff(time, raw):
        if len(raw) > 12 and raw[12] == 12:
            admitted.append(time)
        return original(time, raw)
    p.t.handoff = handoff
    request, _ack, _response = cs.transaction('OPERATE')
    base = (p.now // 1_048_576 + 2) * 1_048_576
    p.at(base + phase, request, master=True)
    p.now = base
    p.settle(horizon=10_000_000)
    released = [t for t, port, raw in p.t.emitted if port == cs.RELAY_PORT and len(raw) > 60 and t > base]
    assert len(admitted) == 1 and released
    return released[0] - admitted[0]


@pytest.fixture(scope='module')
def m7_prepared():
    return _prepared(tb.M7)


def test_m7_releases_a_held_operate_no_earlier_than_j_after_its_true_admission(m7_prepared):
    """End to end on the real P4. This ties the arithmetic proof to the build; it is not a sensitive negative control:
    measured 2026-10-16, the pre-m7 T also releases no earlier than J end to end (minimum +128 ns) because release
    latency exceeds its sub-grid error, so the exact proof of "never early" is the 1,024-phase sweep above."""
    holds = [operate_hold(m7_prepared, phase) for phase in END_TO_END_PHASES]
    assert min(holds) >= cs.qs.OP_J


# ---- rollover and lifetime of the m7 clock ----------------------------------------------------------------
WRAP_NS = 1 << 40                              # global_tstamp[39:8] wraps every 2^32 x 256 ns (18.33 minutes)
HORIZON_NS = (1 << 31) * 256                   # signed horizon, 9.16 minutes


def m7_sign_ok(now_ns, anchor_ns, duration_ns):
    now_u = (now_ns >> 8) & MASK32 & ~1
    t0_u = (anchor_ns >> 8) & MASK32 & ~1
    du = t_config.t_units(dict(op_j=duration_ns), 256, 512)['op_j']
    return ((now_u - du - t0_u) & MASK32) >> 31 == 0


@pytest.mark.parametrize('anchor_ns', (WRAP_NS - 1_000_000, WRAP_NS - 300, WRAP_NS, 3 * WRAP_NS - 4096))
def test_decisions_across_the_clock_wrap_are_correct(anchor_ns):
    """An exchange straddling the 2^40 ns wrap of global_tstamp[39:8] decides as one that does not."""
    for d in (950_000, 2_400_000):
        assert not m7_sign_ok(anchor_ns + d - 1, anchor_ns, d)
        assert m7_sign_ok(anchor_ns + d + 2048, anchor_ns, d)


def test_lifetime_bound_is_declared_and_aliasing_beyond_it_is_real():
    """Within the signed horizon an expired deadline stays expired; past it the decision flips (the declared
    lifetime: T must resolve every held packet within 9.16 minutes of its anchor)."""
    d = 2_000_000_000
    assert HORIZON_NS / 60e9 == pytest.approx(9.16, abs=0.01)
    assert WRAP_NS / 60e9 == pytest.approx(18.33, abs=0.01)
    a = 5 * WRAP_NS + 12345
    assert m7_sign_ok(a + HORIZON_NS - 4096, a, d)          # still expired just before 2^31 units after the anchor
    assert not m7_sign_ok(a + HORIZON_NS + d + 4096, a, d)  # aliased just past it
