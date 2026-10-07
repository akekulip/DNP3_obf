"""Independent reference of the Step 2 READ release schedule (STEP2_DESIGN.md 1.5, 4.2-4.4).

Expected-output oracle for later packet tests. Pure arithmetic on integer nanoseconds, no
import of ownership/reference.py (the tests cross-check the two). All instants are
unwrapped Python ints; `wrap()` gives the 32-bit clock value the P4 sees. The P4 clock is
the low 32 ns bits masked to 256 ns, so every instant here is floored to that grid.

Equations (t0 = request arrival, D_A one of 5/10/15/20 ms, normal path):
    e_A = max(t0 + D_A, t_A, t_R)          ACK released, response clock armed
    e_R = e_A + CLRT_new                   CLRT_new = 999,936 ns (1 ms on the grid)
Fallbacks (finite):
    readiness  t0 + 29,999,872 ns (30 ms on the grid)
        ACK:  released at max(readiness, t_A) if the normal condition is not met first
        response with no committed ACK: released at max(readiness, t_R)   (FALLBACK_NO_ACK)
    cap        t0 + 40,000,000 ns: no held release is later than the cap; an original that
               arrives at or after the cap is not held ('bypass').
Tie rule: a response deadline is armed only by a commit strictly earlier than the instant
being evaluated (the readiness snapshot precedes a commit in the same instant).

The cap and FALLBACK_NO_ACK are this reference's reading of POLICY_CONTRACT / the design;
the frozen probe implements neither (design 0.3). Heartbeat model: eligibility is observed
only at ticks (period HEARTBEAT_NS requested, phase free); no loop latency is modelled and
internal release is not a wire departure.
"""
from dataclasses import dataclass

MASK = 0xFFFFFFFF
GRID = 256


def quantize(t):
    return t & ~(GRID - 1)


def wrap(t):
    return t & MASK


DA_NS = {ms: quantize(ms * 1_000_000) for ms in (5, 10, 15, 20)}
READINESS_NS = quantize(30_000_000)
GAP_NS = quantize(1_000_000)
CAP_NS = 40_000_000
HEARTBEAT_NS = 100_000


@dataclass(frozen=True)
class Result:
    e_ack: object
    e_rsp: object
    ack_reason: object
    rsp_reason: object


def _identity(t):
    return t


def _schedule(t0, d_ms, t_ack, t_rsp, snap):
    t0 = quantize(t0)
    ready, cap = t0 + READINESS_NS, t0 + CAP_NS
    t_ack = None if t_ack is None else quantize(t_ack)
    t_rsp = None if t_rsp is None else quantize(t_rsp)
    ack_held = t_ack is not None and t_ack < cap
    rsp_held = t_rsp is not None and t_rsp < cap

    e_ack = ack_reason = None
    if t_ack is not None and not ack_held:
        e_ack, ack_reason = t_ack, 'bypass'
    elif ack_held:
        normal = max(t0 + DA_NS[d_ms], t_ack, t_rsp) if rsp_held else None
        fallback = max(ready, t_ack)
        if normal is not None and snap(normal) <= snap(fallback):
            e_ack, ack_reason = snap(normal), 'normal'
        else:
            e_ack, ack_reason = snap(fallback), 'fallback'
        e_ack = min(e_ack, cap)

    e_rsp = rsp_reason = None
    if t_rsp is not None and not rsp_held:
        e_rsp, rsp_reason = t_rsp, 'bypass'
    elif rsp_held:
        fallback = snap(max(t_rsp, ready))
        if e_ack is None or ack_reason == 'bypass' or fallback <= e_ack:
            e_rsp, rsp_reason = fallback, 'fallback_no_ack'
        else:
            e_rsp, rsp_reason = max(snap(e_ack + GAP_NS), t_rsp), 'gap'
        if e_rsp > cap:
            e_rsp, rsp_reason = cap, 'cap'
    return Result(e_ack, e_rsp, ack_reason, rsp_reason)


def ideal(t0, d_ms, t_ack, t_rsp):
    """Continuous-service schedule. t_ack / t_rsp are arrival instants or None (absent)."""
    return _schedule(t0, d_ms, t_ack, t_rsp, _identity)


def tick_ge(t, phase=0, period=HEARTBEAT_NS):
    """First heartbeat instant phase + k*period that is at or after t."""
    return phase + -(-(t - phase) // period) * period


def ticked(t0, d_ms, t_ack, t_rsp, phase=0, period=HEARTBEAT_NS):
    """Same schedule when eligibility is only observed at heartbeat ticks phase + k*period."""
    return _schedule(t0, d_ms, t_ack, t_rsp, lambda t: tick_ge(t, phase, period))
