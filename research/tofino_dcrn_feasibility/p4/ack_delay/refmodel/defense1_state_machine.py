#!/usr/bin/env python3
"""defense1_state_machine.py — executable reference model for Dr. Lin's ACK-centric CLRT control.

Purpose: validate the CASE A zero-inversion ordering guarantee (ACK always egresses before the
response) *in simulation*, before any P4 is authored, under a faithful model of Tofino-1 semantics:

  * recirculation = a sequence of "passes"; the pipeline SALUs are traversed one pass at a time,
    so there is a TOTAL ORDER of passes (a global sequence number `seq`);
  * MONOTONE, NON-SAME-CYCLE register visibility: a value written on pass `seq=S` is visible only to
    reads on passes `seq >= S + VIS_DELAY` (VIS_DELAY >= 1). This models "you cannot read a value the
    same packet just wrote" — the exact hazard test_cases.md:554-564 flags;
  * a SHARED FIFO egress queue on PORT_VISION: packets leave in ascending egress-`seq` order.

The zero-inversion invariant (STATE_MACHINE.md §3): a response is directed to PORT_VISION only on a
pass where it reads `reg_ack_gone == 1`; the ACK sets `reg_ack_gone := 1` on the pass it is directed
to PORT_VISION. With monotone visibility, the response's release pass is strictly LATER than the ACK's
=> on the shared FIFO the ACK dequeues first. This module demonstrates that holds across randomized
interleavings, per-pass jitter, and visibility delay.

Case B (deadline-governed) is modelled too, to show its release is caused by the deadline, not
MAX_PASS, and that target selection is device-independent.

Python 3.8 compatible (no match/case, no X|None). Pure logic — no network, no P4, no switch.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import heapq
import math

MAX_PASS = 65536          # pure fail-open cap (alarm), never the normal release cause
VIS_DELAY = 1             # register write visible only to strictly-later passes (>=1)


class RegStore:
    """Per-flow register file with versioned writes and visibility-delayed reads (total pass order)."""

    def __init__(self) -> None:
        self._w: Dict[str, List[Tuple[int, int]]] = {}   # key -> [(write_seq, value)]

    def write(self, key: str, value: int, at_seq: int) -> None:
        self._w.setdefault(key, []).append((at_seq, value))

    def read(self, key: str, at_seq: int, vis_delay: int = VIS_DELAY) -> int:
        """Latest value written at seq <= at_seq - vis_delay; 0 if none (controller cold-seeds 0)."""
        hist = self._w.get(key, [])
        val = 0
        for wseq, wval in hist:
            if wseq <= at_seq - vis_delay:
                val = wval
            else:
                break
        return val


@dataclass(order=True)
class _Ev:
    time: float
    tiebreak: int
    frame: "Frame" = field(compare=False)


@dataclass
class Frame:
    role: str                 # 'ack' | 'response'
    enter_time: float         # when it first enters the pipeline
    pass_count: int = 0
    entered: bool = False
    egress_seq: Optional[int] = None
    reason: str = ""          # 'released' | 'fail_open' | 'bypass'


@dataclass
class SimResult:
    egress_order: List[Tuple[str, int]]      # [(role, egress_seq)] in FIFO order
    ack_egress_seq: Optional[int]
    resp_egress_seq: Optional[int]
    inversion: bool                          # response before ack on the wire (a §21 hard-fail)
    resp_reason: str
    ack_reason: str
    total_passes: int


def simulate_case_a(response_offset: float,
                    pass_latency: float = 1.0,
                    jitter: float = 0.0,
                    vis_delay: int = VIS_DELAY,
                    guard_passes: int = 2,
                    rng=None,
                    response_arrives: bool = True) -> SimResult:
    """CASE A: hold the pure ACK; release it when the response is seen; response after `guard_passes`.

    Models the ACK and the response as two frames recirculating on a shared FIFO PORT_VISION queue,
    interleaved by a discrete-event clock (per-pass latency +/- jitter). Returns the wire egress order.
    """
    import random
    rng = rng or random.Random(0)
    reg = RegStore()
    seq = 0                                  # global pass sequence (total order)
    egress: List[Tuple[int, str]] = []       # (egress_seq, role) -> FIFO order after sort by seq

    ack = Frame("ack", enter_time=0.0)
    resp = Frame("response", enter_time=response_offset)

    heap: List[_Ev] = []
    tb = 0
    heapq.heappush(heap, _Ev(ack.enter_time, tb, ack)); tb += 1
    if response_arrives:
        heapq.heappush(heap, _Ev(resp.enter_time, tb, resp)); tb += 1

    def sched(fr: Frame, t: float) -> None:
        nonlocal tb
        heapq.heappush(heap, _Ev(t, tb, fr)); tb += 1

    while heap:
        ev = heapq.heappop(heap)
        fr = ev.frame
        seq += 1                             # this pass takes the next global sequence number
        fr.pass_count += 1
        now_t = ev.time
        step = pass_latency * (1.0 + (rng.uniform(-jitter, jitter) if jitter else 0.0))

        if fr.role == "ack":
            resp_seen = reg.read("resp_seen", seq, vis_delay)
            if resp_seen == 1:
                fr.egress_seq = seq; fr.reason = "released"
                reg.write("ack_gone", 1, seq)          # set on the SAME pass it egresses
                egress.append((seq, "ack"))
            elif fr.pass_count >= MAX_PASS:
                fr.egress_seq = seq; fr.reason = "fail_open"
                egress.append((seq, "ack"))
            else:
                sched(fr, now_t + step)

        else:  # response
            if not fr.entered:
                fr.entered = True
                reg.write("resp_seen", 1, seq)         # response arrival flips the trigger
            ack_gone = reg.read("ack_gone", seq, vis_delay)
            if ack_gone == 1:
                # ack has been directed out; hold guard_passes more, then egress
                if fr.pass_count - getattr(fr, "_gone_at", fr.pass_count) >= guard_passes:
                    fr.egress_seq = seq; fr.reason = "released"
                    egress.append((seq, "response"))
                else:
                    if not hasattr(fr, "_gone_at"):
                        fr._gone_at = fr.pass_count
                    sched(fr, now_t + step)
            elif fr.pass_count >= MAX_PASS:
                # corner-fix: response has NO time-based fail-open in correct operation; a MAX_PASS
                # here means the ACK never released => a design bug. Record it (not a normal exit).
                fr.egress_seq = seq; fr.reason = "resp_maxpass_BUG"
                egress.append((seq, "response"))
            else:
                sched(fr, now_t + step)

    egress.sort()   # FIFO: ascending egress seq
    order = [(role, s) for (s, role) in egress]
    ack_s = ack.egress_seq
    resp_s = resp.egress_seq
    inversion = (resp_s is not None and ack_s is not None and resp_s < ack_s)
    return SimResult(order, ack_s, resp_s, inversion, resp.reason, ack.reason, seq)


def simulate_combined_bypass() -> str:
    """COMBINED: a response with reg_ack_seen==0 (no pure ACK armed) must bypass, forward unchanged."""
    reg = RegStore()
    ack_seen = reg.read("ack_seen", at_seq=10)   # never set => 0
    if ack_seen == 0:
        return "bypass_forward"                  # no hold; native order preserved
    return "held"


def simulate_case_b(t_ack: float, g_i: float, t_resp_ready: float,
                    clock_ok: bool = True) -> Tuple[float, str]:
    """CASE B: forward ACK now; hold response to deadline = t_ack + G_i; release at max(ready, deadline).

    `clock_ok` models whether the recirc time source refreshes (deadline maturable). If not, the
    release degenerates to MAX_PASS fail-open (the current bug) — which this returns as reason.
    """
    deadline = t_ack + g_i
    if not clock_ok:
        return (t_ack + MAX_PASS * 0.0007, "max_pass_fail_open")   # bug path: unmatured deadline
    t_out = max(t_resp_ready, deadline)
    reason = "deadline" if deadline >= t_resp_ready else "ready_after_deadline_miss"
    return (t_out, reason)


def target_from_global_counter(global_index: int, seq_values: List[float]) -> float:
    """Device-INDEPENDENT target: index a preloaded seeded sequence by a GLOBAL transaction counter."""
    return seq_values[global_index % len(seq_values)]


def case_b_ack_egress(t_ack_native: float) -> float:
    """CASE B forwards the pure ACK IMMEDIATELY — its egress time is native, never held."""
    return t_ack_native


def simulate_case_b_hold(g_i: float,
                         t_resp_ready: float,
                         t_ack: float = 4.0,
                         pass_latency_ms: float = 0.1,
                         clock_refresh: bool = True,
                         max_pass: int = MAX_PASS) -> Dict[str, object]:
    """CASE B response hold to an ACK-relative deadline, with the recirc clock-refresh model.

    deadline = t_ack + G_i ; release at max(t_resp_ready, deadline). The response recirculates; each
    pass a REFRESHING tick (the egress-`global_tstamp`-bridged-back fix) advances by `pass_latency_ms`.
    Release is caused by the DEADLINE when the clock refreshes and the deadline is within the MAX_PASS
    cap; `max_pass` is a PURE FAIL-OPEN and should never be the cause for a valid bounded G_i.

    `clock_refresh=False` models the current bug: the tick is frozen (ig_prsr_md not refreshing on
    recirc) → the deadline never matures → release degenerates to MAX_PASS.

    Returns {release_time, reason, passes, deadline}. reason ∈
      {'ready_after_deadline_miss', 'deadline', 'max_pass_fail_open'}.
    """
    deadline = t_ack + g_i
    if t_resp_ready >= deadline:
        return {"release_time": t_resp_ready, "reason": "ready_after_deadline_miss",
                "passes": 0, "deadline": deadline}
    if not clock_refresh:                                   # frozen tick -> never matures -> cap
        return {"release_time": t_resp_ready + max_pass * pass_latency_ms,
                "reason": "max_pass_fail_open", "passes": max_pass, "deadline": deadline}
    passes_needed = int(math.ceil((deadline - t_resp_ready) / pass_latency_ms))
    if passes_needed <= max_pass:
        return {"release_time": t_resp_ready + passes_needed * pass_latency_ms,
                "reason": "deadline", "passes": passes_needed, "deadline": deadline}
    return {"release_time": t_resp_ready + max_pass * pass_latency_ms,
            "reason": "max_pass_fail_open", "passes": max_pass, "deadline": deadline}


if __name__ == "__main__":
    import random
    # randomized robustness sweep for the Case-A zero-inversion invariant
    inversions = 0
    n = 20000
    for i in range(n):
        rng = random.Random(i)
        r = simulate_case_a(
            response_offset=rng.uniform(0.0, 50.0),
            pass_latency=rng.uniform(0.3, 2.0),
            jitter=rng.uniform(0.0, 0.9),
            vis_delay=rng.choice([1, 1, 2, 3]),
            guard_passes=rng.choice([1, 2, 3, 5]),
            rng=rng,
        )
        if r.inversion or r.resp_reason == "resp_maxpass_BUG":
            inversions += 1
    print("Case A zero-inversion sweep: %d runs, %d inversions/bugs" % (n, inversions))
    print("Combined bypass:", simulate_combined_bypass())
    print("Case A fail-open (no response):",
          simulate_case_a(response_offset=0, response_arrives=False).ack_reason)
    print("Case B (clock ok):", simulate_case_b(4.0, 30.0, 16.0))
    print("Case B (clock broken -> the current bug):", simulate_case_b(4.0, 30.0, 16.0, clock_ok=False))
