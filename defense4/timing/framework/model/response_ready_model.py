"""Independent event model of the READ response-ready release policy.

Written from framework/contract/POLICY_CONTRACT.md, not from the P4. Times are integer
nanoseconds on one unbounded timeline. Modular 32-bit tick decoding is provided by due() and checked
separately (tests/test_model_scenarios.py); the model itself does not wrap.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

TICK_NS = 256
MASK = (1 << 32) - 1
HALF = 1 << 31
DEFAULT_H_NS = 18000 * 1711  # 18,000 passes x ~1.711 us; an estimate, see the contract


def quantize_ns(ns: int) -> int:
    """Floor to the 256 ns grid (1 ms -> 999,936 ns, as control.py realizes it)."""
    return (ns // TICK_NS) * TICK_NS


def to_tick(ns: int) -> int:
    return (ns // TICK_NS) & MASK


def due(now_tick: int, deadline_tick: int) -> bool:
    """Modular half-range comparison: deadline has been reached at now."""
    return ((now_tick - deadline_tick) & MASK) < HALF


@dataclass(frozen=True)
class Ev:
    t: int                      # ns
    kind: str                   # REQ ACK RESP FIN
    epoch: int = 0
    seq: int = 0                # TCP seq of the segment
    length: int = 0             # payload length
    ack: int = 0                # TCP ack number
    app: int = 0                # DNP3 application sequence
    supported: bool = True      # READ, single frame, no unsupported options


@dataclass
class Out:
    kind: str                   # ACK RESP REQ
    t: int
    reason: str


@dataclass
class Result:
    outs: List[Out] = field(default_factory=list)
    counters: Dict[str, int] = field(default_factory=dict)
    state: str = "IDLE"

    def count(self, name: str) -> None:
        self.counters[name] = self.counters.get(name, 0) + 1

    def find(self, kind: str) -> List[Out]:
        return [o for o in self.outs if o.kind == kind]


class ResponseReadyModel:
    def __init__(self, da_ns: int, gap_ns: int, anchor: str = "request",
                 horizon_ns: int = DEFAULT_H_NS, policy: str = "dual"):
        assert anchor in ("request", "native_ack")
        assert policy in ("dual", "response_focused")
        self.policy = policy
        self.da, self.gap = quantize_ns(da_ns), quantize_ns(gap_ns)
        self.anchor, self.H = anchor, horizon_ns
        self.r = Result()
        self.s = "IDLE"
        self._clear()

    def _clear(self) -> None:
        self.epoch = None
        self.t0 = self.expect_ack = self.app = None
        self.tA = self.tR = self.eA = self.eR = None

    # ---- timers -----------------------------------------------------------------------
    def _timers(self) -> List[Tuple[int, int, str]]:
        """(time, priority, name). Lower priority wins a tie: ack release before watchdog."""
        if self.s != "ARMED":
            return []
        out = []
        if self.policy == "response_focused":
            # ACK is forwarded on arrival; only the response is scheduled, ACK-relative.
            if self.eR is None and self.tA is not None and self.tR is not None:
                out.append((max(self.tR, self.tA + self.gap), 0, "resp_release"))
            if self.eR is None:
                out.append((self.t0 + self.H, 1, "watchdog"))
            return out
        if self.eA is None and self.tA is not None and self.tR is not None:
            if self.anchor == "request":
                e = max(self.t0 + self.da, self.tR, self.tA)
            else:
                e = max(self.tA + self.da, self.tR)
            out.append((e, 0, "ack_release"))
        if self.eA is None:
            out.append((self.t0 + self.H, 1, "watchdog"))
        if self.eR is not None:
            out.append((self.eR, 0, "resp_release"))
        return out

    def _fire(self, t: int, name: str) -> None:
        if name == "ack_release":
            self.eA = t
            self.eR = t + self.gap
            self.r.outs.append(Out("ACK", t, "normal"))
        elif name == "resp_release":
            if self.policy == "response_focused":
                self.eR = t
            self.r.outs.append(Out("RESP", t, "normal"))
            self.r.count("normal")
            self.s = "IDLE"
            self._clear()
        elif name == "watchdog":
            if self.policy == "response_focused":
                # the ACK already left on arrival; only a seen response is still held
                if self.tR is not None:
                    self.r.outs.append(Out("RESP", t, "watchdog"))
                self.r.count("fallback_no_response" if self.tR is None else "fallback_no_ack")
                self.s = "FALLBACK"
                return
            if self.tA is not None:
                self.r.outs.append(Out("ACK", t, "watchdog"))
            if self.tR is not None:       # response was seen but the ACK never arrived
                self.r.outs.append(Out("RESP", t, "watchdog"))
            self.r.count("fallback_no_response" if self.tR is None else "fallback_no_ack")
            self.s = "FALLBACK"

    def _run_until(self, t_limit: Optional[int]) -> None:
        while True:
            tm = sorted(self._timers())
            if not tm or (t_limit is not None and tm[0][0] > t_limit):
                return
            self._fire(tm[0][0], tm[0][2])

    # ---- external events --------------------------------------------------------------
    def run(self, events: List[Ev]) -> Result:
        for ev in sorted(events, key=lambda e: e.t):
            self._run_until(ev.t - 1)          # timers strictly earlier first; equal-time externals go first
            self._on(ev)
            self._run_until(ev.t)              # then timers due at this instant
        self._run_until(None)
        self.r.state = self.s
        return self.r

    def _on(self, e: Ev) -> None:
        r = self.r
        if e.kind == "REQ":
            if not e.supported:
                r.outs.append(Out("REQ", e.t, "bypass_unsupported")); r.count("bypass_unsupported"); return
            if self.s == "ARMED":
                r.outs.append(Out("REQ", e.t, "bypass_busy")); r.count("bypass_busy"); return
            if self.s == "FALLBACK":
                self._clear()
            self.s, self.epoch, self.t0 = "ARMED", e.epoch, e.t
            self.expect_ack, self.app = e.seq + e.length, e.app
            self.r.outs.append(Out("REQ", e.t, "forwarded"))
        elif e.kind == "ACK":
            if self.s != "ARMED" or e.epoch != self.epoch or e.ack != self.expect_ack:
                r.outs.append(Out("ACK", e.t, "unmatched_forwarded")); r.count("ack_unmatched"); return
            if self.tA is not None or self.eA is not None:
                r.count("dup_ack_dropped"); return
            self.tA = e.t
            if self.policy == "response_focused":
                r.outs.append(Out("ACK", e.t, "forwarded"))
        elif e.kind == "RESP":
            match = (e.epoch == self.epoch and e.ack == self.expect_ack and e.app == self.app)
            if self.s == "FALLBACK" and match:
                r.outs.append(Out("RESP", e.t, "late_native")); r.count("late_response")
                self.s = "IDLE"; self._clear(); return
            if self.s != "ARMED" or not match:
                r.outs.append(Out("RESP", e.t, "stale_forwarded")); r.count("stale_response"); return
            if self.tR is not None:
                r.count("dup_response_dropped"); return
            self.tR = e.t
        elif e.kind == "FIN":
            if self.s == "ARMED" and e.epoch == self.epoch:
                if self.tA is not None and self.eA is None:
                    r.outs.append(Out("ACK", e.t, "reset_flush"))
                if self.tR is not None and self.eR is None:
                    r.outs.append(Out("RESP", e.t, "reset_flush"))
                r.count("reset_flush")
            self.s = "IDLE"; self._clear()
