"""Independent event model of the Case 4 response-ready release policy.

Written from framework/contract/POLICY_CONTRACT.md, not from the P4. Times are integer
nanoseconds on one unbounded timeline. Modular low-32 nanosecond decoding is provided by due() and checked
separately (tests/test_model_scenarios.py); the model itself does not wrap.
"""
from dataclasses import dataclass, field
from itertools import groupby
from typing import Dict, List, Optional, Tuple

TICK_NS = 256
MASK = (1 << 32) - 1
HALF = 1 << 31
DEFAULT_H_NS = 30_000_000  # Absolute model readiness expiry; not a token-loop estimate.


def quantize_ns(ns: int) -> int:
    """Floor to the 256 ns grid (1 ms -> 999,936 ns, as control.py realizes it)."""
    return (ns // TICK_NS) * TICK_NS


def to_tick(ns: int) -> int:
    """Compatibility name: return masked low-32 nanoseconds, not a tick count."""
    return quantize_ns(ns) & MASK


def due(now_tick: int, deadline_tick: int) -> bool:
    """Modular half-range comparison: deadline has been reached at now."""
    return ((now_tick - deadline_tick) & MASK) < HALF


@dataclass(frozen=True)
class Ev:
    t: int                      # ns
    kind: str                   # REQ ACK RESP FIN RST
    epoch: int = 0
    seq: int = 0                # TCP seq of the segment
    length: int = 0             # payload length
    ack: int = 0                # TCP ack number
    app: int = 0                # DNP3 application sequence
    supported: bool = True      # Caller verified complete supported frame/profile
    flow: Optional[Tuple[str, str, int, int]] = None  # Canonical master/outstation tuple
    operation: str = "READ"     # Parent operation, including split control responses
    response_seq: Optional[int] = None  # REQ: expected first response TCP sequence
    owner_cookie: Optional[int] = None  # Explicit terminal/drain evidence for the association
    reset_seq: Optional[int] = None  # REQ: allowed TCP FIN/RST sequence, if strictly bound
    reset_validated: Optional[bool] = None  # True only after caller verified tuple/sequence
    transformed_length: Optional[int] = None  # REQ: bytes forwarded to the outstation


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
                 horizon_ns: int = DEFAULT_H_NS, policy: str = "dual",
                 deferred_returns: bool = False):
        assert anchor in ("request", "native_ack")
        assert policy in ("dual", "response_focused")
        self.policy = policy
        self.deferred_returns = deferred_returns
        self.owner_cookie = 0
        self.originals = set()
        self.after_drain = "IDLE"
        self.da, self.gap = quantize_ns(da_ns), quantize_ns(gap_ns)
        self.anchor, self.H = anchor, horizon_ns
        self.r = Result()
        self.s = "IDLE"
        self._clear()

    def _clear(self) -> None:
        self.epoch = self.flow = self.operation = self.response_seq = self.reset_seq = None
        self.t0 = self.expect_ack = self.app = None
        self.tA = self.tR = self.eA = self.eR = None

    def _emit_original(self, kind: str, t: int, reason: str) -> None:
        self.r.outs.append(Out(kind, t, reason))
        if not self.deferred_returns:
            self.originals.discard(kind)

    def _retire(self, after: str) -> None:
        self.after_drain = after
        if self.originals:
            self.s = "QUARANTINED"
        else:
            self.s = after
            if after == "IDLE":
                self._clear()

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
            self._emit_original("ACK", t, "normal")
        elif name == "resp_release":
            if self.policy == "response_focused":
                self.eR = t
            self._emit_original("RESP", t, "normal")
            self.r.count("normal")
            self._retire("IDLE")
        elif name == "watchdog":
            if self.policy == "response_focused":
                # the ACK already left on arrival; only a seen response is still held
                if self.tR is not None:
                    self._emit_original("RESP", t, "watchdog")
                self.r.count("fallback_no_response" if self.tR is None else "fallback_no_ack")
                self._retire("FALLBACK")
                return
            if self.tA is not None:
                self._emit_original("ACK", t, "watchdog")
            if self.tR is not None:       # response was seen but the ACK never arrived
                self._emit_original("RESP", t, "watchdog")
            self.r.count("fallback_no_response" if self.tR is None else "fallback_no_ack")
            self._retire("FALLBACK")

    def _run_until(self, t_limit: Optional[int]) -> None:
        while True:
            tm = sorted(self._timers())
            if not tm or (t_limit is not None and tm[0][0] > t_limit):
                return
            self._fire(tm[0][0], tm[0][2])

    # ---- external events --------------------------------------------------------------
    def run(self, events: List[Ev]) -> Result:
        for t, simultaneous in groupby(sorted(events, key=lambda e: e.t), key=lambda e: e.t):
            self._run_until(t - 1)             # timers strictly earlier first
            for ev in simultaneous:
                self._on(ev)                  # all equal-time externals precede timers
            self._run_until(t)
        self._run_until(None)
        self.r.state = self.s
        return self.r

    def _on(self, e: Ev) -> None:
        r = self.r
        if e.kind in ("TERMINAL_ACK", "TERMINAL_RESP", "DRAIN_COMPLETE"):
            if e.owner_cookie != self.owner_cookie or e.epoch != self.epoch or e.flow != self.flow:
                r.count("drain_stale"); return
            if e.kind.startswith("TERMINAL_"):
                self.originals.discard(e.kind[len("TERMINAL_"):])
                return
            if self.s != "QUARANTINED" or self.originals:
                r.count("drain_incomplete"); return
            r.count("drain_complete")
            self._retire(self.after_drain)
            return
        if e.kind == "REQ":
            if not e.supported:
                r.outs.append(Out("REQ", e.t, "bypass_unsupported")); r.count("bypass_unsupported"); return
            if self.s in ("ARMED", "QUARANTINED"):
                r.outs.append(Out("REQ", e.t, "bypass_busy")); r.count("bypass_busy"); return
            if self.s == "FALLBACK":
                self._clear()
            self.owner_cookie += 1
            self.originals.clear()
            self.reset_seq = e.reset_seq
            self.s, self.epoch, self.t0 = "ARMED", e.epoch, e.t
            self.flow, self.operation, self.response_seq = e.flow, e.operation, e.response_seq
            wire_length = e.length if e.transformed_length is None else e.transformed_length
            self.expect_ack, self.app = (e.seq + wire_length) & MASK, e.app
            self.r.outs.append(Out("REQ", e.t, "forwarded"))
        elif e.kind == "ACK":
            if (self.s != "ARMED" or e.epoch != self.epoch or e.flow != self.flow
                    or e.ack != self.expect_ack):
                r.outs.append(Out("ACK", e.t, "unmatched_forwarded")); r.count("ack_unmatched"); return
            if self.tA is not None or self.eA is not None:
                r.count("dup_ack_dropped"); return
            self.tA = e.t
            if self.policy == "dual":
                self.originals.add("ACK")
            if self.policy == "response_focused":
                r.outs.append(Out("ACK", e.t, "forwarded"))
        elif e.kind == "RESP":
            if not e.supported:
                r.outs.append(Out("RESP", e.t, "bypass_unsupported"))
                r.count("bypass_unsupported")
                return
            match = (e.epoch == self.epoch and e.flow == self.flow
                     and e.ack == self.expect_ack and e.app == self.app
                     and e.operation == self.operation
                     and (self.response_seq is None or e.seq == self.response_seq))
            if self.s == "FALLBACK" and match:
                r.outs.append(Out("RESP", e.t, "late_native")); r.count("late_response")
                self.s = "IDLE"; self._clear(); return
            if self.s != "ARMED" or not match:
                r.outs.append(Out("RESP", e.t, "stale_forwarded")); r.count("stale_response"); return
            if self.tR is not None:
                r.count("dup_response_dropped"); return
            self.tR = e.t
            self.originals.add("RESP")
        elif e.kind in ("FIN", "RST"):
            if (e.epoch != self.epoch or e.flow != self.flow or not e.supported
                    or e.reset_validated is False
                    or (self.reset_seq is not None
                        and (e.seq != self.reset_seq or e.reset_validated is not True))):
                return
            if self.s == "ARMED":
                if self.policy == "dual" and self.tA is not None and self.eA is None:
                    self._emit_original("ACK", e.t, "reset_flush")
                # eR is a scheduled release, not proof that the response left.
                if self.tR is not None:
                    self._emit_original("RESP", e.t, "reset_flush")
                r.count("reset_flush")
            self._retire("IDLE")
