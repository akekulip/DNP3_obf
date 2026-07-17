#!/usr/bin/env python3
"""phase04b_dcrn_policy.py -- DCRN (Dual-Case Release-Time Normalizer) reference policy (spec sec 4-10).

Pure, side-effect-free decision logic: it arms per-flow request state, selects a class-independent
release deadline, classifies reverse packets (pure TCP ACK vs ACK-bearing DNP3 response), and computes
absolute release times for BOTH native structures -- separate (request -> pure ACK -> response) and
combined (request -> ACK-bearing response) -- preserving packet structure. It never modifies bytes,
never synthesizes/suppresses packets, and fails open (native forwarding) on any ambiguity.

This is the ground-truth policy the eBPF wire executor must match; it is fully unit-testable without
root, and the paired-condition harness uses it to predict expected release times for validating the
real eBPF run. All times are milliseconds unless suffixed _ns.

Terminology (strict, per spec sec 1):
  pure TCP ACK          -- ACK set, zero TCP payload, no SYN/FIN/RST, cumulatively acks the request.
  ACK-bearing RESPONSE  -- payload-bearing outstation response that cumulatively acks the request.
  DNP3 application CONFIRM -- only the actual DNP3 CONFIRM function code.
A DNP3 RESPONSE is never called an "application ACK".
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

DNP3_PORT = 20000
READ_FC = 1                       # routine solicited READ request
RESPONSE_FC = 129                 # DNP3 RESPONSE
CONFIRM_FC = 0                    # DNP3 application CONFIRM

# Transaction classes eligible for normalization (allowlist; everything else bypasses).
CLASS_ROUTINE_READ = "routine_solicited_read"

# Bypass reasons (fail-open -> native forwarding, never drop).
B_NO_STATE = "no_request_state"
B_UNKNOWN_CLASS = "unknown_transaction_class"
B_NOT_READ = "not_routine_read"
B_HANDSHAKE = "handshake_ack_not_request_armed"
B_DUP_ACK = "duplicate_ack"
B_SACK = "sack_loss_signal"
B_WINDOW_UPDATE = "window_update"
B_KEEPALIVE = "keepalive"
B_CONFIRM_ACK = "ack_of_dnp3_confirm"
B_CONCURRENT = "concurrent_outstanding_request"
B_RETRANSMISSION = "retransmission_or_loss_recovery"
B_UNKNOWN_RTO = "unknown_rto"
B_MAP_EXHAUSTED = "map_exhausted"
B_UNSAFE_TARGET = "unsafe_target_exceeds_rto_margin"
B_CONTROL = "control_or_unsolicited_traffic"

# --------------------------------------------------------------------------- #
# Conformance core: exact integer mirror of bpf/phase04b_dcrn_common.h. These functions MUST match
# the eBPF/userspace C decision core bit-for-bit (validated by tests/test_phase04b_conformance.py).
# --------------------------------------------------------------------------- #
_MASK64 = (1 << 64) - 1
DCRN_MODE_NATIVE, DCRN_MODE_FIXED, DCRN_MODE_BOUNDED = 0, 1, 2
DCRN_KIND_BYPASS, DCRN_KIND_PURE_ACK, DCRN_KIND_RESPONSE = 0, 1, 2


def splitmix64(x: int) -> int:
    x = (x + 0x9E3779B97F4A7C15) & _MASK64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & _MASK64
    return (x ^ (x >> 31)) & _MASK64


def select_target_ns(mode: int, seed: int, counter: int, lo_ns: int, hi_ns: int, fixed_ns: int) -> int:
    if mode == DCRN_MODE_NATIVE:
        return 0
    if mode == DCRN_MODE_FIXED:
        return fixed_ns
    span = (hi_ns - lo_ns + 1) if hi_ns > lo_ns else 1
    h = splitmix64((seed ^ ((counter * 0x9E3779B97F4A7C15) & _MASK64)) & _MASK64)
    return lo_ns + (h % span)


def ack_covers(cum_ack: int, expected: int) -> bool:
    return ((cum_ack - expected) & 0xFFFFFFFF) < 0x80000000


def classify_reverse_core(payload_len, ack, syn, fin, rst, dnp3_present, dnp3_is_confirm, covers) -> int:
    if payload_len > 0:
        if not dnp3_present or not covers:
            return DCRN_KIND_BYPASS
        if dnp3_is_confirm:
            return DCRN_KIND_BYPASS
        return DCRN_KIND_RESPONSE
    if not (ack and not syn and not fin and not rst):
        return DCRN_KIND_BYPASS
    if not covers:
        return DCRN_KIND_BYPASS
    return DCRN_KIND_PURE_ACK


def release_ns(kind: int, ready_ns: int, deadline_ns: int, is_separate: bool,
               guard_ns: int, fifo_reliable: bool):
    target = deadline_ns
    if kind == DCRN_KIND_RESPONSE and is_separate and not fifo_reliable:
        target = deadline_ns + guard_ns
    if ready_ns > target:
        return ready_ns, 1
    return target, 0


@dataclass
class ReqState:
    flow_key: str
    request_ts: float
    request_seq: int
    request_len: int
    expected_ack: int            # request_seq + request_len (cumulative ACK that covers the request)
    txn_counter: int
    txn_class: str
    target_ms: float
    deadline_ts: float           # request_ts + target_ms
    pure_ack_seen: bool = False
    response_seen: bool = False


@dataclass
class TargetPolicy:
    """Class-independent target selection (spec sec 4). Depends ONLY on class + seed + counter."""
    mode: str = "P1_FIXED"        # P0_NATIVE | P1_FIXED | P2_COMMON_BOUNDED
    fixed_ms: float = 32.39
    bounded_lo_ms: float = 32.39
    bounded_hi_ms: float = 42.39
    seed: int = 20260717

    def select_target_ms(self, txn_class: str, txn_counter: int) -> float:
        if self.mode == "P0_NATIVE":
            return 0.0
        if self.mode == "P1_FIXED":
            return float(self.fixed_ms)
        if self.mode == "P2_COMMON_BOUNDED":
            # Deterministic and reproducible; keyed ONLY on (seed, counter) via the SAME splitmix64
            # integer core the eBPF uses -- never on device, capture, session, or response size.
            ns = select_target_ns(DCRN_MODE_BOUNDED, self.seed, txn_counter,
                                  int(round(self.bounded_lo_ms * 1e6)),
                                  int(round(self.bounded_hi_ms * 1e6)), 0)
            return round(ns / 1e6, 4)
        raise ValueError("unknown target mode %r" % self.mode)


@dataclass
class SafetyConfig:
    effective_rto_ms: float = 211.0
    rto_safety_guard_ms: float = 60.0
    scheduler_guard_ms: float = 3.0
    response_guard_delta_ms: float = 0.2   # ACK-before-response guard when equal-deadline FIFO not proven
    fifo_equal_deadline_reliable: bool = False

    @property
    def dhigh_ms(self) -> float:
        return self.effective_rto_ms - self.rto_safety_guard_ms


class DCRNPolicy:
    def __init__(self, target: TargetPolicy, safety: SafetyConfig, max_flows: int = 4096):
        self.target = target
        self.safety = safety
        self.max_flows = max_flows
        self.flows: dict = {}

    # ---- target safety -------------------------------------------------- #
    def target_is_safe(self, target_ms: float) -> bool:
        return 0.0 <= target_ms < self.safety.dhigh_ms

    # ---- request arming (spec sec 6) ------------------------------------ #
    def classify_request(self, pkt: dict) -> Optional[str]:
        """Return the transaction class if this is a payload-bearing master->outstation DNP3 request
        eligible to arm timing, else None (handshake / non-request / non-READ do not arm)."""
        if pkt.get("dst_port") != DNP3_PORT:
            return None
        if pkt.get("payload_len", 0) <= 0 or not pkt.get("dnp3_present"):
            return None                      # handshake / pure control -> never arms
        if pkt.get("dnp3_func") != READ_FC:
            return None                      # only routine READ in the initial allowlist
        return CLASS_ROUTINE_READ

    def arm_request(self, pkt: dict):
        """Attempt to arm per-flow state. Returns (ReqState|None, bypass_reason|None)."""
        cls = self.classify_request(pkt)
        if cls is None:
            return None, B_HANDSHAKE if pkt.get("dst_port") == DNP3_PORT else B_CONTROL
        key = pkt["flow_key"]
        if key in self.flows and not (self.flows[key].pure_ack_seen and self.flows[key].response_seen):
            return None, B_CONCURRENT        # a prior transaction on this flow is still outstanding
        if len(self.flows) >= self.max_flows and key not in self.flows:
            return None, B_MAP_EXHAUSTED
        if self.target.mode != "P0_NATIVE" and self.safety.effective_rto_ms <= 0:
            return None, B_UNKNOWN_RTO
        counter = pkt["txn_counter"]
        target_ms = self.target.select_target_ms(cls, counter)
        if not self.target_is_safe(target_ms):
            return None, B_UNSAFE_TARGET
        st = ReqState(
            flow_key=key, request_ts=pkt["ts"], request_seq=pkt["seq"], request_len=pkt["payload_len"],
            expected_ack=(pkt["seq"] + pkt["payload_len"]) & 0xFFFFFFFF, txn_counter=counter,
            txn_class=cls, target_ms=target_ms, deadline_ts=pkt["ts"] + target_ms)
        self.flows[key] = st
        return st, None

    # ---- reverse-packet classification (spec sec 7) --------------------- #
    def classify_reverse(self, pkt: dict):
        """Return (kind, reason). kind in {'pure_ack','response', None}; reason is a bypass tag if None."""
        st = self.flows.get(pkt["flow_key"])
        if st is None:
            return None, B_NO_STATE
        if pkt.get("src_port") != DNP3_PORT:
            return None, B_CONTROL
        if pkt.get("retransmission"):
            return None, B_RETRANSMISSION
        cum_ack = pkt.get("cum_ack")
        covers = cum_ack is not None and _ack_covers(cum_ack, st.expected_ack)
        payload = pkt.get("payload_len", 0)
        if payload > 0:
            if not pkt.get("dnp3_present") or not covers:
                return None, B_CONTROL
            if pkt.get("dnp3_func") == CONFIRM_FC:
                return None, B_CONFIRM_ACK
            return "response", None
        # zero-payload reverse packet -> candidate pure ACK
        if not (pkt.get("ack") and not pkt.get("syn") and not pkt.get("fin") and not pkt.get("rst")):
            return None, B_HANDSHAKE
        if pkt.get("duplicate_ack"):
            return None, B_DUP_ACK
        if pkt.get("sack"):
            return None, B_SACK
        if pkt.get("window_update"):
            return None, B_WINDOW_UPDATE
        if pkt.get("keepalive"):
            return None, B_KEEPALIVE
        if pkt.get("acks_confirm"):
            return None, B_CONFIRM_ACK
        if not covers:
            return None, B_HANDSHAKE          # an ACK that does not cover the armed request
        return "pure_ack", None

    # ---- release scheduling (spec sec 8) -------------------------------- #
    def release_time(self, kind: str, ready_ts: float, st: ReqState, is_separate: bool):
        """Absolute release time + deadline_miss flag. Preserves structure; never drops/synthesizes."""
        deadline = st.deadline_ts
        if kind == "response" and not is_separate:
            # COMBINED: hold the existing ACK-bearing response to the common deadline.
            rel = max(ready_ts, deadline)
            return rel, (ready_ts > deadline)
        if kind == "pure_ack":
            # SEPARATE: hold the existing pure ACK to the common deadline.
            rel = max(ready_ts, deadline)
            return rel, (ready_ts > deadline)
        if kind == "response" and is_separate:
            # SEPARATE response: same deadline if equal-deadline FIFO reliably emits the earlier-enqueued
            # ACK first; else deadline + a small COMMON guard delta (reported as a residual).
            eff_deadline = deadline if self.safety.fifo_equal_deadline_reliable \
                else deadline + self.safety.response_guard_delta_ms
            rel = max(ready_ts, eff_deadline)
            return rel, (ready_ts > eff_deadline)
        raise ValueError("bad kind %r" % kind)

    def cleanup(self, flow_key: str):
        self.flows.pop(flow_key, None)


def _ack_covers(cum_ack: int, expected: int) -> bool:
    """True if cum_ack >= expected in 32-bit sequence space (wrap-aware, within half the space)."""
    return ((cum_ack - expected) & 0xFFFFFFFF) < 0x80000000
