"""
timing_policy.py -- reusable response-timing policy for the DNP3 replay/split server.

This module decides *when* an already-prepared DNP3 response (or, in Phase 2, an
existing pure TCP ACK and its DNP3 response) is released. It never changes *which*
bytes are sent: it only computes release deadlines. The byte-preservation invariant
of the split harness (``b"".join(chunks) == response``) is therefore untouched --
this is the timing axis, layered on top of the existing per-chunk pacing.

Design (Phase 1, bounded normalization of the combined ACK-bearing response):

    target_delay   = sample from a common, class-INDEPENDENT bounded distribution
    desired_release = request_received + target_delay
    actual_release  = max(response_ready, desired_release)      # never send early

This is normalization, NOT additive jitter: the target distribution does not depend
on CROB count, response size, request size, native response-ready time, or device
identity. Two devices/configurations that meet the target look identical on the wire.

The scheduler is a *pure* decision function (no clock reads, no sleeps) so it is
deterministic and unit-testable; the caller performs the actual absolute-deadline
wait via :func:`wait_until`. All times are integer nanoseconds from a monotonic
clock (``time.monotonic_ns()``).

Nothing here forges packets. Phase 1 releases the one response the server already
holds. The Phase 2 helper (:func:`plan_ack_response_release`) only *reschedules*
two packets that already exist (a pure ACK and a DNP3 response) and strictly
enforces ``ack_release <= response_release`` -- it never emits an ACK after the
response and never synthesizes a new packet.
"""

from __future__ import annotations

import argparse
import enum
import logging
import random
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional, Tuple

_log = logging.getLogger(__name__)

MS_TO_NS = 1_000_000
NS_TO_MS = 1e-6

NATIVE = "native"
FIXED = "fixed"
BOUNDED = "bounded"
TIMING_MODES = (NATIVE, FIXED, BOUNDED)

# Packet roles (Phase 1 uses combined_response; Phase 2 uses the split roles).
COMBINED_RESPONSE = "combined_response"
PURE_ACK = "pure_ack"
DNP3_RESPONSE = "dnp3_response"


class BypassReason(enum.Enum):
    """Why a transaction was sent immediately (fail-open) instead of held."""
    NONE = "none"
    CRITICAL_TRANSACTION = "critical_transaction"
    UNSUPPORTED_TRAFFIC = "unsupported_traffic"
    QUEUE_LIMIT = "queue_limit"
    UNSAFE_TARGET = "unsafe_target"
    RTO_UNKNOWN_STRICT = "rto_unknown_strict"


# ------------------------------------------------------------------ #
# Configured policy
# ------------------------------------------------------------------ #

@dataclass
class TimingProfile:
    """The configured timing policy (the operator's chosen experimental policy).

    A profile is the *configured* policy, deliberately kept separate from any
    *observed* device profile measured from a trace (see profiles/*.json). It is
    never auto-derived from a device without operator approval.
    """

    mode: str = NATIVE
    # fixed mode
    target_delay_ms: float = 0.0
    # bounded mode
    target_min_ms: float = 0.0
    target_max_ms: float = 0.0
    seed: Optional[int] = None
    # safety / fail-open limits
    max_hold_ms: Optional[float] = None          # backstop: never hold longer than this
    max_queue_depth: Optional[int] = None        # bypass when a flow's queue exceeds this
    strict_safety: bool = False                  # bypass when no RTO-safe bound is known
    critical_function_bypass: bool = True        # never hold a transaction marked critical
    unknown_traffic_bypass: bool = True          # never hold traffic we cannot classify

    _rng: random.Random = field(default=None, repr=False, compare=False)
    _sample_index: int = field(default=0, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.mode not in TIMING_MODES:
            raise ValueError("mode must be one of {}, got {!r}".format(TIMING_MODES, self.mode))
        if self.mode == BOUNDED:
            if self.target_max_ms < self.target_min_ms:
                raise ValueError(
                    "bounded range invalid: target_max_ms ({}) < target_min_ms ({})".format(
                        self.target_max_ms, self.target_min_ms))
            if self.target_min_ms < 0:
                raise ValueError("target_min_ms must be >= 0")
        if self.mode == FIXED and self.target_delay_ms < 0:
            raise ValueError("target_delay_ms must be >= 0")
        if self.max_hold_ms is not None and self.max_hold_ms < 0:
            raise ValueError("max_hold_ms must be >= 0")
        self._rng = random.Random(self.seed)

    def sample_target_delay_ns(self) -> Tuple[int, int]:
        """Sample a target delay (ns) from the configured distribution.

        Returns ``(target_delay_ns, sample_index)``. The sample is class-independent
        by construction: it uses only the configured distribution, never any feature
        of the transaction. In ``bounded`` mode the PRNG is seeded, so a run is
        reproducible.
        """
        idx = self._sample_index
        self._sample_index += 1
        if self.mode == NATIVE:
            return 0, idx
        if self.mode == FIXED:
            return int(round(self.target_delay_ms * MS_TO_NS)), idx
        # bounded
        sample_ms = self._rng.uniform(self.target_min_ms, self.target_max_ms)
        return int(round(sample_ms * MS_TO_NS)), idx


# ------------------------------------------------------------------ #
# Per-transaction decision
# ------------------------------------------------------------------ #

@dataclass
class TimingDecision:
    """The scheduler's per-transaction output (one row of the timing log)."""
    flow_id: str
    transaction_id: int
    packet_role: str
    timing_mode: str
    request_size: int
    response_size: int
    request_received_ns: int
    response_ready_ns: int
    selected_target_delay_ns: int
    target_release_ns: int
    actual_release_ns: int
    hold_delay_ns: int                 # added hold = actual_release - response_ready
    native_ready_delay_ns: int         # response_ready - request_received (server-side prep)
    visible_delay_ns: int              # actual_release - request_received (observer-visible)
    deadline_missed: bool
    bypassed: bool
    bypass_reason: str
    queue_depth: int
    sample_index: int
    # Wall of the actual write, stamped by the sender after the release wait.
    # Default 0 until _send_chunks runs; send_duration_ns = complete - start.
    send_start_ns: int = 0
    send_complete_ns: int = 0

    def to_log_dict(self) -> dict:
        d = asdict(self)
        # convenient ms views for humans; ns remain authoritative
        d["hold_delay_ms"] = round(self.hold_delay_ns * NS_TO_MS, 4)
        d["visible_delay_ms"] = round(self.visible_delay_ns * NS_TO_MS, 4)
        d["native_ready_delay_ms"] = round(self.native_ready_delay_ns * NS_TO_MS, 4)
        d["selected_target_delay_ms"] = round(self.selected_target_delay_ns * NS_TO_MS, 4)
        if self.send_start_ns and self.send_complete_ns:
            d["send_duration_ms"] = round(
                (self.send_complete_ns - self.send_start_ns) * NS_TO_MS, 4)
        else:
            d["send_duration_ms"] = 0.0
        return d


# ------------------------------------------------------------------ #
# Per-flow FIFO state
# ------------------------------------------------------------------ #

@dataclass
class FlowTimingState:
    """Per-flow FIFO bookkeeping. Release times within a flow never go backwards."""
    flow_id: str
    last_release_ns: Optional[int] = None
    released_count: int = 0
    queue_depth: int = 0


# ------------------------------------------------------------------ #
# Release scheduler
# ------------------------------------------------------------------ #

class ReleaseScheduler:
    """Computes release deadlines for prepared responses. Never reorders a flow.

    One scheduler owns many flows; each flow keeps strict FIFO ordering (a release
    time is clamped up so it never precedes the flow's previous release). There is
    no global scheduler that can reorder packets within a TCP flow.
    """

    def __init__(self, profile: TimingProfile):
        self.profile = profile
        self._flows: Dict[str, FlowTimingState] = {}

    def flow(self, flow_id: str) -> FlowTimingState:
        state = self._flows.get(flow_id)
        if state is None:
            state = FlowTimingState(flow_id=flow_id)
            self._flows[flow_id] = state
        return state

    def decide(
        self,
        flow_id: str,
        transaction_id: int,
        request_received_ns: int,
        response_ready_ns: int,
        request_size: int,
        response_size: int,
        packet_role: str = COMBINED_RESPONSE,
        is_critical: bool = False,
        is_supported: bool = True,
        rto_safe_ms: Optional[float] = None,
    ) -> TimingDecision:
        """Decide when to release a prepared response for one transaction.

        Pure function of its arguments (no clock reads). ``request_received_ns`` and
        ``response_ready_ns`` are monotonic timestamps captured by the caller.
        """
        profile = self.profile
        state = self.flow(flow_id)
        native_ready = response_ready_ns - request_received_ns

        def _decision(target_release, actual_release, target_delay_ns,
                      deadline_missed, bypassed, reason, sample_index):
            return TimingDecision(
                flow_id=flow_id,
                transaction_id=transaction_id,
                packet_role=packet_role,
                timing_mode=profile.mode,
                request_size=request_size,
                response_size=response_size,
                request_received_ns=request_received_ns,
                response_ready_ns=response_ready_ns,
                selected_target_delay_ns=target_delay_ns,
                target_release_ns=target_release,
                actual_release_ns=actual_release,
                hold_delay_ns=max(0, actual_release - response_ready_ns),
                native_ready_delay_ns=native_ready,
                visible_delay_ns=actual_release - request_received_ns,
                deadline_missed=deadline_missed,
                bypassed=bypassed,
                bypass_reason=reason.value,
                queue_depth=state.queue_depth,
                sample_index=sample_index,
            )

        # native mode: send exactly when ready, no policy applied.
        if profile.mode == NATIVE:
            state.last_release_ns = response_ready_ns
            state.released_count += 1
            return _decision(response_ready_ns, response_ready_ns, 0,
                             False, False, BypassReason.NONE, -1)

        # fail-open pre-checks: send immediately (when ready) and record why.
        bypass = self._precheck_bypass(state, is_critical, is_supported, rto_safe_ms)
        if bypass is not None:
            state.last_release_ns = response_ready_ns
            state.released_count += 1
            return _decision(response_ready_ns, response_ready_ns, 0,
                             False, True, bypass, -1)

        target_delay_ns, sample_index = profile.sample_target_delay_ns()
        desired_release = request_received_ns + target_delay_ns

        # safety backstop: an over-long hold or an RTO-unsafe target fails open.
        prospective_hold = max(0, desired_release - response_ready_ns)
        if profile.max_hold_ms is not None and prospective_hold > profile.max_hold_ms * MS_TO_NS:
            state.last_release_ns = response_ready_ns
            state.released_count += 1
            return _decision(desired_release, response_ready_ns, target_delay_ns,
                             False, True, BypassReason.UNSAFE_TARGET, sample_index)
        if rto_safe_ms is not None and target_delay_ns > rto_safe_ms * MS_TO_NS:
            state.last_release_ns = response_ready_ns
            state.released_count += 1
            return _decision(desired_release, response_ready_ns, target_delay_ns,
                             False, True, BypassReason.UNSAFE_TARGET, sample_index)

        # FIFO: never release before this flow's previous release.
        release = desired_release
        if state.last_release_ns is not None and release < state.last_release_ns:
            release = state.last_release_ns

        actual_release = max(response_ready_ns, release)
        deadline_missed = response_ready_ns > desired_release
        state.last_release_ns = actual_release
        state.released_count += 1
        return _decision(desired_release, actual_release, target_delay_ns,
                         deadline_missed, False, BypassReason.NONE, sample_index)

    def _precheck_bypass(self, state, is_critical, is_supported, rto_safe_ms):
        profile = self.profile
        if is_critical and profile.critical_function_bypass:
            return BypassReason.CRITICAL_TRANSACTION
        if (not is_supported) and profile.unknown_traffic_bypass:
            return BypassReason.UNSUPPORTED_TRAFFIC
        if profile.max_queue_depth is not None and state.queue_depth > profile.max_queue_depth:
            return BypassReason.QUEUE_LIMIT
        if profile.strict_safety and rto_safe_ms is None:
            return BypassReason.RTO_UNKNOWN_STRICT
        return None


# ------------------------------------------------------------------ #
# Phase 2 helper: reschedule an EXISTING pure ACK + DNP3 response
# ------------------------------------------------------------------ #

@dataclass
class AckResponsePlan:
    ack_release_ns: int
    response_release_ns: int
    ack_hold_ns: int
    response_hold_ns: int
    gap_ns: int                        # response_release - ack_release (observer-visible)
    clamped: bool                      # ordering constraint forced a change


def plan_ack_response_release(
    request_received_ns: int,
    ack_ready_ns: int,
    response_ready_ns: int,
    ack_mode: str = NATIVE,
    ack_delay_ns: int = 0,
    response_delay_ns: int = 0,
    gap_target_ns: Optional[int] = None,
) -> AckResponsePlan:
    """Reschedule an already-existing pure TCP ACK and DNP3 response (Phase 2B).

    This does NOT forge any packet: both the pure ACK and the response already
    exist on the flow. It only chooses two release times and strictly enforces the
    ordering invariant ``ack_release <= response_release`` -- a delayed ACK is never
    released after the DNP3 response (the ACK is clamped to the response time if a
    configured delay would violate ordering).

    Modes:
      native            -- release both when ready.
      ack-delay-only    -- hold the ACK by ack_delay_ns (shrinks the visible gap).
      response-delay-only -- hold the response by response_delay_ns (grows the gap).
      independent-delay -- apply both delays.
      gap-normalized    -- schedule so response_release - ack_release == gap_target_ns.
    """
    ack_rel = ack_ready_ns
    resp_rel = response_ready_ns

    if ack_mode == "ack-delay-only":
        ack_rel = ack_ready_ns + ack_delay_ns
    elif ack_mode == "response-delay-only":
        resp_rel = response_ready_ns + response_delay_ns
    elif ack_mode == "independent-delay":
        ack_rel = ack_ready_ns + ack_delay_ns
        resp_rel = response_ready_ns + response_delay_ns
    elif ack_mode == "gap-normalized":
        if gap_target_ns is None:
            raise ValueError("gap-normalized mode requires gap_target_ns")
        # release the response no earlier than ready, then place the ACK gap_target
        # before it (but never before the ACK was actually ready).
        resp_rel = max(response_ready_ns, ack_ready_ns + gap_target_ns)
        ack_rel = max(ack_ready_ns, resp_rel - gap_target_ns)
    elif ack_mode != NATIVE:
        raise ValueError("unknown ack_mode {!r}".format(ack_mode))

    clamped = False
    if ack_rel > resp_rel:               # ordering invariant: ACK must not follow response
        ack_rel = resp_rel
        clamped = True

    return AckResponsePlan(
        ack_release_ns=ack_rel,
        response_release_ns=resp_rel,
        ack_hold_ns=max(0, ack_rel - ack_ready_ns),
        response_hold_ns=max(0, resp_rel - response_ready_ns),
        gap_ns=resp_rel - ack_rel,
        clamped=clamped,
    )


# ------------------------------------------------------------------ #
# Absolute-deadline wait (used by the caller, not the scheduler)
# ------------------------------------------------------------------ #

def wait_until(release_ns: int, clock=time.monotonic_ns, sleep=time.sleep) -> None:
    """Block until the monotonic clock reaches ``release_ns`` (absolute deadline).

    Recomputes the remaining interval each iteration rather than issuing one fixed
    relative sleep, so scheduler jitter does not accumulate.
    """
    while True:
        remaining = release_ns - clock()
        if remaining <= 0:
            return
        sleep(remaining * 1e-9)


# ------------------------------------------------------------------ #
# CLI wiring (so split_server just calls these two helpers)
# ------------------------------------------------------------------ #

def add_timing_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the Phase 1 timing-policy flags on an argparse parser."""
    group = parser.add_argument_group("response-time normalization (Phase 1)")
    group.add_argument("--timing-mode", choices=list(TIMING_MODES), default=NATIVE,
                       help="native = send immediately (default); fixed = one target "
                            "delay from request arrival; bounded = sample a target from "
                            "a bounded distribution.")
    group.add_argument("--target-delay-ms", type=float, default=0.0,
                       help="fixed-mode target delay from request arrival (ms).")
    group.add_argument("--target-min-ms", type=float, default=0.0,
                       help="bounded-mode lower target bound (ms).")
    group.add_argument("--target-max-ms", type=float, default=0.0,
                       help="bounded-mode upper target bound (ms).")
    group.add_argument("--timing-seed", type=int, default=None,
                       help="PRNG seed for reproducible bounded sampling.")
    group.add_argument("--max-hold-ms", type=float, default=None,
                       help="fail-open backstop: never hold a response longer than this (ms).")
    group.add_argument("--max-queue-depth", type=int, default=None,
                       help="fail-open: bypass when a flow's queue exceeds this depth.")
    group.add_argument("--strict-safety", action="store_true",
                       help="fail-open when no RTO-safe bound is known.")
    group.add_argument("--no-critical-function-bypass", dest="critical_function_bypass",
                       action="store_false", default=True,
                       help="do NOT auto-bypass transactions marked critical (default: bypass).")
    group.add_argument("--no-unknown-traffic-bypass", dest="unknown_traffic_bypass",
                       action="store_false", default=True,
                       help="do NOT auto-bypass unclassifiable traffic (default: bypass).")
    group.add_argument("--rto-safe-ms", type=float, default=None,
                       help="measured RTO-safe upper bound (ms); targets above it fail open.")


def profile_from_args(args: argparse.Namespace) -> TimingProfile:
    """Build a TimingProfile from parsed CLI args produced by add_timing_arguments."""
    return TimingProfile(
        mode=args.timing_mode,
        target_delay_ms=args.target_delay_ms,
        target_min_ms=args.target_min_ms,
        target_max_ms=args.target_max_ms,
        seed=args.timing_seed,
        max_hold_ms=args.max_hold_ms,
        max_queue_depth=args.max_queue_depth,
        strict_safety=args.strict_safety,
        critical_function_bypass=getattr(args, "critical_function_bypass", True),
        unknown_traffic_bypass=getattr(args, "unknown_traffic_bypass", True),
    )
