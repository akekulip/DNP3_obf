#!/usr/bin/env python3
"""defense2_state_machine.py — pass-based reference model of Case B (RESPONSE_DELAY_INCREASE_CLRT).

Case B is DEADLINE-governed and ACK-RELATIVE (the opposite of Case A's event-governed ACK hold):
  request  -> arm, store G_i
  pure ACK -> record deadline = t_ack + G_i ; FORWARD THE ACK IMMEDIATELY (never held)
  response -> release at max(t_resp_ready, deadline); held on recirc while now < deadline
  release  -> clear transaction state (-> IDLE)

Release equation (ACK-relative, NOT request-relative):
  t_response_out = max(t_resp_ready, t_ack + G_i)

The recirc clock: a held response reads the CURRENT wall clock (global_tstamp refreshed on recirc)
each pass and compares to the stored deadline. `clock_refreshes=False` models the recirc-clock bug
(stale time) -> the deadline never matures -> MAX_PASS fail-open (the ONLY role of MAX_PASS).

This module models Case B ONLY. It does not import or modify the Case-A model.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

IDLE, ARMED, ACKED, RESP_HELD = "IDLE", "ARMED", "ACKED", "RESP_HELD"
MAX_PASS = 65536
TICK_MS = 65.536 / 1000.0          # global_tstamp[47:16] granularity = 65.536 us
RECIRC_PERIOD_MS = 0.10            # one recirc pass ~ 100 us (dp68 qid5 pacing); clock granularity


@dataclass
class Flow:
    state: str = IDLE
    expected_ack: Optional[int] = None
    deadline_ms: Optional[float] = None


@dataclass
class BResult:
    ack_egress_ms: Optional[float] = None      # when the ACK left toward the master
    resp_egress_ms: Optional[float] = None      # when the response left toward the master
    resp_release_reason: Optional[str] = None   # "deadline" | "ready_after_deadline" | "max_pass_fail_open"
    resp_bytes_unchanged: bool = True           # byte-preservation (identity in the model)
    final_state: str = IDLE
    egress_order: List[Tuple[str, float]] = field(default_factory=list)   # (kind, t) in egress order
    ack_held: bool = False                      # must stay False (Case B forwards the ACK)
    max_pass_used: bool = False


def simulate_case_b(g_i_ms: float,
                    t_request_ms: float,
                    t_ack_ms: float,
                    t_resp_ready_ms: float,
                    clock_refreshes: bool = True,
                    tick_ms: float = RECIRC_PERIOD_MS) -> BResult:
    """Run one Case-B transaction through the pass model. Times are ms on a shared wall clock."""
    f = Flow()
    r = BResult()

    # ---- REQUEST: arm ----
    f.state = ARMED
    f.expected_ack = 1000 + 22            # symbolic: req_seq + req_len (exact-ACK target)

    # ---- PURE ACK (exact match): record ACK-RELATIVE deadline, forward IMMEDIATELY ----
    assert f.state == ARMED
    f.deadline_ms = t_ack_ms + g_i_ms     # <-- ACK-relative. NEVER request-relative.
    f.state = ACKED
    r.ack_egress_ms = t_ack_ms            # forwarded on arrival, not held
    r.ack_held = False
    r.egress_order.append(("ack", r.ack_egress_ms))

    # ---- RESPONSE: hold until the deadline matures ----
    assert f.state == ACKED
    if t_resp_ready_ms >= f.deadline_ms:
        # deadline already passed when the response arrived -> release immediately, unchanged
        r.resp_egress_ms = t_resp_ready_ms
        r.resp_release_reason = "ready_after_deadline"
    else:
        # hold on recirc: advance the wall clock one pass at a time until now >= deadline
        f.state = RESP_HELD
        now = t_resp_ready_ms
        passes = 0
        if not clock_refreshes:
            # recirc-clock bug: `now` never advances past the seed -> deadline never matures
            passes = MAX_PASS
            r.resp_egress_ms = t_resp_ready_ms + MAX_PASS * tick_ms
            r.resp_release_reason = "max_pass_fail_open"
            r.max_pass_used = True
        else:
            while now < f.deadline_ms and passes < MAX_PASS:
                now += tick_ms
                passes += 1
            if passes >= MAX_PASS:
                r.resp_egress_ms = now
                r.resp_release_reason = "max_pass_fail_open"
                r.max_pass_used = True
            else:
                r.resp_egress_ms = now            # first pass at/after the deadline
                r.resp_release_reason = "deadline"
    r.egress_order.append(("response", r.resp_egress_ms))

    # ---- RELEASE: clear transaction state -> IDLE ----
    f.state = IDLE
    f.expected_ack = None
    f.deadline_ms = None
    r.final_state = f.state
    return r


def measured_clrt_ms(r: BResult) -> float:
    """CLRT as the on-path observer measures it: response egress - ACK egress."""
    return r.resp_egress_ms - r.ack_egress_ms
