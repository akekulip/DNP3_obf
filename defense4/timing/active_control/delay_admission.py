#!/usr/bin/env python3
"""Delay admission with the constraints kept apart and the provenance kept attached.

This does not edit `implementation/control/parameter_policy.py`, which is the frozen record of
what admitted the campaign's policy. It is the corrected version for future use, and it exists
because the frozen one collapses three different constraints into one field named `tcp_rto` and
reports a verdict without saying where its inputs came from.

The three constraints are not interchangeable. They differ in who is waiting, for what, and from
when:

| what is delayed | whose feedback is postponed | the bound that governs it |
|---|---|---|
| the outstation's ACK of a master request | the **master**, which sent the request | the master's TCP retransmission timer |
| the outstation's response, awaiting the master's ACK | the **outstation** | the outstation's TCP retransmission timer |
| the response the application is waiting for | the master application | an application deadline, not a TCP timer |

The 2026-09-15 diagnostic measured the third column's middle row, the outstation's timer, at
roughly 3 s. The frozen policy's 200 ms is the top row, the master's. Substituting one for the
other is the mistake this module is built to make impossible: each bound is a separate named
input, and none of them is called `tcp_rto`.

Nothing here has run against hardware. It admits or refuses a policy; it does not install one.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any


class Provenance(str, Enum):
    """Where a number came from. This travels with the number into the verdict."""

    MEASURED_THIS_CONNECTION = "measured on the connection this policy governs"
    MEASURED_OTHER_SETTING = "measured, but on a different connection, device or build"
    INHERITED_EARLIER_BUILD = "inherited from an earlier build's measurements"
    OPERATOR_SUPPLIED = "supplied by the operator for this deployment"
    ESTIMATED = "estimated; no measurement behind it"
    UNAVAILABLE = "not available"


#: Provenances that can support a claim of verified transport safety. Nothing else can.
SUFFICIENT_FOR_VERIFIED = frozenset({Provenance.MEASURED_THIS_CONNECTION})


@dataclass(frozen=True)
class Bound:
    name: str
    value_ms: float | None
    provenance: Provenance
    source: str = ""

    def is_known(self) -> bool:
        return self.value_ms is not None and self.provenance is not Provenance.UNAVAILABLE


@dataclass(frozen=True)
class AdmissionInputs:
    """Every quantity the decision needs, each with its own provenance.

    `policy_cap_ms` is deliberately not derived from any measured round-trip time. If the cap
    were a function of measured RTT, then the mechanism's own inflation of that RTT would raise
    the cap, which would license a longer hold, which would inflate it further. The cap is an
    independent deployment decision and is the one bound that does not move when the network does.
    """

    # what the policy proposes
    d_a_ms: float                       # the ACK hold
    clrt_new_ms: float                  # the configured CLRT_new

    # the three separate constraints
    master_rto_ms: Bound
    outstation_rto_ms: Bound
    application_deadline_ms: Bound

    # the terms that consume budget before and around the hold
    ack_latency_bound_ms: Bound         # outstation ACK latency, before the hold starts
    detect_ms: Bound                    # deadline detection latency in the data plane
    release_tail_ms: Bound              # post-deadline blocking plus service
    path_uncertainty_ms: Bound          # propagation and capture, both directions, counted ONCE
    safety_margin_ms: float

    policy_cap_ms: float                # independent ceiling; not a function of measured RTT

    def required_bounds(self) -> list[Bound]:
        return [self.master_rto_ms, self.outstation_rto_ms, self.application_deadline_ms,
                self.ack_latency_bound_ms, self.detect_ms, self.release_tail_ms,
                self.path_uncertainty_ms]


def remaining_headroom_note() -> str:
    """Why an RTO duration is not a countdown, and what would be needed to get one."""
    return (
        "A retransmission timeout is a duration, not the time remaining. The sender's timer "
        "started when it queued the segment, which a master-facing capture of a later packet "
        "does not reveal, so knowing that the timer is 3000 ms does not say how much of it is "
        "left when the switch begins to hold. Computing the remainder needs the segment's own "
        "send timestamp, or the sender's TCP_INFO sampled and time-aligned with the capture. "
        "Where neither is available the conservative alternative is to assume the timer is "
        "already running and has been since the earliest instant consistent with the trace, and "
        "to admit a hold only if it fits in the bound minus that worst-case elapsed time."
    )


def evaluate(inp: AdmissionInputs) -> dict[str, Any]:
    """Admit, admit provisionally, or refuse. Never claims more than the inputs support."""
    problems: list[str] = []
    unknown = [b.name for b in inp.required_bounds() if not b.is_known()]
    weak = [b.name for b in inp.required_bounds()
            if b.is_known() and b.provenance not in SUFFICIENT_FOR_VERIFIED]

    # --- the budget, accounted once, with the boundaries stated ---------------------------
    # Consumed before the hold begins: the outstation's own ACK latency. Then the two holds
    # themselves. Then the switch's detection and release tail. Then one allowance for path and
    # capture uncertainty, counted ONCE rather than an RTT added at both ends. Then the margin.
    terms = {
        "ack_latency_before_the_hold": inp.ack_latency_bound_ms.value_ms,
        "ack_hold_D_A": inp.d_a_ms,
        "configured_CLRT_new": inp.clrt_new_ms,
        "deadline_detection": inp.detect_ms.value_ms,
        "release_tail": inp.release_tail_ms.value_ms,
        "path_uncertainty_counted_once": inp.path_uncertainty_ms.value_ms,
        "safety_margin": inp.safety_margin_ms,
    }
    if unknown:
        total = None
        problems.append("cannot total the budget: %s unknown" % ", ".join(unknown))
    else:
        total = float(sum(v for v in terms.values() if v is not None))

    # --- the three constraints, checked separately ----------------------------------------
    checks = []

    # The master's timer is consumed by holding the ACK of ITS request. The response hold does
    # not enter this check, because the master is not waiting on feedback for the response.
    if inp.master_rto_ms.is_known() and inp.ack_latency_bound_ms.is_known():
        consumed = (inp.ack_latency_bound_ms.value_ms + inp.d_a_ms
                    + (inp.detect_ms.value_ms or 0.0) + (inp.release_tail_ms.value_ms or 0.0)
                    + (inp.path_uncertainty_ms.value_ms or 0.0) + inp.safety_margin_ms)
        checks.append({"constraint": "master TCP retransmission",
                       "bound_ms": inp.master_rto_ms.value_ms,
                       "consumed_ms": round(consumed, 4),
                       "provenance": inp.master_rto_ms.provenance.value,
                       "ok": consumed < inp.master_rto_ms.value_ms})
    else:
        checks.append({"constraint": "master TCP retransmission", "ok": None,
                       "reason": "bound or ACK latency unavailable"})

    # The outstation's timer is consumed by holding ITS response until the master's ACK gets
    # back. This is the bound the 2026-09-15 diagnostic measured, and it is NOT the master's.
    if inp.outstation_rto_ms.is_known():
        consumed = (inp.clrt_new_ms + (inp.release_tail_ms.value_ms or 0.0)
                    + (inp.path_uncertainty_ms.value_ms or 0.0) + inp.safety_margin_ms)
        checks.append({"constraint": "outstation TCP retransmission",
                       "bound_ms": inp.outstation_rto_ms.value_ms,
                       "consumed_ms": round(consumed, 4),
                       "provenance": inp.outstation_rto_ms.provenance.value,
                       "ok": consumed < inp.outstation_rto_ms.value_ms})
    else:
        checks.append({"constraint": "outstation TCP retransmission", "ok": None,
                       "reason": "bound unavailable"})

    # The application deadline runs from the request, so it sees the whole path.
    if inp.application_deadline_ms.is_known() and total is not None:
        checks.append({"constraint": "master application deadline",
                       "bound_ms": inp.application_deadline_ms.value_ms,
                       "consumed_ms": round(total, 4),
                       "provenance": inp.application_deadline_ms.provenance.value,
                       "ok": total < inp.application_deadline_ms.value_ms})
    else:
        checks.append({"constraint": "master application deadline", "ok": None,
                       "reason": "bound unavailable or budget incomputable"})

    # --- the independent cap --------------------------------------------------------------
    cap_ok = (inp.d_a_ms + inp.clrt_new_ms) <= inp.policy_cap_ms
    if not cap_ok:
        problems.append("D_A + CLRT_new exceeds the policy cap of %g ms" % inp.policy_cap_ms)

    failed = [c for c in checks if c.get("ok") is False]
    undecided = [c for c in checks if c.get("ok") is None]

    if failed or not cap_ok:
        verdict = "refused"
    elif undecided or unknown or weak:
        verdict = "provisional"
    else:
        verdict = "admitted"

    return {
        "verdict": verdict,
        "claim": {
            "admitted": verdict == "admitted",
            "transport_safety_verified": verdict == "admitted",
            "why": ("every required bound is measured on this connection and every check passes"
                    if verdict == "admitted" else
                    "a verified claim requires every required bound to be measured on this "
                    "connection; unknown or inherited inputs cannot be filled with convenient "
                    "numbers"),
        },
        "budget_terms_ms": terms,
        "budget_total_ms": total if total is None else round(total, 4),
        "checks": checks,
        "policy_cap": {"cap_ms": inp.policy_cap_ms,
                       "requested_ms": inp.d_a_ms + inp.clrt_new_ms,
                       "ok": cap_ok,
                       "note": "independent of any measured RTT, so the mechanism's own "
                               "inflation of RTT cannot raise it"},
        "inputs": {b.name: {"value_ms": b.value_ms, "provenance": b.provenance.value,
                            "source": b.source} for b in inp.required_bounds()},
        "unknown_inputs": unknown,
        "inputs_not_measured_here": weak,
        "problems": problems,
        "unverified_cases": [
            "the FIRST delayed exchange, where no adaptation has happened yet",
            "reconnection, where the sender's timer restarts from its initial value",
            "a policy change mid-session, where the previous holds do not predict the next",
        ],
        "remaining_headroom": remaining_headroom_note(),
    }


def render(verdict: dict[str, Any]) -> str:
    return json.dumps(verdict, indent=1)
