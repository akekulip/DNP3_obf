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

## The response hold is not the configured CLRT_new

An earlier version of this module charged the outstation's timer only `CLRT_new` plus allowances.
That is wrong, and it wrongly admitted policies. Under the common native-ACK anchor the switch
schedules the ACK at the native ACK time plus `D_A`, and the RESPONSE one configured `CLRT_new`
after that scheduled ACK. A response that arrives on time arrived `CLRT_original` after the native
ACK, so the time it waits inside the switch is

    response_hold = D_A + CLRT_new - CLRT_original

With `D_A = 20 ms`, `CLRT_new = 4 ms` and a native switch-side interval of 1 ms the response waits
23 ms, not 4 ms. The ACK hold is the dominant term and omitting it understated the outstation's
consumption roughly threefold.

`CLRT_original` may be unknown. Taking it as zero is the conservative direction, because it makes
the computed hold longer and the admission stricter, so an exact native interval is not required
to stay safe. Every such substitution is reported in `conservative_substitutions`.

## Each timer is charged its whole interval, not just the hold

A retransmission timeout is a duration, not the time remaining, so it is not enough to ask whether
the hold alone fits inside it. Each check charges the complete interval that the relevant sender's
timer spans, from the moment that sender transmits to the moment its feedback returns. The network
portion of that interval is a single named input per timer, measured with the mechanism disabled,
which is why no path allowance is added twice and why the elapsed time before the switch begins to
hold is never treated as unused.

Nothing here has run against hardware. It admits or refuses a policy; it does not install one.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

#: Values outside this range are treated as a unit error rather than a policy. A hold of 10^7 ms
#: is not a policy anyone configured in milliseconds.
MAX_REPRESENTABLE_MS = 1e7


class Provenance(str, Enum):
    """Where a number came from. This travels with the number into the verdict."""

    MEASURED_THIS_CONNECTION = "measured on the connection this policy governs"
    MEASURED_OTHER_SETTING = "measured, but on a different connection, device or build"
    INHERITED_EARLIER_BUILD = "inherited from an earlier build's measurements"
    OPERATOR_SUPPLIED = "supplied by the operator for this deployment"
    ESTIMATED = "estimated; no measurement behind it"
    UNAVAILABLE = "not available"


@dataclass(frozen=True)
class Applicability:
    """What a measured number actually applies to.

    A provenance tag alone cannot establish that a number is current and belongs here. Two
    measurements can both be `MEASURED_THIS_CONNECTION` and still describe different directions,
    different builds or different timers. This is the identity that gets compared.
    """

    connection_id: str = ""
    direction: str = ""          # "master_to_outstation", "outstation_to_master" or ""
    build_id: str = ""
    timer: str = ""              # "master_rto", "outstation_rto" or ""

    def matches(self, ctx: "PolicyContext", *, want_direction: str = "",
                want_timer: str = "") -> tuple[bool, str]:
        """Whether this measurement applies here, compared by role and not by label.

        `want_direction` and `want_timer` come from the field the bound occupies, so a value
        measured on the outstation's timer cannot be accepted into the master's field merely
        because whoever built it wrote a convenient name on it.
        """
        if not ctx.connection_id or not ctx.build_id:
            return False, ("the policy context names no connection or no build, so no "
                           "measurement can be shown to apply to it")
        if self.connection_id != ctx.connection_id:
            return False, "measured on connection %r, policy governs %r" % (
                self.connection_id or "<unset>", ctx.connection_id)
        if self.build_id != ctx.build_id:
            return False, "measured on build %r, policy targets build %r" % (
                self.build_id or "<unset>", ctx.build_id)
        if want_timer and self.timer != want_timer:
            return False, "describes timer %r, this field is %r" % (
                self.timer or "<unset>", want_timer)
        if want_direction and self.direction != want_direction:
            return False, "measured in direction %r, this field is %r" % (
                self.direction or "<unset>", want_direction)
        return True, ""


@dataclass(frozen=True)
class PolicyContext:
    """The connection and build this policy is being admitted for."""

    connection_id: str = ""
    build_id: str = ""


@dataclass(frozen=True)
class Bound:
    name: str
    value_ms: float | None
    provenance: Provenance
    source: str = ""
    observed_at: str = ""                    # when the observation was taken, ISO-8601
    applies_to: Applicability | None = None

    def is_known(self) -> bool:
        return self.value_ms is not None and self.provenance is not Provenance.UNAVAILABLE

    def applicability_problem(self, ctx: PolicyContext, *, field: str = "",
                              want_direction: str = "", want_timer: str = "") -> str:
        """Empty when this number can be shown to apply here; otherwise why it cannot."""
        if not self.is_known():
            return ""
        if field and self.name != field:
            return "is named %r but occupies the %r field; a bound must be named for the field "\
                   "it fills" % (self.name, field)
        if self.provenance is not Provenance.MEASURED_THIS_CONNECTION:
            return ""                         # not claiming to be from here in the first place
        if self.applies_to is None:
            return "claims to be measured here but records no applicability"
        if not self.observed_at:
            return "claims to be measured here but records no observation time"
        try:
            datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return ("records %r as its observation time, which is not a date this module can "
                    "read; a timestamp that cannot be parsed cannot be aged or compared"
                    % (self.observed_at,))
        ok, why = self.applies_to.matches(ctx, want_direction=want_direction,
                                          want_timer=want_timer)
        return "" if ok else why


#: Which provenances make a given input authoritative for its role. An application deadline is a
#: requirement the operator sets, so being operator-supplied is exactly right for it and is not a
#: weakness. A transport timer is a property of a running connection, so only a measurement of
#: that connection is authoritative.
ROLE_AUTHORITATIVE: dict[str, frozenset] = {
    "application_deadline_ms": frozenset({Provenance.OPERATOR_SUPPLIED,
                                          Provenance.MEASURED_THIS_CONNECTION}),
}
DEFAULT_AUTHORITATIVE = frozenset({Provenance.MEASURED_THIS_CONNECTION})

#: What each field must describe. The role belongs to the field, not to whatever name the caller
#: wrote on the bound, so a measurement of the outstation's timer cannot be admitted into the
#: master's field by being renamed.
FIELD_ROLE: dict[str, tuple[str, str]] = {          # field -> (direction, timer)
    "master_rto_ms": ("master_to_outstation", "master_rto"),
    "outstation_rto_ms": ("outstation_to_master", "outstation_rto"),
    "master_feedback_path_ms": ("master_to_outstation", ""),
    "outstation_feedback_path_ms": ("outstation_to_master", ""),
}


def _authoritative(field: str, b: Bound) -> bool:
    """Judged by the field's role. `field` is where the bound sits, not what it calls itself."""
    return b.provenance in ROLE_AUTHORITATIVE.get(field, DEFAULT_AUTHORITATIVE)


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

    # The native interval the mechanism replaces, switch-side. For admitting a policy over a
    # population of exchanges this must be the **smallest** native interval to be admitted, not
    # the largest or the typical one: the response hold is D_A + CLRT_new - CLRT_original, so the
    # smallest native interval produces the longest hold and is the case that has to fit. An
    # unknown value is taken as zero, which is that direction taken to its limit.
    clrt_original_ms: Bound

    # the complete network intervals each timer spans, measured with the mechanism disabled, so
    # that no path allowance is counted twice and no elapsed time is treated as unused
    # Network round trip only, **excluding** the outstation's own acknowledgment latency, which
    # is charged separately as ack_latency_bound_ms. Supplying the full request-to-ACK interval
    # here would count that latency twice.
    master_feedback_path_ms: Bound
    outstation_feedback_path_ms: Bound  # outstation sends response -> it receives master's ACK
    native_request_to_response_ms: Bound  # what the application sees with the mechanism off

    # terms the mechanism itself adds
    ack_latency_bound_ms: Bound         # outstation ACK latency, before the hold starts
    detect_ms: Bound                    # deadline detection latency in the data plane
    release_tail_ms: Bound              # post-deadline blocking plus service
    safety_margin_ms: float

    policy_cap_ms: float                # independent ceiling; not a function of measured RTT

    context: PolicyContext = field(default_factory=PolicyContext)

    def required_fields(self) -> dict[str, Bound]:
        """Field name to the bound that occupies it. The key is the role; the bound is the value."""
        return {"master_rto_ms": self.master_rto_ms,
                "outstation_rto_ms": self.outstation_rto_ms,
                "application_deadline_ms": self.application_deadline_ms,
                "clrt_original_ms": self.clrt_original_ms,
                "master_feedback_path_ms": self.master_feedback_path_ms,
                "outstation_feedback_path_ms": self.outstation_feedback_path_ms,
                "native_request_to_response_ms": self.native_request_to_response_ms,
                "ack_latency_bound_ms": self.ack_latency_bound_ms,
                "detect_ms": self.detect_ms,
                "release_tail_ms": self.release_tail_ms}

    def required_bounds(self) -> list[Bound]:
        return list(self.required_fields().values())


def remaining_headroom_note() -> str:
    """Why an RTO duration is not a countdown, and how this module avoids needing one."""
    return (
        "A retransmission timeout is a duration, not the time remaining. The sender's timer "
        "started when it queued the segment, which a master-facing capture of a later packet "
        "does not reveal, so knowing that the timer is 3000 ms does not say how much of it is "
        "left when the switch begins to hold. Computing the remainder needs the segment's own "
        "send timestamp, or the sender's TCP_INFO sampled and time-aligned with the capture. "
        "Rather than estimate the remainder, each check here charges the whole interval the "
        "sender's timer spans, from its transmission to the return of its feedback, so the time "
        "already elapsed when the switch begins to hold is inside the accounting instead of "
        "being assumed unused."
    )


def validate(inp: AdmissionInputs) -> list[str]:
    """Reject values that are not policies before any verdict is computed."""
    errs: list[str] = []

    def num(name: str, v: float, *, allow_zero: bool = True) -> None:
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            errs.append("%s is not a number" % name)
            return
        if not math.isfinite(v):
            errs.append("%s is not finite" % name)
            return
        if v < 0:
            errs.append("%s is negative (%g); a duration cannot run backwards" % (name, v))
            return
        if v == 0 and not allow_zero:
            errs.append("%s must be greater than zero" % name)
            return
        if abs(v) > MAX_REPRESENTABLE_MS:
            errs.append("%s is %g ms, outside the representable range; check the units"
                        % (name, v))

    num("d_a_ms", inp.d_a_ms)
    num("clrt_new_ms", inp.clrt_new_ms)
    num("safety_margin_ms", inp.safety_margin_ms)
    num("policy_cap_ms", inp.policy_cap_ms, allow_zero=False)

    for b in inp.required_bounds():
        if b.value_ms is None:
            if b.provenance is not Provenance.UNAVAILABLE:
                errs.append("%s has no value but is not marked unavailable" % b.name)
            continue
        num(b.name, b.value_ms)

    # inconsistent combinations
    if (inp.clrt_original_ms.is_known() and inp.native_request_to_response_ms.is_known()
            and inp.clrt_original_ms.value_ms > inp.native_request_to_response_ms.value_ms):
        errs.append("clrt_original_ms exceeds native_request_to_response_ms; the ACK-to-response "
                    "interval cannot be longer than the whole request-to-response interval")
    return errs


def _response_hold_ms(inp: AdmissionInputs) -> tuple[float, list[str]]:
    """The time an on-time RESPONSE waits inside the switch, and any conservative substitution.

    D_A + CLRT_new - CLRT_original, floored at zero. An unknown CLRT_original is taken as zero,
    which lengthens the hold and so tightens admission.
    """
    subs: list[str] = []
    if inp.clrt_original_ms.is_known():
        original = float(inp.clrt_original_ms.value_ms)
        subs.append("clrt_original_ms is used as the SMALLEST native interval to be admitted; a "
                    "larger value here understates the hold and would admit a policy that a fast "
                    "exchange violates")
    else:
        original = 0.0
        subs.append("clrt_original_ms unknown; taken as 0 ms, which overstates the response hold "
                    "and therefore refuses more policies than an exact value would")
    return max(0.0, inp.d_a_ms + inp.clrt_new_ms - original), subs


def _check(constraint: str, bound: Bound, parts: dict[str, Bound | float],
           margin: float, *, bound_field: str = "") -> dict[str, Any]:
    """One constraint. Undetermined if the bound or any term it needs is unavailable.

    A term that is missing is never replaced with zero: a check that cannot be computed reports
    `ok: None` and names what was missing, because an `ok: True` produced by treating an unknown
    latency as zero is exactly the kind of false assurance this module exists to prevent.
    """
    missing = [v.name for v in parts.values() if isinstance(v, Bound) and not v.is_known()]
    if not bound.is_known():
        return {"constraint": constraint, "ok": None,
                "reason": "%s unavailable" % bound.name, "missing": [bound.name]}
    if missing:
        return {"constraint": constraint, "ok": None,
                "reason": "cannot be computed: %s unavailable" % ", ".join(missing),
                "missing": missing, "bound_ms": bound.value_ms}
    terms = {n: (float(v.value_ms) if isinstance(v, Bound) else float(v))
             for n, v in parts.items()}
    terms["safety_margin"] = margin
    consumed = float(sum(terms.values()))
    return {"constraint": constraint,
            "bound_ms": bound.value_ms,
            "consumed_ms": round(consumed, 4),
            "terms_ms": {k: round(v, 6) for k, v in terms.items()},
            "provenance": bound.provenance.value,
            "authoritative": _authoritative(bound_field or bound.name, bound),
            "ok": consumed < bound.value_ms}


def evaluate(inp: AdmissionInputs) -> dict[str, Any]:
    """Admit conditionally, admit provisionally, refuse, or reject the inputs."""
    input_errors = validate(inp)
    if input_errors:
        return {"verdict": "rejected",
                "policy": {"d_a_ms": inp.d_a_ms, "clrt_new_ms": inp.clrt_new_ms,
                           "policy_cap_ms": inp.policy_cap_ms,
                           "context": {"connection_id": inp.context.connection_id,
                                       "build_id": inp.context.build_id}},
                "claim": {"kind": "rejected",
                          "statement": "the inputs are not a well-formed policy, so no admission "
                                       "decision was computed",
                          "conditions": [], "not_established": []},
                "input_errors": input_errors,
                "checks": [], "problems": input_errors,
                "unknown_inputs": [], "inputs_not_authoritative": [],
                "conservative_substitutions": [],
                "remaining_headroom": remaining_headroom_note()}

    problems: list[str] = []
    fields = inp.required_fields()
    unknown = [f for f, b in fields.items() if not b.is_known()]
    weak = [f for f, b in fields.items() if b.is_known() and not _authoritative(f, b)]

    applicability = {}
    for f, b in fields.items():
        want_dir, want_timer = FIELD_ROLE.get(f, ("", ""))
        applicability[f] = b.applicability_problem(
            inp.context, field=f, want_direction=want_dir, want_timer=want_timer)
    misapplied = [n for n, why in applicability.items() if why]
    for n in misapplied:
        problems.append("%s: %s" % (n, applicability[n]))
        if n not in weak:
            weak.append(n)

    response_hold, subs = _response_hold_ms(inp)

    # --- the three constraints, each charged its own complete interval ---------------------
    checks = [
        # The master's timer runs from its request to the ACK of that request. The response hold
        # does not enter it: the master is not awaiting feedback for the response.
        _check("master TCP retransmission", inp.master_rto_ms,
               {"network_round_trip_excluding_outstation_processing": inp.master_feedback_path_ms,
                "outstation_ack_latency": inp.ack_latency_bound_ms,
                "ack_hold_D_A": inp.d_a_ms,
                "deadline_detection": inp.detect_ms,
                "release_tail": inp.release_tail_ms},
               inp.safety_margin_ms, bound_field="master_rto_ms"),
        # The outstation's timer runs from its response to the master's ACK of that response. The
        # hold charged here is the scheduled release minus the native arrival, which contains D_A.
        _check("outstation TCP retransmission", inp.outstation_rto_ms,
               {"network_round_trip": inp.outstation_feedback_path_ms,
                "response_hold_in_switch": response_hold,
                "deadline_detection": inp.detect_ms,
                "release_tail": inp.release_tail_ms},
               inp.safety_margin_ms, bound_field="outstation_rto_ms"),
        # The application waits from its request to the response, so it sees the native latency
        # plus whatever the mechanism adds to the response.
        _check("master application deadline", inp.application_deadline_ms,
               {"native_request_to_response": inp.native_request_to_response_ms,
                "response_hold_in_switch": response_hold,
                "deadline_detection": inp.detect_ms,
                "release_tail": inp.release_tail_ms},
               inp.safety_margin_ms, bound_field="application_deadline_ms"),
    ]

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
        verdict = "admitted_conditional"

    if verdict == "admitted_conditional":
        statement = ("admitted against the stated bounds, none of which is a universal property "
                     "of this connection. The inputs do not all play the same role: the latency "
                     "terms have to be observed maxima for the conditions they were measured "
                     "under, the timer and deadline budgets have to be values the connection "
                     "will not beat, and CLRT_original has to be a lower bound, because a "
                     "smaller native interval makes the implied response hold longer")
    elif verdict == "refused":
        statement = "refused: a check failed or the policy cap was exceeded"
    else:
        statement = ("not decided: an input is unknown, is not authoritative for its role, or "
                     "cannot be shown to apply to this connection and build")

    return {
        "verdict": verdict,
        "policy": {"d_a_ms": inp.d_a_ms, "clrt_new_ms": inp.clrt_new_ms,
                   "policy_cap_ms": inp.policy_cap_ms,
                   "context": {"connection_id": inp.context.connection_id,
                               "build_id": inp.context.build_id}},
        "claim": {
            "kind": verdict,
            "statement": statement,
            "conditions": [
                "the bounds hold for the connection and build named in the context",
                "the response arrives on time, so the hold is D_A + CLRT_new - CLRT_original",
                "the network intervals were measured with the mechanism disabled",
            ] if verdict == "admitted_conditional" else [],
            "not_established": [
                "that the observed maxima bound every future exchange",
                "that the corrected policy has been exercised on hardware",
            ],
        },
        "input_errors": [],
        "response_hold_ms": round(response_hold, 6),
        "response_hold_formula": "max(0, D_A + CLRT_new - CLRT_original)",
        "conservative_substitutions": subs,
        "checks": checks,
        "policy_cap": {"cap_ms": inp.policy_cap_ms,
                       "requested_ms": inp.d_a_ms + inp.clrt_new_ms,
                       "ok": cap_ok,
                       "note": "independent of any measured RTT, so the mechanism's own "
                               "inflation of RTT cannot raise it"},
        "inputs": {f: {"value_ms": b.value_ms, "provenance": b.provenance.value,
                       "source": b.source, "observed_at": b.observed_at,
                       "bound_name": b.name,
                       "authoritative_for_role": _authoritative(f, b),
                       "applicability_problem": applicability[f]}
                   for f, b in fields.items()},
        "unknown_inputs": unknown,
        "inputs_not_authoritative": weak,
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
