# Phase 9 — timeouts, blocker drain and epsilon: measurement design (2026-10-06)

Design only. Nothing here has been measured on the response-ready candidate. Numbers quoted from earlier notes are labelled as such.

## Three budgets, kept apart

| budget | who owns the timer | what consumes it | recorded how |
|---|---|---|---|
| master request feedback timer | the master's TCP | withholding the request's acknowledgment | sender repetition observed on the wire; socket SRTT/RTTVAR/RTO from `TCP_INFO` on the **DNP3 connection** when the platform exposes them (units and field availability checked first) |
| outstation response feedback timer | the outstation's TCP | the response waiting for its acknowledgment | not observable from the master; the relay's roughly 3/6/12 s retransmission intervals belong to this sender and direction and cannot justify an ACK hold |
| master application deadline, and for SBO the device's select-to-operate constraint | application | the whole transaction | the driver's monotonic budget (500 ms in the planned runs) |

SSH socket statistics do not describe the DNP3 connection. The first repeated master request at 200.8 ms in the earlier diagnostic is an
observed repeat threshold, not a `TCP_INFO` RTO, and its near-equal first two gaps can involve a tail-loss probe (RFC 8985).

## Admission

Admission charges the whole interval from sender transmission to feedback: native path elapsed before the hold, the hold itself, release
and service, and the return path. For the response-ready candidate the hold bound is the watchdog horizon H (estimate 18,000 passes × 1.711 µs
= 30.8 ms), because the ACK can be held until the response is seen. Inputs carry provenance tags, a declared margin, and an independent
deployment cap (40 ms, the control-plane clamp). The defence's own RTT inflation must not raise its cap. `framework/control/profiles.py` binds
an admission record to the exact policy, build and connection and refuses a profile whose bound exceeds the cap. An acknowledged request can
still lack an application response; an application timeout is not necessarily a request retransmission.

## Residual blocker serialization versus reservoir lifetime

Residual estimate, by plain endpoints: time = remaining blockers × wire bits per blocker ÷ link rate. A minimum frame is 64 B, plus 8 B
preamble and 12 B inter-frame gap = 84 B = 672 bits. 64 remaining blockers at 25 Gb/s serialize in 43,008 bits ÷ 25 Gb/s = **1.72032 µs**
(checked this session). This holds only under the stated service assumptions and uses the **remaining occupancy at expiry**, not every seeded token.
It is not the lifetime of the whole recirculation reservoir: the earlier roughly 31 ms budget-drain diagnostic counted many token orbits
and is not a 31 ms post-deadline epsilon. Per-loop period for 64 tokens at 37.4 Mpps is 1.711 µs; budget × period is a watchdog estimate, not a
wall-clock deadline under load.

The earlier attributed instrumented diagnostic (carried, not reproduced): median internal blocker-termination intervals of 1,706 ns on ACK and
1,705 ns on RESPONSE over twelve exchanges. Those are ingress-to-ingress timestamps on blocker tokens: neither queue-empty nor held-packet
wire-departure, and with no established bound relation to epsilon.

## Intervals to measure, and what each really is

| interval | start | end | clock domain | precision | observable? | name to use |
|---|---|---|---|---|---|---|
| release deadline → expiry detection | deadline word | the token pass that decides | switch ingress, 256 ns grid | 256 ns | yes, instrumented build | "expiry-detection lag" |
| last blocker service → end of gating | last token service | queue empty | TM | n/a | **not observable** from ingress | none; report the proxy below |
| blocker termination, ingress to ingress | token dropped | next token or held packet's ingress | switch ingress | 256 ns grid | yes, instrumented build | "ingress-to-ingress blocker-termination interval" (a proxy, **not** epsilon) |
| held ACK/response service or departure | release decision | wire | master-facing capture clock vs switch clock | capture resolution; cross-domain offset unknown | only with a supported tap on the relay-facing side | "master-facing release time" unless both ends are tapped |
| response latency D_R | outstation transmission | master receipt | needs both ends | — | **not measured** without both endpoints; stays unmeasured |

An egress timestamp needs its hardware definition before it is called a departure; none is assumed to be wire departure. Record the
observation boundary, clock domain, precision, marker decoding and instrumented build for each interval, decode the deadline marker bits
before any arithmetic, and test clock wrap, quantisation and modular half-range assumptions (done offline in the model and simulator).

Instrumentation changes the program: keep separate production and measurement builds, measure the perturbation (stage and PHV use, loop
period) rather than assuming it away, and do not remove functional correctness or relax a target gate to fit. If actual end of gating cannot be
observed, report the proxy under its correct name; never claim a direct epsilon. Measured CLRT also carries differential ACK/response release
and downstream path effects, so a single non-negative drain term cannot explain samples above and below a target, and a drain term must
not be added again to an actual hold that already includes it. Observed maxima are observations, not future bounds.
