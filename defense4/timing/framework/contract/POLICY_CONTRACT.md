# Case 4 response-ready policy contract (working, 2026-10-06)

This is the current intended Case 4 contract, implementing Philip's updated 6 October assignment.
It supersedes the earlier timing-only/no-size scope for new working candidates. The independent
`framework/model/response_ready_model.py` implements an ideal event model; it does not establish
P4 queue behavior, packet validation, physical release timing, or hardware recovery. Historical
implementations, raw evidence and the frozen manuscript remain separate.

## Quantities and ideal release

Notation follows `defense4/timing/NOTATION_MAPPING.md`; archived `D_R_ms` still denotes configured
`CLRT_new`, not full response latency `D_R`.

| Quantity | Meaning |
|---|---|
| `t_0` | supported request arrival at switch ingress |
| `t_A` | associated native pure TCP ACK arrival at the switch |
| `t_R` | complete supported response availability at the switch; for one complete frame in one segment, that segment's arrival |
| `D_A` | configured ACK deadline offset from `t_0`; actual ACK hold is `e_A - t_A` |
| `e_A`, `e_R` | physical ACK/response departures toward the master; the equations below are ideal scheduling, not measured departures |
| configured `CLRT_new` | chosen response gap, floored to 256 ns; 1 ms becomes 999,936 ns |
| measured `CLRT_new` | `m_R - m_A`, including differential downstream path and capture effects |
| `CLRT_original` | `t_R - t_A` at the same switch boundary |
| `D_R` | whole response latency from outstation transmission to master receipt; unmeasured without that transmission endpoint and aligned observations |

For a matching complete response, the ideal request-anchored schedule is:

```
e_A = max(t_0 + D_A, t_A, t_R)
e_R = e_A + configured CLRT_new
ACK hold      = max(t_0 + D_A, t_A, t_R) - t_A
response hold = max(t_0 + D_A - t_R, t_A - t_R, 0) + configured CLRT_new
```

Equivalently, response hold is
`max(D_A - (t_A - t_0) - CLRT_original, -CLRT_original, 0) + configured CLRT_new`.
The old `max(0, D_A + configured CLRT_new - CLRT_original)` expression omits the request-to-ACK
interval and the response-ready condition. A late ready response is held for the full configured
gap after ACK release; the old absolute response deadline cannot shorten it.

The implementation observes a released ACK at qualified loopback ingress and starts its response
schedule there. That internal observation is not measured wire departure `e_A`. Arrival, frame
validation, association, readiness, scheduled eligibility, queue occupancy, actual departure,
and master observation are distinct. An event-model `Out.t` is an ideal instant, not a hardware
measurement.

## Supported profiles and association inputs

There is one active connection/epoch owner and one outstanding association slot. READ, SELECT and
OPERATE are distinct parent operations; SELECT and OPERATE are separate control phases. The initial
profile accepts one complete supported DNP3 frame per TCP segment, with valid lengths and CRCs,
without IP fragmentation, TCP negotiation needing unsupported translation, frame coalescing,
segmented application frames or unsolicited messages. Packet decoding/validation must establish
eligibility before holding or rewriting; parsing the first application header alone is insufficient.
The model's caller supplies `supported`, so its tests do not establish a data-plane CRC check.

The model accepts these backward-compatible `Ev` inputs:

- `flow`: canonical `(master_ip, outstation_ip, master_port, outstation_port)` identity, equal for
  request and reverse-direction ACK/response; `epoch` disambiguates reconnect/tuple reuse.
- `seq`, `length`, optional `transformed_length`: request end is
  `(seq + forwarded_length) mod 2^32`; forwarded length includes accepted switch-side insertion.
- `operation` and `app`: parent request operation and DNP3 application sequence. The response's
  generic function code is decoded into its parent operation by the caller; it is not itself SELECT.
- Optional request `response_seq`: expected first response TCP sequence, checked against response
  `seq`. This must be supplied for strong TCP-position association.

ACKs require owner identity and the expected request-end ACK. Responses additionally require
operation, application sequence and the configured response TCP position. Non-matching packets
are forwarded unchanged, counted and cannot mutate the owner. FIN/RST can retire only their matching
flow/epoch. Historical events with `flow=None` or no `response_seq` retain their weaker abstract
semantics; they are not evidence that real tuple/TCP-position matching works. Application-sequence
wrap alone does not identify a transaction; epoch and TCP positions remain necessary.

The supported size target is compatibility-first switch insertion: preserve all real CROB fields,
append one configured inert CROB using endpoint-accepted trailing-header encoding, and use identical
objects across SELECT/OPERATE. The expected complete response profile is **57 bytes -> [28,29]** in
TCP sequence order. Keep the historical **49 bytes -> [28,21]** profile distinct. A split segment
inherits its parent operation. Endpoint acceptance, every object status, checksums and transport
translation must pass independently; software processing does not establish a Tofino fit.

## Finite readiness and terminal outcomes

The model uses absolute `t_0 + 30 ms` readiness expiry (`horizon_ns` remains an explicit override
for historical comparisons). The timer progresses independently of ACK/response arrival and of
blocker-token survival. Model timer progression is an assumption, not proof of a hardware heartbeat.
A matching response and ACK at the expiry instant win normal release; all equal-time external
events precede timers, then ACK release precedes readiness expiry.

Once the normal ACK releases, readiness expiry is retired. Response completion has its own finite
ideal deadline, ACK release plus the full configured gap. The switch candidate needs a distinct
post-ACK cleanup deadline allowing heartbeat detection and bounded drain/service overhead; it must
not reuse readiness expiry to truncate the gap. Cleanup is owner-qualified; old queues must drain
before a slot is rearmed.

| Outcome | Behavior |
|---|---|
| NORMAL | matching ACK and response available by readiness expiry; use ideal schedule, retain full gap, then retire owner |
| FALLBACK_NO_RESPONSE | expiry with no matching response: release any held ACK, retire holding; no fabricated response |
| FALLBACK_NO_ACK | expiry with response but no matching ACK: release held response; no fabricated ACK |
| LATE_RESPONSE | matching response after fallback: forward natively at arrival, count separately, retire fallback identity |
| BYPASS_BUSY / BYPASS_UNSUPPORTED | forward request unchanged; leave the active association intact; unsupported response cannot establish readiness |
| STALE_FORWARDED | forward non-matching response unchanged; leave owner intact |
| DUP_ACK_DROPPED / DUP_RESPONSE_DROPPED | coalesce duplicate copies while the original is held; suppression does not persist after owner retirement |
| RESET_FLUSH | matching FIN/RST releases pending originals once, including a response scheduled after ACK release; retire state |

`FALLBACK` in the model retains only the expired association's identity to classify a late response;
it has no live holding timers and accepts the next supported request. Busy retransmitted requests
are forwarded, and requests after completion can start a new association. A same TCP sequence number
is not sufficient grounds for permanent retransmission suppression. No endpoint-visible ACK is
generated. Both-token/single-token loss, stale tokens and internal-generation wrap require independent
packet/pass tests: this model does not simulate reservoir occupancy or generation-qualified tokens.

## Clock, admission and evidence boundary

P4 uses masked **low-32 nanoseconds**, with low eight bits cleared; its armed marker is metadata and
must be removed before comparing deadlines. Resolution is 256 ns, wrap is **4.294967296 s** and
modular half-range is **2.147483648 s**. It is not a 32-bit count of 256 ns ticks. Compatibility API
`to_tick(ns)` now returns `(floor(ns/256)*256) mod 2^32`.

```
due(now, deadline) = ((now - deadline) mod 2^32) < 2^31
```

All compared intervals must stay below the half-range, and stale ownership must retire before
wrap ambiguity. The event model uses an unbounded integer nanosecond timeline; clock helper tests
alone cannot prove the P4's armed-marker handling or generation wrap.

Admission must charge complete endpoint feedback intervals: request-to-switch transit, request-
anchored readiness/deadline wait, independent heartbeat detection, blocker drain and actual release,
and the return feedback path. Outstation feedback includes the response gap and subsequent ACK
translation/path. Retain the 40 ms policy cap. Absolute readiness plus configured gap is a scheduling
budget, not a proven wall-clock bound until detection/drain/service costs are bounded for the exact
build and observation point. A nominal token budget times loop period (previously 18,000 x 1,711 ns,
about 30.798 ms) and observed maxima are estimates, not guarantees. Missing timing evidence leaves
admission provisional; RTT estimates and historical endpoint timers do not close those gaps.

As of the execution base, source-bound SDE 9.13.2 build_03 proves the existing timing candidate's
seven-stage fit. Its OFF READ smoke proves only that path's transparency. App-sequence/epoch/TCP-
position qualification, independent timeout recovery after both tokens vanish, immediate FIN/RST
flush, switch-side CROB insertion, padded response carving and joint resource fit remain hardware
acceptance gates until new source-bound builds and independent evidence establish them. Neither
this contract nor model assertions promote those capabilities to physical results. BMv2's token-
count gating/real-packet recirculation remains software emulation.

## Preserved explanation-only policy history

The section below records earlier model/API policies. Cases 1-3 are explanation-only under the
current assignment; their historical implementations and tests are retained without new campaigns.
These old status rows do not override the current source/build support matrix or Case 4 contract.

## Per-type timing cases (2026-10-06)

Only `MODE_D4_DUAL` armed in the source before this date; D1, D2 and D3 were accepted by the control plane and bypassed the
request as busy. Two cases are now selectable from the same machinery.

| case | mode / config | ACK | response | ideal rule | status |
|---|---|---|---|---|---|
| combined (existing) | `MODE_D4_DUAL`, D_A > 0 | held to max(t_0 + D_A, t_R) | e_A + gap | as above | offline-tested, compiled |
| Case 1, ACK-focused | `MODE_D4_DUAL`, **D_A = 0**, gap = minimal guard | held until the response is seen, then released at once | e_A + guard | e_A = max(t_R, t_A); e_R = e_A + guard | offline-tested against the model; needs a control profile that allows D_A = 0 (`control.py` allows only 5/10/15/20 ms) |
| Case 2, response-focused | `MODE_D2_RESP` | forwarded on arrival (never held) | held to the ACK-relative deadline | e_R = max(t_R, t_A + gap) | offline-tested, compiled (9.13.1); new P4 rows |

Case 1 removes the native ACK-to-response spread but moves request-to-ACK onto the response latency, so it compresses CLRT without
removing the information. Case 2 leaves request-to-ACK native and normalises only responses that arrive inside the window; a late
response is not delayed. A fixed ACK shift is a separate analytical case and is not implemented. A combined-ACK device has no
separate ACK: Case 2 never arms (no pure ACK), so the response is held to the watchdog; use a request-relative policy or bypass.
