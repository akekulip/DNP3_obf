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
| RESET_FLUSH | validated matching FIN/RST flushes pending ACK/response originals once and aborts an unsent OPERATE; quarantine remains until originals terminate |

Case4 recovery conserves **original envelopes**, not blocker arrivals. The one-association profile
holds at most one ACK, one response and one unsent OPERATE. A cookie-bound three-bit mask records
these originals. The current source stores its zero-extended 16-bit identity in a separate 32-bit
cookie bank and the mask in a 16-bit bank; a matching immutable-cookie read gates every mask
mutation. A new association cannot reinitialise either bank during quarantine. Repeated ACK/response
copies create no extra ownership credit. Each original's
terminal forward/abort clears only its own cookie's bit, idempotently. Readiness expiry, reset and
normal response commitment enter quarantine. A second internal completion pass may release the
slot only after a matching cookie observes zero original bits. Lost blocker tokens are not a
reason to wait for a configured token count; old blockers stop recycling after retirement. A lost
**original** cannot prove termination and therefore keeps the slot quarantined until a separately
verified drain/reset procedure. No fixed initial reservoir population establishes residual occupancy.

The timing cookie has non-wrapping 16-bit association identity and distinct active, ACK-committed,
quarantined and idle phase bits. Late matching ACK/response envelopes of a quarantined owner still
flush natively and debit that cookie. An unsent OPERATE aborts after reset/retirement. Its ordinary
first return checks the absolute OPERATE deadline; only a subsequent cookie-qualified commitment
marks release and forwards it. Blocker loss alone does not authorize early OPERATE forwarding.
Cookie exhaustion refuses reuse. Physical queue service and successful drain remain deployment gates.
Current original-bank terminal debit requires `read_release == 1`; phase-2 native repair forwarding
can continue after that policy is disabled. Remaining credit conservatively holds quarantine.
Stop/drain liveness therefore requires a verified lifecycle cleanup procedure; disabling a
configuration field is not evidence that originals terminated or a new owner can be admitted.

The current standalone target source accepts Case4 state changes only through an explicitly trusted
internal validation handoff on reserved processing port 69, EtherType 0x88C9. It requires complete
IPv4/TCP and DNP3 CRC proof, supported profile and tuple/phase/application association flags before
application state mutation. Pure ACK proof and reset sequence proof have separate flag profiles;
reset also matches the connection cookie. The producer must preserve original request/response
observation time and supply the dynamic request wire end before ACK reverse translation. **That
complete validation/cache/transport producer is not implemented by the timing source**. Prefix
parsing is not full-frame validation, and a proof header is not itself evidence that validation ran.
The seam is disabled by default, restricted to the internal port and stripped before endpoint emission.
The full joint candidate, ledger lifecycle, unsupported-after-insertion refusal and verified port 69
service are unfinished integration gates; the timing seam alone is not a runnable joint candidate.

The independent model defaults to ideal immediate terminal service for compatibility. With
`deferred_returns=True`, explicit cookie/flow/epoch-bound TERMINAL_ACK/TERMINAL_RESP and
DRAIN_COMPLETE events exercise quarantine without fabricating physical service. A reset sequence
bound on the request requires both matching sequence and explicit caller validation. Legacy events
without that binding retain their weaker epoch/flow-only reset API. Historical disabled-expiry
source profiles retain their old immediate retirement; the current Case4 candidate requires
independent expiry enabled. This compatibility path does not establish current recovery acceptance.

Instrument variants emit bounded management learn records for ingress and **internal** commitment,
expiry, blocker termination, reset and quarantine-completion events. They add no endpoint frame
marker and report no wire departure or endpoint acceptance. Raw timestamp values are low 32-bit
nanoseconds with no inferred armed marker. Pulse-only records retain their unavailable zero socket
tuple; the offline decoder cannot establish same-socket physical intervals or manufacture packet
observations. Core and instrument variants require independent source-bound target builds.

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

## Bounded software transport and controller gates

The independent `size/case4_preprocess.py` oracle requires an exact MSS-only
SYN/SYNACK/final-ACK identity with MSS at least 57 before insertion. An initially
segmented SELECT or unsupported negotiation excludes insertion for the connection.
After SELECT commits, its bounded OPERATE assembler stores exactly 35 bytes and
a 35-bit receipt mask. Consistent duplicate/reordered fragments retain the first
fragment's observation time and absolute 30 ms deadline; they cannot extend it.
Conflicting bytes, incompatible objects/flags/CRC, expiry or excess processing
passes enter sticky transport fault. Cached replay and ACK/window translation
remain available; unfinished command suffixes are not forwarded and no ACK is
fabricated. This software oracle is not the missing TNA validation/image producer.

Control admission also needs the outstation's SELECT retention budget, measured
from successful SELECT acceptance to matching OPERATE acceptance. The native
holding-OFF cycle, SELECT-side response delay and complete OPERATE added cost
are charged once, separately for normal and fallback paths. Operation/profile,
connection/build and explicit observation endpoints must match. A master response
timeout cannot stand in for this retention budget. Imported internal records
cannot manufacture wire departure, queue drain or outstation acceptance; an
observed maximum remains an observation, not a bound on future traffic.

The whole controller mutation inventory binds its exact source/schema/build,
operation/profile and policy parameters. Every keyed/register/default write is
validated before device calls, backed up exclusively, disabled first, read back,
and enabled last. Cancellation attempts restoration and retains failed restore
evidence. Configuration restoration does not claim restoration of a different
program or physical traffic/drain state. The production qualification registry
is empty until a complete target, approved compiler, artifacts, loaded identity
and applicable admission are verified. Mock fixtures cannot qualify activation.
Acquisition reserves a fresh exclusive evidence directory before side effects;
failed, aborted and interrupted runs remain available without overwrite or retry.

## Preserved explanation-only policy history

The section below records earlier model/API policies. Cases 1-3 are explanation-only under the
current assignment; their historical implementations and tests are retained without new campaigns.
These old status rows do not override the current source/build support matrix or Case 4 contract.

## Per-type timing cases (2026-10-06)

The numbering below follows the meeting: Case 1 is ACK-focused, Case 2 is response-focused,
Case 3 generates an ACK, and Case 4 combines response-ready timing with supported size processing.
These numbers do not rename the historical defense modes. The earlier implementation made
the ACK-focused and response-focused policies selectable; this assignment preserves that history.

| case | mode / config | ACK | response | ideal rule | status |
|---|---|---|---|---|---|
| combined (existing) | `MODE_D4_DUAL`, D_A > 0 | held to max(t_0 + D_A, t_R) | e_A + gap | as above | offline-tested, compiled |
| Case 1, ACK-focused | `MODE_D4_DUAL`, **D_A = 0**, gap = minimal guard | held until the response is seen, then released at once | e_A + guard | e_A = max(t_R, t_A); e_R = e_A + guard | offline-tested against the model; needs a control profile that allows D_A = 0 (`control.py` allows only 5/10/15/20 ms) |
| Case 2, response-focused | `MODE_D2_RESP` | forwarded on arrival (never held) | held to the ACK-relative deadline | e_R = max(t_R, t_A + gap) | offline-tested, compiled (9.13.1); new P4 rows |
| Case 3, generated ACK | historical BMv2 mode 3 | intermediary creates an ACK for the request | follows the prototype's response schedule | creates a separate ACK-to-response channel when the original device combined its ACK and response | explanation-only; receiver acceptance and checksum tests are retained, but retaining/retransmitting downstream transport responsibility is incomplete; [bounded evidence](../../audit_current/framework_20261005/PHASE7_GENERATED_ACK.md) |
| Constant shift, analytical reference | fixed k_A and k_R, not a new implementation | native ACK + k_A | native response + k_R | CLRT_new = CLRT_original + k_R - k_A; equal shifts leave the gap unchanged | analytical transformation only; fixed shifts preserve the population variance, and do not establish physical measurements |

Case 1/2 support is recorded in the [source-driven packet tests](../tests/test_model_vs_p4.py)
and [historical BMv2 tests](../tests/test_bmv2_artifact.py). Their archived successes and failures
remain separate from the current Case 4 implementation and its target-fit gates.
Replacement schedules a declared target gap under its readiness/release conditions; shifting
adds a fixed offset to an existing interval. Neither a fixed shift nor a reduced variance proves
that visible plaintext operation/object information or device identity has been hidden.

Case 1 removes the native ACK-to-response spread but moves request-to-ACK onto the response latency, so it compresses CLRT without
removing the information. Case 2 leaves request-to-ACK native and normalises only responses that arrive inside the window; a late
response is not delayed. A fixed ACK shift is a separate analytical case and is not implemented. A combined-ACK device has no
separate ACK: Case 2 never arms (no pure ACK), so the response is held to the watchdog; use a request-relative policy or bypass.
