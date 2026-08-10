# Decision memo — one-Tofino native revision

**Decision: `NO_GO_FULL_TRANSCRIPT`.**

Under the binding testbed `Master <-> Tofino-1 <-> Outstation`, full plaintext fixed-transcript
invariance is unattainable, and the reason is structural, not a tuning gap. This memo supersedes the
baseline decision of `f2bd3e4` (which recommended `GO_WITH_BOUNDED_CLAIM` on the now-excluded paired
gateway) and is reconciled from three independent specialist investigations and an adversarial review
that tried and failed to break it. The project's value is an **impossibility contribution**, not a
positive fixed-transcript defense. This memo incorporates the skeptical review (`SKEPTICAL_REVIEW.md`)
in full: the positive floor is demoted to a non-closing mitigation, the timestamp-closure novelty is
withdrawn, and the empirical residual numbers are labeled single-unit illustrative pending a powered
campaign.

## Why the full claim is closed

Three structural walls, each verified against frozen source:

1. **Ignore-rule equals strip-rule.** In self-describing, CRC-checked, correctness-critical plaintext
   DNP3, the rule by which the receiver ignores a filler packet is the same rule, written in the packet,
   by which a passive observer strips it. So the only cover an observer cannot strip is cover a genuine
   endpoint actually produces, which a stock endpoint plus a DNP3-blind Tofino-1 (DNP3 bytes are the
   unparsed deparser residual, never in the PHV) cannot synthesize. **[verified fact]**
2. **Correct size/count closure needs a proxy.** The switch can rewrite parsed headers and truncate to a
   fixed prefix, but cannot excise an interior byte range or re-slice an application object spanning
   several TCP segments. Fixed-`K` re-slicing or padding of the single authoritative TCP stream requires
   store-and-forward reassembly, which is a proxy. The upstream `split_server.py` that "preserves bytes"
   is in fact a TCP-terminating socket proxy, so that byte-preservation result does not port to the
   switch. The skeptical PI tried five constructions (recirculation buffering, mirror + per-copy seq,
   segment-boundary truncation, CRC-block cuts, coalescing) and one of its own (retransmission-as-cover);
   all failed. **[falsification result]**
3. **Endpoint-stamped headers are unreachable statelessly.** TCP timestamps, sequence/acknowledgment
   progression, data-offset / option layout, and window-scale cannot be rewritten on one switch without
   breaking TCP, and the device fingerprint is an injective `(TTL, data_offset)` map, so normalizing TTL
   leaves `data_offset` and identity intact. **[verified fact]**

Together these terminate the full-transcript claim. The single thing that would reopen it is a stateful,
non-proxy on-switch closure of any one of {size, count, TCP-timestamp} that both compiles on the live
core and is accepted by the unchanged endpoints; the frozen resource audit predicts it fails
(`W0-15` 512/512 bits, tail stages 8-11 at 16/16 logical tables).

## 1. The strongest one-Tofino candidate

**Request-synchronized, real-packet-only release at public offsets, plus a stateless header-scrub.** The
switch classifies the public transaction, releases the genuine ACK and RESPONSE at public
request-anchored offsets `t_wire = min{tau_i : tau_i >= t_eligible}` with the deadline a public runtime
constant (the frozen Defense 4 mechanism, generalized to a public slot offset), and statelessly rewrites
the reachable header subset (TTL, `ip.id`, DF, IP/TCP checksums, window) to class constants. It changes
no DNP3 byte, injects no cover, and sends no control to the relay. This is the only native, endpoint-safe,
realizable mechanism. It closes the **release-schedule (timing)** axis and normalizes the two reachable
header tells (TTL, `ip.id`). **It is a non-closing mitigation, not a device-identity defense:**
`data_offset`, TCP timestamps, and window-scale survive, so the device is still separable, and size and
(for multi-segment responses) count are untouched. Sold as a defense it would be cosmetic over Defense 4;
its honest role is to demonstrate the achievable floor above the impossibility boundary.

## 2. The strongest rejected candidate

**Paired software gateways with an encrypted fixed-cell tunnel** (`TRANSPORT_AND_ENCRYPTION_OPTIONS.md`).
It is the only design that reaches full invariance, and it is excluded by the hard constraint (it needs a
second endpoint and encryption). It is retained as the correct account of what full invariance requires,
and it now functions as the impossibility argument: the property needs exactly the proxy and encryption
the testbed forbids.

## 3. The exact protected and leaked observables

- **Protected (closed on one switch):** the release schedule / timing (the CLRT axis), and the header
  fields TTL and `ip.id` (rewritten to class constants, so no `ip.id`-progression residual remains).
- **Leaked / residual (require a proxy the testbed forbids):** size (`ip.len`, `tcp.len`, and the
  `tcp.seq`/`tcp.ack` byte-count channel); packet count `K` for multi-segment responses (for the tested
  single-segment READ class, responses are one sub-MSS segment so `K = 1` is naturally invariant and the
  residual there is size, not count); `tcp.data_offset` / option layout / window-scale; TCP timestamps
  (TSval/TSecr); and DNP3 application content (function code, transport/app sequence, object indices, the
  per-16-byte-block CRC — the secret itself, and CRC recompute is spec-barred). Device identity survives
  through the `data_offset` half of the injective fingerprint.

## 4. The endpoint-safety argument

The surviving mechanism is safe by construction: it forwards the genuine request and response with no
DNP3 byte changed, so the master receives exactly the semantics it requested; it injects no cover, so no
fabricated CONFIRM (which would delete relay SER records) and no `ProcessIIN`-triggering frame ever
reaches the relay; and it issues no control, so no SELECT/OPERATE and no Remote-Bit assertion touch the
outstation. The physical SEL-751 stays read-only. **Scope caveat (from the review):** this safety and
correctness is proven only inside Defense 4's tested envelope (single-segment READ, one active
transaction, no induced loss or retransmission, sequential polling, R11 reservoir margin OPEN).
Multi-segment (the 12,204-byte READ), loss, retransmission, teardown, and control are offline-validated
only and must be re-established live, not inherited.

## 5. What is inherited from Ditto

Only its **TM scheduling discipline** (in-switch, queue-based, request-anchored release). Ditto's security
rests on MACsec encryption and a peer switch that strips padding, both unavailable here, so its
cover-and-depad model does not transfer. IP-TFS, NetShaper, and Pacer likewise need encryption and
cooperating endpoints the testbed forbids and are imported only for what they establish.

## 6. What is DNP3-specific

- The protected observable is the **separate-acknowledgment cross-layer response time**, the Formby
  fingerprint, which the general obfuscation literature does not target.
- The **ignore-rule = strip-rule theorem** is a property of self-describing, CRC-checked,
  correctness-critical plaintext protocols; it generalizes to Modbus and IEC 60870-5-104, but it is
  specific to legacy ICS, not to encrypted web traffic.
- Native cover is not a benign dummy but a **write to a protection relay**: a fabricated CONFIRM deletes
  Sequential-Events-Recorder records, and a decoy CROB asserts Remote Bits and writes SER. The safety
  escalation is DNP3/ICS-specific.
- The **12,204-byte integrity READ against tiny routine polls** is the DNP3-specific reason a fixed count
  is expensive and a single `K` is not a general bound.

## The reconciled contribution (novelty)

The defensible result is the **impossibility boundary**, framed as: (a) the ignore-rule = strip-rule
theorem for self-describing correctness-critical plaintext protocols; (b) tied to a refuted, plausible,
in-repo belief — the "CRC-boundary splitting preserves bytes" result, which source inspection confirms is
a TCP-terminating socket proxy, not a switch capability; and (c) the ICS-specific safety escalation of
native cover. This is not "no one has done single-switch plaintext DNP3" (a strawman), and it is not the
positive floor (cosmetic) or a TCP-timestamp closure (an endpoint-stamped residual that the resource
audit predicts is infeasible on the live core). The analytical impossibility is stated on small data; the
empirical residual-leak numbers (data_offset, TSval, size carrying identity) are **single-unit
illustrative** until the powered campaign runs.

## 7. The first falsification experiment

Experiment 1 (endpoint-safe native normalization): prove or falsify one READ mechanism (the real-packet
timing release with header-scrub) and one SBO mechanism (on an isolated simulator with non-physical
points, never the SEL-751) on unchanged endpoints, measuring requests/responses, endpoint acceptance,
IIN, event and SOE state, TCP/DNP3 correctness, count and size invariance (expected: not closed), observer
labelability of any cover, and behavior with the 12,204-byte response. This is the first
security-and-safety go/no-go.

## 8. The first silicon experiment

Experiment 2 (fixed-slot cadence, risk R13): measure the pktgen periodic-timer grid on the switch —
slot-jitter p50/p95/p99/p99.9, missed/duplicated/silent slots, chaff-inventory exhaustion, burst
clumping, eligibility-to-slot latency, overlapping epochs, sustained operation, and behavior under
competing traffic. Do not cite the Defense 4 deadline-release result as proof the periodic grid works.

## 9. The first functional compile probe

Experiment 3 (functional co-residency compile, compile-only): the preserved D4 semantic requirements plus
one functional size mechanism plus the pktgen/TM slot machinery plus the required correctness and
privacy-failure counters, budgeted in real compiler categories. An inert table, unused metadata, a
trailer-padding hook, or an idealized egress normalizer does not count. Expected result: the functional
size mechanism does not fit the saturated tail; the probe confirms the boundary with a real compile.

## 10. The condition that terminates the full fixed-transcript claim

It is already met: correct native size and count closure require a proxy (walls 1-3), which the testbed
forbids. The full claim is terminated. It would reopen only under the single condition in the review: a
stateful, non-proxy on-switch closure of one of {size, count, TCP-timestamp} that compiles on the live
core and is endpoint-safe. The frozen resource audit predicts that fails, so absent such a probe the
impossibility framing is locked.

## Path forward

The next phase, if Philip approves, is measurement and writing, not building: run Experiment 1 (the
endpoint-safety go/no-go, mostly offline), specify and gate Experiments 2 and 3 on hardware
authorization, and write the impossibility result with the theorem + refuted-belief + safety-escalation
framing. If the powered residual campaign (at least two units per model, at least five sessions per
device) is available, it upgrades the empirical half from illustrative to a device-family measurement.
The decisions that gate this are in `OPEN_QUESTIONS_FOR_PHILIP.md`; the most consequential is whether the
project is content to be an impossibility-plus-floor contribution, since a positive bounded defense is not
reachable under the hard constraint.
