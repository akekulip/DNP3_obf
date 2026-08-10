# Threat model

Revised for the binding testbed `Master <-> Tofino-1 <-> Outstation` (see `CORRECTION_LOG.md`). This
names the adversary, the secret, the public context, the observables, the trust and safety boundaries,
and the parts that are Philip's to decide (collected in `OPEN_QUESTIONS_FOR_PHILIP.md`).

## The adversary

The adversary is a passive on-path observer sitting on the **master-facing side** of the Tofino. It
captures packets in both directions, reads every plaintext DNP3 byte, records arrival times with fine
resolution, and reads all headers. It can inspect contents, headers, sizes, counts, and timing. It does
not inject, drop, delay, or modify packets, and it does not compromise the switch or the endpoints. It
is offline-strong: it may keep long captures, train a classifier, and run the best statistical attack it
can over count, sizes, gaps, duration, direction, headers, request features, DNP3 content (function
codes, object headers, indices, CRCs), and TCP behavior (sequence/acknowledgment progression, window,
options, timestamps).

The vantage is fixed to the master-facing segment because that is where the testbed places the observer
and because there is no WAN encryptor in this architecture: the switch shapes bare plaintext DNP3/TCP.
The observer sees both directions, so the request side leaks too; the leakage study found that request
size alone separates READ from DIRECT_OPERATE in the corpus, which is acceptable here only because
operation class is public (below).

## The secret and the public context

For the first bounded claim:

- **Secret `X`** = physical outstation identity, and response-dependent size, timing, count, and stack
  behavior. This bundles what must not leak: which physical device answers, how large its true response
  is, when it naturally answers, how many segments it naturally produces, and the fingerprint of its TCP
  stack.
- **Public `C`** = transaction occurrence and operation class. It is public that a transaction happened
  and whether it was a READ or an SBO.

Because occurrence and operation class are public, **READ and SBO may use different public patterns**,
and the defense makes no claim to hide activity, to hide operation type, to provide encrypted-content
indistinguishability, or to deliver universal fixed-transcript confidentiality. What must not leak is
the protected secret inside the public class: which device answered, and any response-dependent size,
count, timing, or stack detail.

## The observables

The observer records the master-facing pattern `P_c = [(delta_i, S_i, d_i)]` and, in addition, the outer
headers and DNP3 contents of every packet. The axes leak independently and in combination:

- **Count `K` and duration.** Adaptive splitting moves response-size information into count and
  duration (the leakage study measured roughly 1.06 bits, about 60.6% of the response-size entropy,
  re-encoded into timing). `K` and epoch length must be public constants, not functions of the response.
- **Size `S_i`.** CRC-boundary splitting preserves the aggregate size; trailer padding below IP does not
  change `ip.len`. Only a fixed set of visible sizes, produced natively, closes this axis.
- **Release offset `delta_i`.** Must follow the public slot schedule, not the device's natural ACK or
  response timing.
- **Direction `d_i`.** The direction sequence must be a public constant of the class.
- **Outer headers.** TTL and TCP data offset fingerprint the device; TCP timestamps carry its clock;
  sequence/acknowledgment progression and window trajectory are device-stack specific. These live in the
  endpoints' own headers.
- **DNP3 contents.** Function code, object headers, indices, and CRCs are readable; a native template or
  decoy is only cover if the observer cannot separate it from a genuine exchange by content.

## The endpoint-safety boundary (new, first-class)

Because the endpoints are unchanged and one of them is a real protection relay, endpoint safety is a
proof obligation equal to privacy, not an afterthought:

- The **master** must receive exactly the DNP3 semantics it requested. Any native template, decoy, or
  segmentation must be reassembled and interpreted by the unchanged master as the correct response, in
  order, within DNP3 and TCP timers.
- The **outstation** must receive only safe operations. The physical SEL-751 stays read-only; no real
  SELECT/OPERATE/DIRECT-OPERATE is issued to it. Any decoy CROB must target a point explicitly
  configured as non-physical, and a decoy point is not assumed safe merely because it lacks a physical
  conductor: SELECT/OPERATE state, command status, IIN bits, event buffers, SOE retention, retries,
  timeouts, and duplicate suppression must all be shown benign.
- A **fabricated DNP3 CONFIRM** is treated as dangerous unless proved safe, because it can affect event
  and SOE retention. Invalid-CRC, invalid-checksum, obviously duplicated, or trivially labeled filler is
  both unsafe-or-useless as cover and detectable, so it does not establish real-versus-cover
  indistinguishability.

## Trust boundaries

- The switch is a trusted observation and control point on the plaintext path. It classifies DNP3
  transactions, schedules releases into public slots, and rewrites only the header fields it can reach.
- The endpoints are untrusted-to-modify and are never enlisted to reshape their own traffic.
- There is no encryption endpoint and no decoding peer, so real and cover traffic are distinguishable
  unless a native mechanism makes them content- and header-identical, which is the central open
  question.

## The likely impossibility boundary

Without a proxy, the switch cannot rewrite endpoint-stamped header fields (TCP timestamps, the
sequence/acknowledgment clock, the window trajectory, and the data-offset/option layout) without
breaking the endpoints' TCP semantics. These fields identified devices in the corpus and survive timing
shaping, so device-identity hiding at the full-header level is likely unreachable on one switch. The
revision's job is to establish this boundary exactly (the TCP specialist owns it) and to determine the
strongest bounded defense that survives above it: closing selected size, count, and timing features of
the DNP3 payload while declaring the endpoint-stamped header channel as a measured residual.

## Request-triggered epochs, not continuous cover

Phase 1 is request-synchronized: a public pattern is emitted per recognized transaction of the public
class. Because occurrence is public, there is no continuous bidirectional cover requirement and no
activity-hiding claim. This is a deliberate, cheaper scope than the superseded continuous-cover
direction; hiding occurrence is explicitly out of scope for the first bounded claim.
