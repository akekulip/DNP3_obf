# Threat model

This document names the adversary, the secret, the public context, the observables, and the trust
boundaries. It answers the security-objective questions the charter raised, and it marks the choices
that are Philip's to make rather than ours to assume. Those choices are also listed in
`OPEN_QUESTIONS_FOR_PHILIP.md`.

## The adversary

The adversary is a passive on-path observer. It captures packets, reads every plaintext byte,
records arrival times with fine resolution, and reads outer headers. It does not inject, drop, delay,
or modify packets, and it does not compromise the switch or the endpoints. This is the same adversary
class the Defense 4 work assumed and the same class the DNP3 fingerprinting literature assumes
(Formby et al. read the cross-layer response time straight from routine polling).

We treat the adversary as offline-strong: it may keep long captures, train a classifier, and run the
best statistical attack it can over count, sizes, gaps, duration, direction, headers, request
features, and any combination of these. A defense that only survives a weak attacker is not counted.

### Where the adversary sits

The observable transcript depends entirely on the vantage point, so we fix it. Two vantage points
matter and they are not the same problem:

- **Master-facing segment, before any WAN encryptor.** The observer sees the DNP3/TCP traffic as the
  defense shapes it. This is the vantage the upstream Defense 4 result used and the one this project
  targets first. If there is no WAN encryptor at all, this is simply the wire.
- **After a WAN encryptor.** If an IPsec or MACsec gateway already sits between the shaped segment
  and the observer, the observer sees only the outer tunnel. The tunnel then carries the transcript,
  and the shaping and the tunnel must be co-designed so the tunnel's own cell sizes and timing are
  the fixed transcript. Which of these two the design must defeat is a Philip decision; the
  transport analysis (`TRANSPORT_AND_ENCRYPTION_OPTIONS.md`) works both.

### Direction visibility

We assume the observer sees both directions of the link (master to outstation and outstation to
master). Assuming it sees only the outstation-to-master direction would be a weaker and less
defensible model, so we do not rely on it. The request direction leaks too: the leakage study found
that request size alone separates READ from DIRECT_OPERATE in the present corpus, so a design that
shapes only responses leaves a request-side channel open.

## The secret and the public context

The protected secret `X` is a design choice, and it changes what a defense must hide. The candidates,
from the leakage evidence, are:

- **Device identity.** Which physical device or vendor or model is behind the link. TTL and TCP
  data-offset identified the three physical devices perfectly in the corpus, and the cross-layer
  response time separates vendors, so identity leaks through headers and timing today.
- **Response value.** The content of a reading. This mostly leaks through size and, once split,
  through count and timing.
- **Response size.** The true number of bytes in the response. This is the axis CRC splitting
  preserves for an aggregating observer and the axis fixed-K was meant to close.
- **Operation type.** READ versus DIRECT_OPERATE versus SELECT/OPERATE. This leaks through request
  size and through response structure.
- **Transaction occurrence.** Whether a protected exchange happened at all in a given window. This is
  the hardest to hide because it needs cover traffic when nothing real is happening.

`C` is what we deliberately publish. The natural candidate is an allowed public transaction class:
if the fact that the link runs READ polling on a fixed schedule is already public and considered
acceptable to reveal, then `C` contains "this is READ polling" and the pattern is allowed to depend
on it. What must never leak is the protected secret inside that public class, for example which
device answers or what value it returns.

**Working assumption for this phase, subject to Philip's confirmation.** `X` = device identity plus
response value plus response size plus operation type. `C` = the existence and cadence of a public
polling class (that polling happens, and its period), but not which device or what value. Transaction
occurrence within the public class is public; a protected transaction that is not part of the public
class must be hidden, which is what forces cover traffic. This assignment is the single most
consequential decision in the project and is the first item in `OPEN_QUESTIONS_FOR_PHILIP.md`.

### May a pattern depend on READ versus SBO?

Yes, if and only if the operation type is in `C` and therefore public. If the deployment already
reveals that a link does READ polling, a fixed pattern keyed to READ is sound, because it leaks only
what `C` already publishes. If operation type is in `X` (the deployment wants to hide whether a poll
was a READ or a control), then the pattern must be identical across operation types, which is a
strictly harder design. The safe default is to treat operation type as secret unless Philip places it
in `C`.

## The observables

The observer records the transcript `O = [(d_i, S_i, t_i, h_i)]`, i = 1..K, defined in
`OBSERVABLE_TRANSCRIPT_SPEC.md`. The four axes leak independently and also in combination:

- **Count `K` and duration.** Adaptive splitting moves response-size information into count and
  duration; the leakage study measured about 1.06 bits, roughly 60.6% of the response-size entropy,
  re-encoded into timing. This is why `K` and epoch length must never depend on a protected response
  property.
- **Size `S_i`.** CRC splitting preserves the total size for an observer that sums the pieces.
  Trailer padding below IP does not change `ip.len`, so it does not hide size. Only a fixed set of
  visible sizes closes this axis.
- **Time `t_i`.** The cross-layer response time is the Defense 4 target. TCP timestamps remain
  visible after arrival-time shaping, so shaping release times is not enough on its own.
- **Header `h_i`.** TTL and TCP data-offset fingerprint the device; TCP timestamps carry a clock.
  These live in the outer header and are not touched by queue timing, so the design must normalize
  them explicitly, which points at an encrypted outer layer.

## Trust boundaries

- The switch is a trusted observation and control point on the plaintext path. It sees cleartext
  DNP3, matches transactions, and controls release timing.
- The physical outstation is untrusted-to-modify: it runs vendor firmware, it is never asked to
  reshape its own traffic, and in this project it is never sent a control command. The physical
  SEL-751 stays read-only.
- If the design needs to make real and chaff traffic indistinguishable, that requires an encrypted
  outer layer, and the endpoints of that layer (a local encapsulator near the outstation and a peer
  near the master) become trusted. Whether such a local function is unavoidable is answered in
  `TRANSPORT_AND_ENCRYPTION_OPTIONS.md`.

## What follows from request-triggered epochs versus continuous cover

- **Request-triggered epochs** can make the response transcript independent of the response, because
  the switch knows when a protected exchange starts and can emit a fixed pattern of cells for it. This
  protects response value, response size, and (if the pattern is identical across operations)
  operation type, at the cost of overhead only when polls happen. It does not hide transaction
  occurrence, because the epoch itself is triggered by a real request.
- **Continuous bidirectional cover traffic** is what hides transaction occurrence: the link emits the
  same pattern whether or not a protected exchange is happening, so the observer cannot tell a busy
  period from an idle one. This is strictly more expensive and is the only way to close the
  occurrence channel. Whether the deployment must hide occurrence, or only value/size/type within a
  public polling class, is again Philip's call and sets the whole cost of the system.
