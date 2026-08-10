# Observable transcript specification

Revised for the one-Tofino testbed (`CORRECTION_LOG.md`). This fixes exactly what the master-facing
observer sees, so that "the pattern does not depend on the secret" is testable. The `PROOF_OBLIGATIONS.md`
and `EXPERIMENT_PLAN.md` refer back to these definitions.

## The public pattern

For a declared public transaction class `c`, the observer captures an ordered list of packets on the
master-facing segment during one transaction:

```
P_c = [ (delta_1, S_1, d_1), ..., (delta_K, S_K, d_K) ]
```

- `delta_i` — the scheduled release offset of slot `i`, measured from the transaction trigger. We test
  the offset sequence and the epoch length, not absolute wall-clock.
- `S_i` — observable size of packet `i` on the layer the observer uses (below).
- `d_i` — direction: master-to-outstation or outstation-to-master.
- `K` — the public packet or slot count for class `c`.

Everything in `P_c` is a public constant of the class `c`. The claim is that in `PATTERN_NORMAL`, `P_c`
is identical across protected secrets under the same `c`.

## The forbidden dependencies

No element of `P_c` (`K`, any `delta_i`, any `S_i`, any `d_i`), and no derived quantity (epoch length,
continuation count, termination time), may depend on physical device identity, actual response size,
response values, response readiness, natural ACK timing, or natural response timing. A design that lets
any of these leak into the pattern has failed, regardless of how the leak is packaged.

## Which size the observer reads

Sub-IP tricks do not help: trailer padding below IP leaves `ip.len` unchanged, so the observer reads the
original network-layer length (falsified upstream). The size axis is therefore defined at the layer the
observer actually uses, and the invariance test records all of `frame.len` (L2), `ip.len` (IPv4 total
length, the field that defeated trailer padding), and `tcp.len` (TCP payload length), per packet, plus
the multiset over the transaction and the aggregate sum (an aggregating observer sums split pieces). A
size defense that only moves `frame.len` while `ip.len` or `tcp.len` stays secret-dependent has not
closed the size axis.

## Headers and DNP3 content are observed but not fully in the claimed pattern

`P_c` claims independence over `(delta, S, d)`. The observer also reads outer headers and DNP3 content,
and those carry secret information the switch cannot fully remove on its own:

- **Switch-rewritable header fields** (candidate to normalize with a checksum delta): TTL, DF, IP-ID,
  Ethernet padding. These are folded into the claim only to the extent the switch actually rewrites them
  to a class-constant value; the TCP specialist's per-field table (`analysis/tcp_segmentation_and_headers.md`)
  fixes which qualify.
- **Endpoint-stamped fields** (normalization UNRESOLVED, not proven unreachable): TCP timestamps
  (TSval/TSecr), sequence/acknowledgment progression, window scale, data-offset / option layout. Whether
  one switch can normalize them (handshake option suppression, canonical data offset, per-flow TSval/ISN
  translation with checksum correction) without breaking TCP is an open question with concrete
  counterexamples to compile and test (`EXPERIMENT_PLAN.md`, `analysis/tcp_segmentation_and_headers.md`).
  Until then they are treated as open, quantified where measured, and not claimed normalized.
- **DNP3 content**: function code, object headers, indices, and CRC blocks. A native template or decoy is
  cover only if the observer cannot separate it from a genuine exchange by this content; the DNP3
  specialist's analysis (`analysis/native_dnp3_mechanisms.md`) fixes what is achievable.

So the honest claim shape is: invariance over `(K, delta_i, S_i, d_i)` and the switch-rewritable header
subset in `PATTERN_NORMAL`, with the endpoint-stamped header fields and any residual DNP3-content
distinguishability reported as measured residuals.

## Exact equality versus a declared randomized design

Per axis, a design picks one and justifies it:

1. **Exact equality** — `P_c` is identical across secrets on that axis (same `K`, same size multiset,
   same direction sequence, same slot schedule). This is the target for count, size, direction, and the
   switch-rewritable headers, and it is tested by equality, not statistics.
2. **Declared secret-independent distribution** — if release offsets carry deliberate public jitter, the
   claim is that the offset distribution is fixed, public, and secret-independent, tested by the methods
   in `EXPERIMENT_PLAN.md`. The randomization source must be independent of the secret.

The default is exact equality on count, size, and direction; on release timing, either exact offsets or
a declared public offset distribution, subject to the silicon cadence result (risk R13).

## Pattern states

The defense is always in exactly one named state, recorded by an auditable counter:

- `PATTERN_NORMAL` — the public pattern `P_c` is being produced; the only state in which invariance is
  claimed.
- `PATTERN_OVERFLOW` — a real transaction did not fit the pattern (for example a response larger than the
  provisioned slots, such as the 12,204-byte READ against a pattern sized for small polls). The design
  must define whether overflow extends the pattern in a secret-independent way (a public larger class) or
  is a privacy event.
- `AVAILABILITY_BYPASS` — correctness or a DNP3/TCP timer forced a real packet onto the wire outside the
  pattern (the Defense 4 fail-open path is an example). No privacy is claimed while this is nonzero.
- `PATTERN_DROP` — the design deliberately dropped or deferred a scheduled slot (for example an empty
  slot that was skipped). Counted, because a skipped slot is an observable deviation.
- `RECOVERY_MODE` — returning to `PATTERN_NORMAL` after any of the above.

Every departure from `PATTERN_NORMAL` increments the matching counter. A privacy claim is made only over
intervals that stayed in `PATTERN_NORMAL`; any interval containing an `AVAILABILITY_BYPASS` is excluded,
not averaged in. No privacy claim survives an unrecorded bypass.

## Non-negotiable constraints on the pattern

- `K`, the epoch length, the continuation count, and the termination time are public constants of `c`,
  never functions of a protected response property.
- The set of visible sizes is fixed and public; adaptive `K` and adaptive cell sizing are barred.
- Real and native cover must be indistinguishable to the observer in content and in the claimed pattern
  axes; without encryption this must be demonstrated natively, not assumed.
- Endpoint safety is part of the specification: a pattern that the unchanged master or outstation would
  act on unsafely is invalid even if its observable axes are perfectly invariant.
