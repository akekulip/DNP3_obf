# Observable transcript specification

This fixes exactly what the observer sees, so that "the transcript does not depend on the secret" is
a testable statement and not a slogan. Everything in `THREAT_MODEL.md` and the proofs in
`PROOF_OBLIGATIONS.md` refers back to the definitions here.

## The transcript

For one protected exchange the observer captures an ordered list of packets on the monitored segment:

```
O = [ (d_1, S_1, t_1, h_1), ..., (d_K, S_K, t_K, h_K) ]
```

- `d_i` — direction. Two values: master-to-outstation, outstation-to-master.
- `S_i` — observable size. The number of bytes the observer can count for packet `i` on the monitored
  layer. We fix the layer below.
- `t_i` — release time, as the observer timestamps arrival. We care about the sequence of inter-packet
  gaps `g_i = t_i - t_{i-1}` and the total duration `t_K - t_1`, not the absolute wall-clock.
- `h_i` — observable outer-header behavior for packet `i`. The specific fields are listed below.
- `K` — the packet count for the exchange.

### Which size the observer reads

The leakage evidence is explicit that sub-IP tricks do not help: trailer padding below IP leaves
`ip.len` unchanged, so the observer reads the original network-layer length. We therefore define the
size axis at the layer the observer actually uses, and we record all of:

- `frame.len` — the L2 frame length on the wire.
- `ip.len` — the IPv4 total length. This is the field that defeated trailer padding.
- `tcp.len` — the TCP payload length.

A size defense that only moves `frame.len` while leaving `ip.len` or `tcp.len` secret-dependent has
not closed the size axis. The canonical size feature for the invariance test is the tuple
`(frame.len, ip.len, tcp.len)` per packet, plus the multiset of these tuples over the exchange and
their aggregate sum (because an aggregating observer sums split pieces).

### Which header fields are in `h_i`

From the leakage study, the outer-header features that carry secret information today are:

- IPv4 TTL. Identified physical devices in the corpus.
- TCP data offset (header length / options layout). Identified physical devices in the corpus.
- TCP timestamp option behavior (TSval/TSecr progression and slope). Survives arrival-time shaping and
  carries a device clock.

`h_i` also includes anything else stable and device-linked in the outer header: IP flags/DF, window
scaling and other SYN-time options if the observer sees connection setup, and TCP window behavior.
The invariance test treats `h_i` as the vector of these fields.

## The canonical transcript and PATTERN_NORMAL

The defense claims a **canonical transcript**: the exact sequence of `(d, S, t-schedule, h)` that the
observer is supposed to see in the normal protected state, which we call `PATTERN_NORMAL`. The claim
is that in `PATTERN_NORMAL` this canonical transcript is what appears for every protected secret under
the same public `C`.

Two ways to make the claim precise, and a design must pick one per axis:

1. **Exact equality.** The transcript is byte-for-byte identical across secrets on that axis: same
   `K`, same size multiset, same direction sequence, same release schedule, same header vector. This
   is the strongest claim and the easiest to test (equality, not statistics). It is the target for
   count, size multiset, direction sequence, and outer headers.
2. **Statistical indistinguishability under a declared randomized design.** The transcript is drawn
   from a distribution that is fixed and public and does not depend on the secret. If release times
   carry deliberate jitter, or cell emission follows a public random schedule, then the claim is that
   the distribution of the timing features is the same across secrets, tested by the methods in
   `EXPERIMENT_PLAN.md`. The randomization source must be independent of the secret; that
   independence is itself a proof obligation.

The default posture is exact equality on count, size, direction, and headers, and (if any timing
randomization is used at all) a declared secret-independent distribution on the release schedule. A
design that needs statistical indistinguishability on the size or count axis is weaker and must
justify why exact equality is not achievable.

## Invariance is tested on these features

The transcript-invariance obligation (`PROOF_OBLIGATIONS.md`, class B) tests all of:

- count `K`;
- the multiset of size tuples `(frame.len, ip.len, tcp.len)` and their aggregate sum;
- the direction sequence `d_1..d_K`;
- the release schedule: the gap sequence `g_1..g_K`, the epoch length, and the total duration;
- the continuation behavior: how many cells follow the first, and whether that count depends on the
  response;
- the outer-header vector `h_i`;
- the silence/busy behavior: what the transcript looks like when no real exchange is happening (only
  meaningful for designs that claim to hide transaction occurrence).

## Pattern states

The defense is always in exactly one named state, and the state is what an auditable counter records.
These states are used by the privacy-failure accounting in `PROOF_OBLIGATIONS.md`.

- `PATTERN_NORMAL` — the canonical transcript is being produced. This is the only state in which the
  invariance property is claimed.
- `PATTERN_OVERFLOW` — a real exchange did not fit the pattern (for example a response larger than the
  pattern's provisioned cells, such as the 12,204-byte READ against a pattern sized for small polls).
  The design must define whether overflow extends the pattern in a secret-independent way or is a
  privacy event.
- `AVAILABILITY_BYPASS` — the correctness or timing budget forced a real packet onto the wire outside
  the pattern (the Defense 4 fail-open path is an example: when a response is missing or late, the
  mechanism releases to protect availability). No privacy is claimed while this is nonzero.
- `PATTERN_DROP` — the design deliberately dropped or deferred a scheduled cell (for example an empty
  scheduled slot that was skipped). This must be counted because a skipped slot is an observable
  deviation.
- `RECOVERY_MODE` — the system is returning to `PATTERN_NORMAL` after any of the above.

Every departure from `PATTERN_NORMAL` increments the matching counter. A privacy claim is only made
over intervals that stayed in `PATTERN_NORMAL`, and any interval containing an `AVAILABILITY_BYPASS`
is excluded from the privacy claim, not averaged into it.

## Non-negotiable constraints on the pattern

Directly from the leakage evidence and the scope discipline:

- `K`, the epoch length, the continuation count, and the termination time must not depend on any
  protected response property. This is the exact failure mode adaptive splitting exhibited.
- The set of visible sizes must be fixed and public. Adaptive `K` and adaptive cell sizing are
  barred.
- Real and chaff packets must be indistinguishable to the observer. Without an encrypted outer layer
  they are not, so a mixed real/chaff pattern implies encryption (see
  `TRANSPORT_AND_ENCRYPTION_OPTIONS.md`).
- The outer-header vector `h_i` must be secret-independent, which the queue scheduler alone cannot
  achieve.
