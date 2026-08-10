# Experiment 1 — verdict

## `PROMISING` (offline, for the TCP-header fingerprint axis only), conditional

The tested transformation removes the dominant header fingerprint, the transformed packets are
syntactically valid, and the core mechanism (canonical TCP option-layout normalization) is packet-bounded
enough to justify a standalone compile probe. Per the pre-registered rule, **`PROMISING` authorizes only
a later request for Experiment 2; it does not authorize implementation.**

## What the evidence shows

- **Attribution is exact.** Every outstation `data_offset` is explained by specific TCP option bytes; the
  strongest tell is the SYN-ACK option layout, with three pairwise-distinct physical stacks (SEL751,
  ION7550, AB1400), reinforced by established `data_offset`, TTL, MSS, and TCP window.
- **A canonical-option-layout transform (T2) removes it, offline.** Distinct handshake-captured
  signatures collapse 3 -> 1 and established-only 3 -> 1; every device becomes one public profile. Length-
  only IP normalization (T0) and timestamp-origin translation (T1) do **not** remove it.
- **The transform is byte-safe on the trace.** All 12 short-capture transforms pass validation: DNP3
  payload byte-identical, `ip.len`/`data_offset`/payload consistent, Ethernet minimum met, checksums 100%
  valid (the source captures carry a checksum-offload artifact, corrected on output).

## What the evidence does NOT show (the conditions on the verdict)

1. **Endpoint safety is not shown, and the offline method is likely unsafe live.** The collapse was
   achieved by **suppressing** TCP options (TS/WScale/SACK). Offline that is fine; on a live connection it
   removes options the endpoints negotiated end-to-end and rely on (PAWS/RTTM, flow control), so it would
   likely break the connection. The live-safe alternative is **translation** (rewrite option values,
   preserve semantics), which needs per-flow bidirectional state. This is the single most dangerous
   unresolved issue and is the subject of Experiment 3.
2. **Tofino feasibility is not shown.** The packet-bounded option rewrite is one thing; the live-safe
   translation path needs per-flow 32-bit state (TSval offset, ISN delta, window) that the frozen resource
   audit places on the saturated ingress tail and the exhausted W0-15 group, plus a runtime-delta TCP
   checksum flagged as a compile risk. Whether the normalizer compiles standalone is exactly Experiment 2.
3. **Header closure is incomplete.** The **TCP window value** survives T2 as a device tell (AB1400 fixed
   2048, ION7550 small/zero, SEL751 scaled). The size, count, and interarrival axes are untouched (out of
   scope for this header experiment) and remain the dominant residual for device anonymity overall.
4. **The result is exploratory, not general.** One physical unit per model and ~2 real-device sessions
   each. The attribution mechanism is general; the specific collapse is a corpus observation, not a
   device-family claim.

## What this authorizes

Only a request to Philip for **Experiment 2**: a compile-only, separately authorized, standalone Tofino
TCP-header normalizer (handshake option suppression or translation, canonical data offset, checksum
correction, with the per-flow state and counters named in `TOFINO_REQUIREMENTS.md`), compiled in
isolation before any Defense 4 co-residency. A compile failure there would be a bounded target result,
not a universal impossibility.

It does **not** authorize implementation, hardware use, Experiment 2 itself, or Experiment 3. It does not
change the standing decision-memo verdict (`NO_GO_FULL_TRANSCRIPT`, conditional): it advances one open
sub-question (the TCP-header axis) from "unresolved" toward "offline-removable, live-feasibility and
safety still open," which is precisely what a `PROMISING` Experiment 1 is meant to do.
