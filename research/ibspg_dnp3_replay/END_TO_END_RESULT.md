# End-to-end result — real DNP3 through the in-network normalizer on Tofino-1

**Measured 2026-07-25 on the live testbed.** Real DNP3 frames from the SEL-751 corpus, replayed
through the Tofino-1, captured on Vision. No synthetic role markers. No physical SEL involvement.

Evidence tags: `[OBS]` single silicon observation · `[REP]` repeated/statistical · `[FIX]` corrected
defect · `[OPEN]` unresolved.

## Headline

**The timing channel is closed on real DNP3 traffic.** An observer measuring the ACK→response
interval (the Formby CLRT fingerprint) sees the device's own behaviour before the defense and a
policy-chosen constant after it.

| | before (native, bypass) | after (defended, G = 25 ms) |
|---|---:|---:|
| CLRT p50 | 12.717 ms | **24.998 ms** |
| CLRT sd | 1.8527 ms | **0.0068 ms** |
| CLRT range | 6.531 ms | **0.046 ms** |
| distinct values (n=30) | 30 | — |
| observer entropy @ 50 µs bins | **4.707 bits** (27 bins) | **0.211 bits** (2 bins) |
| observer entropy @ 1 ms bins | 2.536 bits (6 bins) | **0.000 bits** (1 bin) |

Standard deviation collapses **272×**. At 1 ms observer resolution the channel carries **exactly
zero bits**. What remains at finer resolution is host capture jitter, not device behaviour — the
on-chip figure is a **1,736 ns** release tail, matching the 1.72 µs measured with synthetic markers
in Part 12. `[REP]`

## What ran

Two-sided replay, which is new and was forced by the design: the silicon classifier derives
direction from the ingress port, so a READ arriving on the outstation port would be misclassified.

```
READ (DNP3 function 1)      injected from VISION -> dp9  -> direction 0   (master side)
pure TCP ACK + RESPONSE     injected from HULK   -> dp11 -> direction 1   (outstation side)
blocker tokens (0x88C1)     injected from HULK, gen = the READ's DNP3 application control byte
capture                     VISION, inbound only, filter admits BOTH 0x0800 and 0x88C1
```

The outstation-side injector reproduces **each transaction's own native CLRT** (10.6–17.0 ms, 30
distinct values measured from the capture) rather than a fixed gap, so the "before" condition is the
device's real timing fingerprint rather than an artifact of the harness.

## Classification on silicon — the gate that had never been run `[OBS]`

| counter | before | after |
|---|---:|---:|
| `ctr_arm` (real DNP3 READ armed a transaction) | 30 | 30 |
| `ctr_ack_arm` (real pure TCP ACK armed the deadline) | 30 | 30 |
| `ctr_resp_enq` / `ctr_resp_release` | 30 / 30 | 30 / 30 |
| `ctr_block_enq` | 0 | 1920 |
| `ctr_block_term_deadline` | 0 | **1920** |
| `ctr_block_term_timeout` / `_stale` | 0 / 0 | **0 / 0** |

Every one of the 1,920 blocker tokens terminated on the **deadline**; not one transaction fell back
to the pass-budget fail-open. `reg_gen` reads `0xC0`, `0xC1`, `0xC2` … — the DNP3 application control
byte — confirming the generation contract holds on live frames.

**The historic parser bug is fixed and proven fixed `[FIX]`.** An earlier switch window was lost to a
parser that extracted DNP3 unconditionally and therefore dropped zero-payload pure TCP ACKs, causing
retransmission storms. Here the pure ACKs are classified, forwarded and counted (`ctr_ack_arm = 30`),
with zero retransmissions.

## Internal-token isolation `[OBS]`

The Vision capture filter admits ethertype `0x88C1`. **Zero blocker tokens appear in either capture**,
across 1,920 tokens circulating internally. The absence is a real observation, not a filter artifact.


## G sweep on real DNP3, and a real operational constraint `[REP]` `[OPEN]`

The normalizer sets whatever interval policy asks for — **provided the target exceeds the native
interval**. Wire-measured at Vision:

| G | CLRT p50 | CLRT sd | range | normalized? |
|---:|---:|---:|---:|---|
| native (bypass) | 12.717 ms | 1.8527 ms | 6.531 ms | — |
| **10 ms** | 12.657 ms | 1.7948 ms | 4.732 ms | **NO** |
| 17 ms | 16.99996 ms | 0.0098 ms | 0.033 ms | yes |
| 25 ms | 24.998 ms | 0.0068 ms | 0.046 ms | yes |
| 40 ms | 40.0002 ms | 0.0041 ms | 0.012 ms | yes |

**G = 10 ms does not normalize, and this is physics rather than a defect.** The device's native CLRT
is ~12.9 ms, so by the time the response reaches the hold queue the deadline `t_ack + 10 ms` has
already passed; the response is released immediately and keeps its native timing. A switch can delay
a packet, it cannot make one arrive earlier than it does.

**The operational rule: G must exceed the native interval it is masking** — in practice at or above
the high quantile of the native CLRT distribution (SEL-751 p95 17.2 ms / p99 25.1 ms, which is
exactly why 17 and 25 ms are the interesting targets). A deployment that picks G too low silently
gets no protection while every counter still reads healthy, so **G selection needs a guard: measure
the native distribution first, or add a telemetry check that flags responses released without
having waited.** That check does not exist today. `[OPEN]`

## Port isolation `[OBS]`

`ctr_bypass` is a two-entry counter — [0] forwarded, [1] dropped on an unexpected ingress port — and
the Part 12 reader only ever read index 0, so this had never been checked. Read directly:
**`ctr_bypass[0] = 161`, `ctr_bypass[1] = 0`**. No frame arrived on an unexpected port.


## What this closes, and what it does not — measured across all three devices `[OBS]`

Running the analyzer over the full corpus separates three distinct channels, which matters for
claiming the right thing:

| device | CLRT samples | distinct wire sizes |
|---|---:|---|
| SEL-751 (separate-ACK) | **300** | 6 (66, 74, 88, 101, 103, 120) |
| AB1400 (combined-ACK) | 1 | 12 |
| ION7550 (combined-ACK) | 1 | 12 |

1. **CLRT magnitude — CLOSED by this work.** For the one device that has a CLRT, its value is now a
   policy constant (0 bits at 1 ms observer resolution).
2. **ACK MODE — NOT closed, and not closed by timing normalization in principle.** Only the SEL-751
   emits a separate pure ACK at all; the combined-ACK devices yield a single CLRT sample because the
   ACK is piggybacked. **The existence of a separate ACK is itself the strongest device
   discriminator** — normalizing its value does not hide that it exists. This is the
   "anonymity-set-of-one" residual the project identified earlier, and it is untouched here.
3. **SIZE — NOT closed** (below), and the devices differ in size alphabet (6 vs 12 distinct sizes),
   so it is a genuine discriminator independent of timing.

The honest claim is therefore: *this closes the CLRT magnitude channel on a separate-ACK device*.
It is not a complete device-anonymity result, and the two remaining channels are named rather than
elided.

## Size channel — RESOLVED, and the answer is a negative `[OBS]`

The size path had never run on silicon. Two measured facts settled it in this session.

**The root cause of the total failure:** `eg_intr_md.pkt_length` reports `ipv4.total_len + 18`, i.e.
the Ethernet frame length **plus the 4-byte FCS**, while every table key was computed as
`total_len + 14`. Every entry was short by exactly 4 and every frame fell through to fail-open.
Determined without a recompile by injecting nine probe frames spanning the parser's length classes:
exactly one normalized (`total_len = 48`), which only the FCS hypothesis predicts, and that
hypothesis then reproduces all thirteen classes uniquely. Detail:
`evidence/pktlen_rootcause/PKTLEN_ROOT_CAUSE.md`.

**After the fix, the mechanism fires perfectly — and closes nothing.** All 30 frames of a defended
campaign left at **128 bytes**, one size, checksums GOOD, DNP3 still decoding, timing still
normalized. But:

| observer feature | padding OFF | padding ON |
|---|---:|---:|
| `frame.len` | 1.000 bits | **0.000 bits** |
| `ip.len` | 1.000 bits | **1.000 bits** |
| `tcp.len` | 1.000 bits | **1.000 bits** |

The pad sits below IP, so `ipv4.total_len` is untouched **by design** — simultaneously the
byte-preservation correctness argument and the refutation. An observer reading `ip.len` recovers the
original size distribution exactly, and Zeek (already used in this project) reads IP and TCP bytes,
never frame bytes.

**The general result:** any padding that is protocol-*transparent* — strippable by a receiver without
cooperation — is by construction strippable by the observer applying the same rule. Closing the size
channel requires byte modification the receiver cannot undo (grow `total_len` with DNP3-legal filler,
correct checksums, translate TCP sequence space), which is a separate, larger construction.

**A latent corruption hazard was found and is NOT deployed `[OPEN]`.** The table keys only on
`pkt_length` while the egress parser requires `data_offset == 5`, and nothing couples them. For a
`data_offset = 8` frame — 2,102 of 2,104 in the real corpus — the pad would land *between* the TCP
header and its options, corrupting the frame. Correcting the offset does not fix that; it arms it.
The run above was safe only because these replay frames are `data_offset = 5`. Full detail and the
safe re-keying: `evidence/size_falsification/SIZE_MECHANISM_FALSIFIED.md`.

## Scope and honesty

- Real DNP3 **application bytes** replayed verbatim from the corpus; the TCP/IP envelope is
  synthesized onto lab addressing, at `data_offset = 5`. The real corpus uses `data_offset = 8`
  (2,102 of 2,104 packets), which the timing path covers (5–8) and the size path does not yet.
- No physical SEL-751 was involved. Replay only.
- Timing measured on-chip from register pairs; the host capture is a millisecond-scale corroboration
  (its own jitter is ~10 µs) and is not used to support the nanosecond figures.

## Artifacts

`evidence/e2e/` — `before30.pcap`, `after30.pcap` and their switch counter reads, `e2e30_summary.json`,
and `figures30/` (CLRT ECDF, size histogram, joint size/timing scatter, classification counts).
Native corpus baseline for comparison: `evidence/native_baseline.json` and `evidence/figures/`.
