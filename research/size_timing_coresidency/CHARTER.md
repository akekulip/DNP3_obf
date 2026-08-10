# Charter — Size + Timing Co-Residency Research and Optimization Committee

**Opened:** 2026-08-10 · **Status:** wave 1 in progress · **Silicon contact:** FORBIDDEN

## The goal

One Tofino-1 P4 program, at the outstation edge, whose pipeline carries **both** the timing
normalization already demonstrated **and** a size/segmentation obfuscation axis, such that a passive
on-path observer cannot fingerprint the SEL-751 by *either* channel.

Today those two axes have never co-resided in a program that is functional on real traffic. The
timing axis is demonstrated but partial. The size axis has been **falsified on silicon**.

## The two size mechanisms under study (Philip's direction)

1. **CROB-based padding.** Control Relay Output Blocks issued to relay points that are *not
   physically wired to any breaker*, used as inert volume so response sizes stop being informative.
2. **CRC-boundary splitting for large READs.** Cut long responses only on existing DNP3 CRC block
   boundaries so the master reassembles natively, with no CRC recompute and no DNP3 byte modified.

Both must live in the **same pipeline** as the timing engine.

## Hard constraints (measured, not assumed)

| constraint | value | source |
|---|---|---|
| Target | Intel Tofino-1, data plane only, one switch at outstation edge | `defense4/README.md` |
| Stage budget | 12 ingress / 12 egress | TF1 |
| Timing core alone | 8/12 ingress after packed state (P1); 12/12 unpacked | `SIZE_CORESIDENCY_VARIANT_MATRIX.md` |
| Best measured combination | P12 = **8 ingress / 2 egress**, critical path 8, 0 errors | same, sha `c43409c82e93` |
| **Binding resource** | **tagalong PHV: 7 of 8 collections occupied**; 16-bit 83.3%, 32-bit 84.4% | same |
| Real relay TCP header | `data_offset = 8` (32 B) on **2,102 of 2,104** frames; **zero** at 5 | `SEL751.pcap` |
| `pkt_length` semantics | reports **wire + 4** — the FCS is included | falsification note |
| Relay access | physical SEL-751 is **READ-only**; hardware gated on Philip's explicit authorization | `CLAUDE.md` |

## What is already FALSIFIED — do not re-derive, do not repeat

1. **The prior size mechanism normalizes a field no adversary reads.** It drove `frame.len` to a
   single value while leaving `ip.len` and `tcp.len` at full entropy. Any new design must normalize
   what an observer actually parses.
2. **It never fires on real traffic.** The normalizer covers `data_offset = 5` only; the relay uses 8.
   The program compiles, fits, forwards correctly and normalizes **nothing**.
3. **Emission position matters more than the decode trick.** The Level-1 result emitted
   `ethernet → pads → body`; on a live frame the body is the IPv4 header, so the pad displaces it.
   The output was not an IPv4 packet with bad checksums — it was not an IPv4 packet.
4. **A single 32-bit packed state word cannot be built on TF1.** Constants may be packed into a
   32-bit arithmetic word; **runtime fields may not** (PHV allocation fails). Three compiler
   rejections preserved in `variants/p1_packed_state/salu_probes/`.
5. **Stage savings overlap, they do not add.** Packed state 12→8, DNP3 classification 12→11,
   together **8, not 7**. Budget as `max(lever)`, never `sum(lever)`.
6. **Egress telemetry offload saves zero ingress stages.** Measured, after being bounded by deletion.

## Open defect the size design must not lean on

The timing engine has an **open `tag_retire_if_unmarked` lifecycle defect**: the ACK release retires
the transaction before the response is pending. Measured n=240 — `deadline_release` 0, `RESP_BYPASS`
240. Consequently **D2 does not shape**, and **D4 is a mixture**, not a normalizer: 160/240 held
~8 ms, 80/240 bypassed at native (33%). D1 and D3 genuinely shape. Verdict on record: *timing
experiments PARTIAL, integrated-lifecycle defect OPEN*.

Any size mechanism that hangs off the retirement path inherits this bug. Design so the size axis is
**separable from, and re-verifiable after,** the retirement fix.

## Rules of engagement for every committee member

- **No switch contact of any kind.** The switch is currently live in the calibrated D4 policy.
  Offline compiles only, using `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c`.
- **Evidence or silence.** Every resource number must come from a compile you ran or a log you read,
  cited `file:line`. No remembered numbers, no plausible-sounding estimates.
- **Negative results are results.** "This does not fit, and here is the compiler output proving it"
  is a full deliverable. Do not soften a wall into a maybe.
- **Report the constraint you hit**, not the constraint you expected to hit.
- Write findings to `research/size_timing_coresidency/reports/<your-name>.md`.

## Success criterion for the committee

A design proposal that is (a) resource-feasible with a measured compile, (b) functional on real
`data_offset = 8` traffic, (c) normalizing fields an adversary actually reads, (d) protocol-correct
so the master reassembles without error, (e) operationally safe on a protection relay, and
(f) independent of the open retirement defect. Anything short of all six is reported as short.
