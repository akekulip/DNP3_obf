# WS6 — Variant matrix and recommended architecture

Compile-only campaign, local bf-p4c 9.13.1, **no switch contact at any point**. Every row is a real
compile; the P0/P1/P3/P6c/P7-class rows were re-compiled independently by the main session rather than
accepted from an agent report.


> **⚠ VERDICT SUPERSEDED 2026-07-25 — the size mechanism was run on silicon and FALSIFIED.**
> Every resource number below is correct and reproducible; the **defensive value is not**. After
> correcting the `pkt_length` keying (it reports `wire + 4`, i.e. the FCS is included) the mechanism
> normalizes `frame.len` to a single value and leaves `ip.len`/`tcp.len` at full entropy — it
> normalizes a field no adversary reads. It also never fires on the SEL-751 at all (`data_offset = 8`).
> Three rows of the acceptance gate below are **withdrawn in place**. Read
> `research/ibspg_dnp3_replay/PANEL_SYNTHESIS_WAY_FORWARD.md` (part13 worktree) and the audit's §8b–§8e
> before using anything here. The recommended architecture section retains its *timing* conclusions.

## The matrix

| variant | what changed vs P0 | **ig stages** | **eg stages** | crit path | log tables | SRAM | mapRAM | TCAM | SALU | Stats ALU | ig/eg parser states | err |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|
| **P0** | Part 12 baseline | **12** | 0 | 12 | 44 | 36 | 36 | 0 | 7 | 11 | 2/6 | 0 |
| P1 | packed transaction state | **8** | 0 | 8 | 44 | 35 | 34 | 1 | 6 | 11 | 2/6 | 0 |
| P2 | egress telemetry offload | 12 | 1 | 12 | 48 | 36 | 36 | 0 | 7 | 11 | 2/6 | 0 |
| **P3** | P1 + P2 | **8** | 1 | 8 | 48 | 35 | 34 | 1 | 6 | 11 | 2/6 | 0 |
| P4 | size primitive alone (no timing) | 2 | 0 | 2 | 7 | 7 | 6 | 0 | 0 | 3 | 2/6 | 0 |
| P5 | timing + parser pad code, no padding | 12 | 0 | 12 | 44 | 36 | 36 | 0 | 7 | 11 | 3/7 | 0 |
| **P6c** | timing + **egress/deparser padding** | **12** | **2** | 12 | 47 | 46 | 40 | 0 | 7 | 13 | 2/36 | 0 |
| P7 | parser-produced classify metadata | 11 | 0 | 11 | 42 | 36 | 36 | 0 | 7 | 11 | 4/6 | 0 |
| P8 / P9 | P1+P7 (+P2) | 8 | 0/1 | 8 | 42/46 | 35 | 34 | 1 | 6 | 11 | 4/6 | 0 |
| P10 / P11 | P9 + prep / classify folds | 8 | 1 | **7** | 45/41 | 35/36 | 34 | 1/2 | 6 | 11 | 4/6 | 0 |
| **Part 13** | real DNP3 classifier (separate line) | **11** | 0 | 11 | 45 | 38 | 38 | 0 | — | 12 | 9/5 | 0 |
| **P12** | **DNP3 + packed state + egress padding** | **8** | **2** | 8 | — | — | — | — | — | — | 12/— | 0 |

Forensic probes (deletions, upper bounds only — **not shippable**, two of them delete evidence the
gates depend on): remove `reg_ts_first_block` → 12; remove the **entire** timestamp bank → 12; remove
3 diagnostic counters → 12.

## What the matrix says

**1. Only two things move the ingress number, and neither is deletion.**
Packed state (−4) and parser offload (−1). Every deletion probe saved zero. The tail of the pipeline is
a packing outcome; the head is a genuine dependency chain, and that chain *is* the generation-safety
property.

**2. The two levers do not add.** P1 = 8, P7 = 11, P8 = 8. Once state is packed nothing is pinned, so
the head-of-chain edge that parser offload removes is no longer binding. Budget them as
`max(lever)`, not `sum(lever)`.

**3. Egress telemetry offload saves zero ingress stages — bounded, then confirmed.** WS1 predicted this
before P2 was built: deleting the whole telemetry bank saved nothing, and deletion upper-bounds a move.
P2 measured exactly zero. It remains worth shipping for ingress resource headroom (ingress-resident
registers/counters fall from 7/11 in P0 to 4/8 in P3), just never as a stage lever.

**4. Size normalization is free in ingress terms.** P6c's ingress footprint is identical to P0's in
every column — 12 stages, 36 SRAM, 36 map RAM, 7 SALU, 11 Stats ALU, 44 logical tables. The cost is
2 egress stages, out of 12 that were entirely unused, and tagalong PHV.

## Acceptance gate — both arms met

| requirement | verdict |
|---|---|
| saves ≥1 real ingress stage **or** proves zero-ingress-stage size integration | **BOTH** — P1 saves 4; P6c integrates size at zero ingress cost |
| generation safety unchanged | yes — and P1 *strengthens* it (see below) |
| stale/unrelated events still rejected | yes, per-variant |
| deadline release still correct | yes; P10 additionally makes it never fire early |
| timeout/fail-open still present | yes (pass-budget watchdog intact everywhere) |
| blocker isolation still present | yes; Part 13 forces 0x88C1 → ROLE_BLOCK in the parser |
| ACK-before-response structurally enforceable | yes — untouched TM priority mechanism |
| live packet lengths/checksums valid | **NO — WITHDRAWN 2026-07-25.** Frame lengths/checksums are valid only when the parser consumed the payload. The table keys on `pkt_length` alone and the parser requires `data_offset==5`; nothing couples them, and **2104/2104 real-corpus frames match on length while the parser has fallen through**. See the size-falsification note. |
| oversize packets fail open safely | **NO — WITHDRAWN 2026-07-25.** Un-parsed frames do not fail open; they match on length and are padded mid-datagram. |
| original payload semantically unchanged | **NO — WITHDRAWN 2026-07-25** for the combined program. True for standalone P6c only, because its table and parser were generated from the same class list with nothing else on the wire. |

Two invariants came out **stronger**, not merely preserved: P1 eliminates P0's deadline-zero sentinel
ambiguity (the armed flag is bit 0 of the deadline word, so one ternary tests armed-and-due together),
and Part 13 forces the internal token ethertype to ROLE_BLOCK in the parser regardless of the role byte
in the token header.

## Recommended architecture

**Packed transaction state (P1) + egress telemetry offload (P2) + egress/deparser size normalization
(P6c), on top of the parser-classifying DNP3 program.**

Measured budget of the pieces, individually: 8 ingress stages for the packed timing core, 0 additional
ingress stages for size, 2 egress stages for padding, 1 egress stage for telemetry, out of 12 ingress
and 12 egress. The DNP3 classifier measures 11 ingress on the *unpacked* state machine.

**MEASURED: the combination fits.** `p12_combined.p4` compiles 0 errors at **8 of 12 ingress stages
and 2 of 12 egress stages**, critical path 8, PHV allocation successful — recompiled independently by
the main session (sha `c43409c82e93`). The predicted tagalong blow-up did **not** happen, but tagalong
is now unambiguously the binding resource: **7 of 8 tagalong collections occupied**, 16-bit containers
83.3% and 32-bit 84.4% — roughly one collection of headroom left. The size normalizer dominates
tagalong (127 B of `pay*` plus 127 B of `pad*` definitions); the DNP3 classifier is second.

**The stage savings overlap rather than add, now confirmed on the real combination:** packed state
alone 12→8, DNP3 classification alone 12→11, together **8, not 7**. Both levers remove the *same*
stage-0 obstruction from different directions. Do not budget them additively.

One measured regression, real but not binding: min packet size at 100 Gbps rises from 82 B (DNP3 alone)
to 93 B, with the ingress parser at 12 states instead of 9. Irrelevant at DNP3 poll rates.

**Byte preservation was machine-checked, not asserted:** extracted from the compiler's own assembly,
the only MAU instruction writing a container holding a header field is `add W0, 4294967295, W0` — i.e.
`hdr.ib.seq -= 1` on the internal blocker token. Every IPv4, TCP, TCP-option, DNP3 and `pay*` container
is tagalong and is written by no MAU instruction at all.

## ⚠ The size axis is currently INERT on real traffic — measured, not projected

`[OPEN]` **The egress normalizer is P6c verbatim and covers only `data_offset = 5` (a 20-byte TCP
header). The real corpus does not use that.** Measured directly from `SEL751.pcap`: **2,102 of 2,104
packets carry a 32-byte TCP header (`data_offset = 8`, TCP timestamps)** and 2 carry 40 bytes. Zero
carry 20. So on live DNP3 traffic as captured, essentially every frame would miss `size_norm` and take
the fail-open `pad_none` default — **the program would compile, fit, forward correctly and normalize
nothing.**

This does not affect the timing axis, which is `data_offset`-independent and covers 5–8 in the Part 13
classifier. It does mean the headline "size and timing co-reside" is currently a *structural* result,
not yet a functional one on real traffic.

The fix is understood and is its own experiment: extend the chunk-class set across `data_offset`
values, roughly +13 length classes per value, landing squarely on the tagalong constraint that is
already at 7/8 collections. Folding it into P12 would also have changed two variables at once and made
the egress column incomparable with the standalone P6c measurement, which is why it was correctly left
out.

## Two negatives worth carrying forward

**The single 32-bit packed state word cannot be built on TF1.** Three distinct compiler rejections,
evidence preserved in `variants/p1_packed_state/salu_probes/`: a SALU takes at most 2 PHV inputs; SALU
compare immediates must be small; and decisively, depositing a **runtime** 8-bit field into bits [7:0]
of a 32-bit arithmetic word forces a byte split across the whole cluster and PHV allocation fails
("33 field slices remain unallocated"). The generalizable rule — **constants may be packed into a
32-bit arithmetic word, runtime fields may not** — is the same invalid-SuperCluster trap Part 12
documented, reached from the write side instead of the read side.

**The validated Level-1 size result was length-only on fully synthetic frames.** Its own silicon
capture is 150/150 frames of 128 B with *every byte after the Ethernet header zero* — no IPv4 header,
no TCP, no DNP3, no CRC. Its deparser emits `ethernet → pads → body`, and on a live frame the body is
the IPv4 header, so the pad displaces it: the output is not an IPv4 packet with bad checksums, it is
not an IPv4 packet. The decode trick is reusable; the emission position is not. This is why P6c exists.

## One behaviour change to verify on silicon

P1 clears transaction state on the **pass-budget timeout only**, because staleness is register-derived
and cannot gate the access that discovers it. Every clear P1 performs, P0 also performed — the clearing
set strictly shrinks and one cross-generation interference path is removed — but it is a real change
and must be exercised by the negative-control gates before deployment.

## Scope

Nothing in this campaign ran on silicon. P6c's byte identity is proved against a model of the emit
order, not a capture. No RFC *requires* a receiver to accept Ethernet trailer octets, and the SEL-751's
stack is unverified `[OPEN]`.
