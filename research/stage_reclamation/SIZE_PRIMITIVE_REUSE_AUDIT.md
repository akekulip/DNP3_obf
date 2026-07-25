# SIZE_PRIMITIVE_REUSE_AUDIT.md

**Status: CHARACTERIZED NEGATIVE.** The Ethernet-trailer size-normalization mechanism was built,
compiled, loaded and run on Tofino-1 silicon. It works exactly as designed — and it closes nothing.
This document records why, because the reason is general and is the contribution: it explains why
in-network size normalization for cleartext ICS traffic has not been done, and it rules out an
entire family of mechanisms rather than one implementation.

Originally an audit of whether one fixed size state could be made co-resident with the Part 12/13
timing mechanism **without costing an ingress MAU stage**. That question was answered — yes, zero
ingress stages — and the answer turned out not to matter, because the primitive it makes room for
does not defeat the observer.

Compile numbers below come from **local `bf-p4c 9.13.1` runs performed for this audit**, not from
quoted notes:

```
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out <file>.p4
```

Extractor: `research/stage_reclamation/size_audit/extract_resources.py`
(reads `out/pipe/logs/{table_summary.log,resources.json,parser.characterize.log,phv_allocation_summary_0.log}`).
Silicon results are attributed inline and were produced by the coordinator on the Hulk/Vision/Tofino
testbed, 2026-07-25.

---

## 0. Verdict up front

| Question | Answer |
|---|---|
| Does egress-only size normalization cost an ingress MAU stage? | **No. Zero.** The ingress MAU footprint of P6, P6c, P12 and P13 is *bit-identical* to P0. Still true, still uninteresting. |
| Does merely *deciding* to normalize cost an ingress stage? | **No**, when the decision is produced in the ingress parser (P5). |
| Is the validated Level-1 primitive reusable on live traffic as-is? | **No.** It never carried IP, TCP or DNP3 bytes at all. §5. |
| Is the Ethernet-trailer mechanism constructible on Tofino-1? | **Yes** — compiled (§8), then **confirmed on silicon**: 30/30 frames left at one fixed 128 B size, IP and TCP checksums good, DNP3 still decoding. |
| **Does it defeat a passive observer?** | **NO.** §8b. The pad sits below IP, so `ipv4.total_len` is untouched *by design*; the observer reads `ip.len` and recovers the original distribution exactly. Frame-length entropy 1.000 → 0.000 bits; **IP-length entropy 1.000 → 1.000 bits, unchanged.** |
| Is the mechanism safe to extend to the real corpus as it stands? | **NO — it would corrupt 100 % of it.** §8c. This is an active hazard, not a limitation. |
| What generalizes from this? | **Protocol-transparent padding is observer-transparent padding.** §8b.1. Any pad a receiver can strip without cooperation, an observer can strip by the same rule. This kills the trailer mechanism, encapsulation, and options padding together. |

---

## 0.1 URGENT — do not run the +4-corrected P12 binary against real traffic

The silicon run that produced the §8b measurements was safe **only** because its replay frames were
built with `data_offset = 5`. The real corpus is `data_offset = 8` on 2102 of 2104 frames. In
`p12_combined.p4` the egress parser requires `data_offset == 5` while `size_norm` keys on
`eg_intr_md.pkt_length` alone, and **nothing couples the two**. Applying the +4 FCS key correction
to that program and pointing it at the relay would pad *inside* the IP datagram on every frame.

Computed against the measured corpus (`ipv4.total_len` from `Traffic Trace/SEL751.pcap`,
`pkt_length = wire + 4` as measured on silicon, entries = P12's set each +4):

| `data_offset` | `total_len` | wire | `pkt_length` | matches table? | parser consumed? | packets |
|---|---|---|---|---|---|---|
| 8 | 52 | 66 | 70 | **YES** | **NO** | 906 |
| 8 | 74 | 88 | 92 | **YES** | **NO** | 198 |
| 8 | 87 | 101 | 105 | **YES** | **NO** | 400 |
| 8 | 89 | 103 | 107 | **YES** | **NO** | 400 |
| 8 | 106 | 120 | 124 | **YES** | **NO** | 198 |
| 10 | 60 | 74 | 78 | **YES** | **NO** | 2 |

**2104 / 2104 frames (100 %) would match the table while the parser had fallen through**, placing
the pad between the 20-byte TCP base header and the TCP options — breaking the IP checksum scope,
the TCP checksum, and the DNP3 block CRC on every packet of a live substation link. See §8c.

---

## 1. What the validated program is, and where it lives

| | |
|---|---|
| Source | `research/tofino_dcrn_feasibility/p4/queue_microbench/queue_microbench_trace_v1.p4` (484 lines) |
| SHA-256 | `3e3750650a6e36bd6902db189bd03ae369c06c885991a4645a270c1e5bc798ea` |
| Control plane | `queue_microbench_trace_setup.py` (contains `build_trace_frame()`, the executable frame spec) |
| Generator | `harness/mb_trace_gen.py` |
| Hardware evidence | `autonomous_run_20260722/{HARDWARE_RESULT.md,evidence/}` |
| Recorded parity | `autonomous_run_20260722/SWITCH_COMPILE_PARITY.md` (local 9.13.1 vs on-switch 9.13.2) |

**Recompile parity check.** My 9.13.1 recompile reproduces the recorded build *exactly* — 3 ingress
stages, SRAM/map-RAM/TCAM 13/12/0, Meter(SALU)/Stats ALU 2/4, gateways 6, VLIW 21, logical tables 15.
This confirms the source in the tree is the source that ran on silicon, and that my extraction is
reading the same quantities the earlier report did.

---

## 2. Parser states used

Three user-written ingress states; the compiler reports **4 ingress parser states / 5 parser TCAM
rows** after its own splitting.

| State | Action | Transition |
|---|---|---|
| `start` | `extract(ig_intr_md)`, `advance(PORT_METADATA_SIZE)`, zero-init 15 metadata fields | → `parse_ethernet` |
| `parse_ethernet` | `extract(hdr.ethernet)` | `select(ether_type)`: `0x88B7` → `parse_replay`; default → `accept` |
| `parse_replay` | `extract(hdr.trace_replay)` (19 B) | → `accept` |

Egress: a single `start` state, no header extraction (6 states after the compiler's mandatory
min-parse-depth padding). **The parser never sees IPv4, TCP, or DNP3.** Everything past the 19-byte
replay header is opaque deparser residual.

---

## 3. Padding design and deparser emission order

**Pad-header set.** Seven power-of-2 headers — `pad1_h`(8b), `pad2_h`(16b), `pad4_h`(32b),
`pad8_h`(64b), `pad16_h`(128b), `pad32_h`(256b), `pad64_h`(512b). Bit *i* of the delta selects the
2^i-byte header, so any delta in {8…68} is a subset sum. At most 7 valid at once.

**Decode is compile-time, not runtime.** One table, `size_class_pad`, exact-matches the declared
class and each matched action sets its *entire* pad subset valid inside a single action
(`p4:286-323`). This is the load-bearing trick: all pads for a class land in that table's one stage.
The equivalent runtime form (store `delta`, then seven `if (delta[i]) hdr.padI.setValid()` bit-tests)
is functionally identical but **serializes into 7 stages** because the compiler cannot overlap seven
independent validity writes. That is the difference between 3 stages and 9.

**Deparser emission order** (`p4:425-433`):

```
ethernet → pad64 → pad32 → pad16 → pad8 → pad4 → pad2 → pad1 → trace_replay → (residual)
```

Invalid headers emit nothing, so:
* normalized frame → `ethernet | pads | residual-body` = 128 B (replay header stripped in the MAU)
* fail-open frame → `ethernet | trace_replay | residual-body`, unchanged

**Note the position: the pad is emitted immediately after the Ethernet header, ahead of the body.**
This is the single most important structural fact in this audit. See §4 and §7.

---

## 4. Why the output is 128 bytes

From `autonomous_run_20260722/CANDIDATE_SELECTION.md`:

* The 3-device base corpus has 13 distinct frame sizes, max **120 B**. 128 is the smallest round
  target that covers the maximum with **0 unfit packets** and requires no splitting.
* Measured size-channel leakage of a single 128 B state is **0** (MI = 0; a constant-feature
  property, not a finite-sample artifact). Mean pad 45.9 B/packet.
* Two-state alternatives (`[80,128]`, `[72,128]`) reduce mean padding to ~21 B but were rejected:
  they **re-introduce a size→operation signal**, and their small state "is not a compile-time pad
  width".

**Correction worth recording:** that last reason is a *code-generation* constraint, not a hardware
one. The power-of-2 header set realizes **any** delta in [1,127]; only the 13 `pad_dNN` actions were
pre-generated. A different target (e.g. 80) needs regenerated actions, not different silicon. 128 is
therefore a corpus-driven and codegen-driven choice, **not** a Tofino constraint.

---

## 5. THE CRUX — what was synthetic, and exactly what breaks on live traffic

The program's own header comment is candid ("Level-1 … does NOT parse or produce valid live
TCP/DNP3"), but the extent is stronger than that sentence suggests.

### 5.1 Ground truth from the hardware run

`build_trace_frame()` (`queue_microbench_trace_setup.py:97-119`) constructs:

```
eth(14) | trace_replay(19) | body(input_size_class - 14)
```

and the body is:

```python
body_len = input_size_class - ETH_LEN          # S - 14
body = (fill * body_len)[:body_len]            # fill = b"\x00"
```

I decoded the frames captured during the validated run
(`autonomous_run_20260722/evidence/trace1003.pcap`). Every released frame:

```
len=128B  etype=0x0800
02 00 00 00 00 02 | 02 00 00 00 00 01 | 08 00 | 00 00 00 ... 00
^ dst MAC           ^ src MAC           ^type   ^ all 114 remaining bytes are 0x00
non-zero byte offsets after the Ethernet header: []   (none, in every frame)
```

**Every byte after the 14-byte Ethernet header is zero.** The frame declares EtherType `0x0800`
(IPv4) — restored from `orig_ethertype` — while containing no IPv4 packet whatsoever. The first
payload byte is `0x00`, i.e. IP version 0, IHL 0. Any real IP stack discards it at the first check.

### 5.2 Which bytes were synthetic

| Element | Present? | Note |
|---|---|---|
| Ethernet dst/src/type | real | the only genuine bytes on the wire |
| IPv4 header | **absent** | never parsed, never emitted, never existed |
| TCP header | **absent** | " |
| DNP3 link/transport/application bytes | **absent** | " |
| Frame body | **synthetic** | all-zero filler sized to the class |
| Frame *length* | derived from real captures | the length and the labels are the only real information |
| `input_size_class`, device/operation/direction/txn/ack_mode labels | synthetic metadata | cleartext, measurement-only |

So "derived from real captures" is true of the **size distribution and the labels**, and of nothing
else. The primitive was validated as a *size mapper*, not as a packet transformer.

### 5.3 Which length/checksum fields were invalid for live TCP/DNP3

This is not a list of fields that need recomputing. It is a list of fields that **do not exist in
the program**, so nothing in it maintains them:

| Field | Status in `queue_microbench_trace_v1.p4` | What live traffic would require |
|---|---|---|
| IPv4 `total_length` | not parsed, not written | must keep delimiting exactly `ip+tcp+payload`; if the pad lands inside the datagram it must grow, which is the whole problem |
| IPv4 header checksum | not parsed, not written | recompute on any IPv4 header change (`Checksum()` extern; feasible on TF1) |
| TCP checksum | not parsed, not written | covers pseudo-header + TCP header + payload; invalid the instant padding is counted as payload |
| TCP `seq`/`ack` | not parsed, not written | padding-as-payload shifts the sequence space and needs a full per-flow ±Δ translator |
| TCP `data_offset` | not parsed, not written | would have to change for any options-based padding |
| DNP3 CRC-16/DNP (per 16-byte block) | not parsed, not written | breaks if any application byte moves |
| Ethernet FCS | recomputed by the egress MAC | **the one thing that is already correct** |

### 5.4 The structural break, stated precisely

The failure on live traffic is **not** "some checksums would be stale". It is worse and simpler:

> The deparser emits `ethernet → pads → body`. On a live frame the body **is** the IPv4 header.
> The pad bytes therefore *displace* the IPv4 header by up to 68 bytes.

The receiver reads pad bytes where the IP version/IHL/total_length belong. The result is not an
IPv4 packet with bad checksums; it is not an IPv4 packet. Every rejection criterion fires at once:
DNP3 application bytes are displaced, the DNP3 CRC is broken, IP total_length is inconsistent with
the wire, and the TCP checksum is meaningless.

**Conclusion: the validated primitive's *decode mechanism* (compile-time power-of-2 subset in one
action) is reusable and excellent. Its *emission position* is not reusable at all.** §8 fixes exactly
that.

---

## 6. Exact resource cost with telemetry OFF

`telemetry_enable` is a runtime register (default 0), so "telemetry off" at runtime still pays the
compiled cost. To answer the real question I built a compile-time ablation,
`size_audit/recompile_trace_v1_telemoff/trace_v1_telemoff.p4`, which removes the `Digest<>`
instance, the `telem_digest_t` record, the `telemetry_enable` and `run_id_reg` registers with their
RegisterActions, the 14 digest-scratch metadata fields, and `ctr_digest_emit`. The
classify → pad → strip → queue datapath is untouched.

| Resource | as-is | **telemetry OFF** | telemetry costs |
|---|---|---|---|
| Ingress stages | 3 | **2** | **+1 stage** |
| Egress stages | 0 | 0 | — |
| Critical path | 3 | 2 | +1 |
| Logical tables | 15 | 11 | +4 |
| SRAM | 13 | **7** | +6 |
| Map RAM | 12 | **6** | +6 |
| TCAM | 0 | **0** | — |
| SALU (Meter ALU) | 2 | **0** | +2 |
| Stats ALU | 4 | **3** | +1 |
| Gateways | 6 | 5 | +1 |
| VLIW instr | 21 | 17 | +4 |
| Ingress parser states / TCAM rows | 4 / 5 | 4 / 5 | — |
| PHV containers / bits | 33 / 440 | **13 / 117** | +20 / +323 |
| Tagalong bits allocated | 520 | 576 | — |
| Errors / warnings | 0 / 2 | 0 / 2 | — |

**The size primitive proper costs 2 ingress stages, 7 SRAM, 6 map RAM, 0 TCAM, 0 SALU, 3 Stats ALU,
13 PHV containers.** A third of the validated program's stage budget and three quarters of its PHV
were measurement scaffolding.

---

## 7. Can the padding live entirely in egress? — mechanism analysis

Baseline fact that makes this worth asking: **P0 (`ibspg_hold_response.p4`) uses 12/12 ingress
stages and 0/12 egress stages.** Egress is free real estate.

### 7.1 The asymmetry that decides the design

Two facts, both from the SDE headers, point the same way:

* `ingress_intrinsic_metadata_t` (`tofino1_base.p4:108-121`) contains `resubmit_flag`,
  `packet_version`, `ingress_port`, `ingress_mac_tstamp` — **and no packet-length field**.
* `egress_intrinsic_metadata_t` (`tofino1_base.p4:281`) contains **`bit<16> pkt_length`**.

So egress can size a frame with **no help from ingress at all**. The brief anticipated ingress
exporting a `normalize_size` flag, a target-size code and an oversize flag; measurement shows that
export is **unnecessary** — egress already holds strictly more size information than ingress does,
and it holds it as a *measured* value rather than the *declared* label the Level-1 primitive trusted.
Moving the decision to egress therefore upgrades Level-1 → Level-2 (self-validating key) as a side
effect.

The second half of the asymmetry: P0's `to_host()` sets `bypass_egress = 0`, so exactly the two
frames we want normalized — the immediately-forwarded ACK and the released RESPONSE — traverse
egress. The queued blocker/response loopback paths set `bypass_egress = 1` and never reach it, so
the hold mechanism cannot be perturbed.

### 7.2 Mechanism A — protocol-transparent Ethernet trailer

*Construction:* append pad octets after the end of the IP datagram, before the FCS. IP
`total_length` unchanged and still correct; TCP untouched; DNP3 and its CRC untouched; FCS
recomputed by the egress MAC.

**Standards position (researched this session, with citations):**

* **RFC 894 §2** — "the data field should be padded (with octets of zero) to meet the Ethernet
  minimum frame size. **This padding is not part of the IP packet and is not included in the total
  length field of the IP header.**" <https://www.rfc-editor.org/rfc/rfc894.txt>
* **RFC 1042 §3.2** — identical language for IEEE 802 networks.
  <https://www.rfc-editor.org/rfc/rfc1042.txt>
* **Linux** trims rather than drops. `ip_rcv_core()` in `net/ipv4/ip_input.c`:
  `len = iph_totlen(skb, iph); … if (pskb_trim_rcsum(skb, len)) { … goto drop; }` — with the
  in-tree comment "*Our transport medium may have padded the buffer out. Now we know it is IP we can
  trim to the true length of the frame.*" Trailer bytes are silently discarded; the packet is
  accepted. <https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c>
* **RX checksum offload is unaffected** — validation is scoped to the IP datagram via
  `total_length`, not to frame length (Linux `checksum-offloads.html`, FreeBSD ChecksumOffloading
  wiki, Microsoft NetCx checksum-offload docs).
* **Deployed precedent** — F5 BIG-IP Ethernet trailers, Arista timestamp trailers, packet-broker
  metadata trailers; Wireshark has a dedicated `eth.trailer` field and trailer heuristic dissectors.

**Honest limit — [OPEN], now CLOSED and irrelevant.** *No RFC requires a receiver to accept and
ignore trailer octets.* RFC 894/1042 establish that the octets are **not part of the IP packet**;
RFC 1122's robustness principle is aspirational, not normative, on this point. Linux/BSD/Windows
tolerate them in practice, and **silicon confirmed acceptance end to end** (§8b: checksums good,
DNP3 decoding, 30/30 transactions).

**This was the wrong risk to track.** The whole standards case above rests on the pad being *not
part of the IP packet* — which is exactly why the observer discounts it too. The citations are
retained because they are the proof of §8b.1's general rule, not because they support a deployment
claim. Read this subsection as evidence for the negative.

*Tofino obstacle:* a TNA deparser emits its headers and then the unparsed residual; **there is no
way to emit a header after the residual.** If the TCP payload is the residual, a pad header lands
*inside* the IP datagram — the §5.4 failure. §8 solves this **only for frames that take a `pl_*`
state**; §8c is what happens to every frame that does not, and it is the hazard that stopped the
`data_offset = 8` extension.

### 7.3 Mechanism B — outer envelope (encapsulation) — **REJECTED for this topology, and for a second reason**

A valid outer IP/UDP or VXLAN envelope with a correct outer `total_length` covering the pad, and the
inner frame untouched, is protocol-correct **only if something removes it**. The padding must exist
*on the observed link* to defeat the passive observer; therefore it must survive to the far end and
be stripped there. In the inline single-switch topology (host — Tofino — outstation) there is no
second decapsulating hop, and the physical SEL-751 will not decapsulate. Removal would require
**endpoint modification**, which is an explicit rejection criterion. Mechanism B is viable only
with a second cooperating switch/NIC at the far edge; that is a different deployment model and is
out of scope here.

*Second, independent rejection (§8b.1):* even granted a decapsulating far end, the outer envelope
carries the **inner IP header in cleartext inside its payload**. Any observer that parses one layer
deeper reads the inner `total_len` and recovers the original distribution — Wireshark and Zeek both
descend automatically for VXLAN/GRE. Encapsulation hides the length only from an observer who
cannot see inside the tunnel, which is not this threat model.

### 7.4 Mechanism C — options-based padding — **REJECTED, and for a better reason than recorded**

Pad inside IPv4 options and/or TCP NOP options, adjusting `ihl`/`data_offset` and `total_length`,
recomputing both checksums with the `Checksum()` extern (proven on-chip in `p4_decoy`). This
preserves TCP sequence space (options are not payload) and never touches DNP3 bytes or its CRC — it
is genuinely protocol-valid.

*Original objection, still true but secondary:* the ceiling is 40 B of IPv4 options + 40 B of TCP
options against required deltas up to 68 B; reaching them needs *both* option spaces, doubling the
modified surface and the checksum work, and IPv4 options are widely slow-pathed or dropped.

***The decisive objection (§8b.1):*** option padding **changes `data_offset`**, and the observer
therefore recovers the payload length exactly as
`payload_len = total_len − 20 − 4·data_offset`. The mechanism fails at *any* ceiling, so the
resource argument never gets to matter. This is the same failure as mechanism A wearing a different
header: the pad is placed somewhere the packet itself tells the observer to discount.

---

## 8. Proving mechanism A on Tofino-1 — `p6c_true_trailer.p4`

Rather than assert that a trailer is constructible, I built and compiled it.

**Idea:** make the residual *empty*, so the pads emitted last really are last. The egress parser
consumes the entire TCP payload into a **shared** power-of-2 chunk set
(`pay1_h`…`pay64_h`, 127 B of definitions total, not 13 × 66 B), selected by an exact match on
`(tcp.data_offset, ipv4.total_len)` placed *in the tcp-extract state* — a select on `total_len` in a
state placed *after* the TCP extract is a known bf-p4c 9.13.x failure mode on this toolchain.
Extraction order and emission order are both descending, so every subset reconstructs the payload
byte-identically. Frames that are not `ihl=5 / data_offset=5 / a known total_len` fall through to
`accept` with the payload still in the residual and no pad valid → forwarded unchanged (fail open).

**Result — the compiler's own egress deparser field dictionary** (`out_p6c/pipe/*.bfa`):

```
eth → ipv4 → tcp → pay64 → pay32 → pay16 → pay8 → pay4 → pay2 → pay1
    → pad64 → pad32 → pad16 → pad8 → pad4 → pad2 → pad1
```

The pad chunks are emitted **after the complete IP datagram**. 0 errors. Rejection checklist —
**every row below is conditional on the frame having taken a `pl_*` state**, i.e. on
`ihl = 5 / data_offset = 5 / a listed total_len`. That condition was left implicit in the original
audit and it is exactly what §8c shows to be load-bearing:

| Criterion | P6c, **on the `pl_*` path only** | on any other path |
|---|---|---|
| Modifies DNP3 application bytes | **No** — extracted and re-emitted in order; no MAU action reads or writes them | **YES — pad lands inside the datagram** |
| Breaks the DNP3 CRC | **No** — the CRC rides inside those untouched bytes | **YES** |
| Changes TCP sequence space | **No** — no payload byte added or removed | No (but the payload is corrupted) |
| Leaves IP total_length inconsistent | **No** — never written, and still exactly delimits `ip+tcp+payload` | **YES — `total_len` no longer delimits contiguous datagram bytes** |
| Leaves the TCP checksum invalid | **No** — pseudo-header, TCP header and payload all unchanged | **YES** |
| Requires endpoint modification | **No** — the trailer is below IP | No |

**Two claims made earlier in this document and in `SIZE_CORESIDENCY_VARIANT_MATRIX.md` were
wrong and are withdrawn:**

1. ~~"oversize packets fail open safely"~~ — **false as a general property.** Fail-open is a
   property of the *length* dimension only, and only on the `data_offset = 5` path. Nothing in P6c
   or P12 establishes that the parser consumed the payload before the table pads, so a frame can
   take the "safe" default on length while being corrupted on structure. In P12 the safe and unsafe
   cases are not distinguished by any key field.
2. ~~"original payload semantically unchanged"~~ — **false for the combined program.** It holds on
   the `data_offset = 5 / ihl = 5` path and fails on every other path, which is 2102 of 2104 frames
   of the real corpus. It is also, on the path where it *does* hold, precisely the reason the
   defense fails (§8b): a payload semantically unchanged is a payload whose length the observer
   still reads.

The corrected rows for the acceptance gate in `SIZE_CORESIDENCY_VARIANT_MATRIX.md` are given in
§8c; **that file has not been edited by this audit and still carries the two withdrawn claims.**

**Arithmetic and byte-identity check (run, not asserted).**
`variants/p6_egress_pad/verify_p6c_arithmetic.py` parses the P4 source itself and proves, for all 13
classes: the parser select maps `total_len` → the `pl_` state for `payload = total_len - 40`; the
pay-chunk subset sums to the payload; the pad-chunk subset sums to `128 - wire` and matches the pad
table; **the residual is empty**; the inner frame is reconstructed **byte-identically**; and the
output is exactly 128 B. `RESULT: PASS` (13/13). This models the parser/deparser emit order — it is
not a silicon test — but it removes the most likely source of error, a wrong decomposition.

~~Remaining risk is only the §7.2 [OPEN] receiver question, which is an empirical measurement, not
a construction problem.~~ **Withdrawn.** The receiver question was answered favourably on silicon —
and it was the wrong question. The risk that mattered was never receiver acceptance; it was whether
the observer's feature changes at all. It does not. §8b.

**Cost of the true-trailer construction** (vs P6's mid-frame placement): egress parser states
6 → 36, egress parser TCAM rows 11 → 54 (of 256), egress SRAM 8 → 10, and tagalong allocation
560 → 1840 bits (**89.8 % of the T-PHV budget**). Tagalong is the binding constraint, not stages.
The `pay*`/`pad*` bytes land entirely in tagalong (`TW*/TH*/TB*` containers) because no MAU action
touches them — which is precisely why they cost no normal PHV.

---

## 8b. SILICON: the mechanism is constructible, correct — and closes nothing

Measured by the coordinator on Tofino-1, 2026-07-25, on a real-DNP3 campaign of 30 transactions
with the trailer padding A/B-gated. The mechanism performed exactly as designed: **all 30 frames
left at 128 bytes — one single size — with IP and TCP checksums GOOD and DNP3 still decoding.**

Then the observer features:

| observer feature | padding OFF | padding ON |
|---|---|---|
| `frame.len` | 1.000 bits (2 values) | **0.000 bits (1 value)** |
| `ip.len` | 1.000 bits (2 values) | **1.000 bits (2 values)** |
| `tcp.len` | 1.000 bits (2 values) | **1.000 bits (2 values)** |

The frame-length channel closes completely. **The IP- and TCP-length channels do not move at all.**

This is not a bug and not a tuning failure. The pad sits *below* IP precisely so that
`ipv4.total_len` stays untouched — that is the whole byte-preservation correctness argument in §8's
checklist, and it is simultaneously the refutation. The property that makes the mechanism safe is
the property that makes it useless.

It is worse than a null result operationally: **Zeek, which this project already uses, reads IP and
TCP bytes and never frame bytes.** Our own analysis pipeline would report the defense as having no
effect whatsoever, because from Zeek's vantage point it has none.

### 8b.1 The general rule — protocol-transparent padding is observer-transparent padding

> **Any padding that is protocol-transparent — that is, strippable by a receiver without
> cooperation — is by construction strippable by the observer, who applies the same rule.**

A receiver strips the trailer by reading `ipv4.total_len` and trimming to it (Linux
`ip_rcv_core()` → `pskb_trim_rcsum()`, §7.2). The observer performs the identical computation and
recovers the identical original length. There is no asymmetry to exploit: the rule that makes the
pad ignorable is public, cheap, and stated in the packet itself.

The rule generalizes past the trailer and retires two of the three mechanisms in §7 for a stronger
reason than the ones originally recorded:

* **Mechanism A (Ethernet trailer)** — pad is outside the unit `total_len` delimits. Observer reads
  `total_len`. **Fails.** *(Measured above, not argued.)*
* **Mechanism B (encapsulation)** — an outer envelope with a padded outer length leaves the inner IP
  header intact *in cleartext inside the payload*. Any observer that parses one layer deeper reads
  the inner `total_len`; Wireshark and Zeek both do this automatically for VXLAN/GRE. **Fails**, and
  it fails even where the §7.3 objection (no decapsulating hop) does not apply.
* **Mechanism C (options padding)** — the original objection was a 40+40 B ceiling against required
  deltas up to 68 B. The stronger objection: padding into options **changes `data_offset`**, so the
  observer recovers `payload_len = total_len − 20 − 4·data_offset` exactly. **Fails**, at any
  ceiling.

The surviving corollary is the useful part of this negative:

> **A size defense must change the length field the observer actually reads, or make that field
> unreadable.** Only two families qualify: (i) genuinely extend the length-bearing unit — add real
> bytes inside the IP datagram, which forces `total_len` to change and drags TCP sequence-space
> translation in with it; or (ii) encrypt the length-bearing header, which requires a cooperating
> far end and is out of scope for a non-cooperative in-network defense.

Family (i) is the prepend-with-sequence-translation construction in
`research/inline_dnp3_size_normalization/research_design.md`. That is the next real experiment, and
it is a separate gated one — **not** an edit to this program.

---

## 8c. The corruption hazard — why the combined program must not be extended as-is

The defect is a **missing coupling between two keys**, and it is a bug class, not a bug.

In `p12_combined.p4`:

* the egress parser consumes the payload only for `ihl = 5 / data_offset = 5 / a listed total_len`;
  anything else falls through to `accept`, leaving TCP options and payload in the deparser residual;
* `size_norm` keys on `eg_intr_md.pkt_length` **alone**, which says nothing about whether that
  fall-through happened.

The TNA deparser emits its valid headers and *then* the residual. So on a fall-through frame that
still matches on length, the emission order is:

```
eth → ipv4 → tcp(20 B base) → [PAD] → residual(TCP options … payload)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ pad lands INSIDE the IP datagram
```

The pad is inserted between the fixed TCP header and the TCP options. `ipv4.total_len` still claims
a contiguous datagram of the original length, so: the IP datagram is no longer contiguous, the TCP
checksum scope is wrong, and the DNP3 block CRC covers relocated bytes. **Both checksums break and
the DNP3 framing is destroyed.**

§0.1 quantifies the exposure: with the +4 FCS key correction applied, **every one of the 2104
frames of the real corpus matches the table while the parser has fallen through.** The mechanism
goes from dead to frame-corrupting in one commit. This is why extending P12 to `data_offset = 8`
was stopped.

### Corrected acceptance-gate rows for `SIZE_CORESIDENCY_VARIANT_MATRIX.md`

That file is not edited by this audit and still carries the withdrawn claims. The rows should read:

| requirement | corrected verdict |
|---|---|
| live packet lengths/checksums valid | **conditional** — only on the `ihl = 5 / data_offset = 5` path. On any other path the pad lands inside the IP datagram and breaks both checksums and the DNP3 CRC. 2102 of 2104 real frames are on such a path. |
| oversize packets fail open safely | **withdrawn** — fail-open holds on the length dimension only; no key field establishes that the parser consumed the payload, so "safe default" and "corrupting match" are indistinguishable to the table. |
| original payload semantically unchanged | **withdrawn as stated** — true only on the `data_offset = 5` path, and on that path it is the reason the defense fails (§8b). |
| **defeats a passive size observer** | **NO — measured.** `ip.len` entropy unchanged at 1.000 bits with padding ON. |

---

## 8d. The safe re-keying, for anyone who revives this code

Do not fix this by enumerating more `data_offset` values — that scales the table without removing
the bug class. **Make "the table matched" imply "the parser consumed the whole payload" by
construction**, using a parser-produced class tag:

```p4
struct eg_meta_t { bit<8> pad_class; /* 0 = not consumed */ ... }

state parse_tcp {
    pkt.extract(hdr.tcp);
    transition select(hdr.ipv4.total_len) {   /* NOT (data_offset, total_len) */
        16w52 : pl_12; ... default : accept;  /* fall-through leaves pad_class = 0 */
    }
}
state pl_12 { meta.pad_class = 3; pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); transition accept; }

table size_norm {
    key = { meta.pad_class : exact; }         /* 8 bits, one field */
    const default_action = pad_none();        /* pad_class 0 -> never pads */
}
```

Why this is the right shape:

* **The bug class disappears.** The only way to get a non-zero `pad_class` is to execute a `pl_*`
  state, which is the same event as consuming the payload. A fall-through cannot produce a tag, so
  it cannot match, so it cannot be padded. No reasoning about length coincidences is required.
* **`data_offset` drops out of the key entirely.** What a `pl_*` state consumes is every byte of the
  IP datagram after the fixed 20-byte TCP base header — `total_len − 40` — an arbitrary mixture of
  TCP option bytes and payload bytes. The power-of-2 chunks are opaque to where that boundary
  falls: extracted descending, emitted descending, reconstructed byte-identically. **One class set
  therefore serves every `data_offset` with no new state, no new header and no new tagalong byte.**
* **It is strictly cheaper** than a 16-bit length key: one 8-bit exact field instead of two bytes of
  match crossbar plus a validity bit.
* **`eg_intr_md.pkt_length` is not read at all**, so the FCS-convention trap (§8e) cannot recur.

Two implementation gotchas that will otherwise cost a compile cycle:

1. **Parser metadata is write-once per path** on TNA — there is no clear-on-write. Assign
   `pad_class` in each `pl_*` state and **nowhere else**; do not also initialize it in `start`, or
   the compiler rejects it as a hard error. The fall-through default comes from the compiler's own
   `init_zero`, which is verifiable in the `.bfa`.
2. **A `pl_` state that consumes zero bytes is folded into `accept`** by bf-p4c. If a zero-length
   class is ever needed (`total_len = 40`, a `data_offset = 5` pure ACK), its safety must be argued
   arithmetically — at `total_len = 40` the datagram ends with the TCP base header, so there is
   nothing past it to consume — not from the existence of the state.

**Measured, so the cost is not speculative.** `variants/p13_size_do8/` implements the equivalent
coupling using `(hdr.tcp.isValid(), hdr.ipv4.total_len)` as the key — the same invariant reached
with existing fields instead of a new metadata byte — and compiles at **8/12 ingress and 2/12 egress
stages, ingress assembly bit-identical to P12, tagalong 16-bit containers 83.3 % → 81.2 % and bits
used 78.5 % → 78.1 %.** Coverage goes from 0 to 2104/2104 corpus frames. The `pad_class` form above
is cheaper still. **Neither is worth deploying**, because §8b says the output does not move the
observer's feature — they are recorded so that the next person does not rediscover the bug class
while building something that *is* worth deploying.

---

## 8e. Secondary finding: `eg_intr_md.pkt_length` counts the FCS

Measured on silicon 2026-07-25 by injecting nine crafted probe frames one at a time and reading
`ctr_size_normalized` after each. Exactly one normalized (`total_len = 48`), which uniquely
identifies the convention among the candidates:

> **`eg_intr_md.pkt_length` = wire length + 4. It includes the 4-byte FCS.**

The SDE header documents the field only as `bit<16> pkt_length; // Packet length, in bytes`
(`tofino1_base.p4:280`) and fixes no offset convention. Every P6c/P12 entry was therefore short by
exactly 4 and missed — which is why the size axis was silently inert on silicon before any of the
above was discovered.

Two caveats worth carrying, both of which will bite someone otherwise:

* **The durable form of the rule is `pkt_length = wire + 4`, not `total_len + 18`.** The two agree
  only while `wire == 14 + total_len`. For a frame the sending MAC padded up to the 60 B Ethernet
  minimum, the field must track the padded bytes and the `+18` shorthand is wrong.
* **The 4 FCS bytes are *not* in the deparser residual** — the +4 is an accounting convention only.
  Evidence: under P12 a 108 B response took `pl_54` (payload fully consumed, residual should be
  empty) and was forwarded at exactly 108 B. Had 4 FCS bytes been in the residual it would have left
  at 112. So emitting `P` pad bytes yields `wire_out = wire_in + P`, with no FCS correction.

A falsifiable cross-check that also validates the whole length model: the one frame that *did*
normalize under P12 (`total_len = 48`, wire 62) matched the entry meant for a 66 B wire frame, so it
should have left at **124 B, not 128**. Confirming that from the existing capture closes the model
end to end.

---

## 9. Resource table — all variants, one compiler run

All rows produced by the same `bf-p4c 9.13.1` invocation pattern on the same machine, including a
**recompiled P0** so no column is quoted from an older report.

| Metric | **P0** baseline | AUDIT as-is | AUDIT telem-OFF | **P4** size only | **P5** parser padcode | **P6** egress pad | **P6c** true trailer |
|---|---|---|---|---|---|---|---|
| **Ingress stages** | **12** | 3 | 2 | 2 | **12** | **12** | **12** |
| **Egress stages** | **0** | 0 | 0 | 0 | **0** | **2** | **2** |
| Critical path | 12 | 3 | 2 | 2 | 12 | 12 | 12 |
| Logical tables | 44 | 15 | 11 | 7 | 44 | 47 | 47 |
| SRAM | 36 | 13 | 7 | 7 | 36 | 44 | 46 |
| Map RAM | 36 | 12 | 6 | 6 | 36 | 40 | 40 |
| TCAM | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| SALU (Meter ALU) | 7 | 2 | 0 | 0 | 7 | 7 | 7 |
| Stats ALU | 11 | 4 | 3 | 3 | 11 | 13 | 13 |
| Gateways | 25 | 6 | 5 | 2 | 25 | 26 | 26 |
| VLIW instr | 28 | 21 | 17 | 15 | 28 | 38 | 38 |
| Hash bits | 16 | 10 | 10 | 10 | 16 | 56 | 56 |
| Xbar bytes | 65 | 8 | 7 | 3 | 65 | 68 | 69 |
| Ingress parser states | 2 | 4 | 4 | 2 | 3 | 2 | 2 |
| Ingress parser TCAM rows | 4 | 5 | 5 | 4 | 7 | 4 | 4 |
| Egress parser states | 6 | 6 | 6 | 6 | 6 | 6 | **36** |
| Egress parser TCAM rows | 11 | 10 | 10 | 10 | 11 | 11 | **54** |
| PHV containers | 29 | 33 | 13 | 9 | 29 | 32 | 31 |
| PHV bits (total) | 368 | 440 | 117 | 68 | 370 | 407 | 415 |
| **PHV bits ingress** | **354** | 427 | 104 | 55 | **355** | **354** | **354** |
| PHV bits egress | 14 | 13 | 13 | 13 | 15 | 53 | 61 |
| Tagalong bits allocated | 560 | 520 | 576 | 512 | 608 | 560 | **1840 (89.8 %)** |
| **Errors** | **0** | 0 | 0 | 0 | **0** | **0** | **0** |
| Warnings | 2 | 2 | 2 | 2 | 2 | 3 | 3 |

### Per-gress MAU split — the decisive evidence

Derived by joining `resources.json` unit ownership with the `direction` field of each table in
`context.json`:

| | ingress stages | ingress SRAM | ingress map RAM | ingress SALU | ingress Stats ALU | ingress gateways | ingress logical | egress stages | egress SRAM | egress logical |
|---|---|---|---|---|---|---|---|---|---|---|
| **P0** | 12 | 36 | 36 | 7 | 11 | 25 | 44 | 0 | 0 | 0 |
| **P5** | 12 | 36 | 36 | 7 | 11 | 25 | 44 | 0 | 0 | 0 |
| **P6** | 12 | 36 | 36 | 7 | 11 | 25 | 44 | 2 | 8 | 3 |
| **P6c** | 12 | 36 | 36 | 7 | 11 | 25 | 44 | 2 | 10 | 3 |

**The ingress rows are identical across all four programs.** Ingress PHV bits are also identical
(354). P5 and P6 both place 85 ingress tables at max stage 11, exactly as P0 does. Egress-only size
integration costs **zero ingress stages, zero ingress SRAM, zero ingress SALU, zero ingress PHV**.

### Source SHA-256

| Variant | SHA-256 |
|---|---|
| P0 `ibspg_hold_response.p4` | `fa073cf691a6beb45fa8ffa61146cf481fc81e42f6cf4640bcb44ae6fe08f947` |
| AUDIT as-is `queue_microbench_trace_v1.p4` | `3e3750650a6e36bd6902db189bd03ae369c06c885991a4645a270c1e5bc798ea` |
| AUDIT telem-OFF `trace_v1_telemoff.p4` | `828bbe6a1a77f01dfc9bf91f87c67ff58b7cf02a7e242f2e7e846f506863edba` |
| P4 `p4_size_only.p4` | `f1b09334c3db042ddba2e890fb74fd1e01c8dfd68b718293da1fb3c90930a31e` |
| P5 `p5_parser_padcode.p4` | `a7484e0daf0cd62cac11b26de928b75377da75418cfce98d4f45ef308ac5b33a` |
| P6 `p6_egress_pad.p4` | `f6d269b1e4896bca0fbd5b370b09e7b52ccf9be1940199a9d2f9268fe8f28674` |
| P6c `p6c_true_trailer.p4` | `4c7768609f1807d958a10d312514c6b9378c859d45fe20fcfae3a88eb84db162` |

---

## 10. Reading of the numbers

1. **P4 (size primitive alone, this codebase, no telemetry): 2 ingress stages.** Consistent with the
   telemetry-OFF ablation of the validated program. Simplifying the frame format (no 19-byte replay
   header to strip, no ethertype restore) buys 4 logical tables, 3 gateways and 49 PHV bits.

2. **P5 shows the decision is free.** Producing `normalize_size` / target code / oversize flag in the
   *parser* and carrying them in a bridge header costs **0 ingress stages, 0 ingress SRAM, 0 ingress
   SALU**, and moves the critical path not at all (12 → 12). The entire cost is
   +1 ingress parser state, +3 parser TCAM rows, +1 PHV bit. This confirms the Part-13 lever
   generalizes: parser-side classification is essentially free on a stage-saturated pipeline.
   (It did *not* shorten the path here, because unlike the Part-13 case no stage-0-produced metadata
   field was pinning a downstream table — P0's critical path is the serial
   `reg_gen → reg_active → reg_deadline` state chain, which the pad code does not touch.)

3. **P6 shows the padding is free of ingress too.** Ingress bit-identical to P0; the whole primitive
   lands in 2 of the 12 idle egress stages. **Size and timing are co-resident with zero ingress
   cost.** The earlier "10/12 + 5-6 > 12 ⇒ timing and size cannot co-reside" conclusion was reasoning
   about ingress-side padding; it does not apply once padding moves to egress.

4. **P6c shows the protocol-valid form is also affordable in stages**, and relocates the binding
   constraint to **tagalong (89.8 %)** and egress parser TCAM (54/256 rows). Neither is exhausted.
   *(Superseded in part: P13 shows the tagalong figure was driven by the `pay*`/`pad*` header
   definitions, not by the class count. Removing `data_offset` from the select key covers every
   `data_offset` with no new classes and moves tagalong 83.3 % → 81.2 % on its tightest dimension.
   The class ceiling is 32 contiguous classes and the wall there is **action instruction memory**,
   not tagalong.)*

5. ~~**Egress upgrades the key from declared to measured.**~~ **Withdrawn — this was the trap.**
   `eg_intr_md.pkt_length` is not the frame's wire length: it counts the FCS (§8e), which no SDE
   header states. Keying on it silently disabled the whole mechanism on silicon. The measured value
   was also never needed: the wire length is a deterministic function of the declared
   `total_len`, so the *declared* field was the better key all along — and a parser-produced class
   tag (§8d) is better than either, because it encodes parser state rather than a length coincidence.

6. **The headline result of this document is none of the above.** Every resource number here is
   correct and every one of them is beside the point: the mechanism they cost so little to build
   does not move the observer's feature (§8b). Resource affordability was measured to four
   significant figures for a primitive whose effect size is zero.

---

## 11. What is NOT claimed

* **This is not a claim that size normalization is impossible.** It is a claim that
  *protocol-transparent* size normalization is self-defeating (§8b.1), which rules out padding
  below IP, encapsulation, and options padding — not padding that genuinely extends the
  length-bearing unit.
* **The negative is measured for the observer features listed in §8b** (`frame.len`, `ip.len`,
  `tcp.len`) on a 30-transaction campaign. It is not a claim about every conceivable feature; it is
  a claim about the ones an off-the-shelf analyzer reads, which is the threat model that matters
  here and the one our own Zeek pipeline uses.
* The compile-side content (§6, §9) was produced locally with `bf-p4c 9.13.1` and **not** on
  silicon. The silicon results (§8b, §8c exposure arithmetic, §8e) were produced by the coordinator
  and are attributed inline.
* P6c/P13 byte identity on the `pl_*` path is proved against a **model** of the parser/deparser emit
  order plus the compiler's own deparser field dictionary — and, for P13, against the compiled
  `context.json` rather than the P4 text. Silicon corroborated it: checksums good, DNP3 decoding.
* Scope held: **one** fixed target state (128 B on the wire, FCS excluded). No runtime size-pattern
  table, no third queue, no cover traffic, no splitting, no operation-specific target.
* **The timing half is unaffected** and remains validated on silicon: 25.001 ms with sd 0.0068 ms,
  1920 blocker tokens all deadline-terminated, `ctr_bypass[1] = 0`. Nothing in this negative touches
  it. In P13 the ingress assembly is bit-identical to P12's, so that is true by construction rather
  than by re-argument.

---

## 12. What this changes about the next experiments

**Dropped.** These were queued against a mechanism that is now refuted; doing them would refine the
cost of something with no effect:

1. ~~Tagalong headroom study as a function of class count~~ — partially answered as a side effect
   (§10.4), and no longer decision-relevant.
2. ~~Reduce the parser class count via range-match or coarser chunking~~ — an optimization of a
   dead path.
3. ~~Receiver-tolerance measurement on the physical SEL-751~~ — the §7.2 [OPEN] no longer gates
   anything. Trailer acceptance was confirmed on silicon and does not help.

**Live.**

1. **Prepend-with-sequence-translation** — the only surviving family (§8b.1, family (i)): add real
   bytes *inside* the IP datagram so `total_len` genuinely changes, which forces per-flow TCP
   sequence-space translation (`seq += Δ`, `ack −= Δ`) and a guarded checksum update. Gated
   experiment against `research/inline_dnp3_size_normalization/research_design.md`. **Not an edit to
   this program.**
2. **Confirm the 124 B cross-check** (§8e) from the existing capture. Zero cost, closes the length
   model end to end.
3. **Propagate the two withdrawn claims** into `SIZE_CORESIDENCY_VARIANT_MATRIX.md` (corrected rows
   in §8c) and into any paper draft derived from it. The matrix currently still asserts both.
4. **Carry §8b.1 into the paper as a result, not a caveat.** "Protocol-transparent padding is
   observer-transparent padding" is a general negative with a clean mechanism and a measured
   demonstration, and it explains the absence of prior in-network size normalization for cleartext
   ICS traffic better than a resource argument does.
