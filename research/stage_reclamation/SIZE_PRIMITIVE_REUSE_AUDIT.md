# SIZE_PRIMITIVE_REUSE_AUDIT.md

Audit of the hardware-validated Level-1 size-normalization primitive, and whether one fixed
size state can be made co-resident with the Part 12/13 timing mechanism **without costing an
ingress MAU stage**.

Compile-only study. No switch contact, no `ssh`, no load. All numbers below come from a
**local `bf-p4c 9.13.1` run performed for this audit**, not from quoted notes:

```
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out <file>.p4
```

Extractor: `research/stage_reclamation/size_audit/extract_resources.py`
(reads `out/pipe/logs/{table_summary.log,resources.json,parser.characterize.log,phv_allocation_summary_0.log}`).

---

## 0. Verdict up front

| Question | Answer |
|---|---|
| Does egress-only size normalization cost an ingress MAU stage? | **No. Zero.** The ingress MAU footprint of P6 and P6c is *bit-identical* to P0. |
| Does merely *deciding* to normalize cost an ingress stage? | **No**, when the decision is produced in the ingress parser (P5). |
| Is the validated Level-1 primitive reusable on live traffic as-is? | **No.** It never carried IP, TCP or DNP3 bytes at all. §4. |
| Which padding mechanism could be *proved*? | **Mechanism A (Ethernet trailer)** — proved *constructible on Tofino-1* (§8), and standards-grounded but **not standards-guaranteed** at the receiver (§7, [OPEN]). |

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

**Honest limit — [OPEN].** *No RFC requires a receiver to accept and ignore trailer octets.*
RFC 894/1042 establish that the octets are **not part of the IP packet**; RFC 1122's robustness
principle is aspirational, not normative, on this point. Linux/BSD/Windows tolerate them in
practice. **A specific IED stack — notably the physical SEL-751 — is unverified and must be measured
before any deployment claim.** Do not upgrade this to "protocol-valid" on the basis that the wire
length changed.

*Tofino obstacle:* a TNA deparser emits its headers and then the unparsed residual; **there is no
way to emit a header after the residual.** If the TCP payload is the residual, a pad header lands
*inside* the IP datagram — the §5.4 failure. This is what §8 solves.

### 7.3 Mechanism B — outer envelope (encapsulation) — **REJECTED for this topology**

A valid outer IP/UDP or VXLAN envelope with a correct outer `total_length` covering the pad, and the
inner frame untouched, is protocol-correct **only if something removes it**. The padding must exist
*on the observed link* to defeat the passive observer; therefore it must survive to the far end and
be stripped there. In the inline single-switch topology (host — Tofino — outstation) there is no
second decapsulating hop, and the physical SEL-751 will not decapsulate. Removal would require
**endpoint modification**, which is an explicit rejection criterion. Mechanism B is viable only
with a second cooperating switch/NIC at the far edge; that is a different deployment model and is
out of scope here.

### 7.4 Mechanism C — options-based padding — **partial, rejected at this target size**

Pad inside IPv4 options and/or TCP NOP options, adjusting `ihl`/`data_offset` and `total_length`,
recomputing both checksums with the `Checksum()` extern (proven on-chip in `p4_decoy`). This
preserves TCP sequence space (options are not payload) and never touches DNP3 bytes or its CRC — it
is genuinely protocol-valid. **But the ceiling is 40 B of IPv4 options + 40 B of TCP options, and
the required deltas run to 68 B**; reaching them needs *both* option spaces, doubling the modified
surface and the checksum work. IPv4 options are also widely slow-pathed or dropped by real devices.
Not worth it when mechanism A reaches any delta for free.

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

The pad chunks are emitted **after the complete IP datagram**. 0 errors. Rejection checklist:

| Criterion | P6c |
|---|---|
| Modifies DNP3 application bytes | **No** — extracted and re-emitted in order; no MAU action reads or writes them |
| Breaks the DNP3 CRC | **No** — the CRC rides inside those untouched bytes |
| Changes TCP sequence space | **No** — no payload byte added or removed |
| Leaves IP total_length inconsistent | **No** — never written, and still exactly delimits `ip+tcp+payload` |
| Leaves the TCP checksum invalid | **No** — pseudo-header, TCP header and payload all unchanged |
| Requires endpoint modification | **No** — the trailer is below IP |

**Arithmetic and byte-identity check (run, not asserted).**
`variants/p6_egress_pad/verify_p6c_arithmetic.py` parses the P4 source itself and proves, for all 13
classes: the parser select maps `total_len` → the `pl_` state for `payload = total_len - 40`; the
pay-chunk subset sums to the payload; the pad-chunk subset sums to `128 - wire` and matches the pad
table; **the residual is empty**; the inner frame is reconstructed **byte-identically**; and the
output is exactly 128 B. `RESULT: PASS` (13/13). This models the parser/deparser emit order — it is
not a silicon test — but it removes the most likely source of error, a wrong decomposition.

Remaining risk is **only** the §7.2 [OPEN] receiver question, which is an empirical measurement, not
a construction problem.

**Cost of the true-trailer construction** (vs P6's mid-frame placement): egress parser states
6 → 36, egress parser TCAM rows 11 → 54 (of 256), egress SRAM 8 → 10, and tagalong allocation
560 → 1840 bits (**89.8 % of the T-PHV budget**). Tagalong is the binding constraint, not stages.
The `pay*`/`pad*` bytes land entirely in tagalong (`TW*/TH*/TB*` containers) because no MAU action
touches them — which is precisely why they cost no normal PHV.

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
   constraint to **tagalong (89.8 %)** and egress parser TCAM (54/256 rows). Neither is exhausted,
   but tagalong is close enough that a larger corpus (more length classes, or a 256 B target) needs
   a headroom check before anything is built.

5. **Egress upgrades the key from declared to measured.** `eg_intr_md.pkt_length` is the frame's
   actual length; the Level-1 primitive trusted a label in a cleartext header. This removes the
   Level-1 caveat for free, which was not an anticipated benefit.

---

## 11. What is NOT claimed

* Nothing here was loaded or run on silicon. This is a compile-fit and construction study.
* P6c's byte identity is proved against a **model** of the parser/deparser emit order (§8), not
  against a pcap from silicon. What is established on the compiler side is that the pad is emitted
  after the complete IP datagram and that no MAU action touches the payload or any length/checksum
  field. A wire capture remains the natural next gate.
* Receiver acceptance of trailer octets by the physical SEL-751 is **[OPEN]** (§7.2). No RFC
  mandates it.
* Scope held: **one** fixed target state (128 B). No runtime size-pattern table, no third queue, no
  cover traffic, no splitting, no operation-specific target.

---

## 12. Proposed next experiments

1. ~~Byte-identity model for P6c~~ — **done this session**,
   `variants/p6_egress_pad/verify_p6c_arithmetic.py`, PASS 13/13 (§8). The remaining step is a real
   capture, which needs the switch.
2. **Tagalong headroom study.** P6c sits at 89.8 %. Measure the tagalong cost as a function of the
   number of length classes and the target size, and find the class count at which T-PHV allocation
   fails. This bounds the corpus the design can serve.
3. **Reduce the parser class count.** 13 exact `(data_offset, total_len)` classes cost 30 extra
   egress parser states. A range-match or a coarser chunking (e.g. round the payload to a multiple
   of 4 and pad the remainder) would cut states and tagalong at the cost of a few wasted bytes.
4. **Receiver-tolerance measurement.** Send trailer-padded frames to the SEL-751 and to a Linux host
   and count accepted DNP3 transactions. This is the only way to close the §7.2 [OPEN], and it needs
   no P4 change — a host-side scapy sender is enough.
