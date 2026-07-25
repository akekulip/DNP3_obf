# P6 — timing + egress/deparser padding  (THE CANDIDATE)

Two programs live here:

* `p6_egress_pad.p4` — the stage-cost experiment.
* `p6c_true_trailer.p4` — the protocol-validity experiment (mechanism A, actually constructed).

Both keep the ingress parser, ingress control and ingress deparser **byte-for-byte identical to P0**
(`research/ibspg_hold_response/p4/ibspg_hold_response/ibspg_hold_response.p4`). Not one table,
action, register, counter or metadata field is added to ingress.

---

## Why egress is the right home

Two facts from the SDE headers, pointing the same way:

* `ingress_intrinsic_metadata_t` (`tofino1_base.p4:108-121`) has `resubmit_flag`, `packet_version`,
  `ingress_port`, `ingress_mac_tstamp` — **no packet-length field**.
* `egress_intrinsic_metadata_t` (`tofino1_base.p4:281`) has **`bit<16> pkt_length`**.

Egress can therefore size a frame with no help from ingress: no bridge header, no exported flag, no
shared metadata. The ingress export the brief anticipated is **unnecessary**. It also upgrades the
key from the Level-1 *declared* label to a *measured* length, for free.

Second half of the asymmetry: P0 is 12/12 ingress and **0/12 egress**, and `to_host()` sets
`bypass_egress = 0`, so exactly the two frames we want normalized — the immediately-forwarded ACK and
the released RESPONSE — traverse egress. The queued loopback paths set `bypass_egress = 1` and never
reach it, so the hold mechanism cannot be perturbed.

---

## Build

```bash
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out      p6_egress_pad.p4      # log: compile.log
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out_p6c  p6c_true_trailer.p4   # log: compile_p6c.log
```

Both **0 errors**. P6 = 3 warnings, P6c = 3 warnings (benign parser-unroll notices plus an
`uninitialized_out_param` notice on the egress metadata struct, which the MAU table writes on every
path).

| | SHA-256 |
|---|---|
| `p6_egress_pad.p4` | `f6d269b1e4896bca0fbd5b370b09e7b52ccf9be1940199a9d2f9268fe8f28674` |
| `p6c_true_trailer.p4` | `4c7768609f1807d958a10d312514c6b9378c859d45fe20fcfae3a88eb84db162` |

---

## Result — the headline

| | P0 | **P6** | **P6c** |
|---|---|---|---|
| **Ingress stages** | 12 | **12** | **12** |
| **Egress stages** | 0 | **2** | **2** |
| Critical path | 12 | **12** | **12** |
| Ingress SRAM / map RAM / TCAM | 36 / 36 / 0 | **36 / 36 / 0** | **36 / 36 / 0** |
| Ingress SALU / Stats ALU / gateways | 7 / 11 / 25 | **7 / 11 / 25** | **7 / 11 / 25** |
| Ingress logical tables | 44 | **44** | **44** |
| **PHV bits ingress** | 354 | **354** | **354** |
| Egress SRAM / map RAM / logical | 0 / 0 / 0 | 8 / 4 / 3 | 10 / 4 / 3 |
| Egress parser states / TCAM rows | 6 / 11 | 6 / 11 | **36 / 54** |
| Tagalong bits allocated | 560 | 560 | **1840 (89.8 %)** |

**The ingress MAU footprint is bit-identical to P0 in every column.** Egress-only size integration
costs **zero ingress stages, zero ingress SRAM, zero ingress SALU, zero ingress PHV**. Size and
timing are co-resident.

---

## `p6_egress_pad.p4` — stage cost, with a known protocol caveat

One egress table exact-matching `eg_intr_md.pkt_length` over the 13 base-corpus sizes, selecting the
compile-time power-of-2 pad subset that brings the frame to one fixed 128 B state. Fail open (no
pads) on any other length, oversize included — never truncate.

**Caveat, stated plainly:** the pads are emitted after the last *parsed* header and before the
unparsed residual, because a TNA deparser cannot emit a header after the residual. For the synthetic
IBSPG frame that is a trailer. **For a live IPv4/TCP/DNP3 frame whose payload is the residual it is
not a trailer and not protocol-valid** — it would displace the IP header. P6 measures the stage-cost
question only.

## `p6c_true_trailer.p4` — mechanism A, actually constructed

Makes the residual **empty** so the pads emitted last really are last. The egress parser consumes
the whole TCP payload into a *shared* power-of-2 chunk set (`pay1_h`…`pay64_h`, 127 B of definitions
total, not 13 × 66 B), selected by an exact match on `(tcp.data_offset, ipv4.total_len)` placed **in
the tcp-extract state** — a select on `total_len` in a state placed *after* the TCP extract is a
known bf-p4c 9.13.x failure mode on this toolchain. Extraction and emission orders are both
descending, so every subset reconstructs the payload byte-identically. Anything that is not
`ihl=5 / data_offset=5 / a known total_len` falls through to `accept` with the payload still in the
residual and no pad valid → forwarded unchanged.

**Verified from the compiler's own egress deparser field dictionary** (`out_p6c/pipe/*.bfa`):

```
eth → ipv4 → tcp → pay64 → pay32 → pay16 → pay8 → pay4 → pay2 → pay1
    → pad64 → pad32 → pad16 → pad8 → pad4 → pad2 → pad1
```

Pads land **after the complete IP datagram**. Rejection checklist: DNP3 bytes untouched (no MAU
action reads or writes them), DNP3 CRC intact, TCP sequence space unchanged, IP `total_length` never
written and still exactly delimiting `ip+tcp+payload`, TCP checksum still valid, no endpoint
modification. The Tofino MAC recomputes the FCS, so the frame is well-formed Ethernet.

**Binding constraint is tagalong, not stages.** The `pay*`/`pad*` bytes go entirely to tagalong
(`TW*/TH*/TB*` containers) because no MAU action touches them — which is why they cost no normal
PHV — but that puts T-PHV at **89.8 %**. Check headroom before adding length classes or a 256 B
target.

**Remaining risk is empirical, not structural.** No RFC *requires* a receiver to accept trailer
octets. RFC 894 §2 and RFC 1042 §3.2 establish they are not part of the IP packet; Linux
`ip_rcv_core()` trims to `ntohs(iph->tot_len)` via `pskb_trim_rcsum()` and accepts the packet. The
physical SEL-751's stack is **[OPEN]**. See `SIZE_PRIMITIVE_REUSE_AUDIT.md` §7.2.

**Arithmetic + byte-identity check (run).** `verify_p6c_arithmetic.py` parses the P4 source and
proves for all 13 classes that the parser select maps `total_len` → the right `pl_` state, the
pay-chunk subset sums to the payload, the pad-chunk subset sums to `128 - wire`, the residual is
empty, the inner frame is byte-identical, and the output is exactly 128 B. `RESULT: PASS` (13/13).

**Not claimed:** nothing here was loaded or run on silicon. The byte-identity result is against a
*model* of the parser/deparser emit order, not a capture. A wire pcap is the next gate.
