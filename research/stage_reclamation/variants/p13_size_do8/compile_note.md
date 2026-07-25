# P13 — the size axis made live on real traffic

> ## ⚠ SUPERSEDED — DO NOT DEPLOY. Kept as evidence, not as a candidate.
>
> On 2026-07-25 the trailer mechanism this program implements was run on Tofino-1 silicon and
> **refuted as a defense**. It works exactly as designed — 30/30 frames at one fixed 128 B size,
> checksums good, DNP3 decoding — and it closes nothing: frame-length entropy goes 1.000 → 0.000
> bits while **`ip.len` entropy stays at 1.000 bits**. The pad sits below IP so `ipv4.total_len` is
> untouched *by design*, and the observer simply reads `ip.len`. Zeek, which this project uses,
> reads IP and TCP bytes and never frame bytes, so it would report no effect at all.
>
> The general rule, which is the actual contribution: **any padding a receiver can strip without
> cooperation, an observer can strip by the same rule.** See
> `../../SIZE_PRIMITIVE_REUSE_AUDIT.md` §8b — that document is now the authority; this note is
> the construction record behind its §8c/§8d.
>
> **What is still worth reading here:** §"MUST-NOT-BREAK properties" and the two-key coupling,
> because P13 is the variant that *closes* the frame-corruption hazard P12 carries (audit §8c).
> P12 keys `size_norm` on length alone while its parser requires `data_offset = 5`, and nothing
> couples them — with the +4 FCS correction applied, **100 % of the real corpus would be padded
> mid-datagram**. P13 removes that by construction. The audit's §8d records a cheaper form of the
> same fix (a parser-produced `pad_class`) for whoever revives this code.
>
> **Do not write more P4 against this mechanism.** The next real construction is
> prepend-with-sequence-translation, a separate gated experiment against
> `research/inline_dnp3_size_normalization/research_design.md`.

**As a compile result it fits, and it costs essentially nothing. 8 of 12 ingress stages, 2 of 12
egress stages, 0 errors — and the ingress assembly is bit-identical to P12's. Tagalong went *down*,
not up: 16-bit containers 83.3 % → 81.2 %, bits used 78.5 % → 78.1 %, still 7 of 8 collections.**

P12's size normalizer was inert on real traffic for **two** independent reasons. Both are fixed
here, and the fix for each turned out to be a **deletion from a key**, not an addition:

| # | why nothing normalized | fix |
|---|---|---|
| 1 | the egress parser select was keyed on `(tcp.data_offset, ipv4.total_len)` and every entry said `data_offset = 5`. The measured corpus is `data_offset = 8` on 2102 of 2104 frames and 10 on the other 2. **Zero frames carry 20-byte TCP headers.** | drop `data_offset` from the select key |
| 2 | `size_norm` was keyed on `eg_intr_md.pkt_length`, whose convention on this target is **wire length + 4 (it counts the FCS)** — measured on silicon 2026-07-25. Every entry was short by exactly 4 and missed, *including* replay frames deliberately built at `data_offset = 5` so that reason 1 would not apply. | drop `pkt_length` from the key entirely |

Coverage after both: **all 2104 packets of the measured corpus, plus all three
`data_offset = 5` replay frame types, normalize to one fixed 128-byte wire frame.**
Previously: zero.

---

## Build

```bash
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out p13_size_do8.p4            # log: compile.log
```

Local bf-p4c **9.13.1**, exit status **0**, **0 errors, 4 warnings** — the same four benign
families P12 produced (two `uninitialized_out_param` notices on the parser `meta` structs, two
`min_parse_depth_accept_loop will be unrolled` notices). Compile-only; nothing was loaded and no
hardware claim is made below except where it is explicitly attributed to the coordinator's
silicon run.

| | SHA-256 |
|---|---|
| `p13_size_do8.p4` | `94e0c738d1c3154d9975a23ea7189eab7358829a739928f5dac226da47379579` |
| `p12_combined.p4` (the input it was derived from) | `c43409c82e932b6be19ddbee03a90f80ae9a564ee3870c38490c30bb1598112b` |

An optional diagnostic build exists behind a compile flag and is **not** part of the deliverable
— the root cause it was written to chase has since been settled on silicon. It costs nothing when
off. Build it only if a future egress surprise needs a length histogram:

```bash
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -DSIZE_LEN_PROBE -o out_probe p13_size_do8.p4
```

---

## TARGET SIZE: 128 bytes ON THE WIRE, FCS excluded

Stated explicitly because the two conventions differ by 4 and a reader would otherwise have to
guess. **128 B is what a capture reports and what an observer measures.** The same frame reads as
`eg_intr_md.pkt_length` = 132.

Why 128 is the right target, verified rather than assumed: the largest frame in the measured
corpus is **120 B** (a `total_len = 106` DNP3 response), and the largest in the replay corpus is
**108 B**. 128 clears both, is the value the earlier validated Level-1 silicon run produced, and
leaves the class set covering every `total_len` up to **114** (wire 128, pad 0).

**The FCS is not in the deparser residual, so no FCS correction appears anywhere in the
arithmetic.** That is not an assumption — it follows from the coordinator's own capture: under
P12 a 108 B response took `pl_54`, which consumes the payload and should leave the residual
empty, and it was forwarded at exactly 108 B. Had 4 FCS bytes been sitting in the residual it
would have left at 112. So emitting `P` pad bytes yields `wire_out = wire_in + P`, full stop.

---

## The mechanism, and why it is `data_offset`-independent

The `pl_*` states do not consume "the TCP payload". They consume **every byte of the IP datagram
after the fixed 20-byte TCP base header** — `total_len - 40` bytes — which is an arbitrary mixture
of TCP option bytes and payload bytes. That count is a function of `total_len` **only**.

The power-of-2 chunks are opaque to where the option/payload boundary falls inside them: they are
extracted descending and emitted descending, so any mixture is reconstructed byte-identically.
**One class set therefore serves every `data_offset`, with no new parser state, no new header, no
new pad action and no new tagalong byte.** This is why the tagalong blow-up the brief anticipated
did not happen — the thing that consumes tagalong is the `pay*`/`pad*` header *definitions*, which
are unchanged, not the number of classes that reference them.

The pad amount likewise needs no measured length, because the wire length is a deterministic
function of the declared IP length:

```
wire = max(60, 14 + total_len)          # 60 = the Ethernet minimum frame
pad  = 128 - wire
```

That is exact for this traffic, and it is measured, not assumed: over **all 2104 packets** of
`Traffic Trace/SEL751.pcap`, `frame.len - ip.len == 14` for **every** packet — no Ethernet
trailer anywhere, and no frame below 60 B.

```bash
tshark -r SEL751.pcap -T fields -e frame.len -e ip.len \
  | awk '{c[$1-$2]++} END {for (k in c) print "frame.len - ip.len =", k, "->", c[k], "packets"}'
# frame.len - ip.len = 14 -> 2104 packets
```

### The key, and what each field is load-bearing for

```p4
key = { hdr.tcp.isValid()  : exact;
        hdr.ipv4.total_len : exact; }
```

- **`tcp.isValid()`** proves the egress parser *reached* `parse_tcp`, i.e. the frame is IPv4 /
  `ihl = 5` / TCP. Without it an `ihl != 5` frame would carry a matching `total_len` while its
  options, TCP header and payload sat in the deparser residual — and the pads would be emitted
  **before** that residual, splitting the IP datagram in two. **P6c and P12 both had this hole**
  (their `pkt_length`-only key could not tell the two cases apart); it is closed here.
- **`total_len`** proves the parser *consumed* the datagram past the TCP base header. The 14
  values in the table are a subset of the values the egress parser selects on, so tcp-valid plus a
  listed `total_len` together imply the frame took its `pl_*` state and the residual is empty.

Anything else — unknown length, `ihl != 5`, non-TCP, non-IPv4, or **oversize** (`total_len > 114`)
— has no entry, takes the `const default_action = pad_none()`, and is forwarded byte-for-byte
unchanged. Never truncated.

---

## Coverage: which `data_offset` values and which frame lengths

**`data_offset` is not tested anywhere in the egress path, so every value 5–15 is covered
identically.** What is enumerated is `total_len`, in 14 classes:

| `total_len` | wire | pad | out | present in |
|---|---|---|---|---|
| 40 | 60 \* | 68 | 128 | replay pure ACK, `do=5` |
| 46 | 60 | 68 | 128 | — |
| 48 | 62 | 66 | 128 | — |
| **52** | **66** | **62** | **128** | **corpus pure ACK, `do=8` — 906 pkts** |
| **60** | **74** | **54** | **128** | **corpus SYN/SYN-ACK, `do=10` — 2 pkts** |
| 62 | 76 | 52 | 128 | replay READ request, `do=5` |
| **74** | **88** | **40** | **128** | **corpus READ request, `do=8` — 198 pkts** |
| 75 | 89 | 39 | 128 | — |
| 77 | 91 | 37 | 128 | — |
| **87** | **101** | **27** | **128** | **corpus response, `do=8` — 400 pkts** |
| **89** | **103** | **25** | **128** | **corpus response, `do=8` — 400 pkts** |
| 94 | 108 | 20 | 128 | replay response, `do=5` |
| 101 | 115 | 13 | 128 | — |
| **106** | **120** | **8** | **128** | **corpus response, `do=8` — 198 pkts** |

\* `total_len = 40` is the one class whose wire length comes from the `max(60, …)` arm: it is 54 B
before the sending MAC pads it to the 60 B Ethernet minimum. Its **safety** does not depend on
that padding (at `total_len = 40` the IP datagram ends with the TCP base header, so there is
nothing past it to consume and the residual is by definition outside the datagram); only its
**output size** does. The coordinator's capture shows these ACKs arriving at 60 B, so the padding
is present in practice.

**Corpus coverage: 2104 / 2104 packets (100 %).** Six of the fourteen classes carry the whole
measured corpus; three carry the whole replay corpus.

### Pure TCP ACKs — the one-fixed-size claim holds

The coordinator flagged that ACKs leaving at 60 B while data leaves at 128 B would let an observer
trivially separate them. **Both ACK forms are now covered and leave at 128 B:** the real corpus
ACK is `total_len = 52` (it carries TCP timestamps, so it is a 66 B frame, not a 60 B one) and the
`data_offset = 5` replay ACK is `total_len = 40`, added in this variant. No narrowing of the claim
is needed.

---

## Measured result, against P12

| | **P12** | **P13 (ship)** | of budget | Δ |
|---|---|---|---|---|
| **ingress MAU stages** | 8 | **8** | 12 | — |
| **egress MAU stages** | 2 | **2** | 12 | — |
| critical path | 8 | **8** | — | — |
| logical tables | 48 | **48** | — | — |
| SRAM / map RAM / TCAM | 47 / 40 / 1 | **47 / 40 / 1** | — | — |
| stateful ALUs / Stats ALUs | 6 / 14 | **6 / 14** | — | — |
| gateways / VLIW instructions | 24 / 36 | **24 / 36** | — | — |
| exact / ternary crossbar bytes | 54 / 2 | **55** / 2 | — | **+1** |
| action bus bytes | 21 | **21** | — | — |
| ingress / egress MAU latency | 196 / 170 | **196 / 170** | — | — |
| ingress parser states / rows | 12 / 89 | **12 / 89** | 256 rows | — |
| egress parser states / rows | 36 / 54 | **41 / 60** | 256 rows | **+5 / +6** |
| min packet at 100 Gbps | 93 B | **93 B** | — | — |
| normal PHV containers / bits | 33 / 471 | **33 / 471** | 4096 bits | — |
| **tagalong 8b containers** | 15 (46.9 %) | **16 (50 %)** | 32 | +1 |
| **tagalong 16b containers** | 40 (83.3 %) | **39 (81.2 %)** | 48 | **−1** |
| **tagalong 32b containers** | 27 (84.4 %) | **27 (84.4 %)** | 32 | — |
| **tagalong bits used** | 1608 (78.5 %) | **1600 (78.1 %)** | 2048 | **−8** |
| **tagalong bits allocated** | 2480 (121 %) | **2464 (120 %)** | 2048 | **−16** |
| **tagalong collections occupied** | **7** | **7** | 8 | — |
| PHV allocation | successful | **successful, no unallocated slices** | — | — |
| errors / warnings | 0 / 4 | **0 / 4** | — | — |

**The binding resource did not move, and on its tightest dimension it improved.** The brief's
concern — that adding ~13 classes per `data_offset` value would exhaust the 7-of-8 tagalong
budget — did not materialise, because no class was added at all: the fix removed a key field
rather than enumerating more cases. The only real costs are **+6 egress parser TCAM rows** (60 of
256) and **+1 exact-match crossbar byte**.

The optional `-DSIZE_LEN_PROBE` build, for completeness: identical stages (8 / 2) and identical
tagalong (16 / 39 / 27, 1600 bits, 7 collections); it costs SRAM 47 → 55, map RAM 40 → 48, tables
48 → 52, stateful ALUs 6 → 10, crossbar 55 → 59, egress latency 170 → 176 cycles. Ingress logic is
still identical to P12 — only physical RAM row/bus assignment shifts, because the added egress
memory moves the shared allocator.

---

## MUST-NOT-BREAK properties — one line each, and where each is verified

| property | status | evidence |
|---|---|---|
| **inner IP datagram complete and byte-identical, pads strictly after it** | **holds, machine-checked** | Egress deparser field dictionary read out of `out/pipe/p13_size_do8.bfa`: `eth → ipv4 → tcp → pay64…pay1 → pad64…pad1`. Extraction order and emit order are both descending, so any chunk subset reconstructs the consumed bytes exactly. `verify_p13_size.py` ARM 1 simulates all 14 classes at `data_offset` 5, 8 and 10 and asserts `out[:14+total_len] == inner[:14+total_len]` and that the bytes after the datagram are exactly the pads. |
| **IP `total_len` consistent** | **holds** | `total_len` is never written — it is now a *match key*, i.e. read-only. Confirmed by the MAU instruction census below; the pads are outside the datagram `total_len` delimits, so the field stays correct without being touched. |
| **TCP checksum still valid** | **holds** | No TCP field is read or written by any MAU action, and the TCP options (which the checksum covers) are carried through the `pay*` chunks byte-identically. No `Checksum()` extern exists in egress. |
| **DNP3 application bytes and CRC untouched** | **holds** | The egress pipeline never parses DNP3 at all; those bytes ride inside the opaque `pay*` chunks. |
| **no TCP sequence-space change** | **holds** | `hdr.tcp.seq_no` / `ack_no` are written by no MAU instruction, and pads are appended outside the IP datagram so they are not payload. |
| **oversize frames fail open safely** | **holds** | `total_len > 114` has no entry → `const default_action = pad_none()` → forwarded unchanged. `verify_p13_size.py` ARM 2 asserts no entry could ever require a negative pad. |
| **byte preservation of the held packet's inner frame** | **holds, machine-checked** | The MAU write-instruction census over the whole program is **identical to P12's**: `24 set meta, 23 set ig, 3 set H0, 2 sub hi, 1 set W4, 1 set B15, 1 or W5, 1 and W4, 1 add W6, 1 add W0`. The only container holding a *header* field that any instruction writes is `W0 = ingress::hdr.ib.seq` (`add W0, 4294967295, W0`, the blocker token's pass-budget decrement). Every IPv4 / TCP / TCP-option / DNP3 / `pay*` / `pad*` container is written by no MAU instruction. |
| **generation safety** | **preserved, byte-identical** | `tbl_state_decode`'s compiled entries are unchanged: `(CLASS_BLOCK_DEQ, 0x00 &&& 0xFF) → dec_live` at priority 3, plus the ACK partition `(CLASS_ACK, 0x00 &&& 0xFE) → dec_none` / `(CLASS_ACK, 0x00 &&& 0x00) → dec_ack_arm` at priorities 1 and 2. Extracted from both `context.json` files and diffed. |
| **correct deadline release** | **preserved** | `tbl_deadline_expiry_0-gateway` compiles with the same 4-byte `meta.age` match and the same `run_table` structure as P12. |
| **pass-budget fail-open** | **preserved** | Ingress is bit-identical (below), so the `budget_zero → TAG_INACTIVE` watchdog is the same machine. |
| **internal blocker-token isolation** | **preserved** | Same — ethertype `0x88C1` is still forced to `ROLE_BLOCK` in the ingress parser. |
| **the two parser-hardening gates** | **preserved** | GATE 1 (`total_len >= 20 + 4*data_offset + 13`, range-matched in the tcp-extract state) and GATE 2 (DNP3 `LEN >= 8`, with `LEN == 5` a valid link-only frame) are inside the identical ingress parser: same 9 named states, same 89 of 256 TCAM rows. |

### The strongest single piece of evidence

**The ingress assembly is identical.** Extracting `phv ingress`, `parser ingress`,
`deparser ingress` and all 8 `stage N ingress` blocks from both `.bfa` files, and canonicalising
only the compiler-generated table names (which embed source line numbers that shifted when
comments changed) by order of first appearance:

```
ship ingress assembly vs p12: IDENTICAL
```

Every timing-side property therefore carries over **because it is the same compiled machine**, not
because it was re-argued. The P4 source for the ingress parser and the whole `Ingress` control is
byte-identical too (`diff` over that region is empty).

---

## Cross-check: the model reproduces the silicon result exactly

Applying `pkt_length = wire + 4` to P12's *old* key and entry set predicts which of P12's 13
classes could have fired on silicon:

```
p12 classes that would fire: [48]        (coordinator observed: [48])
  total_len=48 wire=62 pkt_length=66 -> pad_d62 -> OUTPUT 124 B  (NOT 128)
```

Predicted set and observed set agree exactly, on a 13-way test. **One falsifiable consequence
worth confirming from the existing capture:** that single frame should have left at **124 B**, not
128 — it matched the entry meant for a 66 B wire frame while actually being 62 B. If the capture
shows 124, the whole length model is confirmed end to end; if it shows 128, then the 4 FCS bytes
*are* in the deparser residual after all and every pad in this table wants to be 4 smaller
(a one-line change to the target constant, and the "one fixed size" property survives either way
— only its value shifts).

A caveat on the `+18` shorthand, so it does not cause the next surprise: **`pkt_length =
total_len + 18` holds only while `wire == 14 + total_len`.** For a frame the sending MAC padded up
to 60 B the field must track the padded bytes, so the durable form of the rule is
`pkt_length = wire + 4`. This program depends on neither.

---

## Verification actually run

```bash
python3 verify_p13_size.py          # RESULT: PASS
```

It reads the **compiled** `out/pipe/context.json` for the entry set (not the P4 text), so its
claims are about what bf-p4c emitted. Four arms:

1. **All 14 compiled entries**, each simulated at `data_offset` 5, 8 and 10: the select maps
   `total_len → pl_(total_len-40)`, the pay chunks sum to `total_len-40`, the pad chunks sum to
   the action's delta, `wire + pad == 128`, all chunks are distinct descending powers of 2, the
   residual lies outside the IP datagram, the datagram is byte-identical, the pads land after it,
   and the output is exactly 128 B.
2. **The frames that must not be padded**: every entry is gated on `tcp.isValid()`; no entry
   exists for a `total_len` without a parser class; no entry would need a negative pad.
3. **Corpus coverage**: 2104 / 2104 packets (100 %).
4. **The replay frames**: all three `data_offset = 5` types normalize.

Not claimed: nothing here was loaded or run on silicon by me. ARM 1 is a model of the
parser/deparser emit order, not a capture. **The gate is a wire pcap showing 128 B frames.**

---

## Coverage headroom — measured, and the wall is not tagalong

The brief asked what it would take to widen coverage. `gen_widen_probe.py` generates a variant
covering a **contiguous** `total_len` range (the strongest coverage statement: *every* IPv4/TCP
frame with `ihl = 5` and `total_len` in range, at any `data_offset`, leaves at 128 B) and
`probe_widen/` holds the compiles. Bisected:

| contiguous classes | `total_len` range | result |
|---|---|---|
| 75 | 40–114 | **fails** |
| 63 | 52–114 | **fails** |
| 40 | 75–114 | **fails** |
| **33** | **82–114** | **fails** |
| **32** | **83–114** | **fits** — 8 / 2 stages, tagalong 20 / 43 / 27, 1696 bits (82.8 %), 7 collections, egress parser 157 / 256 rows |

The wall is sharp and it is **instruction memory**, not tagalong:

```
error: Could not place table Egress.size_norm:
       The table size_norm_0 could not fit within the instruction memory
```

Each additional length class needs its own pad action (a distinct compile-time `setValid` subset),
and one table's action instruction memory runs out at 33. Tagalong is still at 7 of 8 collections
even at the ceiling. **So the ship configuration's 14 classes sit at 44 % of the class budget —
there is room for 18 more before anything has to change.** If a contiguous range ever becomes
necessary, the smallest change that clears the wall is to split `size_norm` into two tables in
series, each holding half the actions, which costs one additional egress stage out of the ten
still free.

---

## What was not touched

Nothing in the timing or classification logic. Ingress is bit-identical to P12 — same parser, same
tables, same registers, same counters, same gates, same stage assignment. Nothing was weakened to
make anything fit, and no coverage was narrowed: the class set **grew** by one (`total_len = 40`)
and the `data_offset` restriction was removed entirely.
