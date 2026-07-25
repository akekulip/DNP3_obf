# P12 — the full target architecture, combined and measured

**It fits. 8 of 12 ingress MAU stages, 2 of 12 egress stages, 0 errors.**

The three pieces of the target architecture — real DNP3 classification in the ingress parser,
packed transaction state, and egress/deparser size normalization — had each compiled alone. This is
the first program that contains all three. The headline is that the ingress cost of the combination
is the *packed-state* cost and nothing more: combining DNP3 classification with packed state costs
**zero additional ingress stages**, and the size primitive costs **zero ingress stages**, exactly as
each was measured separately.

The predicted failure mode — tagalong PHV exhaustion, since P6c alone already sat at 89.8 % — did
**not** occur, but it is now the binding resource: **7 of the 8 tagalong collections are occupied**,
16-bit tagalong containers are at **83.3 %** and 32-bit at **84.4 %**. The next feature that adds
deparser-only header bytes is the one that will fail, and it will fail in PHV allocation, not in
stage placement.

---

## Build

```bash
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out p12_combined.p4     # log: compile.log
```

Local bf-p4c **9.13.1**, exit status **0**, **0 errors, 4 warnings**. Compile-only; nothing was
loaded, no switch was touched, no hardware claim is made anywhere in this note.

| | SHA-256 |
|---|---|
| `p12_combined.p4` | `c43409c82e932b6be19ddbee03a90f80ae9a564ee3870c38490c30bb1598112b` |

Sources it was built from, for provenance:

| input | SHA-256 |
|---|---|
| `ibspg_dnp3.p4` (DNP3-part13, read-only reference) | `ed72a4743aa08dcda0589725550e04728ce00cd5c6cf974b69c1fd263cc2982f` |
| `p1_packed_state.p4` | `60910b808076ae90c851647a5ef42d1862e36d607181647893bdf29a146e0f31` |
| `p6c_true_trailer.p4` | `4c7768609f1807d958a10d312514c6b9378c859d45fe20fcfae3a88eb84db162` |
| `p0_baseline.p4` | `fa073cf691a6beb45fa8ffa61146cf481fc81e42f6cf4640bcb44ae6fe08f947` |

### The four warnings

All benign, and the same families the three inputs produced:

1. `uninitialized_out_param` on `IgParser`'s `meta` — the six classification fields
   (`role`, `dir`, `fwd_port`, `port_ok`, `gen_in`, `dequeued`) are deliberately not written in
   `start`, because Tofino's parser has no clear-on-write. Their defaults are the compiler's own
   zero-init, which is confirmed present in the assembly (`out/pipe/p12_combined.bfa:587`,
   `init_zero: [ B5, B6, H1, B7, ... ]` — 25 containers).
2. `uninitialized_out_param` on `EgParser`'s `meta` — `eg_meta_t.normalized`, which the egress table
   writes on every path (`pad_none` is a `const default_action`). Carried over from P6c.
3. and 4. Two `min_parse_depth_accept_loop will be unrolled up to 3 times` notices from the egress
   minimum-parse-depth padding. Carried over from P6c.

---

## Measured result

| | value | of budget |
|---|---|---|
| **ingress MAU stages** | **8** | 12 |
| **egress MAU stages** | **2** | 12 |
| critical path through the table dependency graph | **8** | — |
| logical tables | 48 | — |
| SRAM | 47 | — |
| map RAM | 40 | — |
| TCAM (MAU) | 1 | — |
| stateful ALUs (SALU) | 6 | — |
| Stats ALUs | 14 | — |
| gateways | 24 | — |
| VLIW instructions | 36 | — |
| exact / ternary match crossbar bytes | 54 / 2 | — |
| action bus bytes | 21 | — |
| ingress parser states / match (TCAM) rows | **12 / 89** | 256 rows |
| egress parser states / match (TCAM) rows | **36 / 54** | 256 rows |
| ingress / egress MAU latency | 196 / 170 cycles | — |
| normal PHV containers / bits | 33 (14.7 %) / 471 (11.5 %) | 4096 bits |
| — 8b / 16b / 32b normal | 18 c / 127 b · 6 c / 63 b · 9 c / 281 b | — |
| **tagalong bits allocated** | **2480 (121 %)** | 2048 bits |
| tagalong bits *used* | 1608 (78.5 %) | 2048 bits |
| tagalong containers 8b / 16b / 32b | 15 (46.9 %) / 40 (83.3 %) / 27 (84.4 %) | 32 / 48 / 32 |
| tagalong collections occupied | **7** | 8 |
| PHV allocation | **successful, no unallocated slices** | — |
| errors / warnings | 0 / 4 | — |

### Reading the two tagalong numbers

The compiler's PHV summary reports both *bits used* and *bits allocated*, and they mean different
things. **Bits used** (1608 / 2048 = 78.5 %) is how much container space is physically consumed.
**Bits allocated** (2480 = 121 %) sums the widths of all fields placed there, counting fields that
share a container by overlay because they are mutually exclusive — which is why it can exceed 100 %
without anything failing. P6c's headline 89.8 % was the *allocated* figure, so the comparable
combined figure is **121 %**, up from 89.8 %; the physical figure went 53.1 % → 78.5 %.

The number that actually predicts the next failure is neither: it is **collections occupied, 7 of 8**,
with 16b at 83.3 % and 32b at 84.4 %. Roughly one collection of headroom is left.

---

## Comparison against the three inputs and the P0 baseline

| program | ig stages | eg stages | crit path | log tables | SRAM | mapRAM | TCAM | SALU | StatsALU | ig parser states/rows | eg parser states/rows | tagalong alloc | err/warn |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **P0** baseline (synthetic roles, no size) | 12 | 0 | 12 | 44 | 36 | 36 | 0 | 7 | 11 | 2 / 4 | 6 / 11 | 560 (27.3 %) | 0 / 2 |
| **piece 1** — DNP3 classification (`ibspg_dnp3.p4`) | 11 | 0 | 11 | 45 | 38 | 38 | 0 | 7 | 12 | 9 / 86 | 5 / 8 | 1144 (55.9 %) | 0 / 3 |
| **piece 2** — packed state (`p1_packed_state.p4`) | **8** | 0 | 8 | 44 | 35 | 34 | 1 | 6 | 11 | 2 / 4 | 6 / 11 | 560 (27.3 %) | 0 / 2 |
| **piece 3** — size normalization (`p6c_true_trailer.p4`) | 12 | **2** | 12 | 47 | 46 | 40 | 0 | 7 | 13 | 2 / 4 | 36 / 54 | **1840 (89.8 %)** | 0 / 3 |
| **P12 combined (this program)** | **8** | **2** | **8** | 48 | 47 | 40 | 1 | 6 | 14 | 12 / 89 | 36 / 54 | **2480 (121 %)** | 0 / 4 |

### What the table says, in order of importance

**1. The stage costs do not add — they overlap, and the deeper reduction wins.**
Piece 2 alone takes 12 → 8. Piece 1 alone takes 12 → 11. Combined is **8**, not 7. Both pieces
remove the *same* stage-0 obstruction from different directions: piece 1 by classifying
`ingress_port` and the role in the parser so the ARM write-driver can share stage 0, piece 2 by
collapsing three register levels into one decode table so that driver disappears entirely. Once the
state chain is packed, the classifier's saving has nothing left to save. The combined ingress depth
is exactly the packed-state depth, i.e. **the DNP3 classifier is free on top of packed state.**

**2. The size primitive is still free in ingress.**
Ingress stages, critical path, SALU count and gateway count are identical to piece 2 alone
(8 / 8 / 6 / 24). Egress is 2 stages, identical to piece 3 alone. The `bypass_egress = 1` on both
loopback paths means blocker tokens and held responses never enter egress at all, so nothing in the
size primitive can perturb the hold mechanism.

**3. The costs that *do* add are memories, ALUs and parser rows — all of them small.**
SRAM 47 (P1's 35 + roughly P6c's egress 10 + 2 from the classifier's tables), map RAM 40, Stats ALU
14 (11 ingress counters + 2 egress size counters, plus the two-index bypass counter), VLIW 36. MAU
TCAM stays at **1 block**, consumed by the packed-state decode table (`tbl_state_decode`, the only
table in the program with real ternary entries); `tbl_deadline_expiry` compiled as an `exact_match`
with a **gateway** (`tbl_deadline_expiry_0-gateway` in the assembly) and costs no TCAM, exactly as in
pieces 1 and 2. Parser TCAM is the roomiest resource of all: 89 of 256 ingress rows and 54 of 256
egress rows.

**4. Where it got worse: parser rate.**
Piece 1 alone reported *min packet size at 100 Gbps: 82 B, max rate for min-sized packets
89.06 Gbps*. Combined reports **93 B / 78.08 Gbps**, and the ingress parser grew 9 → 12 states. This
is the one measured regression. It is not an error and it is not near a hard limit; it means
back-to-back sub-93-byte frames cannot be parsed at full 100 Gbps line rate. For a DNP3 poll
workload (single-digit frames per second per session) it is irrelevant, and the egress parser
already sat at exactly this figure in piece 3 alone, so the pipe-level number is unchanged from P6c.

I tested the obvious explanation and it is **wrong**: `probe_parser_init/` is `p12_combined.p4` with
all 18 all-zero metadata initializations deleted from the parser `start` state, relying on the
compiler's `init_zero`. It compiles 0 errors, and on everything that matters here it is **identical**:

| | p12_combined | probe (no parser init) |
|---|---|---|
| ingress / egress stages, critical path | 8 / 2, 8 | **same** |
| every MAU figure (SRAM 47, map RAM 40, TCAM 1, tables 48, crossbar, latency) | — | **byte-identical JSON** |
| ingress parser states / rows | 12 / 89 | **same** |
| min packet at 100 Gbps | 93 B | **same** |
| tagalong (containers 15/40/27, used 1608, allocated 2480) | — | **same** |
| normal PHV containers / bits | 33 / 471 | **28 / 439** |

So deleting the initializations returns **5 normal-PHV containers and 32 bits — and nothing else**.
It does not touch the parser depth, the parse rate, any stage, or a single tagalong bit. The compiler
was already folding those writes into `init_zero`; the extra parser states come from the merged
header set itself, not from the initialization style. Since normal PHV is at 14.7 % and tagalong is
the binding resource, this lever buys headroom in the place that is not scarce.

---

## Non-negotiable properties — one line each, and where each is verified

| property | status | evidence |
|---|---|---|
| generation safety | **preserved** | `tbl_state_decode` entry `(CLASS_BLOCK_DEQ, 0x00 &&& 0xFF) → dec_live` fires only on an exact tag match, so only a token of the current generation is ever `tag_ok`. Compiled entry confirmed at `out/pipe/p12_combined.bfa` priority 3, `value 0x3 / value 0x00 mask 0xFF`. |
| stale / unrelated event rejection | **preserved** | dequeued BLOCK with `tag_ok == 0` → `drop_pkt` + `ctr_block_term_stale`; anything else looping back → `drop_pkt`; `meta.port_ok == 0` → `drop_pkt` + `ctr_bypass[1]`. |
| correct deadline release | **preserved** | `reg_deadline` bit 0 is the armed marker; `tbl_deadline_expiry` entry `0x00000000 &&& 0x800000FF` tests armed-and-due in one ternary match. Unchanged from piece 2. |
| pass-budget fail-open | **preserved** | `budget_zero` → `tag_val = TAG_INACTIVE` at the tag write and `ctr_block_term_timeout` at the act; every later token then reads a stale tag and terminates. |
| internal blocker-token isolation | **strengthened** | ethertype 0x88C1 is forced to `ROLE_BLOCK` in the parser, so a token can only reach `to_block()` or `drop_pkt()`, never a host port. Carried from piece 1. |
| byte preservation of the held packet's inner frame | **preserved, and machine-checked** | Extracted from `out/pipe/p12_combined.bfa`: the **only** MAU instruction that writes a container holding a header field is `add W0, 4294967295, W0`, i.e. `hdr.ib.seq -= 1` on the internal blocker token. Every IPv4 / TCP / TCP-option / DNP3 / `pay*` container is tagalong and is written by **no** MAU instruction. Ingress deparser field dictionary: `eth → ib → ipv4 → tcp → tcp_opt4 → tcp_opt8 → tcp_opt12 → dnp3_dl → dnp3_tp → dnp3_app` = extraction order. Egress: `eth → ipv4 → tcp → pay64…pay1 → pad64…pad1`, so pads land after the complete inner datagram. |
| the two parser-hardening gates | **preserved** | GATE 1 (`total_len >= 20 + 4*data_offset + 13`, range-matched in the same state that extracts TCP) and GATE 2 (DNP3 `LEN >= 8`, with `LEN == 5` a valid link-only frame that is forwarded, never dropped) are carried verbatim from piece 1 and appear in the compiled parser. |

Nothing was weakened to make anything fit. Nothing was dropped: all three pieces are present in full,
and piece 3 is byte-for-byte the P6c mechanism (same 13 length classes, same one fixed 128 B target,
same 36 egress parser states and 54 rows).

---

## The four joins — where two pieces disagreed

Full derivations are in the file header. Summary:

**JOIN A — the generation source.** Piece 2 read `hdr.ib.gen` from a synthetic header; a real frame
has none. The generation is now piece 1's `meta.gen_in` (the DNP3 application control byte, or the
token's `gen` byte for 0x88C1 frames), fed straight into the tag SALU. Piece 2's separate `exp_tag`
copy was deleted — one fewer 8-bit field in a program whose binding constraint is PHV. Confirmed in
the assembly: `reg_tag` input crossbar is `{ 64: meta.gen_in, 72: meta.tag_val }` — exactly the two
PHV inputs a TF1 SALU permits.

**JOIN B — an ACK has no generation, but the packed tag fuses generation with "active".** This was
the one real semantic collision. Piece 1 qualifies an ACK on "transaction active" and deliberately
does not check the generation, because a pure TCP ACK carries no DNP3 application sequence. Piece 2
has no separate active bit: `tag_diff == 0` means active *and* my generation, and an ACK's `gen_in`
is 0, so that test would degenerate into "the register is still at power-on" — exactly backwards.

Closed inside the same decode table, with **one extra const entry and no extra MAU level**, by
reading the SALU difference for what it is. With `exp = 0` the SALU returns `0 - v`, and the stored
tag has a closed domain: `0x00` (power-on) → `0x00`, `0xFF` (`TAG_INACTIVE`) → `0x01`, a live
generation `g` → `0x100 - g`. So "a transaction is live" is exactly `tag_diff ∉ {0x00, 0x01}`, which
one ternary pattern `0x00 &&& 0xFE` captures:

```
(CLASS_ACK, 0x00 &&& 0xFE) : dec_none()      # no live transaction
(CLASS_ACK, 0x00 &&& 0x00) : dec_ack_arm()   # otherwise live -> arm
```

Compiled entries confirmed in priority order (`bfa` priorities 1 then 2). This reproduces piece 1's
ACK qualification exactly while the blocker path keeps the full generation test.

The domain argument is load-bearing, so it is **enforced in the parser, not assumed**: `g` must never
be `0x00` (piece 2's measured SALU no-write sentinel — a compare immediate must be small, so zero is
the only cheap sentinel) and never `0xFF`. `g` is the application control byte of a READ, and IEEE
1815 requires a request to be a single application fragment, so FIR = FIN = 1 and CON = UNS = 0: the
byte is always `0xCn`. That expectation became a parser gate at zero cost — the existing `func_code`
select gained an `app_control` mask, using match registers the select already held. The compiled
parser shows it:

```
parse_dnp3_tp:
  0x**81 : ... B5: 2   # any app_control + FC 129 -> ROLE_RESP
  0xc*01 : ... B5: 6   # app_control 0xCn + FC 1  -> ROLE_ARM     <-- the gate
  0x**** : ...         # everything else          -> ROLE_BYPASS
```

A READ whose application control byte is not `0xCn` is not dropped; it simply does not arm and is
forwarded as `ROLE_BYPASS`, which is this program's standing fail-open posture. The tag domain is
therefore provably `{0x00, 0xC0..0xCF, 0xFF}` and the two ACK patterns partition it exactly.

**JOIN C — where G comes from.** Piece 2 read the guard interval out of the synthetic ACK's `seq`
field; a real ACK has none. G now comes from piece 1's `tbl_guard`, whose default action parameter
the control plane rewrites for a G sweep with no recompile. `tbl_guard` has no dependencies and was
placed in stage 0, so the merge costs no depth. **Control-plane contract:** the parameter is G
already expressed in 256 ns ticks, i.e. its **low byte must be zero**, because bit 0 of the deadline
word is the armed marker and only a zero low byte lets that marker survive the addition. The default
`0x017D7800` = 24.999936 ms is 25 ms rounded down to a tick. Violating the contract is fail-open, not
fail-closed: a non-zero low byte makes the age's low byte non-zero, the expiry pattern never matches,
and the blocker drains on its pass budget instead of on the deadline.

**JOIN D — the stale test.** Piece 1's `active_now == 0 || gen_mismatch == 1` becomes piece 2's
`tag_ok == 0`, set by the one decode table. Identical meaning, one level shallower, and piece 2's
deliberate tightening comes with it: a stale token can no longer write state at all, so it can no
longer clear `active` for a live generation and release that generation's response early.

---

## Known functional gap, stated rather than papered over

Piece 3 is carried over verbatim, which means the egress size normalizer still covers only
`ihl = 5, data_offset = 5` and the 13 total_len classes of the P6c corpus. Real DNP3 traffic from a
Linux master carries TCP timestamps, i.e. **`data_offset = 8`**, and those frames will miss
`size_norm` and take the `pad_none` default — forwarded unchanged, which is the intended fail-open
behaviour, but *not size-normalized*. Piece 1's ingress classifier already handles `data_offset`
5..8 (that is what its option headers are for); the egress normalizer does not.

This was left alone on purpose. Extending it means roughly 13 more length classes per additional
`data_offset` value, each of which adds egress parser states and, more importantly, tagalong-eligible
bytes — and tagalong is now the binding resource at 7 of 8 collections. Extending the class set and
re-measuring is its own experiment; folding it into this one would have changed two variables at once
and made the egress column incomparable with the standalone P6c measurement.

---

## If the next feature does not fit

It will fail in PHV allocation with `N field slices remain unallocated`, not in stage placement —
there are 4 free ingress stages and 10 free egress stages, but only about one free tagalong
collection. In that order, the cheapest levers are:

1. **Narrow the egress payload chunk set.** `pay1_h … pay64_h` is 127 B of definitions that exist
   only to empty the deparser residual. The 13 classes span payloads of 6..66 B; `pay64` is used by
   exactly one class (`pl_66`). Dropping the 66 B class costs one corpus length and returns 512
   tagalong bits.
2. **Drop `tcp_opt12_h` from ingress** if `data_offset = 8` coverage is not needed on the ingress
   side, returning 96 bits.
3. **Do not** reach for the parser metadata initializations to relieve *tagalong* — measured above,
   they return 5 normal-PHV containers and zero tagalong bits. Useful only if normal PHV is what ran
   out, which at 14.7 % it is nowhere near.
4. **Do not** trade away safety logic. The ingress MAU has four free stages; anything that needs
   depth rather than PHV has plenty of room.
