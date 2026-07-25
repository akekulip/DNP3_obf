# PACKED_STATE_DESIGN — one 32-bit transaction word (variant P1 / WS2)

Compile-only, local bf-p4c 9.13.1. Subject: Part 12 `ibspg_hold_response.p4` (P0, sha `fa073cf6`,
12/12 ingress stages, critical path 12).

The goal is to collapse the three **serial** state RegisterActions of P0 — `reg_gen` (stage 2),
`reg_active` (stage 5), `reg_deadline` (stage 7) — into **one** register access, and with them the
three driver/compare levels that sit between them (stages 3, 4, 6, 8). That block, stages 2–8, is
the part of the pipeline the WS1 forensics show is genuinely dependency-bound.

Everything below is arithmetic and encoding. The measured compile results are in
`variants/*/compile_note.md`.

---

## 0. The two hardware limits that shape the design (both measured, not assumed)

**Limit A — a Tofino-1 stateful ALU accepts at most 2 PHV inputs.**
The naive packed form (one RegisterAction that reads the word, compares it against the packet's
generation, and writes one of three values) needs five PHV operands. It is rejected outright:

```
error: Could not place table tbl_probeB_full74: The table tbl_probeB_full74 could not fit within
the input crossbar by itself: Ingress.reg_state requires more than 2 PHV inputs
```
(`variants/p1_packed_state/salu_probes/probeB_full.p4`, `probeB_compile.log`)

This is the single most important constraint in this document. Every RegisterAction below is built
to use **exactly two** PHV fields, and where two RegisterActions share one register they are built
to use **the same two** fields, so the register's input crossbar sees two inputs in total.

**Limit B — an SALU comparison immediate must be small.**
`if (meta.dl_val != 32w0xFFFFFFFF)` passes the frontend, passes table placement, and then dies in
the assembler:

```
probeC_2phv.bfa:480: error: constant value -4294967295 too large for stateful alu
```
(`salu_probes/probeC_2phv.p4`, `probeC_compile.log`)

Re-encoding the same predicate against zero (`!= 32w0`) compiles clean, 0 errors
(`probeD_2phv_zerosentinel.p4`, `probeD_compile.log`). So **the "do not write" sentinel must be
zero**, and every value the design actually wants to store must be non-zero. That is not a
restriction in practice — it is arranged for free below.

**What *does* work** (all three verified in probe D, 0 errors, 6 stages):
1. an SALU output that is an *expression* of a PHV and the register — `rv = meta.now_word - v`;
2. a write predicated on a PHV-vs-zero test — `if (meta.salu_new != 0) { v = meta.salu_new; }`;
3. a write predicated on a **register-vs-PHV equality** — `if (v == meta.salu_ref) { ... }`.

(3) is what makes write-side generation qualification possible without a second serial register
read, and (1) is what pulls the deadline subtraction *out* of the MAU and into the SALU.

---

## 1. The word

One 32-bit register, `reg_state`, one index. Layout, most significant field first:

```
 bit 31                                   8 7                0
+------------------------------------------+------------------+
|      deadline, 24 bits of 256 ns ticks    |    tag, 8 bits   |
+------------------------------------------+------------------+
                                             tag = armed(1) | generation(7)
                                             bit 7   = armed
                                             bits 6:0 = generation
```

Tag values, exhaustively:

| tag | meaning | written by |
|---|---|---|
| `0x00` | power-on only; no transaction | (register initial value) |
| `g`, `g ∈ [1,126]` | generation `g` active, deadline **not** armed | ARM |
| `g \| 0x80` | generation `g` active, deadline **armed** | qualifying ACK |
| `0xFF` | explicitly INACTIVE (fail-open clear) | pass-budget timeout |

Generation is restricted to `[1,126]`. `0` is excluded so that the power-on word (all zeros) can
never be mistaken for a live transaction, and `127` is excluded so that `g | 0x80` can never
collide with the `0xFF` INACTIVE marker. P0 accepted any 8-bit generation; the harness uses `gen=7`,
which is inside the range. A host that violates the range does not break safety — it produces a
transaction that never arms and is released by the fail-open budget.

**Deadline is the high field, deliberately.** The expiry test is a subtraction, and a borrow out of
the tag field propagates *upward* into the deadline field. Putting the deadline on top means a
borrow can only corrupt the deadline bits in exactly the cases where the tag did **not** match — and
those cases are stale, where the deadline is never consulted. The reverse layout (tag on top) is
incorrect: a deadline borrow would corrupt the tag comparison and turn "not yet due" into "stale",
which releases the held response early.

## 2. The now-word, and why there is no bit slicing anywhere

The packet side builds a word in the **same** alignment as the stored word:

```
now_word = (ingress_mac_tstamp[31:0] & 0xFFFFFF00) | (gen | 0x80)
```

Two whole-container ALU operations, `AND` then `OR`. No sub-field is ever *read out* of a packed
word in the MAU. This is the answer to the known trap: P0 documents, and I reproduced in probe form,
that slicing a 32-bit arithmetic field (`meta.age[31:31]`) either fails as `condition expression too
complex` in a gateway or breaks PHV allocation outright with *"N field slices remain unallocated"*.

The design never needs a slice because:

- **fields are combined, never extracted** — masking and OR-ing build a word (legal ALU ops on whole
  containers);
- **every sub-field test is a ternary match** on the whole 32-bit container under a TCAM mask, which
  is exactly the escape hatch P0 already uses for the sign bit, extended to do more work;
- the only slice in the program is `ig_intr_md.ingress_mac_tstamp[31:0]`, which P0 already contains
  and which allocates (it slices an *intrinsic* container that nothing else shares an arithmetic
  cluster with).

`(bit<32>)hdr.ib.gen` is a widening cast, not a slice, and is free.

## 3. The one subtraction that decides everything

```
age = now_word - stored_word          (32-bit wrapping)
```

Because both operands carry the tag in the low 8 bits, the low byte of `age` is
`(gen|0x80) - stored_tag (mod 256)`, and the top 24 bits are the tick difference **iff** that low
byte subtraction did not borrow. Three cases, and they are provably the only three:

| low byte of `age` | stored tag must be | meaning | borrow into deadline? |
|---|---|---|---|
| `0x00` | `gen \| 0x80` | same generation, **armed** | no |
| `0x80` | `gen` | same generation, **not armed** | no |
| anything else | anything else | stale / inactive / other generation | possibly, and harmless |

*Proof that only those two tags produce `0x00` or `0x80`.* Let `d = (gen|0x80) − t (mod 256)`, with
`gen ∈ [1,126]` so `gen|0x80 = gen + 128`. If `d ∈ {0, 128}` then `d ≡ 0 (mod 128)`, so
`t ≡ gen + 128 ≡ gen (mod 128)`, i.e. `t`'s low 7 bits equal `gen`. The only two 8-bit values with
low 7 bits equal to `gen` are `gen` and `gen|0x80`, giving `d = 128` and `d = 0` respectively. ∎

The excluded tags check out: INACTIVE `0xFF` gives `d = gen + 128 − 255 = gen − 127`, which is
neither `0` nor `128` for `gen ∈ [1,126]`; the power-on tag `0x00` gives `d = gen + 128`, likewise
neither. A different generation `g' ≠ gen` gives `d ≡ gen − g' (mod 128) ≠ 0`. So **no unrelated
state is ever read as live**, which is the register-read half of the generation-safety invariant.

The deadline is only trusted in the `0x00` case, which is exactly the no-borrow case, so the
**wrapping comparison is exact**: bit 31 of `age` is the sign bit of the 24-bit tick difference,
because the low 8 bits of the difference are zero and the subtraction is uncorrupted.

One ternary table decodes all of it:

| `age` value `&&&` mask | decision |
|---|---|
| `0x00000000 &&& 0x800000FF` | armed, same generation, `now ≥ deadline` → **EXPIRED** |
| `0x80000000 &&& 0x800000FF` | armed, same generation, `now < deadline` → live, keep looping |
| `0x00000080 &&& 0x000000FF` | same generation, not yet armed → live, keep looping |
| default | **STALE** → terminate |

The three entries are pairwise disjoint (the first two differ in bit 31, the third has a different
low byte), so there is no priority subtlety to get wrong.

### Wrap case, worked explicitly

The tick field wraps every `2^24 × 256 ns = 2^32 ns = 4.295 s`. Take a deadline 1 ms before a wrap
and a `now` 1 ms after it:

```
deadline ticks  d = 0xFFFFFE  (2 ticks, 512 ns, short of the 24-bit wrap)
now ticks       n = 0x000002  (2 ticks past it)      elapsed = 4 ticks = 1.024 us
age[31:8] = n − d = 0x000002 − 0xFFFFFE = 0x000004 (mod 2^24)   -> bit 23 = 0 -> EXPIRED
```

Correct: 1.024 µs really has elapsed. The naive magnitude comparison `n ≥ d` would have said
`0x000002 ≥ 0xFFFFFE` is false and held the response for a further 4.29 s. The wrapping subtraction
is what makes the test correct across the wrap, and it is inherited unchanged from P0 — only the
width changes, from 32 bits of ns to 24 bits of ticks.

Validity condition, unchanged in substance from P0: the test is correct while
`|now − deadline| < 2^23 ticks`.

## 4. Range and quantization — worked numbers

**Does 40 ms fit?**

```
G = 40 ms = 40,000,000 ns
ticks     = 40,000,000 / 256 = 156,250 ticks
24-bit field capacity          = 2^24     = 16,777,216 ticks   (156,250 is 0.93 % of it)
unambiguous half-space         = 2^23     =  8,388,608 ticks   (156,250 is 1.86 % of it)
```

Yes, with ~53× headroom against the binding limit.

**Maximum representable G.** The binding limit is not the field width but the sign convention, and
it is `2^23 − 1 = 8,388,607 ticks = 2,147,483,392 ns ≈ 2.147 s`.

**This is exactly P0's limit.** P0 stores a 32-bit ns deadline and is valid while
`|now − deadline| < 2^31 ns = 2.147 s`. The packed field holds `2^24` ticks × 256 ns/tick = `2^32` ns
— the *same total span* — so quantizing to 256 ns costs **no range at all**. The 8 bits handed to
the tag are bought entirely from resolution, not from reach.

**Quantization error.** Both operands are truncated to a 256 ns boundary (`& 0xFFFFFF00`), so the
test is `trunc(now) ≥ trunc(deadline)` instead of `now ≥ deadline`.

- If `now ≥ deadline` then `trunc(now) ≥ trunc(deadline)`: the release **can never fire late**.
- `trunc(now) ≥ trunc(deadline)` can hold while `now < deadline` only when both fall in the same
  256 ns block, so the release can fire at most **255 ns early**.

Error interval: `[−255 ns, 0]`, one-sided.

**Effect on the measured ~1.72 µs release tail:** 255 ns is 14.8 % of the tail in the worst case and
0 in the typical case, and it is *not* the dominant term. The deadline is evaluated once per blocker
recirculation pass, so the achievable release granularity is the pass period, which is hundreds of
ns to microseconds — already coarser than 256 ns. The quantization is therefore absorbed by a
sampling interval that P0 also has. `G_observed = ts_first_resp_release − ts_ack_arm` continues to
be measured from full-resolution 32-bit ns timestamps, so **the measurement is not quantized — only
the decision is.**

There is a second, smaller term: the deadline is computed as `trunc(t_ack + G)`, one truncation, so
it contributes no error beyond the ≤255 ns already counted.

## 5. Stale-generation rejection with a 7-bit generation

Reuse distance is **254 generations**, not 128: the tag byte distinguishes `g` and `g|0x80` as
*states of the same generation*, so the generation space is `[1,126]` = 126 values, and a stale token
is accepted only if the counter advanced by an exact multiple of 126 between its injection and its
arrival. A trial is milliseconds; 126 trials is on the order of a second of wall time, against a
token whose own pass budget kills it in milliseconds. The blocker's own fail-open budget bounds its
lifetime far below the reuse distance, so a false generation match is not reachable in this design.

The write side is qualified as well, which P0 also does and which is the property that matters most:
a non-qualifying ACK cannot move the release time of a live transaction. See §6.

## 6. Removing the deadline-zero sentinel

P0 uses `deadline == 0` to mean "unarmed", and documents the resulting `2^-32` ambiguity: a genuine
deadline whose ns value happens to be zero reads as unarmed.

**In P1 the sentinel is gone, and not by being made rare — by being made unreachable.** "Armed" is
an explicit bit (tag bit 7), and every armed word is written with it set. The three encodings are
disjoint by construction:

- armed ⟹ tag `= gen|0x80` ⟹ low byte of `age` is `0x00` ⟹ the expiry entry can match;
- unarmed (`tag = gen`) ⟹ low byte `0x80` ⟹ the expiry entry **cannot** match, for any deadline
  bits whatsoever, including all-zero;
- INACTIVE (`0xFF`) and power-on (`0x00`) ⟹ neither ⟹ stale.

There is no value of the 24 deadline bits that changes any of these classifications. The
`2^-32` case is eliminated rather than reduced.

One sentinel does remain, in a different place and with no ambiguity: `meta.salu_new == 0` means
"do not write this packet". Forced by Limit B. It is collision-free because **every value the
program stores is non-zero by construction** — ARM stores `gen ∈ [1,126]`, a qualifying ACK stores a
word whose tag has bit 7 set, the fail-open clear stores `0xFF`. Zero is not a storable word, so
"zero" cannot be confused with a value someone wanted to store.

## 7. The RegisterActions

Two RegisterActions on one register, sharing **the same two PHV fields**, `meta.salu_ref` and
`meta.salu_new`, whose contents are selected by packet class before the access. This keeps the
register's input crossbar at two inputs (Limit A) while giving the ACK a register-vs-PHV predicate
it could not otherwise have.

```p4
/* every packet except a fresh ACK */
rv = meta.salu_ref - v;                              /* salu_ref = now_word  -> rv = age  */
if (meta.salu_new != 32w0) { v = meta.salu_new; }    /* ARM writes gen; timeout writes 0xFF */

/* a fresh ACK on the slot */
rv = v;                                              /* pre-value, for the telemetry compare */
if (v == meta.salu_ref) { v = meta.salu_new; }       /* salu_ref = (bit<32>)gen  == "active,
                                                        this generation, not yet armed"     */
```

The ACK's predicate `v == (bit<32>)gen` is a **full-word** equality: it demands tag `= gen` *and*
deadline bits `= 0`, i.e. exactly the word ARM writes. So a qualifying ACK is one that finds its own
generation active and not yet armed — the write-side generation qualification, evaluated inside the
SALU, in the same access as the read. This is the step that removes P0's stages 3–6.

**Where this is stricter than P0, stated plainly.** P0 re-arms on *every* qualifying ACK; P1 arms on
the **first** one and ignores later ones (a second ACK finds the deadline bits non-zero and does not
match). This is a deliberate tightening, and it is the semantics the measurement already assumes:
`reg_ts_ack_arm` is a write-if-zero register, so `t_ack` is the *first* ACK's timestamp, and a
re-arming second ACK in P0 would move the release without moving `t_ack`, corrupting
`G_observed`. One ACK per transaction is the protocol; P1 makes the state machine agree with the
timestamp.

**A second forced consequence, also a tightening.** P0 clears `active` when a blocker is *stale or*
out of budget. Stale is a register-derived condition, so in P1 it is not known until after the
single register access, and it cannot drive that same access. P1 therefore clears on the **pass
budget timeout only**. Both halves check out:

- *fail-open is preserved.* The timeout clear is packet-derived (`hdr.ib.seq == 0`), still writes
  INACTIVE, and every other token then reads a stale tag and terminates — the same atomic fail-open
  propagation P0 has.
- *stale rejection is strengthened.* In P0 a leftover token from generation `g−1` clears `active`
  for the live generation `g`, killing a legitimate transaction and releasing its response early. In
  P1 a stale token cannot write state at all; it only terminates itself. This removes a
  cross-generation interference path rather than adding one.

## 8. Resulting dependency chain

| level | P0 | P1 |
|---|---|---|
| 0 | classify (`dequeued`, `ts32`, `budget_zero`) | classify + `ts_m`, `sum`, `tag_armed`, `exp_word` |
| 1 | ARM write drivers | `now_word`, `sum_m`, class + write drivers |
| 2 | **`reg_gen` SALU** | `ack_val` |
| 3 | `gen_mismatch` compare | **`reg_state` SALU** (the only state access) |
| 4 | active clear driver | decode ternary (`tag_ok`, `expired`) ∥ ACK qualify compare |
| 5 | **`reg_active` SALU** | ACT |
| 6 | ACK qualify → deadline driver | ACT |
| 7 | **`reg_deadline` SALU** | timestamp bank |
| 8 | `age`, `dl_armed` | — |
| 9 | expiry ternary | — |
| 10–11 | ACT, timestamp bank | — |

Three serial SALU levels and four driver/compare levels between them become one SALU level and one
decode level. The expiry ternary disappears as a separate level because the decode table does the
expiry test *and* the tag test in one lookup, off one subtraction.

## 9. Invariants — how each survives

| invariant | mechanism in P1 |
|---|---|
| generation safety | tag byte carries the generation; §3 proves only `g` and `g\|0x80` read as live; ACK's write is gated on a full-word match |
| stale / unrelated event rejection | strengthened — a stale token cannot write state at all (§7); non-qualifying ACK fails the SALU predicate and cannot move the deadline |
| correct deadline release | wrapping 24-bit tick compare, exact in the no-borrow case, ≤255 ns early and never late (§4) |
| timeout / fail-open watchdog | unchanged: `hdr.ib.seq == 0` is packet-derived, terminates the token and writes INACTIVE, which propagates to every other token |
| internal blocker-token isolation | unchanged: `ETHERTYPE_IBSPG_TOKEN` 0x88C1, `PORT_L` loopback, `bypass_egress=1`; tokens never egress to a host port |
| byte preservation of the held packet | unchanged: the held RESP is enqueued and released with no header write on either path; egress stays a pure pass-through |
