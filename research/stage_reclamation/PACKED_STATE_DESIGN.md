# PACKED_STATE_DESIGN — packing the transaction state (variant P1 / WS2)

Compile-only, local bf-p4c 9.13.1, no switch. Subject: Part 12 `ibspg_hold_response.p4` (P0,
sha `fa073cf6…`, **12/12 ingress stages, critical path 12**).

Result up front: **P1 compiles at 8/12 ingress stages, critical path 8** — four stages reclaimed,
with every safety property preserved and two of them strengthened. Ingress latency drops from 284
to 196 cycles. The evidence for every claim below is a real compile under
`variants/*/out/pipe/logs/`.

The target was P0's stages 2–8: three **serial** state RegisterActions (`reg_gen` @2,
`reg_active` @5, `reg_deadline` @7) with a compare level and a write-driver level wedged between
each pair. WS1 forensics established that this block, not the telemetry tail, sets the budget.

---

## 0. Four hardware limits, all measured, that shaped the design

These are the load-bearing findings. Three of them killed a design that looked correct on paper.

**Limit A — a Tofino-1 SALU accepts at most 2 PHV inputs.**
The ideal form — one RegisterAction that reads the packed word, compares it against the packet's
generation, and writes one of three values — needs five PHV operands, and is rejected outright:

```
error: Could not place table tbl_probeB_full74: The table tbl_probeB_full74 could not fit within
the input crossbar by itself: Ingress.reg_state requires more than 2 PHV inputs
```
`variants/p1_packed_state/salu_probes/probeB_full.p4` + `probeB_compile.log`

Every RegisterAction in the shipped variant therefore uses **exactly two** PHV fields. Confirmed in
the compiled binary — `p1_packed_state.bfa` shows the deadline register's crossbar as
`exact group 0: { 64: meta.now_word, 96: meta.dl_val }`, two inputs and no more.

**Limit B — an SALU comparison immediate must be small.**
`if (meta.dl_val != 32w0xFFFFFFFF)` passes the frontend, passes table placement, and dies in the
assembler:

```
probeC_2phv.bfa:480: error: constant value -4294967295 too large for stateful alu
```
Re-encoding the same predicate against zero (`!= 32w0`) compiles clean, 0 errors
(`probeD_2phv_zerosentinel.p4`). So **zero is the "do not write" sentinel**, and every value the
program actually stores must be non-zero. That is arranged for free below.

**Limit C — the runtime generation cannot be packed into the 32-bit deadline word.**
This is the finding that decided the architecture. A single 32-bit word
`[deadline:24][armed:1][generation:7]` requires depositing the 8-bit `hdr.ib.gen` into bits [7:0] of
a field that also does 32-bit arithmetic. That forces a `[7:0]/[31:8]` split on every field sharing
the timestamp's arithmetic cluster, and PHV allocation fails:

```
error: Unable to slice the following group of fields due to unsatisfiable constraints:
  meta.ts32, meta.ts_m, ig_intr_md.ingress_mac_tstamp, meta.sum, hdr.ib.seq, meta.now_word,
  meta.tag_armed, hdr.ib.gen, meta.sum_m, meta.salu_new, meta.exp_word, meta.salu_out, ...
error: PHV allocation was not successful
33 field slices remain unallocated
```
The full rejected program is kept as evidence:
`variants/p1_packed_state/salu_probes/probeE_packed_word_REJECTED.p4` + `probeE_compile.log`.

This is the same invalid-SuperCluster trap P0's header warns about, reached from a new direction:
P0 hit it *reading* a bit out of a 32-bit arithmetic field, P1 hit it *writing* a byte into one.
**The rule generalises: a 32-bit field that does arithmetic must be whole. Constants may be packed
into it; runtime sub-fields may not.**

**What does work** (verified in `probeD`, 0 errors):
1. an SALU output that is an *expression* of a PHV and the register — `rv = meta.now_word - v`;
2. a write predicated on a PHV-vs-zero test — `if (meta.dl_val != 0) { v = meta.dl_val; }`;
3. a ternary match on the SALU's output, which reads a whole container under a TCAM mask.

(1) is what pulls the deadline subtraction out of the MAU and into the stateful ALU. (3) is the
only sub-field extraction mechanism the design uses.

---

## 1. What is packed, and where

Limit C forces the generation to stay in its own register. Everything else packs.

**`reg_tag`, 8 bits — packs P0's `reg_gen` AND `reg_active` into one byte.**

| value | meaning | written by |
|---|---|---|
| `0x00` | power-on; no transaction | (register initial value) |
| `g`, `g ∈ [1,254]` | generation `g` is active | ARM |
| `0xFF` | INACTIVE — fail-open cleared | pass-budget timeout |

"Active" stops being a separate bit and becomes "the tag is a valid generation". `0xFF` is reserved
for INACTIVE and `0x00` is unreachable as a write (it is the SALU's no-write sentinel, Limit B), so
the generation space is `[1,254]`. P0 accepted any 8-bit generation; the harness uses `gen = 7`.

**`reg_deadline`, 32 bits — packs the deadline AND the armed flag into one word.**

```
 bit 31                                  8 7                0
+-----------------------------------------+------------------+
|     deadline, 24 bits of 256 ns ticks    |   marker byte    |
+-----------------------------------------+------------------+
     0x01 = ARMED      0x02 = explicitly unarmed      0x00 = power-on
```

Only **constants** are packed into the 32-bit word, which is exactly what Limit C permits.

## 2. The now-word, and why nothing is ever sliced

The packet side builds a word in the same alignment as the stored one:

```
now_word = (ingress_mac_tstamp[31:0] & 0xFFFFFF00) | 0x01
```

Two whole-container ALU operations, `AND` then `OR`, against constants. The design never *extracts*
a sub-field in the MAU:

- words are **built** with masking and OR (legal whole-container ops);
- every sub-field **test** is a ternary match under a TCAM mask;
- the only slice in the program is `ig_intr_md.ingress_mac_tstamp[31:0]`, which P0 has too, and
  which allocates because it slices an intrinsic container that shares no arithmetic cluster.

## 3. Two subtractions decide everything

**The tag comparison happens inside the stateful ALU.** `reg_tag`'s RegisterAction returns the
*difference*, not the value:

```p4
rv = meta.exp_tag - v;                                  /* exp_tag = hdr.ib.gen */
if (meta.tag_val != 8w0) { v = meta.tag_val; }
```

`tag_diff == 0` ⟺ a transaction is active **and** it is this generation — precisely P0's
`!(active_now == 0 || gen_mismatch)`, but computed in the SALU instead of in a following MAU level.
P0's whole `gen_mismatch` compare level disappears. Stale states are rejected by construction:
INACTIVE gives `g − 255 ≠ 0` and power-on gives `g − 0 = g ≠ 0` for every `g ∈ [1,254]`, and a
different generation `g′` gives `g − g′ ≠ 0`.

**The deadline comparison also happens inside the stateful ALU:**

```p4
rv = meta.now_word - v;                                 /* the age, straight out */
if (meta.dl_val != 32w0) { v = meta.dl_val; }
```

Because both operands carry the marker in the low byte, the low byte of `age` is
`0x01 − stored_marker`, and the top 24 bits are the tick difference **iff** that low-byte
subtraction did not borrow:

| stored marker | low byte of `age` | borrow? | meaning |
|---|---|---|---|
| `0x01` armed | `0x00` | no | armed — the tick difference above is exact |
| `0x02` unarmed | `0xFF` | yes | not armed |
| `0x00` power-on | `0x01` | no | not armed |

So **one ternary entry tests "armed AND due" together**:

```
(32w0x00000000 &&& 32w0x800000FF) : mark_expired();   /* bit 31 clear AND low byte 0x00 */
```

P0 needed a separate `dl_armed = (dl_now != 0)` compare *and* an `age = ts32 − dl_now` subtraction
*and* the expiry table. All three collapse into this one entry, off one subtraction.

Verified in the compiled binary rather than assumed — bf-p4c folds the single-entry table into a
gateway, and `p1_packed_state.bfa` shows the resulting match as:

```
0b0***********************00000000:
  action: mark_expired
```

bit 31 clear, bits 30:8 don't-care, low byte zero. Exactly the intended predicate.

### Wrap case, worked explicitly

The tick field wraps every `2^24 × 256 ns = 2^32 ns = 4.295 s`. Take a deadline 512 ns before a wrap
and a `now` 512 ns after it:

```
deadline ticks  d = 0xFFFFFE          now ticks  n = 0x000002      true elapsed = 4 ticks = 1.024 us
age[31:8] = n - d = 0x000002 - 0xFFFFFE = 0x000004 (mod 2^24)  ->  bit 31 = 0  ->  EXPIRED
```

Correct. A magnitude comparison would have found `0x000002 ≥ 0xFFFFFE` false and held the response a
further 4.29 s. The wrapping subtraction is what makes it correct across the wrap; it is inherited
from P0 unchanged, only the width changes, from 32 bits of ns to 24 bits of ticks.

Validity condition, unchanged in substance: correct while `|now − deadline| < 2^23 ticks`.

## 4. Range and quantization — worked numbers

**Does G ≥ 40 ms fit?**

```
G = 40 ms = 40,000,000 ns  ->  40,000,000 / 256 = 156,250 ticks
24-bit field capacity      = 2^24 = 16,777,216 ticks     (156,250 = 0.93 %)
unambiguous half-space     = 2^23 =  8,388,608 ticks     (156,250 = 1.86 %)
```

Yes, with ~53× headroom against the binding limit.

**Maximum representable G** is set by the sign convention, not the field width:
`2^23 − 1 = 8,388,607 ticks = 2,147,483,392 ns ≈ 2.147 s`.

**That is exactly P0's limit.** P0 stores 32 bits of ns and is valid while
`|now − deadline| < 2^31 ns = 2.147 s`. The packed field holds `2^24 ticks × 256 ns = 2^32 ns` — the
same total span. **Quantizing to 256 ns costs no range at all**; the 8 bits given to the marker are
bought entirely from resolution.

**Quantization error.** Both operands are truncated to a 256 ns boundary, so the test is
`trunc(now) ≥ trunc(deadline)` rather than `now ≥ deadline`.

- `now ≥ deadline` ⟹ `trunc(now) ≥ trunc(deadline)`: the release **can never fire late**.
- `trunc(now) ≥ trunc(deadline)` with `now < deadline` requires both in the same 256 ns block, so
  the release can fire at most **255 ns early**.

Error interval `[−255 ns, 0]`, one-sided.

**Against the measured ~1.72 µs release tail:** 255 ns is 14.8 % of the tail in the worst case and 0
in the typical one — and it is not the dominant term, because the deadline is evaluated once per
blocker recirculation pass, so the achievable granularity is the pass period, already coarser than
256 ns. P0 has that same sampling floor.

**The measurement is not quantized, only the decision is.** `G_observed =
ts_first_resp_release − ts_ack_arm` still comes from full-resolution 32-bit ns timestamps.

(Variant P10 removes even the early-firing side: with the marker moved out of the now-word the
low-byte subtraction always borrows, the test becomes `trunc(now) > trunc(deadline)`, and the
observed interval lands in `[G, G+256) ns` — never early. See `variants/p10_prep_fold/`.)

## 5. Stale-generation rejection

Reuse distance is **254 generations**. A stale token is accepted only if the generation counter
advanced by an exact multiple of 254 between the token's injection and its arrival. A trial is
milliseconds, so 254 trials is on the order of a second of wall time, while the token's own
pass budget kills it in milliseconds. A false generation match is not reachable.

This is stronger than the 7-bit generation the brief sketched (127), because merging `active` into
the tag as "is a valid generation" costs no bits, whereas an explicit active bit would have cost one.

## 6. The deadline-zero sentinel is eliminated, not reduced

P0 uses `deadline == 0` to mean "unarmed" and documents the resulting `2^-32` ambiguity: a genuine
deadline whose ns value happens to be zero reads as unarmed.

**In P1 that ambiguity is unreachable.** "Armed" is an explicit marker bit that every armed word
carries, and the three encodings are disjoint by construction:

- armed ⟹ marker `0x01` ⟹ low byte of `age` is `0x00` ⟹ the expiry entry can match;
- unarmed ⟹ marker `0x02` ⟹ low byte `0xFF` ⟹ the entry **cannot** match, for *any* value of the
  24 deadline bits, including all-zero;
- power-on ⟹ marker `0x00` ⟹ low byte `0x01` ⟹ cannot match either.

No value of the deadline bits changes any classification. The `2^-32` case is gone.

One sentinel remains, in a different place and with no ambiguity: `meta.dl_val == 0` /
`meta.tag_val == 0` mean "do not write this packet", forced by Limit B. It is collision-free because
**no storable value is zero**: ARM stores `g ≥ 1` and the unarmed word `0x02`, a qualifying ACK
stores a word whose bit 0 is set, the fail-open clear stores `0xFF`.

## 7. Where P1 differs from P0 in behaviour

Exactly one difference, and it is a tightening.

P0 clears the transaction when a blocker is **stale OR** out of budget. "Stale" is register-derived,
and a register lives in a single MAU stage, so the condition cannot gate the same access that
discovers it. P1 therefore clears on the **pass-budget timeout only**.

- *Fail-open is preserved exactly.* The timeout clear is packet-derived (`hdr.ib.seq == 0`), still
  writes INACTIVE, and every other token then reads a stale tag and terminates — the same atomic
  fail-open propagation P0 has.
- *Stale rejection is strengthened.* Every clear P1 performs, P0 also performed: the set of
  state-clearing events strictly **shrinks**, so no new interference path can appear. And one is
  removed — in P0 a leftover token from generation `g−1` clears `active` for a live generation `g`,
  killing a legitimate transaction and releasing its response early. In P1 a stale token cannot
  write state at all.

Everything else is unchanged, including the ACK re-arm semantics: qualification is still
"same generation, same slot, transaction active", evaluated one level earlier.

## 8. Measured dependency chain

| level | P0 (12 stages) | P1 (8 stages) |
|---|---|---|
| 0 | classify: `dequeued`, `ts32`, `budget_zero` | classify + `ts_m`, `seq_m`, `exp_tag` |
| 1 | ARM write drivers **[1,1] pinned** | `now_word`, packet class, tag write driver |
| 2 | **`reg_gen` SALU** | **`reg_tag` SALU** (returns the difference) ∥ `dl_cand` |
| 3 | `gen_mismatch` compare | **`tbl_state_decode`** — stale / qualify / disarm, one lookup |
| 4 | active-clear driver | **`reg_deadline` SALU** (returns the age) |
| 5 | **`reg_active` SALU** | expiry gateway + ACT |
| 6 | ACK qualify → deadline driver | ACT |
| 7 | **`reg_deadline` SALU** | timestamp bank |
| 8 | `age`, `dl_armed` | — |
| 9 | expiry table | — |
| 10–11 | ACT, timestamp bank | — |

In P0 stages 0–9 are pinned `[n,n]`. In P1 **nothing is pinned** — every table carries a placement
range (`[0,4]`, `[1,5]`, `[3,7]`…), i.e. the allocator has slack it did not have before.

## 9. Invariants — how each survives

| invariant | mechanism in P1 | status |
|---|---|---|
| generation safety | the tag byte holds the generation; `tag_diff == 0` is the only live classification, and §3 shows no other stored value produces it | preserved |
| stale / unrelated event rejection | a non-qualifying ACK falls to the decode table's default and writes nothing, so it cannot move a release time; a stale token can no longer clear state at all | **strengthened** |
| correct deadline release | wrapping 24-bit tick compare, exact in the no-borrow case, ≤255 ns early and never late; gateway predicate verified in the `.bfa` | preserved |
| timeout / fail-open watchdog | `hdr.ib.seq == 0` is packet-derived, terminates the token, writes INACTIVE, and that propagates to every other token | preserved |
| internal blocker-token isolation | unchanged: ethertype `0x88C1`, `PORT_L` loopback, `bypass_egress = 1`; tokens never reach a host port | preserved |
| byte preservation of the held packet | unchanged: no header write on either the enqueue or the release path; egress is a pure pass-through | preserved |
| deadline-zero sentinel | eliminated by the explicit marker bit (§6) | **strengthened** |
