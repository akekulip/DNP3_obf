# Panel A — Tofino pipeline and PHV architect

**Scope:** Defense 3 (predetermined ACK-delay release, `d_ACK = t_ACK + D`), built from
`research/case_a_read_anchored_dual_release/p4/case_a_stripped_baseline.p4`.
Analysis only. No code changed, no compile run, no switch touched.
All numbers below are read out of committed bf-p4c 9.13.1 logs
(`build_stripped_9.13.1/pipe/logs/`, `build_dual_min_9.13.1/pipe/logs/`), not estimated,
except where explicitly marked ESTIMATE.

---

## 0. The two measured reference points

| | stripped baseline | dual_min (READ-anchored) |
|---|---|---|
| ingress stages | **8** | 10 |
| egress stages | 0 | 0 |
| critical path | **8** | 8 |
| logical tables | 57 | 73 |
| LTID by stage (of 16) | 9,3,3,2,2,**16**,**16**,6 | 8,2,3,2,3,**16**,**16**,**16**,4,3 |
| Meter ALU (SALU) by stage (of 4) | 0,1,1,0,1,0,0,3 | 0,0,1,0,3,0,0,1,4,3 |
| Stats ALU by stage (of 4) | 1,0,0,0,0,2,2,1 | 1,0,0,0,0,1,1,1,0,0 |
| TCAM | 1 (stage 3) | 2 |

Read this pair carefully, because it settles the whole design question:

- The stripped baseline has **stages == critical path == 8**. It is *exactly* at its
  dependency floor. No lever can take it below 8, and no amount of width will take it
  above 8 until the ACT-block region runs out of logical table IDs.
- dual_min has **stages (10) > critical path (8)**. It is *purely* placement-bound —
  three consecutive stages pinned at 16/16 LTIDs. Its two extra stages bought no depth
  whatsoever; they were paid entirely for ACT-block breadth.

Defense 3 must therefore be engineered as a **width** problem, not a depth problem.

---

## 1. Stage dependency analysis — where the single deadline and `ack_release_gen` land

The baseline dependency chain is 8 levels deep and every level is occupied:

```
L0  ts32 / ts_m / budget_zero / tbl_guard          (parser-derived + constants)
L1  tbl_build_now, pkt_class + tag_val driver
L2  reg_tag (tag_rmw | tag_read), tbl_build_cand
L3  tbl_state_decode, tbl_pktgen_active
L4  reg_deadline (deadline_rmw | deadline_arm_once) -> meta.age
L5  tbl_deadline_expiry                             -> meta.expired
L6  ACT block (queue/forward/drop leaves, ev_* flags)
L7  ts-register bank (ts_first_block / ts_ack_arm / ts_block_term / ts_*_release)
```

Confirmed against `table_dependency_summary.log`: stages 0–7 map one-to-one onto L0–L7,
and the ts bank at stage 7 is what makes stage 7 exist (Meter ALU 3/4 there, only 6 LTIDs).
The critical path is the telemetry chain `expired (L5) → ev_block_term (L6) → ts register (L7)`.

**Defense 3's single deadline is already there.** `reg_deadline` + `tbl_deadline_expiry` are
reused verbatim (same 24-bit tick word, same ARMED marker in the low byte, same whole-container
ternary `0x00000000 &&& 0x800000FF`). Defense 3 changes *which packet is enqueued where*, not
how the deadline is computed or compared. **Zero depth added by the deadline.**

**`ack_release_gen` adds width, not depth**, provided it is built as an SALU-difference register
placed in parallel with `reg_deadline`:

```p4
/* 8-bit released-generation register. rv == 0  <=>  the ACK of THIS generation
 * has already left Q_HOLD, so a RESPONSE arriving now is LATE. */
Register<bit<8>, bit<1>>(1, 0) reg_ack_rel;
RegisterAction<bit<8>, bit<1>, bit<8>>(reg_ack_rel) ack_rel_rmw = {
    void apply(inout bit<8> v, out bit<8> rv) {
        rv = meta.cur_gen - v;                       /* compare inside the SALU */
        if (meta.relw != TAG_NO_WRITE) { v = meta.relw; }
    }
};
```

- Two PHV inputs (`cur_gen`, `relw`) — exactly the SALU ceiling, same shape as `tag_rmw`.
- `cur_gen` comes from the existing `tag_read` RegisterAction at **L2**; `relw` is set by
  `tbl_state_decode` at **L3**; so `reg_ack_rel` sits at **L4, in parallel with `reg_deadline`**.
  Stage 4 currently holds 1/4 Meter ALU and 2/16 LTIDs. It lands free.
- Its result is consumed only in the ACT block at L6. Two levels of slack.

**Verdict for item 1: Defense 3 extends WIDTH only. Predicted critical path stays 8.**
Registers accessed in parallel cost zero depth — measured previously on this family, and the
dual_min data point confirms it (12 SALU accesses, critical path still 8).

Two structural gifts from the baseline that Defense 3 gets for free and should not re-invent:

1. **The release pass needs no marker.** The held ACK re-enters ingress on dp8 and the parser
   re-derives `role = ROLE_ACK` from the pure-ACK predicate (`flags 0x10 &&& 0x17`, `total_len ==
   20 + 4*data_offset`); the held early RESPONSE re-derives `role = ROLE_RESP` from the DNP3
   function code. `from_loopback` already sets `dequeued = 1`, `dir = DIR_OUT`,
   `fwd_port = PORT_VISION`. So `(dequeued==1 && role==ROLE_ACK)` *is* "this is the released
   ACK", from parser fields alone. **No internal shim, no role marker, no bridge header.**
   This is the single most consequential fact in this memo — see §4.
2. **"Prevent the ACK from being held again" is already structural.** The `CLASS_ACK` assignment
   sits inside `if (meta.dequeued == 8w0)`, and the ACT block splits fresh/dequeued at the top.
   A released ACK can never re-arm or re-enter Q_HOLD. Costs nothing, needs no `ack_released`
   flag for that purpose.

### One correctness trap the panel must not miss

**The RESPONSE's generation is NOT the READ's generation.** `meta.gen_in` is
`hdr.dnp3_app.app_control`: `0xCn` on the READ (FIR|FIN, seq n) but typically `0xEn` on the
solicited RESPONSE (CON set). The baseline never noticed because its fresh-RESPONSE branch reads
no tag state at all. Therefore the early/late test **must** compare the raw stored generation
(`cur_gen` from `tag_read`) against the stored release generation — it must **not** be built as
`gen_in − stored`, which would mis-fire on every response. The construction above is correct
because both the released ACK and the fresh RESPONSE take the `tag_read` (raw) arm.

### Why `ack_release_gen` is load-bearing and `expired` alone is not

Tempting shortcut: use `meta.expired` as the early/late test (free, already computed). It fails.
Sequence: ACK releases at `t_ACK+D`, next READ arrives and arms a new transaction — the ARM
writes `UNARMED_WORD`, so `expired` returns to 0 — and only *then* the stale RESPONSE arrives.
With `expired` it would be routed into Q_HOLD and stuck behind the **new** reservoir for a full
`D`, reordered against the new transaction. Generation-binding is what prevents that. The
directive's insistence on `ack_release_gen == current_generation` over a stale boolean is correct
and I endorse it; my only refinement is that the comparison belongs **inside the SALU**
(`rv = cur_gen - v`), which deletes an MAU compare level relative to storing the generation and
comparing it in the MAU.

---

## 2. Logical-table saturation — the binding resource

Tofino-1 has **16 logical table IDs per stage**. dual_min proves this is what binds this program
family: it went 8 → 10 stages with the critical path unmoved, purely because the ACT block widened
from 2 queue actions to 4 and from one blocker class to two.

**The number that matters for Defense 3:** ACT-block tables have `min stage` 5 or 6 (they depend on
`expired`, produced at stage 5). Stages 5 and 6 are already **16/16**. So the only place an added
ACT leaf can go is **stage 7, which has 10 of 16 free**. That is the entire budget before a 9th
stage appears. The 61 free LTIDs in stages 0–4 are unreachable by ACT-block work.

### Branch-by-branch delta (ESTIMATE, to be confirmed by compile)

| ACT branch | baseline | Defense 3 | Δ LTID |
|---|---|---|---|
| fresh `ROLE_ACK` | `tbl_to_fwd` + cond + 2 counters = 4 | inlined: cond + 2 leaves = 3 | **−1** |
| fresh `ROLE_RESP` | `tbl_to_resp` + counter = 2 | early/late: cond + 2 leaves = 3 | **+1** |
| dequeued `ROLE_ACK` (new: release pass) | — | cond + 1 leaf = 2 | **+2** |
| dequeued `ROLE_RESP` | unchanged (2) | unchanged | 0 |
| blocker branches | unchanged | unchanged | 0 |
| **ACT-region net** | | | **+2 of 10 free** |

Non-ACT additions (`relw`/raw selector at L1–L3, `reg_ack_rel` table at L4) land in stages 1–4
where 13–14 LTIDs per stage are free. Total ~57 → ~62.

### How to structure the ACT block to avoid dual_min's fate

Four rules, in priority order:

1. **Never write a bare action call next to a `count()`.** A bare call becomes its own logical
   table and will *not* merge with the adjacent statement. Measured on dual_min: inlining
   `ig_dprsr_md.drop_ctl = 3w1;` in place of `drop_pkt()` at 16 leaves took that program
   **11 → 10 stages** (90 → 76 tables); inlining five queue actions took a further **10 → 9**
   (→ 57 tables). Check with `grep tbl_drop_pkt pipe/logs/table_summary.log` — one
   `tbl_<action>_N` row per call site is the tell.

   **The stripped baseline has NOT had this lever applied.** `table_summary.log` shows
   **15 bare-action tables**: `tbl_to_fwd`, `tbl_to_fwd_0/1/2`, `tbl_to_block`,
   `tbl_to_block_0/1`, `tbl_to_resp`, `tbl_drop_pkt`, `tbl_drop_pkt_0..4`, `tbl_arm_clone`.
   Roughly 12 of these sit in the ACT region (stages 5–7). **This is a ~12-LTID reserve, held
   in hand, costing nothing behavioural.** If the first Defense 3 compile lands at 9 stages,
   apply this lever before considering anything else. It will not take the program below 8
   (the dependency floor), but it will keep it at 8.

   Keep a named action only where the *name* is load-bearing evidence — e.g. `to_hold()` is worth
   keeping as one named action if we want `pipe/context.json` to show that `qid = QID_HOLD` is
   assigned from a single compile-time immediate at exactly one site (a real safety claim:
   "nothing else can enqueue to Q_HOLD"). A bare `drop_pkt()` is not worth a stage.

2. **Prefer a widened const-entry table over a widened `if/else` chain.** `tbl_state_decode`
   already keys `(pkt_class exact, tag_diff ternary)` with 4 of 8 entries used and 1 TCAM at
   stage 3. Adding `CLASS_RESP` and `CLASS_ACK_REL` entries with new actions (`dec_resp`,
   `dec_ack_rel { meta.relw = meta.cur_gen; }`) costs **0 additional logical tables** — the table
   already exists. This is where the `relw` driver belongs. Do not spend gateways on it.

3. **Keep the fresh/dequeued split and the role dispatch flat.** The baseline's `if/else if`
   chain over roles compiles to one gateway per test plus one table per leaf. Adding a *nested*
   condition inside a leaf (the early/late RESPONSE test) costs one gateway + one extra leaf —
   that is the +1 above and it is unavoidable. Adding a *third* level of nesting anywhere would
   multiply leaves and is the specific mistake that cost dual_min its two stages.

4. **Do not add branches for telemetry.** Every new counter branch is ~1.2 logical tables
   (measured marginal rate: +6 counter branches = +7 tables = +1 stage). Defense 3's new counters
   (`CF_ACK_HOLD`, `CF_RESP_HOLD_EARLY`, `CF_RESP_FWD_LATE`, `CD_ACK_RELEASE`) must ride inside
   branches that already exist for forwarding reasons, never create their own.

Counter mechanics to carry forward: all `count()` sites on one `Counter` object must be
**mutually exclusive per packet** or bf-p4c hard-errors — so a total plus a subset must be
re-expressed as a partition recoverable by addition (the baseline already did this for
`ctr_arm` and `ctr_resp_release`). `ctr_fresh` has 6 free slots of 16, `ctr_deq` has 2 free of 8
— widen `ctr_deq` to 16 now rather than discovering it later. And indexed counters replicate
across the stages they are touched in (`ctr_fresh` is already allocated in two stages), so
control-plane readback must **aggregate across stages**, not read one instance.

Stats-ALU check: 4 per stage; current 1,0,0,0,0,2,2,1. Moving ACT leaves into stage 7 takes its
Stats occupancy from 1 to at most 2. Not binding.

---

## 3. PHV lifetimes and SALU use

### Which of §9's minimum state genuinely needs a Register

| §9 state | verdict | mechanism |
|---|---|---|
| active transaction generation | **Register** (exists) | `reg_tag`, 8b, packs generation + active; SALU returns `gen_in − stored` so "active AND my generation" is one compare inside the ALU |
| ACK deadline | **Register** (exists) | `reg_deadline`, 32b: 24b of 256 ns ticks in [31:8] |
| deadline-valid marker | **NOT a register** | it is **bit 0 of the deadline word**. `ARMED_MARK`/`UNARMED_WORD` + the single whole-container ternary `0x00000000 &&& 0x800000FF` tests armed-AND-due together. Do not re-introduce a separate `deadline_valid` register or flag |
| ACK-release generation | **Register** (new, 1) | `reg_ack_rel`, 8b, SALU-difference form (§1) |
| compact transaction state (`transaction_active`, `awaiting_ack`, `response_queued`) | **NOT registers** | `transaction_active` is already implied by `cur_gen ∈ 0xC0..0xCF` (`tbl_pktgen_active`, a masked ternary). `awaiting_ack` is implied by "deadline word still `UNARMED_WORD`" and is already enforced *atomically inside the SALU* by `deadline_arm_once` (writes only if `v == UNARMED_WORD`) — that is the one-shot. `response_queued` is implied by `rel_diff != 0` and does not need to persist |
| expected master acknowledgment / expected relay sequence | **Registers, 2 × 32b** (new, if §8 is implemented in full) | write at READ/ACK, read at RESPONSE, difference form. Inputs are parser fields (level 0) so they place in parallel at stages 1–3 → **0 added depth**, +2 Meter ALU, ~+4 LTIDs. **This is the largest un-costed item in the whole design — budget it now** |
| optional cleanup/watchdog | **NOT a new register** | the existing `hdr.ib.seq` pass budget + `budget_zero` fail-open already is the watchdog |

Net: **one new 8-bit register for the core mechanism**, two more 32-bit registers if the full §8
predicate lands. Total SALU accesses 6 → 7 (core) or 9 (with §8).

### SALU-per-stage ceiling

4 stateful ALUs per stage. Current per-stage: 0,1,1,0,1,0,0,3. Adding `reg_ack_rel` at stage 4
(1→2) and two predicate registers at stages 1–3 (each ≤2) leaves every stage at ≤3 of 4.
**The SALU ceiling is not binding for Defense 3.** dual_min hit 4/4 at stage 8 only because it
carried two deadline registers plus dual telemetry; Defense 3 carries neither.

Hard SALU rules that constrain the code shape (each cost a compile cycle to learn):
- **Max 2 PHV inputs per Register**, shared across all its RegisterActions — so two RegisterActions
  on one register must reference the same two fields.
- **Compare immediates must be small.** Use 0 as the no-write sentinel and arrange that no
  storable value is 0. `reg_ack_rel` satisfies this: stored values are `0xC0..0xCF` (a live
  generation), never `TAG_NO_WRITE = 0`.
- **One RegisterAction per action**, ≤2 access phases per register per packet.
- Sub-field tests are **ternary matches on the whole container, never slices**.

### PHV — the one real allocation risk

`phv_allocation_summary_0.log`: **MAU group B0-15 is at 16/16 containers (100%), 116/128 bits, all
ingress.** The 8-bit ingress metadata group is *container-exhausted*. Overall PHV is only 16.5%
used and B16-31/B32-47/B48-63 are empty, so there is plenty of raw space — but a new SALU whose
two 8-bit operands get split across MAU groups is exactly the shape that produces
`could not fit within the input crossbar by itself: Ingress.reg_X requires more than 2 PHV inputs`
or an unsatisfiable slicing constraint.

**Predicted #1 failure mode, with the fix pre-identified:** if `reg_ack_rel` fails placement with
fresh metadata fields, **reuse two fields that are provably dead on exactly the two paths that
touch it**:
- write operand → reuse `meta.tag_val` (both the released ACK and the fresh RESPONSE take the
  `tag_read` arm, which has no PHV input, so `tag_val` is dead on both; the sentinel semantics
  `0 = no write` are identical);
- result → reuse `meta.tag_diff` (dead on both paths for the same reason).

Both are already resident in B0-15 and already wired to the stateful input crossbar. This costs
**zero new PHV containers**. It couples two registers' liveness and hurts readability, so do it
only if the clean version fails — but have it in hand before the first compile rather than
after.

Tagalong: 3 ingress collections of 8 occupied, collection 0 at 100% containers / 122% bits
allocated. Read **collections occupied**, not the >100% bits figure — that is normal overlay
accounting, not an overflow. Defense 3 adds no header, so tagalong does not move.

**Constraints I am carrying forward and will not violate:** introduce **no new bit-slice** — a
slice in a gateway gives `condition expression too complex`, and a slice of a 32-bit arithmetic
field gives a PHV allocation failure. The only slice in the program is
`ig_intr_md.ingress_mac_tstamp[31:0]`, and it stays untouched. `rel_diff != 8w0` is a
whole-container compare, exactly like the existing `tag_diff != 8w0`.

---

## 4. Egress placement — variants A / B / C

**I disagree with §10's premise, and I want that on the record.**

§10 asks which *stateless* work can move to egress: internal role-marker cleanup, internal shim
removal, final stateless port/header rewrite, release-path counter, measurement-only release
timestamp. Item by item, against this specific program:

1. **Internal role-marker cleanup — does not exist.** The only internal header is `hdr.ib`
   (`0x88C1`) on blocker tokens, and blockers set `bypass_egress = 1`; they are dropped or
   re-enqueued in ingress and **never reach egress**. The 4-byte recirc tag on the pktgen trigger
   clone is written by the *ingress* deparser (`clone_mirror.emit`) and consumed by the dp68
   parser — zero egress cost, already. The held ACK and the held RESPONSE carry **no marker at
   all** (§1, gift 1). There is nothing to clean up.
2. **Internal shim removal — does not exist.** Same reason.
3. **Final stateless port/header rewrite — cannot move.** `ucast_egress_port` and `qid` are
   consumed by the TM at enqueue; egress runs *after* the queue. Queue selection is
   architecturally ingress-only on TF1. §10 itself lists queue selection as ingress-mandatory,
   which makes "final release rewrite in egress" self-contradictory for the one rewrite that
   matters.
4. **Release-path counter — can move, but only by paying for bridged metadata.** Egress cannot
   identify the released ACK from `eg_intr_md.egress_port` alone: all ordinary forwarded traffic
   also leaves via dp9 with `bypass_egress = 0`. (Discriminating by egress port alone works only
   when *all* ordinary traffic to that port bypasses egress — not the case here.) So variant B
   requires a bridge header: new PHV, a new egress parser state, and a deparser that must not
   emit it. That is a modification to the **byte-preserving pass-through** — currently egress
   extracts ethernet only and re-emits everything else as residual, which is precisely why byte
   identity is provable today. Trading that property for a counter is a bad trade.
5. **Measurement-only release timestamp — moving it makes the measurement WORSE.** The release
   instant is the moment the ACK leaves Q_HOLD, which *is* an ingress event: the packet re-enters
   ingress on dp8 and `ig_intr_md.ingress_mac_tstamp` at that pass is the true dequeue time. An
   egress timestamp would be taken on the *second* pass, after the forward hop, contaminating
   the release-tail measurement with a hop we currently exclude. Since the ACK is held and the
   relay leg is untappable, these on-chip registers are the *only* possible measurement of the
   hold — do not degrade them for a stage that is not needed.

**Architectural read: Variant A (all ingress) wins, and it wins by construction, not by a
close margin.** Ingress is predicted at 8 of 12 stages with four stages of margin; there is no
resource pressure for egress migration to relieve, and every candidate item is either
non-existent, architecturally immovable, or made worse by the move.

**Recommendation to the panel:** honour §10's requirement to *compile and report* A, B and C —
the directive wants the numbers and they are cheap (each is a ~1-minute probe compile with `-g`)
— but pre-register the prediction that A is the selection, and define B and C narrowly so they
are measurements rather than redesigns:

- **A** — all logic in ingress. Predicted **8 ingress / 0 egress**.
- **B** — A plus a 1-byte bridged role marker and one egress table counting released ACKs.
  Predicted **8 ingress (+1–2 LTIDs, +1 PHV byte) / 1 egress**. Measures the cost of bridging.
- **C** — B plus a 32-bit egress release timestamp register. Predicted **8 ingress / 1 egress**
  (the counter and the register are independent, so they co-locate in one egress stage; if they
  do not, C is 2 egress stages and immediately fails §10's own "no more than one egress stage").

Report for each: ingress stages, egress stages, critical path, LTIDs by stage, PHV
(MAU-group container occupancy, not just overall %), SRAM, Map RAM, TCAM, Meter/Stats ALU.

**What must NOT move to egress, explicitly:**
- queue selection (`ucast_egress_port`, `qid`, `bypass_egress`) — TM consumes it before egress;
- the deadline install and the deadline comparison (`reg_deadline`, `tbl_deadline_expiry`);
- transaction generation and generation matching (`reg_tag`), and `reg_ack_rel`;
- the early-versus-late RESPONSE decision;
- blocker classification, stale-token termination, and the fail-open decision;
- the READ / pure-ACK / RESPONSE classification (it is in the parser and must stay there);
- byte preservation — the egress pass-through must remain "extract ethernet, re-emit residual".
  If a variant cannot keep that property, it is disqualified regardless of its stage count.

---

## 5. Predicted stage count (ESTIMATE — not confirmed until bf-p4c runs)

**Variant A, core Defense 3 (single deadline, one blocker class, `reg_ack_rel`, K=64 pktgen,
Q_BLOCK/Q_HOLD, §8 predicates at the baseline's current strength):**

> **8 ingress stages / 0 egress stages / critical path 8 / ~62 logical tables / 7 SALU accesses.**

Reasoning:
- **Depth unchanged at 8.** Every new element fits inside an existing level: `relw` at L3 inside
  the table that already exists there, `reg_ack_rel` at L4 in parallel with `reg_deadline`, the
  early/late test at L6 inside the ACT block, the re-pointed release timestamp at L7. The
  critical path remains the telemetry chain `expired → ev_* → ts register`.
- **Width: +2 in the ACT region against 10 free LTIDs at stage 7**, +3 elsewhere against 13–14
  free per stage at stages 1–4.
- The floor is 8 and cannot be beaten while the ts bank stays (and it must stay — §3).

**Variant A with §8's full exact predicates** (expected master ack number + expected relay
sequence as two 32-bit SALU-difference registers): **8–9 ingress stages, critical path 8.**
Two more registers add 0 depth (parser-level inputs, parallel placement) but ~4 more LTIDs, and
if any of them lands in the ACT region the 10-slot stage-7 budget gets tight. Budget 9, target 8.

**Confidence and the pre-planned recovery.** Moderate — placement is recomputed from scratch
each compile and greedy packing has surprised this program family before (the dual_min +2 was
not predicted). If the first compile lands at 9 or 10:

1. Read `mau.resources.log`'s **Logical TableID column first**, before PHV, SALU or stages. If
   stages > critical path, it is LTIDs, full stop.
2. Apply the **inline lever** to the 15 bare-action tables (~12 of them in the ACT region).
   Measured on the sibling program at 16 leaves: 11 → 10 stages, then 10 → 9. Zero behavioural
   change. This is the reserve and it should be enough on its own.
3. Only then consider collapsing counter leaves or folding two forwarding leaves into one action
   with a metadata-selected `qid`.
4. Do **not** delete the ts-register bank to chase a number. It is the only instrument that can
   see the hold, and §3/§13 depend on it.

§11's ceiling is ingress ≤ 10/12 and egress ≤ 1. Variant A is predicted to clear it with two
stages to spare, which is the margin that lets the protocol engineer's §8 predicates land later
without a re-architecture.

---

## 6. Disagreements and flags, stated plainly

1. **§10 (egress variants) is investigating a problem this program does not have.** Every movable
   item is non-existent (no markers, no shims), architecturally immovable (queue selection), or
   degraded by the move (release timestamp). I will run the variants because the directive asks
   for the numbers, but B and C add bridged metadata to a byte-preserving path in exchange for
   nothing. Selection should be A. See §4.
2. **§7's `ack_release_gen == current_generation` is correct and load-bearing** (I show in §1 why
   `expired` alone is insufficient and why a stale boolean is wrong), but it should be
   *implemented* as an SALU difference (`rv = cur_gen − v`) rather than a store-then-MAU-compare.
   Same semantics, one MAU level cheaper.
3. **§9's `deadline_valid`, `awaiting_ack`, `transaction_active` and `response_queued` should not
   become state.** Three of the four are already implied by existing encodings (deadline marker
   bit, `UNARMED_WORD` atomic arm-once, `cur_gen ∈ 0xCn`), and `response_queued` is derivable.
   Adding registers or flags for them would widen the ACT block, which is the one resource that
   binds. This is consistent with §9's own instruction to collapse booleans.
4. **The DNP3 RESPONSE's `app_control` is not the READ's `app_control`** (CON bit). Any
   generation test on the RESPONSE built from `gen_in` will silently mis-fire. Flagged to the
   protocol engineer (Panel C) as well — it changes their predicate, not just my placement.
5. **§8's full ACK/RESPONSE predicate is the largest un-costed item in the design.** Expected
   ack number and expected relay sequence are two more 32-bit registers (or two more 32-bit exact
   key fields, which the control plane cannot populate for a live session). They are affordable
   — 0 added depth — but they must be budgeted in the resource ledger from the first compile, not
   discovered at gate 4. I recommend compiling a probe with them present *early*, even before the
   predicates are semantically finished, so the ledger has a real number.
6. **Do not delete the timestamp bank to buy a stage.** It is the critical path, so it is the
   tempting target; it is also the only instrument that can observe a hold whose relay leg is
   untappable. `reg_ts_first_resp_release` should be *re-pointed* to the ACK release
   (`dequeued==1 && role==ROLE_ACK`, a parser-derived predicate, so it keeps its float to an
   early stage), not removed. Any fifth timestamp belongs in the instrumented build only.

---

*Sources: `research/case_a_read_anchored_dual_release/p4/case_a_stripped_baseline.p4`;
`.../build_stripped_9.13.1/pipe/logs/{table_summary,mau.resources,phv_allocation_summary_0,
table_dependency_summary}.log`; `.../build_dual_min_9.13.1/pipe/logs/{table_summary,
mau.resources}.log`; bf-p4c 9.13.1. Everything marked ESTIMATE awaits a compile.*
