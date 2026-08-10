# W5 — Root cause of the Defense 4 `tag_retire_if_unmarked` lifecycle defect

**Scope:** workstream W5 of `research/size_timing_coresidency/reports/pi-scoping.md`.
**Method:** offline source reading, offline `bf-p4c` compiles, and re-derivation of every quoted
number from the committed raw per-block evidence dumps. **No switch contact.** No file under
`defense4/` or `defense3/` was modified.
**Analyst artifacts:** `research/size_timing_coresidency/evidence/retirement/`.
**Date:** 2026-08-10.

---

## 0. Status correction — read this before anything else

**The defect described in the assignment is not open. It was fixed on 2026-08-07 in commit
`e47bcaa`, and the fix is present in the working tree, in the compiled binary, and in the running
switch policy.** The task brief quotes `RESUME_STATE.md:46-63`, which is **stale**: it was last
rewritten at commit `5682bc7` ("overnight: correct durable state … after freeze reopen"), and
**39 commits have landed since**, including the repair itself.

| Question | Answer | Evidence |
|---|---|---|
| Is the defect open in the source? | **No.** Repaired at `e47bcaa` (2026-08-07 13:38). | `git show e47bcaa -- defense4/timing/p4/defense4_caseA.p4` |
| Is the repair in the deployed binary? | **Yes.** Source sha256 `1242ca4d…`, binary `97175e7d…`, BF-SDE 9.13.2. | `defense4/timing/evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md:13-16` |
| Is the repair proven on silicon? | **Yes**, across two independent campaigns, n=240 per mode. | re-derived below, §4 |
| Is `RESUME_STATE.md` current? | **No.** Its Defense 4 paragraph describes the pre-fix state. | see §7, recommendation R1 |
| Does the underlying *defect class* still threaten the size axis? | **Yes.** See §5 — this is the part that matters for the committee. | §5 |

I still traced the defect end to end, because (a) the assignment asks for the root cause at
file:line and the asymmetry explanation, and (b) the separability answer in §5 is only
trustworthy if the mechanism is understood rather than assumed. Everything below distinguishes
**traced** (read in the source or recomputed from raw evidence) from **inferred**.

---

## 1. The root cause, at a named file:line

### 1.1 One sentence

Defense 4 grafted Defense 2's *response-deadline hold* onto Defense 3's *transaction-tag
lifecycle*, in which **the release of the held ACK is a terminal event that clears the
transaction tag**. In every mode whose RESPONSE obligation outlives the ACK, that terminal event
fired first and destroyed the state the RESPONSE needed in order to be admitted to its hold
queue. It is not a race and not a hardware hazard: it is a designed ordering of two different
packets' ingress passes, and it is wrong for exactly the modes that need the response hold.

### 1.2 The offending line (pre-fix source, preserved at `bf641ac`)

Working copy of the pre-fix source:
`research/size_timing_coresidency/evidence/retirement/defense4_caseA_PREFIX_bf641ac.p4`

```p4
// defense4_caseA_PREFIX_bf641ac.p4:2398-2402
} else if (meta.pkt_class == CLASS_ACK_REL) {
    /* E1: THE REPAIR. Retire iff nothing is pending. cur_gen is the
     * PRE-state, so tbl_txn_active below reports WHICH branch ran:
     * txn_active == 1 -> it retired; == 2 -> a RESPONSE is queued. */
    meta.cur_gen  = tag_retire_if_unmarked.execute(0);
}
```

**This execute site is unconditional across all six modes.** That is the root cause. The register
action itself (unchanged, current source
`defense4/timing/p4/defense4_caseA.p4:1424-1429`) writes the inactive marker whenever the tag's
MSB is set:

```p4
RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_retire_if_unmarked = {
    void apply(inout bit<8> v, out bit<8> rv) {
        rv = v;
        if ((int<8>)v < 8s0) { v = TAG_INACTIVE; }
    }
};
```

`reg_tag`'s domain is `{0x00 = TAG_INACTIVE} ∪ {0xC0..0xCF}` (proved at
`defense4_caseA.p4:1211-1221`). MSB set means `0xCn` — "live, and no RESPONSE has marked itself
pending". So the released ACK retires the whole transaction whenever the RESPONSE has not yet
arrived.

### 1.3 The full execution path, traced

Line numbers below are the **current** source `defense4/timing/p4/defense4_caseA.p4` unless
marked *(pre-fix)*.

**(a) ARM — the master's DNP3 READ.** Parser gates FIR|FIN, CON=0, UNS=0, func 1 and sets
`ROLE_ARM` (`:1228-1233`, `:1247`). Class driver sets `CLASS_ARM` (`:2315`). `tag_arm`
(`:1361-1366`) writes the generation `0xCn` into `reg_tag`. The ACT block forwards the READ and
fires one 2K pktgen burst (`arm_clone()`, `:2688`), split by `packet_id` into the qid7 ACK
reservoir and the qid5 RESPONSE reservoir (`:2505-2522`). `reg_deadline` and `reg_tresp` are
disarmed to `UNARMED_WORD` (`:2056`). **`T_A` is not computed here** — TIMING_SPEC §6.

**(b) Native ACK arrives at `t_A`.** `CLASS_ACK` (`:2318`), decode `dec_ack_arm` under
full-width seq/ack/port masks (`:2148-2150`). `deadline_arm_once` writes `T_A = t_A + D_A`
(`:2446`) and `tresp_arm_once` writes `T_RESP = t_A + D_A + D_R` (`:2455`). The original ACK is
enqueued to qid6 by `to_hold()` (`:2656`, action at `:1794-1799`). It is now starved by the qid7
reservoir.

**(c) The qid7 reservoir drains at `T_A`.** Each looped-back blocker token re-reads
`reg_deadline` via `deadline_rmw` (`:2448`); `tbl_deadline_expiry` (`:2234-2242`) sets
`expired`; at `:2778` the token is dropped instead of re-enqueued. When the reservoir empties,
qid6 becomes eligible and the held ACK is dequeued onto the dp8 loopback.

**(d) THE ACK RELEASE PASS — where the transaction died.** The released ACK re-enters ingress
with `dequeued == 1`, `role == ROLE_ACK`, so the class driver assigns `CLASS_ACK_REL` (`:2333`).
Two levels later the *(pre-fix)* line 2402 executed `tag_retire_if_unmarked`. Because no RESPONSE
had arrived, `reg_tag` held `0xCn`, the MSB test passed, and **`reg_tag` was written to `0x00`**.
The ACT block then forwarded the ACK (`:2808`) and counted `CD_ACK_REL_RETIRE` *(pre-fix `:2775`)*.

**(e) The RESPONSE arrives at `t_R > T_A` and is bypassed.** `CLASS_RESP` (`:2321`), decode
`dec_resp` → `V_RESP` (`:2157-2159`). Generation binding is taken from the **raw** stored value,
not the response's own app_control (`:1378-1383`): `tag_read_or_mark` returns the pre-state into
`meta.cur_gen` (`:2411`), `tbl_txn_active` (`:2210-2219`) maps `0x00` to `mark_txn_inactive()`
→ `txn_active == 0`. In the ACT block the hold arm requires `txn_active == 8w1` (`:2589`), so the
RESPONSE falls through every arm to the final `else` and is **forwarded at native rate**,
counted `CF_RESP_BYPASS` *(pre-fix `:2611`)*.

**(f) Why the qid4/qid5 machinery never engaged.** `to_resp_hold()` is only reached from the
`txn_active == 8w1` arm, so qid4 was never occupied; and the qid5 reservoir's deadline drain
*(pre-fix `:2697`)* had nothing to release. Hence `CD_RELEASE_DEADLINE == 0` — exactly the
counter reported in `RESUME_STATE.md`.

### 1.4 "Why the retirement precedes the response being marked pending"

The tag's *pending* marker `0xCn → 0x1n` is written **only by the RESPONSE's own ingress pass**
(`tag_read_or_mark` at `:2411`, delta `TAG_PENDING_DELTA = 0x50` authorised at `:2085` /
`:2110`). The retirement is written **only by the released ACK's loopback pass**. These are two
different packets. Whichever reaches the ingress pipeline first wins. Therefore:

```
retirement precedes marking   ⟺   t_R > T_A   ⟺   native CLRT > D_A
```

That is the whole mechanism, and it is a **predictive** statement, not a description. §2 tests it.

**Inferred, not traced:** the released ACK's loopback traversal adds a small constant (the
measured loop RTT is (1036, 1176] ns on the Defense 3 build) to the retirement instant, so the
true threshold is `native CLRT > D_A + ε`. This is below the millisecond resolution of the
campaign data and cannot be separated from it.

### 1.5 Why the same line is correct in Defense 3 and absent from Defense 2

- **Defense 3** (`defense3/p4/case_a_defense3.p4:2259`) has the *identical* unconditional
  `tag_retire_if_unmarked` execute on `CLASS_ACK_REL`. Defense 4 inherited it verbatim. It is
  correct there because Defense 3 implements only D3 semantics (see §3).
- **Defense 2** (`research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4`) **has no ACK
  hold at all** — `:964-966`, "*HOLD_RESPONSE: the ACK is NEVER held — forward it now*". There is
  no loopback ACK-release pass, so no retirement event exists. And its RESPONSE admission is
  gated on **role and direction only**, with no transaction-tag conjunct:

  ```p4
  // dnp3_timing_normalizer_pktgen.p4:960-963
  } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
      to_resp();                        /* held on Q_RESP (qid1, LOW) */
  ```

  That is precisely why Defense 2 standalone held 200/200 and the integrated D2 mode held 0/240.
  **The integration added a precondition the original mechanism never had, and then arranged for
  that precondition to be false.**

---

## 2. The prediction test — is this actually the cause?

If the root cause is right, the fraction of RESPONSEs that bypass in a protected mode must equal
the fraction of transactions whose **native** CLRT exceeds that mode's `D_A` — and nothing else.
Recomputed from the raw per-block evidence dumps
(`research/size_timing_coresidency/evidence/retirement/recompute_counters.py`, output in
`recompute_counters.out`; no scorer summary or prose report was used):

| mode | `D_A` | predicted bypass = P(native CLRT > `D_A`) | measured pre-fix bypass (A+B, n=240) |
|---|---|---|---|
| D2 | 0 ms | 100.0 % (240/240) | **100.0 %** (240/240) |
| D4 | 4 ms | 26.7 % (64/240) | **33.3 %** (80/240) |
| D3 | 8 ms | 4.2 % (10/240) | **3.75 %** (9/240) |
| D1 | n/a — event release | 0 % (structural, §3) | **0 %** (0/240) |

Native CLRT distribution used for the prediction (OFF blocks, same campaigns, n=240): median
2.86 ms, p25 1.91, p75 4.14, p95 7.14, max 21.18.

The D4 residual (33.3 % measured vs 26.7 % predicted) is within block-to-block drift of the
relay's own CLRT — the prediction uses the OFF blocks' distribution, not the D4 blocks'. The
monotone collapse from 100 % at `D_A = 0` to 3.75 % at `D_A = 8` across three modes and two
campaigns is not reproducible by any other hypothesis I could construct.

**Corroborating counter identity.** Under the defect, every retirement must be matched by exactly
one bypass, because the retirement is what causes the bypass:

| campaign | mode | `ACK_REL_RETIRE` | `RESP_BYPASS` |
|---|---|---|---|
| pre-fix A | D2 | 120 | 120 |
| pre-fix B | D2 | 120 | 120 |
| pre-fix A | D4 | 40 | 40 |
| pre-fix B | D4 | 40 | 40 |
| pre-fix A | D3 | 5 | 5 |
| pre-fix B | D3 | 4 | 4 |

`ACK_REL_RETIRE == RESP_BYPASS` holds exactly, in every protected block, in both campaigns. This
identity is the defect's fingerprint and I use it as the regression assertion in §6.

**Corroborating distribution.** The D4 "mixture" in `RESUME_STATE.md` reproduces exactly: pre-fix
D4 CLRT (n=240) **p25 3.06, p50 8.00, p99 11.09** — the p25 is the bypassed third delivered at
native rate, the p50 is `D_R = 8 ms` exactly. Two populations, one distribution, and the median
confidence interval sat entirely inside the shaped population.

---

## 3. Why D1 and D3 survive it

This is the discriminating question, and the answer falls straight out of §1.4.

### D1 — structurally immune, not statistically lucky

In `MODE_D1_EVENT` the ACK blocker has **no deadline terminator at all**. Its only two exits are
the RESPONSE event and the fail-open budget:

```p4
// defense4_caseA.p4:2763-2777
} else if (meta.mode == MODE_D1_EVENT) {
    /* D1: event OR budget only — never the ordinary ACK deadline. */
    if (meta.verdict == V_BLOCK_PENDING) { ... release ACK ... }
    else if (meta.budget_zero == 8w1)    { ... fail-open ... }
    else                                  { ... keep holding ... }
```

`V_BLOCK_PENDING` is decoded only when `tag_diff == 0xB0` (`:2185-2186`), i.e. only when
`reg_tag` is already `0x1n` — which only the RESPONSE's own marking pass can produce. So in D1
**the marking is a precondition of the release**: retirement can never precede marking, except
via fail-open, where forwarding the response unprotected is the specified behaviour. Measured:
D1 `RESP_HOLD_EARLY` 240/240, `ACK_REL_RETIRE` 0, in both pre-fix campaigns. The defect is
*unreachable* in D1, not merely rare.

### D3 — mechanically affected, semantically immune

D3 **does** hit the same line — 9/240 pre-fix, and 39/240 post-fix at the smaller `D_A = 4 ms`
(the D3 path is byte-identical before and after the fix; the count moved only because `D_A`
moved from 8 ms to 4 ms, which is itself further confirmation of the `native CLRT > D_A`
predictor). It survives because in D3 `D_R = 0`, so `T_RESP = T_A`, and TIMING_SPEC §1 specifies
D3's RESPONSE behaviour as "*release after ACK commitment*" — nothing more. A RESPONSE arriving
after `T_A` has **already discharged its only obligation**, so forwarding it immediately is
correct. D3's shaping (CLRT collapses to ~0.03 ms) is produced entirely by *where the ACK is
placed*, not by holding the RESPONSE.

### The general law

> The defect bites exactly the modes in which the RESPONSE carries an obligation that outlives
> ACK commitment — i.e. `D_R > 0`. Those are **D2 and D4, and only D2 and D4**.

| mode | ACK obligation | RESPONSE obligation after ACK commit | outcome |
|---|---|---|---|
| OFF | none | none | true bypass by design |
| D1 | until RESPONSE event | none *(the event already happened)* | immune |
| D2 | none (`D_A=0`) | **hold to `T_RESP`** | **100 % destroyed** |
| D3 | to `T_A` | none (`D_R=0`) | semantically immune |
| D4 | to `T_A` | **hold to `T_RESP`** | **destroyed for the fraction with CLRT > `D_A`** |
| FAIL_OPEN | none | none | true bypass by design |

That table was written from the mechanism and it reproduces the measured pattern exactly,
including the ordering `D2 (100 %) > D4 (33 %) > D3 (3.75 %) > D1 (0 %)`. If any other
explanation predicts that ordering, I did not find it.

---

## 4. The minimal fix

### 4.1 It is already in the tree — commit `e47bcaa`

The repair is exactly what the analysis calls for: **make the terminal transition conditional on
the mode having no surviving RESPONSE obligation**, selected between two *existing* register
actions so that no fifth `RegisterAction` and no new PHV operand is needed (`reg_tag`'s
4-action cap and 2-PHV-operand budget are both hard walls — `:1384-1398`, `:1345-1360`).

```p4
// defense4_caseA.p4:2412-2425  (the core of the repair)
} else if (meta.pkt_class == CLASS_ACK_REL) {
    if (meta.mode == MODE_D1_EVENT || meta.mode == MODE_D3_ACK) {
        meta.cur_gen  = tag_retire_if_unmarked.execute(0);   /* unchanged */
    } else {
        meta.cur_gen  = tag_read_or_mark.execute(0);         /* pure read: PRESERVE */
    }
}
```

`tag_read_or_mark` degenerates to a pure read because the class driver zeroes the delta operand
first (`:2337`, `meta.tag_val = 8w0`), and `dec_ack_rel` (`:2069`) overwrites `tag_val` with
`cur_gen` at a later level, before `ack_rel_rmw` at `:2467`, so the ACK-release *generation
record* is unaffected. Six supporting changes complete the lifecycle:

| # | change | line (current) | why it is required |
|---|---|---|---|
| A | zero the preserve operand on `CLASS_ACK_REL` | `:2337` | makes the D2/D4 arm a pure read |
| B | mode-select the `reg_tag` action | `:2412-2425` | **the fix** |
| C | count a retire only when one happened | `:2817-2821` | `txn_active==1` no longer implies "retired" |
| D | qid5 blocker drains on `T_RESP` **only if** a RESPONSE is pending | `:2731-2739` | a live-but-unpending reservoir must not vanish at `T_RESP` and strand the next transaction |
| E/F | read-only `ack_rel_r` on `reg_ack_rel`, executed on `CLASS_RESP` | `:1526-1530`, `:2468-2473` | recovers `rel_diff` without the E1 write hazard |
| G | split the hold count by `rel_diff` | `:2602-2603` | `RESP_HOLD_LATE` becomes reachable and meaningful |

Change **D** is the one an incomplete fix would miss: once D2/D4 stop retiring on ACK release,
a transaction whose RESPONSE never arrives would otherwise have its qid5 reservoir silently
evaporate at `T_RESP`, leaving the next transaction unstarved. It routes that case to the bounded
fail-open budget instead.

### 4.2 Resource cost — verified by my own offline compiles, not quoted

I compiled both sources with `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c --target tofino
--arch tna -g`. Artifacts in `research/size_timing_coresidency/evidence/retirement/`.

| metric | pre-fix (`bf641ac`) | fixed (HEAD) | delta |
|---|---|---|---|
| ingress stages | **12** | **12** | **0** |
| egress stages | 0 | 0 | 0 |
| critical path through the table dependency graph | 10 | 10 | 0 |
| logical tables | 104 | **107** | **+3** |
| SRAM | 47 | 47 | 0 |
| TCAM | 10 | 10 | 0 |
| compiler result | 0 errors, 2 warnings | 0 errors, 2 warnings | — |

**The fix costs zero stages.** The three added logical tables are absorbed into existing stages —
this is the one thing that had to be checked, because the program has no stage headroom, and the
commit message itself flagged the LTID-saturated stage 8-11 tail as the placement risk. It
placed.

I also confirmed the mode conditioning **survived compilation** rather than being folded away.
From the fixed build's assembly (`build_head_9131/pipe/defense4_caseA.bfa:3241-3259`):

```
ternary_match tbl_defense4_caseA2422 4:
    gateway:
      name: cond-87
      input_xbar:  exact group 0: { 24: meta.mode }
      condition:
        expression: "(meta.mode == 1 || meta.mode == 3)"
        true:  tbl_defense4_caseA2422      # -> tag_retire_if_unmarked_0
        false: tbl_defense4_caseA2424      # -> tag_read_or_mark_0
```

and the existing SALU assembly gate still passes on the fixed build (`python3
defense3/analysis/assert_salu_asm.py build_head_9131` → **0 failures**, including the
`lss.s`/`lss.u` sign-test assertions on `tag_retire_if_unmarked_0` and `tag_read_or_mark_0`).

### 4.3 Hardware evidence that the fix works — re-derived from raw

Recomputed per-mode counter deltas, two campaigns, 240 transactions per mode
(`recompute_counters.out`):

| mode | pre-fix (A+B) | post-fix (A+B) |
|---|---|---|
| D2 | `RESP_BYPASS` **240**, `ACK_REL_RETIRE` **240**, `RELEASE_DEADLINE` **0** | `RESP_HOLD_LATE` **240**, `RELEASE_DEADLINE` **240**, `RESP_BYPASS` **0**, `ACK_REL_RETIRE` **0** |
| D4 | `RESP_HOLD_EARLY` 160, `RESP_BYPASS` **80**, `RELEASE_DEADLINE` 160 | `RESP_HOLD_EARLY` 180 + `RESP_HOLD_LATE` 60 = **240**, `RELEASE_DEADLINE` **240**, `RESP_BYPASS` **0** |
| D3 | `RESP_HOLD_EARLY` 231, `RESP_BYPASS` 9 (`D_A`=8) | `RESP_HOLD_EARLY` 201, `RESP_BYPASS` 39 (`D_A`=4) — by design, `D_R`=0 |
| D1 | `RESP_HOLD_EARLY` 240, `ACK_REL_RETIRE` 0 | `RESP_HOLD_EARLY` 240, `ACK_REL_RETIRE` 0 — unchanged |

The `RESP_HOLD_LATE` counter going from 0 (unreachable) to 240 in D2 is the direct positive proof:
those are exactly the responses that arrived *after* the ACK released and were nevertheless
**held**. That is the defect's inverse.

**Verdict on deliverable 3:** no new fix is required. The minimal fix exists, is stage-neutral,
is present in the assembly, and is proven. **A second proposal is not needed and I do not make
one.**

---

## 5. Separability — what a size/segmentation axis may and may not hang off

This is the part the wider committee needs, and the answer is more restrictive than the
timing-fix status suggests.

### 5.1 The release and retirement paths, enumerated

There are exactly four dequeued (loopback) arms in the ingress ACT block, plus two state-clearing
writes and one re-arm escape:

| # | path | line | writes `reg_tag`? | fires per transaction |
|---|---|---|---|---|
| R1 | qid7 ACK-blocker termination (deadline / event / budget) | `:2750-2791` | no | K times (drain) |
| R2 | qid5 RESP-blocker termination (`T_RESP` / budget) | `:2716-2748` | no | K times (drain) |
| R3 | ACK release pass (`CLASS_ACK_REL`) | `:2793-2821` | **yes — mode-conditioned** `:2412-2425` | once |
| R4 | RESPONSE release pass (`role == ROLE_RESP`, dequeued) | `:2823-2834` | **yes — unconditional** `:2344` → `:2427` | **assumed exactly once** |
| — | fresh-RESPONSE admission + one-shot pending marker | `:2584-2603`, `:1407-1416` | yes (marker) | **at most once** |
| — | R2 fail-open note (permits re-arm over a live tag) | `:2361-2363`, `:1361-1366` | via `reg_failopen` | once |

### 5.2 SAFE to hang a size mechanism off

- **R2, the qid5 RESPONSE-blocker termination (`:2731`).** This is the RESPONSE *timing* release
  trigger. It is generation-bound, reads only `reg_tag`'s pending marker and `reg_tresp`, and is
  now correctly conditioned (`V_BLOCK_PENDING && expired_resp`). A size mechanism that needs to
  know "the protected RESPONSE is being released now" should key on this.
  **Caveat, load-bearing:** it requires `reg_tag` to still be `0x1n`, which the fix guarantees in
  D2/D4 but *not* in D1/D3, where R3 retires. So a size mechanism hung on R2 is a **D2/D4-only**
  mechanism. Stating that up front is cheaper than discovering it on silicon.
- **R1, the qid7 ACK-blocker termination.** Purely ACK-side; never touched by any response-side
  state. Safe, but of little use to a size axis.
- **The fresh-RESPONSE admission point `to_resp_hold()` (`:2594`).** Exactly one per transaction,
  guarded by `txn_active == 1`. This is where a size classifier would naturally read the response.

### 5.3 CONTAMINATED — do not hang a size mechanism off these

- **R3, the ACK release pass.** Its retirement semantics are now **mode-split by construction**
  (`:2421`): D1/D3 retire, D2/D4 preserve. Any size logic keyed on "the ACK has left" would
  silently mean two different things in two different policies. This is the original defect's
  axis and it has been *contained*, not *removed* — the asymmetry is now explicit rather than
  wrong, which is the right engineering answer for timing but a trap for a second mechanism.
- **R4, the RESPONSE release retirement (`:2344` → `:2427`).** Still **unconditional, uncounted,
  and single-shot by assumption**. The comment at `:2338-2343` justifies it with "*Q_HOLD is a
  FIFO and the ACK was enqueued first*" — an argument about **one** response packet. It has no
  guard, no predicate, and no counter that would reveal a second firing.
- **The duplicate-suppression drop (`:2604-2638`) and the one-shot pending marker
  (`:1407-1416`).** Both were *purpose-built to make a second in-transaction RESPONSE
  impossible*. They are actively hostile to k > 1.

### 5.4 The k-segment question, concretely

> *If a response is emitted as k segments instead of 1, the state machine sees k release events
> where it assumes exactly 1. Does the current retirement logic survive that?*

**The retirement write itself survives; everything upstream of it does not.** R4 writes
`TAG_INACTIVE`, which is idempotent — k retirements are harmless. The breakage is in *admission*,
*marking*, and *reservoir liveness*, and it depends on how the k segments are produced. Three
cases, all traced in the source; **none has ever been observed on this testbed** (see §5.5).

**Case (i) — k TCP segments splitting one DNP3 frame mid-stream** (natural >MSS segmentation, or
CRC-boundary splitting as in `dnp3_split_harness`).
Segment 1's payload starts with `0x0564`, so the parser reaches `parse_dnp3_dl`
(`:1180-1183`) → `ROLE_RESP` → held. Segments 2..k start mid-frame, fail the `DNP3_START`
select, and fall to `accept` with `meta.role` left at its parser default `ROLE_BYPASS` (`:956`).
The ACT block's final `else` (`:2709-2711`) forwards them **immediately**, counted
`CF_BYPASS_FWD`.
**Consequence:** the head of the response is held to `T_RESP` while the tail leaves at native
time. A passive observer timing the *last byte* of the response sees no shaping at all, and
additionally observes TCP bytes arriving out of order — a *new* fingerprint the defense creates.
**The timing defense is defeated at k > 1 in this case, silently, with `RESP_BYPASS = 0` and
every current assertion green.** This is the single most important finding in §5.

**Case (ii) — k DNP3 link frames (real transport segmentation, FIR/FIN split).**
The transport gate `(tp_ctrl & 0xC0) == 0xC0` at `:1195-1198` rejects every frame of a
multi-segment response, routing them to `parse_dnp3_app_unsup` (`:1238-1244`) → `ROLE_RESP_UNSUP`
→ forwarded transparently and counted `CF_UNSUP_SEG` (`:2702-2707`). The defense simply does not
engage. This is honest (it is counted) and it is documented as a scope limit, but a size axis
that *creates* segmentation would be creating its own bypass.

**Case (iii) — k in-switch segments/copies at the same TCP sequence** (padding, decoys,
fixed-K real-plus-inert schemes).
Segment 1 is classified `V_RESP`, held, and marks the tag `0x1n`. Segment 2 passes the same
full-width seq/ack/port masks (`:2157-2159`), so it is also `V_RESP`, but now reads
`txn_active == 2` and lands on the duplicate-suppression arm — **`D3_DROP()` at `:2637`**. It is
silently destroyed, counted only as `CF_RESP_DUP_SUPP`. **A decoy/padding size mechanism that
reuses the TCP sequence number will have its decoys eaten by the timing engine's
duplicate suppressor.**
If instead the mechanism advances `seq` per segment, segments 2..k miss the full-width `seq_diff`
mask, decode as `dec_resp_bypass` (`:2160-2161`), and are forwarded immediately — case (i)'s
failure by a different route.

**Second-order effect, traced:** in any case where a second in-transaction response *did* reach
qid4, the first release through R4 writes `reg_tag = 0x00`. The qid5 reservoir tokens then read
`tag_diff = carried_gen − 0x00 = 0xCn`, which matches neither the `0x00` live entry nor the
`0xB0` pending entry (`:2183-2186`), so they decode `V_NONE` and terminate on the **stale** arm
at `:2727-2730`. The reservoir that starves qid4 collapses the instant the first segment leaves.
Whether the remaining segments then drain in FIFO order behind it, or race the collapse, is
**not determinable from the source** — see §5.5.

### 5.5 What I could not determine, and the experiments that would settle it

1. **k > 1 has never been observed on this testbed.** Every committed campaign row that records
   the field — **4780 of 4780**, across every `campaign_*/block_*.json` and
   `final_run/*/block_*.json` — has `resp_segments = 1`. (The two bring-up
   `transactions.jsonl` files predate the field and record it for 0 rows, so they neither
   support nor contradict this.) All of §5.4 is
   **source-derived, not measured**. *Experiment:* replay a >MSS DNP3 response (the
   `dnp3_split_harness` split server on the shaped path, or the built-and-offline-validated
   controlled software outstation in `defense4/timing/control/outstation/`) through the switch in
   D2 and D4, and record `CF_BYPASS_FWD`, `CF_UNSUP_SEG`, `CF_RESP_DUP_SUPP` deltas plus a
   master-side capture timing the **last** byte, not the first.
2. **qid4 drain order under mid-drain reservoir collapse.** The four-queue oracle proved strict
   *priority* ordering with finite backlog; it did not test k packets resident in qid4 while the
   qid5 reservoir goes stale. *Experiment:* enqueue 2 synthetic responses into qid4 on the
   synthetic build (`D3_SYNTH_EVENTS`) and read `ts_resp_release_w` for both.
3. **Whether `D_A = 0` is structurally, not just empirically, "ACK always released before the
   response".** The loopback tail is measured (~1 µs) against a native CLRT of ~1.9-21 ms. Safe
   in this lab; not a proof. *Experiment:* none needed for the timing claim, but a size axis that
   shortens the response path must re-check it.
4. **The R4 retirement has no counter.** I can see from the source that it fires once per released
   response, but there is no counter that would show a second firing, so I cannot confirm from the
   evidence that it has only ever fired once. See §6, assertion A4.

### 5.6 Recommendation to the size axis

The current pipeline has **one** RESPONSE obligation slot: one `reg_tag` marker, one `reg_tresp`,
one qid4 hold queue, one qid5 reservoir, one-shot marking, and an active duplicate suppressor.
A size/segmentation mechanism that changes the number of packets carrying a response is not a
new feature on this state machine — it is a **change to its cardinality**, and it must be
designed as one. Given that the program is at 12/12 ingress stages with the W0-15 PHV group full
(`DEFENSE4_BOTTLENECKS.md:34-40`), a per-segment obligation counter cannot be added in ingress
without first relieving that group or moving loop-only reads to the empty egress pipeline. **The
honest options are: (a) restrict the size axis to mechanisms that preserve k = 1 on the protected
path; (b) accept case (ii)'s explicit `CF_UNSUP_SEG` bypass as the segmentation boundary and
claim nothing for segmented responses; or (c) treat "generalize the lifecycle to k releases" as
its own funded workstream with an egress-bridging design.** Anything else will rediscover this
defect at a different line.

---

## 6. Regression test for this class of defect

The existing scorer (`defense4/timing/control/deploy/score_campaign.py`, hardened at commit
`42a3e3b`) already asserts the *mode-specific* consequences: `MUST_HOLD_MODES = {D2, D4}` with
`RESP_BYPASS > 0` hard-failing (`:299-300`), `ACK_REL_RETIRE == 0` for D2/D4 (`:319-320`), and
`RELEASE_DEADLINE == responded` (`:323-324`). Those are good, and they would catch a recurrence
of *this* defect in *these* modes. They would **not** catch the class. Five additions, in
priority order:

**A1 — the structural identity, mode-independent (offline, from counters).**
```
assert  cd.ACK_REL_RETIRE == cf.RESP_BYPASS      for every protected mode, every block
```
*Where:* `score_campaign.py`, next to the existing must-hold block, applied to **all** of
D1/D2/D3/D4 rather than only D2/D4. *Against what counter:* the two named counters, already
dumped per block. *Why it is the right assertion:* it is the defect's fingerprint and it is
**mode-independent** — it held exactly (240/240, 40/40, 5/5, 4/4) in every pre-fix block and is
trivially 0 == 0 post-fix in D2/D4 and 39 == 39 in D3. A future mode that retires early would
break the *equality* whether or not anyone remembered to add it to `MUST_HOLD_MODES`. That is the
property the current scorer lacks.

**A2 — the disposition partition, completed.**
```
assert  cf.RESP_HOLD_EARLY + cf.RESP_HOLD_LATE + cf.RESP_BYPASS + cf.RESP_DUP_SUPP == responded
```
*Where:* `score_campaign.py:310-313`, which currently omits `RESP_DUP_SUPP` and therefore cannot
distinguish "we dropped it" from "we never saw it". *Why:* case (iii) in §5.4 fails **only** here.

**A3 — the behavioural test that needs no counter at all.**
Run the protected mode at ≥3 values of `D_A` in one campaign and assert that the bypass fraction
is **flat and zero**, not tracking `P(native CLRT > D_A)` measured from the OFF block in the same
campaign.
*Where:* a new `--assert-bypass-invariant` mode in the campaign runner, or an analyzer beside
`recompute_counters.py`. *Why:* this is the only assertion that does not trust any single counter's
semantics. It is exactly the test that turns the §2 table from a post-hoc explanation into a gate,
and it would have failed loudly on the pre-fix binary at every `D_A`.

**A4 — the missing counter (a small source change, not just a test).**
R4's retirement (`:2344` → `:2427`) has no counter. Split `CD_RELEASE_DEADLINE` /
`CD_RELEASE_FAILOPEN` by the pre-state of the tag write, or add one slot, so that "a released
RESPONSE retired a transaction that was already inactive" becomes observable. Then assert
`released_responses == transactions_retired_by_response`. *Cost:* one counter slot in the
existing indexed array; `ctr_deq` is already touched exactly once on this path, so no new Stats
ALU. **This should be checked for stage impact before it is proposed as landed** — I did not
compile it.

**A5 — the segmentation guard, mandatory the moment the size axis lands.**
```
assert  cf.UNSUP_SEG == 0  and  all(row.resp_segments == 1)   # for any block claiming normalization
```
and, once k > 1 is intended, replace it with `held_segments == resp_segments` per transaction.
*Where:* `score_campaign.py` already collects `multiseg` and hard-fails it outside the
`multi_segment` scenario (`:271-272`); extend it to fail on `UNSUP_SEG > 0` in any block that
carries a normalization claim, since a response can be segmented at the TCP layer (case (i))
without ever setting the DNP3 multi-segment bit.

**A6 — keep the offline gate honest.** `defense3/analysis/assert_salu_asm.py` already fails the
build on a vacuous `lss.u` sign test. Add one assertion to it (or a Defense 4 sibling): the
`reg_tag` execute site on `CLASS_ACK_REL` must be reached through a gateway whose condition names
`meta.mode`. In the fixed build this is `cond-87`,
`expression: "(meta.mode == 1 || meta.mode == 3)"` in `defense4_caseA.bfa`. A future edit that
makes the retirement unconditional again would fail the build, offline, before any hardware time
is spent — which is where a defect of this class is cheapest to catch.

---

## 7. Recommendations

- **R1 (do this first).** `RESUME_STATE.md:46-63` is stale by 39 commits and states an OPEN defect
  that has been closed, deployed, and validated. It is the file the repo instructs every reader
  and every agent to read first, and it is currently the source of at least one mis-scoped
  workstream (this one). It should be brought forward to the `EXPERIMENTAL_EVIDENCE_FREEZE.md`
  verdict. **I did not edit it** — updating durable project state was outside this assignment.
- **R2.** `EXPERIMENT_MATRIX.md`'s mode table still carries the pre-fix rows ("D2 response
  deadline shaping — FAIL (documented boundary)") below a banner declaring them superseded. The
  banner is doing a lot of work. The rows should be rewritten rather than annotated, or a reader
  will quote the row.
- **R3.** Adopt A1, A2 and A6 now — they are cheap, they are offline or counter-only, and they
  generalize past this defect. A3 is the highest-value gate but needs a campaign slot. A4 needs a
  compile check. A5 is a hard prerequisite for the size axis.
- **R4.** Before any size/segmentation design review, settle §5.5 experiment 1. Everything in
  §5.4 is source-derived, and the testbed has produced `resp_segments = 1` in 4780 of 4780
  campaign rows that record the field, so the entire segmentation story is currently untested.

---

## Appendix — analyst artifacts

All under `research/size_timing_coresidency/evidence/retirement/`. Nothing in `defense4/` or
`defense3/` was modified; the switch was not contacted.

| file | what it is |
|---|---|
| `defense4_caseA_PREFIX_bf641ac.p4` | the pre-fix source, extracted from git at `bf641ac`, for line-accurate citation |
| `build_prefix_9131/` + `compile_prefix_9131.log` | offline bf-p4c 9.13.1 build of the pre-fix source |
| `build_head_9131/` + `compile_head_9131.log` | offline bf-p4c 9.13.1 build of the current source |
| `recompute_counters.py` | recomputes every counter and distribution quoted here, from the raw `ev_pre_*`/`ev_post_*` block dumps only |
| `recompute_counters.out` | its output (the source of every number in §2 and §4.3) |

Reproduce with:
```bash
cd /home/philip/Projects/DNP3/research/size_timing_coresidency/evidence/retirement
python3 recompute_counters.py
/home/philip/bf-sde-9.13.1/install/bin/bf-p4c --target tofino --arch tna -g \
    -o build_head_9131 /home/philip/Projects/DNP3/defense4/timing/p4/defense4_caseA.p4
python3 /home/philip/Projects/DNP3/defense3/analysis/assert_salu_asm.py build_head_9131
```
