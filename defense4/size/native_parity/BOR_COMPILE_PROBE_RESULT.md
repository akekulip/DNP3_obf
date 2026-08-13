# BOR-in-RRC compile probe — result

**Question.** Does adding Bounded OPERATE Release (BOR) as an OPERATE-request-hold phase fit
inside the proven RRC kernel on **one** Tofino-1?

**Verdict (scoped): this ADDITIVE BOR formulation does not fit.** The full additive probe needs
**14 ingress MAU stages** (TF1 has 12); the same formulation with every auxiliary BOR feature
removed still needs **13**. Egress is unchanged.

**What is proven vs. not (claim correction, 2026-08-12).**
- **Proven:** *this additive probe* — which adds BOR as a set of new bare-action TM tables
  alongside the existing ones — is 14 stages, and 13 with the four aux features off.
- **NOT proven:** that *all* one-pipe BOR formulations are infeasible. The driver is **+26 logical
  tables** (125→151), not PHV and not SALU — the baseline tail stages are already at 16/16 logical
  table IDs, so the added tables spill forward. **Table consolidation is therefore an untested
  recovery path**, addressed by the stage-recovery matrix below (SR1: one final TM-dispatch table;
  SR2: fold parameter tables into `tbl_params`). An earlier closeout that called one-pipe BOR
  "infeasible on Tofino-1" over-stated this result and is corrected here.
- The proven RRC ingress is already 12/12 (itself squeezed from a first-round 13), so the margin
  is genuinely zero — consolidation must *net* remove stages, not merely rename tables.

- Probe source: `defense4/size/native_parity/p4/defense4_rrc_bor_compile_probe.p4`
  (byte-for-byte copy of the proven kernel + BOR; every added line tagged `BOR:`).
- Proven baseline (untouched): `defense4/size/native_parity/p4/defense4_rrc_kernel.p4`
  — compiles clean, ingress 12/12, egress 3.
- Compiler: `bf-p4c` from `~/bf-sde-9.13.1` (SDE 9.13.1). Compile-only; nothing loaded on hardware.

---

## 1. Exact bf-p4c command and error tail

```bash
~/bf-sde-9.13.1/install/bin/bf-p4c --target tofino --arch tna -g \
  -o <outdir> defense4/size/native_parity/p4/defense4_rrc_bor_compile_probe.p4
```

(`-g` only adds the resource logs; the pass/fail verdict is identical with or without it, matching
how the proven kernel is compiled.)

```
warning: Parser state min_parse_depth_accept_loop will be unrolled up to 3 times ...  (x2, benign; also present in the baseline)
0 errors, 2 warnings generated.
.../defense4_rrc_bor_compile_probe.bfa:7196: error: tofino supports up to 12 stages, using 14
.../defense4_rrc_bor_compile_probe.bfa:0: error: Due to errors, no binary will be generated
```

The front end is clean (0 errors) — the failure is **table placement**, not a language error. The
underlying placement thrash (from `stage_adv.log`) is:

```
can't place tbl_to_op_block_0 in stage 10 : ran out of memories: too many tables total
can't place tbl_to_op_hold   in stage 11 : ran out of memories: too many tables total
can't place tbl_to_block_0/1 in stage 9/10/11 : ran out of memories: too many tables total
can't place tbl_arm_clone    in stage 11 : ran out of memories: too many tables total
backtracking to stage 11 ...            (spills into stage 12 and 13 = the 13th/14th stages)
```

The tables that cannot place are the **OPERATE hold/release TM-action tables** (`tbl_to_op_hold`,
`tbl_to_op_block`) and the existing blocker-enqueue tables they now compete with
(`tbl_to_block`, `tbl_arm_clone`), all in the **already-full tail** (see §4).

---

## 2. Stage count: FIT/NO-FIT and the bisection

| Build | Ingress stages | Egress stages | Result |
|---|---|---|---|
| Proven RRC baseline | **12** | 3 | fits |
| **Full BOR probe** | **14** | 3 | **NO-FIT (+2)** |
| BOR − TOPJ (drop the 3rd deadline register `reg_topj`) | 14 | 3 | no-fit |
| BOR − T0ANCHOR (drop T0+A / T0+R OPERATE arming) | 14 | 3 | no-fit |
| BOR − CODEBOOK (drop `tbl_bor_codebook`) | 14 | 3 | no-fit |
| BOR − TSGATE (drop the TCP-timestamp violation counter) | 14 | 3 | no-fit |
| **BOR core only** (all four auxiliaries removed) | **13** | 3 | **no-fit (+1)** |

Bisection switches are compile-time and documented in the probe header
(`-DBOR_NO_TOPJ`, `-DBOR_NO_T0ANCHOR`, `-DBOR_NO_CODEBOOK`, `-DBOR_NO_TSGATE`).

### Minimum responsible feature

**There is no single removable feature that tips it over.** Removing any one auxiliary feature
still needs 14 stages, and the **irreducible OPERATE hold/release queue core alone needs 13** — one
stage more than the pipeline has. The bottleneck is therefore **the OPERATE hold/release machinery
itself**, not `reg_topj`, the codebook, the T0-anchored deadlines, or the timestamp gate. Concretely,
the core adds, all in the **ACT block that lands in the tail stages**:

- two new strict-priority TM-action tables — `tbl_to_op_hold` (qid2) and `tbl_to_op_block` (qid3),
  each a bare-action call that becomes its own logical table (the documented "inline-lever" cost);
- the split `CLASS_ARM` OPERATE branch (hold vs forward vs suppress-retransmit vs bypass);
- the qid3 reservoir-admission arm inside the pktgen-admit block;
- the qid3 dequeue-blocker arm and the dequeued-OPERATE→relay release arm.

These expand the logical-table count by **+26** (125 → 151). The tail stages that must absorb them
(0, 1, 7, 8, 9, 10) are already at **16/16 Logical Table IDs** in the baseline, so the new tables
spill forward and force two more stages. The four auxiliary features collectively account for the
gap between 13 (core) and 14 (full); individually each is small enough to be repacked without
freeing a whole stage.

---

## 3. Resource delta vs the proven RRC binary

| Resource | Proven RRC | Full BOR probe | Δ | Notes |
|---|---|---|---|---|
| Ingress MAU stages | 12 | **14** | **+2** | the binding wall (12 max) |
| Egress MAU stages | 3 | 3 | 0 | BOR adds nothing to egress |
| Logical tables (ingress) | 125 | **151** | **+26** | ACT-block tail explosion |
| Registers (SALU) | 12 | 13 | **+1** | `reg_topj` (the 3rd deadline register) |
| Counter objects | `ctr_fresh`,`ctr_deq`,`ctr_rrc` | + `ctr_ts_viol` | **+1** | plus new *indexed slots* `CF_OP_*` in `ctr_fresh` and `CD_OP_*` in `ctr_deq` (no new object) |
| Meter/Stats ALU | not saturated | not saturated | — | not the wall (baseline peak 3/4 meter-ALU, room existed) |

Registers and stateful/stats ALUs were **not** the constraint — only one new register was added and
the meter-ALU budget had headroom in the baseline. The constraint is purely stage/logical-table
count driven by the ACT-block tail.

---

## 4. PHV allocation delta

PHV is **not** the wall. The added metadata is deliberately all 16- or 32-bit so it lands in the
free `W32-47` / `H32-47` groups, never in the baseline's exhausted ingress groups.

Baseline ingress groups: `B0-15` 16/16 containers (exhausted), `H0-15` 16/16 (exhausted),
`W0-15` 16/16 @ 100% bits (exhausted); `W32-47` only 2/16 used.

Full-probe ingress groups (allocator re-packed given the extra stages):

| Group | Baseline containers | Full-probe containers | Note |
|---|---|---|---|
| `B0-15` (8b) | 16/16 | 15/16 | not touched by BOR (no new 8-bit ingress meta) |
| `H0-15` (16b) | 16/16 | 16/16 | new 16-bit meta absorbed via re-pack |
| `W0-15` (32b) | 16/16 (100% bits) | 11/16 | allocator freed/spread with more stages |
| `W32-47` (32b) | 2/16 | **14/16** | where BOR's 8 new 32-bit fields landed |

New ingress metadata (all 16/32-bit): `a_ticks`, `r_ticks`, `j_ticks`, `bor_ack_cand`,
`bor_resp_cand`, `topj_cand`, `age_topj`, `dl_val_topj` (32-bit); `expired_topj`, `ts_opt_present`
(16-bit). No new 8-bit ingress container was requested, so the exhausted `B0-15` group was
respected.

---

## 5. Control-plane / TM / pktgen changes the probe implies

- **TM queues (+2 rungs on the PORT_L loopback ladder):**
  - `qid3` = OPERATE blocker reservoir (drains at `T0+J`);
  - `qid2` = held original OPERATE.
  - New strict-priority order (high→low): qid7 ACK-block · qid6 ACK-hold · qid5 RESP-block ·
    qid4 RESP-hold · **qid3 OP-block · qid2 OP-hold**.
- **pktgen batch / packet_id:** one burst now seeds **three** reservoirs. `packet_id[7:6]` selects
  the slot — `0`→ACK/qid7, `1`→RESP/qid5, `2`→OP/qid3 — with `packet_id[15:8]==0` (id<256). The
  admissible range grows from **0..127 to 0..191**; `192..255` is rejected. The control-plane batch
  size therefore grows accordingly (e.g. 128→192 for three K-token reservoirs).
- **New tables to populate:** `tbl_bor_params` (keyless: A, R, default J), `tbl_bor_codebook`
  (flow-owner → J; keyed on relay dport, never on the DNP3 app-sequence, per the anti-subtraction
  rule), plus the always-present timing params in `tbl_params`.
- **New counters to read:** `ctr_ts_viol[0]` (anti-subtraction violation — non-zero means the
  protected OPERATE flow carried TCP timestamps and the timestamp-safe claim is INVALID);
  `ctr_fresh` slots `CF_OP_HOLD/CF_OP_BYPASS/CF_OP_RETRANS_SUPP`; `ctr_deq` slots
  `CD_OP_LOOP/CD_OP_TERM_{STALE,DL,TMO}/CD_OP_RELEASE`.

---

## 6. What the probe implemented (so the resource cost is genuine)

Faithful to `BOR_RRC_DESIGN.md`, added to the frozen RRC transaction engine:

1. **T0-anchored deadlines.** The OPERATE arm (a fresh master `ROLE_ARM`, `func==0x04`) arms
   `reg_deadline := T0+A`, `reg_tresp := T0+R`, `reg_topj := T0+J`, where `T0 = now` at the OPERATE.
   Storing the *absolute armed deadlines* is the minimal faithful realization of "store T0 and use
   it for T0+A / T0+R": the relay ACK's `deadline_arm_once` is then a no-op (already armed), so the
   ACK/echo release instants are T0-anchored and **never** re-anchored to the delayed release or the
   relay ACK. (Consequence: this needs no separate `reg_t0` register — the OP_RELEASE pass only
   forwards the original, it does not re-arm.)
2. **Queues.** `qid2` (held OPERATE) and `qid3` (OPERATE blocker reservoir, `reg_topj = T0+J`),
   built from the proven qid5/qid4 blocker/hold idiom; the original OPERATE is held byte-identically
   in qid2 and released to **dp64 exactly once** when qid3 drains.
3. **Phase machine.** OPERATE → hold in qid2; qid3 drains at T0+J → dequeued-OPERATE path forwards
   the original to the relay once and the transaction is in WAIT_ACK (deadlines pre-armed); ACK held
   in qid6 to T0+A; echo held in qid4 to T0+R and carved [28,21] by the existing PRE path.
4. **Bounded codebook.** `tbl_bor_codebook` selects J by flow ownership — never from the DNP3
   app-sequence.
5. **TCP-timestamp gate.** The parser flags the 12-byte NOP/NOP/timestamp option width
   (`ts_opt_present`); the MAU counts `ctr_ts_viol` for a protected OPERATE flow. It does **not**
   block — it records that the anti-subtraction claim is invalid when non-zero.
6. **Guards.** Retransmit-while-held → same generation ⇒ `V_ARM_DUP` ⇒ dropped (no second release);
   concurrent/OFF/FAIL_OPEN ⇒ bypass to relay + count; byte-identical original, single release, no
   padding/CRC-rewrite/seq-translation/fabrication.

### Two faithful deviations from the design doc (resource-neutral)
- **`reg_t0` is not a separate register.** T0 is stored as the absolute armed deadlines
  (`reg_deadline/reg_tresp/reg_topj`), which is the idiomatic minimal realization; it removes an SALU
  access on the loopback pass and does not change the fit verdict.
- **qid3 is seeded at the OPERATE's own arm burst, not at SELECT.** Seeding at SELECT (as the design
  prefers for residency) conflicts with generation-binding — SELECT and OPERATE are different DNP3
  transactions with different generations, so a qid3 token stamped with the SELECT generation would
  read *stale* the instant the OPERATE arms and the reservoir would collapse. Seeding at the OPERATE
  keeps the reservoir generation-bound. **The resource footprint is identical either way** (same
  qid3, same admission decode, same register), so the fit verdict is unaffected; only the
  control-plane batch timing differs. This runtime-residency tension is a real design finding worth
  carrying forward.

---

## 7. Bottom line

BOR cannot be added to the proven RRC kernel on one Tofino-1: **14 stages needed, 12 available**, and
even the bare OPERATE hold/release core needs **13**. The cause is structural, not incidental — the
proven ingress is already 12/12 with six tail stages at 16/16 Logical Table IDs, and the OPERATE
hold/release phase is intrinsically an ACT-block tail feature (new strict-priority queues, split
request handling, reservoir admission/drain). No single auxiliary feature is the culprit; the
machinery as a whole is one-to-two stages too large.

**Paths that could make it fit (not attempted here, for follow-up):**
- Move BOR into a **second pipe / second pass** (two-program or two-pass loopback) rather than
  co-residing with RRC on one pipe.
- **Fold TM-action tables** — the OPERATE hold/block are currently bare-action logical tables; a
  keyed classify-table that writes the qid as action data (the pattern that collapsed the RRC decode
  earlier) may recover 1 tail stage, but the core is +1 so folding alone will not reach ≤12.
- **Drop the RRC size-carve** on the OPERATE branch if timing-only OPERATE protection is acceptable,
  freeing egress and some ingress do_shape plumbing — but the wall is the ingress OPERATE tail, which
  the egress carve does not touch, so this is unlikely to be sufficient on its own.
