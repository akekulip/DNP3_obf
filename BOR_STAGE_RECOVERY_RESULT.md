# BOR stage-recovery compile matrix — result

**Question.** The additive BOR probe needs 14 ingress stages (13 with the four aux features off),
and the driver is **logical tables**, not PHV or SALU — the proven RRC tail is already 16/16
Logical-TableIDs. Does a **smarter one-pipe BOR** — consolidating tables — fit **≤12 ingress
stages** without trading away exactly-once OPERATE release, T0-anchoring, fail-open delivery, or the
RRC carve?

**Bottom-line verdict: NO.** The faithful consolidated one-pipe build (**SR1+SR2+SR3+SR4 + a
leak-safe J selector**) needs **13 ingress stages — one over the 12-stage budget.** Table
consolidation recovered exactly the one stage the four auxiliary features had added (14→13), but it
**cannot remove the 13th stage**, which is the irreducible OPERATE hold/release core (the same floor
as the BOR core with all aux off). The residual element over budget is the OPERATE-request
hold/release machinery itself, not any single removable feature.

- Compiler: `bf-p4c` 9.13.1 (`~/bf-sde-9.13.1`), `--target tofino --arch tna -g`. Compile-only;
  nothing loaded on hardware.
- Frozen kernel `p4/defense4_rrc_kernel.p4` and the frozen caseA files were **not** modified.
- SR probe (new, toggled with `#ifdef`): `p4/defense4_rrc_bor_sr_probe.p4`. With **no SR flags it
  reproduces the full additive BOR probe byte-for-byte** (14 stages / 151 tables — sanity row below),
  so every SR delta is measured against a faithful baseline.
- Raw evidence (per variant: full bf-p4c stdout+stderr, `table_summary.log`, placement-thrash
  excerpt, `metrics.json`, `SUMMARY.txt`): `evidence/bor_stage_recovery/<variant>/`.

---

## 1. The matrix

Ingress/egress stages and critical path are the **final** allocation (the last `Table allocation
done … state=REDO_PHV*/NOCC*` block in `table_summary.log`, NOT the INITIAL round — bf-p4c reports
INITIAL=13 for the proven kernel then settles to 12). "tables" = total ingress **logical tables**
(`metrics.json` `mau.logical_tables`). Egress is 3 in every row (BOR touches only ingress).

| Variant | flags | ingress | egress | crit path | logical tables | Δtables vs full-BOR | fit |
|---|---|---:|---:|---:|---:|---:|:--|
| **Proven RRC kernel** (baseline) | — (kernel) | **12** | 3 | 10 | 125 | — | **FITS** |
| Full additive BOR | none | 14 | 3 | 11 | 151 | 0 | +2 |
| BOR core (aux×4 off) | `BOR_NO_{TOPJ,T0ANCHOR,CODEBOOK,TSGATE}` | 13 | 3 | 10 | 144 | −7 | +1 |
| *SR probe, no flags (sanity)* | none | 14 | 3 | 11 | 151 | 0 | +2 (≡ full-BOR ✓) |
| **SR1** TM-dispatch (isolation) | `SR1_TM_DISPATCH` | **13** | 3 | 11 | 138 | **−13** | +1 |
| SR2 fold params (isolation) | `SR2_FOLD_PARAMS` | 14 | 3 | 11 | 150 | −1 | +2 |
| SR3 CP TS-gate (isolation) | `SR3_CP_TS_GATE` | 14 | 3 | 11 | 151 | 0 | +2 |
| SR4 readiness (isolation) | `SR4_READINESS` | 14 | 3 | 11 | 157 | **+6** | +2 |
| SR1+SR2 | `SR1 SR2` | 13 | 3 | 11 | 137 | −14 | +1 |
| SR1+SR2+SR3 | `SR1 SR2 SR3` | 13 | 3 | 11 | 137 | −14 | +1 |
| **SR1+SR2+SR3+SR4 (VERDICT)** | `SR1 SR2 SR3 SR4` | **13** | 3 | 11 | 143 | −8 | **+1 NO-FIT** |
| Part 4 random selector | `SR1 SR2 SR3 PART4_RANDOM` | 13 | 3 | 11 | 140 | — | +1 |
| Part 4 salted selector | `SR1 SR2 SR3 PART4_SALTED` | 13 | 3 | 11 | 140 | — | +1 |

**Per-stage Logical-TableID occupancy at the tail** (authoritative from `mau.resources.log`, which
bf-p4c only emits for a build that *fits* — so this is the **proven baseline**, the reference the
BOR tables spill into):

```
  s0:16  s1:16  s2:9  s3:3  s4:6  s5:2  s6:6  s7:16  s8:16  s9:16  s10:16  s11:3     (/16 max)
  stages at 16/16 (full LTID): 0, 1, 7, 8, 9, 10   ← six of twelve stages are already saturated
```

Failing builds (13/14 stages) do **not** emit the per-stage LTID table (bf-p4c aborts summary
logging: "Error producing mau.resources.log: 12"). Their tail is characterised instead by the
`table_summary.log` per-stage *listing* (tables incl. gateways/egress), which shows the overflow
tables spilling into stages **11 and 12** (full-BOR reaches stage **13**) while stages 0,1,8,9,10 stay
packed — e.g. verdict build: `… s8:16 s9:16 s10:16 s11:16 s12:14`.

**PHV and SALU are NOT the wall** (confirmed across the matrix):
- PHV normal groups stay in range every row (baseline `{8:20, 16:25, 32:30}`; verdict build
  `{8:19, 16:25, 32:39}` — the extra 32-bit metadata lands in the free `W32-47` region; tagalong
  unchanged `{8:11,16:28,32:16}`). No PHV overflow error occurred in any variant.
- SALU/register (the `Meter ALU` column): baseline **12**; full-BOR **13** (`reg_topj`); verdict
  build **14** (`+reg_op_ready`); salted selector **15** (`+reg_bor_salt`). Well under the TF1
  budget; no register-capacity failure. The one register-placement obstacle was a *co-location*
  error, not capacity — see §3.

**First placement failure per failing variant:** all are the same class — `bfa: tofino supports up
to 12 stages, using {13|14}`, driven by "too many tables total" on the OPERATE hold/release +
blocker-enqueue tables in the 16/16 tail (thrash excerpts in each `*/placement_thrash.log`; the named
overflow tables are `tbl_to_op_hold`, `tbl_to_op_block`, `tbl_to_block`, `tbl_to_hold` in the
un-consolidated builds, and their dispatched successors in the consolidated ones).

---

## 2. What each consolidation did, and whether it recovered stages

- **SR1 — one TM-dispatch table.** The six bare-action TM tables
  (`to_block`/`to_hold`/`to_resp_block`/`to_resp_hold`/`to_op_block`/`to_op_hold`) — each a bare
  action call that becomes its own logical table across ~10 call sites — are replaced by a compact
  `meta.tm_dest` code set at each site (folded into the leaf that already runs there) and **one**
  keyed `tbl_tm_dispatch` applied once per packet, whose actions write the identical
  `(PORT_L, qid, bypass_egress)`. **This is the only lever that recovered a stage: 14→13, by removing
  13 logical tables (151→138).** Semantics-identical: no-flags reproduces full-BOR exactly; the
  FWD/DROP/SHAPE paths keep `tm_dest = TMD_NONE` and the dispatch is a no-op for them, so nothing
  clobbers `ig_tm_md`.
- **SR2 — fold A/R/J into `tbl_params`.** The keyless `tbl_bor_params` (A, R, default J) is merged
  into the keyless `set_params`/`tbl_params` default action; the second keyless table is deleted.
  Removes exactly **1** logical table (isolation 151→150; on top of SR1, 138→137) but **recovers 0
  stages** — the freed table was not in the binding stage.
- **SR3 — control-plane TS-gate.** The data-offset-8 timestamp *inference* is removed from the
  parser (`data_offset==8` is **not** proof of TCP option kind 8), and the anti-subtraction violation
  counter now reads a **CP-set per-flow flag** carried as action data on the existing `sess_master`
  session entry (no new table). **Stage-neutral (0 table delta, 14→14; on top of SR1, 13→13)** — this
  is a *correctness* fix, not a stage saver, and the report states it as such.
- **SR4 — reservoir-readiness (faithful, required).** Implements the design's readiness-race
  resolution: the OPERATE is held **only when a confirmed-resident qid3 flag is set**, else it
  **fails open without holding** (forwards immediately, never racing its own reservoir). Costs one
  register (`reg_op_ready`, confirmed by a live qid3 loop, read at the OPERATE arm) plus the
  hold-vs-fail-open branch: **+6 logical tables** (isolation 151→157). It **adds** resource — as a
  correctness requirement must — and was **not** dropped to obtain a compile.

**Cumulative:** SR1+SR2 and SR1+SR2+SR3 both settle at **13 stages / 137 tables**; adding the
required SR4 gives the verdict build at **13 stages / 143 tables**. The 13th stage never falls: even
the most aggressive table removal here (SR1+SR2, −14 logical tables, 151→137) stays at 13, because
the binding constraint at 13 is the **OPERATE dependency chain** (decode → verdict → arm T0+{A,R,J}
→ hold decision; and dequeued qid3 → expiry → OP_RELEASE) packing into the already-16/16 tail, not
raw table count. Critical path rose from 10 (baseline/core) to **11** the moment the T0-anchored
OPERATE deadline arm is present, and 11 is now the depth floor.

---

## 3. Design finding — the readiness register co-location wall

The first SR4 build (read at level 5, confirm deep in the ACT block) failed with
`Table placement was not able to allocate tbl_…(read), tbl_…(confirm) in the same stage along with
Register Ingress.reg_op_ready`. A register's RegisterActions must share the register's single stage,
and a read pinned early plus a confirm pinned late cannot co-locate on an over-full pipeline. **Fix
(applied):** put **both** accesses at the same pipeline level (level 5, mutually exclusive branches —
a dequeued live qid3 token confirms residency; a fresh OPERATE arm reads it), which co-locates them.
After the fix SR4 compiles to a clean placement overflow (0 front-end errors), confirming the
readiness machinery is *implementable and faithful*; it simply does not create the head-room BOR
needs. This is a reusable TF1 lesson: cross-packet readiness state needs its read and its write at a
single pipeline depth.

---

## 4. Part 4 — a REAL leak-safe J selector (does it place, at what cost)

`tcp.dst_port → fixed J` (the existing codebook) is only a per-flow **profile lookup**: it shifts J,
it does not **convolve** it. A **fixed-J MVP therefore does NOT constitute Formby-fingerprint
mitigation** — it moves the operation-time distribution but does not randomize it, so an observer who
learns the per-flow J still subtracts it. Two leak-safe selectors were compile-probed, both drawing a
**bounded bucket index → per-flow delay profile**, and **neither keys J on the public DNP3 sequence**:

| Selector | source | places? | marginal cost vs SR1+SR2+SR3 (137 tbl / 13 st) |
|---|---|:--|---|
| **Part 4-A random** | `Random<bit<8>>()` TF1 RNG extern → low-nibble bucket → J table | **YES** | +3 logical tables (137→140), **+0 stages** (13), +0 registers |
| **Part 4-B salted** | `reg_bor_salt` (CP secret) XOR ingress-hw-timestamp low byte → nibble bucket → J | **YES** | +3 logical tables (137→140), **+0 stages** (13), +1 register (`reg_bor_salt`) |

Both are **front-end clean (0 errors)** and reach placement; `Random<bit<8>>()` is target-legal on
TF1 and `tbl_bor_jbucket` places (stages 2–4 in `part4_random`), so the RNG/salt/bucket machinery
allocates. The only failure is the **+1 stage overflow inherited from the consolidated base** (13),
not any selector-specific error. Gotcha resolved: the salted `(ts[7:0] ^ salt) & 0x0F` first hit
`--Werror=unsupported: action spanning multiple stages` (XOR-then-AND on a slice); split into one XOR
into `j_bucket` with the mask moved to the table key (`j_bucket[3:0]`) → single-stage action.

**Net:** a leak-safe selector adds only ~3 tables and **0 stages**; it is *not* what blocks the fit.
The selector is affordable — the OPERATE hold/release core is the wall.

---

## 5. Verdict

**Does the faithful consolidated one-pipe build (SR1+SR2+SR3+SR4 + leak-safe selector) fit ≤12
ingress stages? NO.**

- Residual: **13 ingress stages (1 over the 12 budget)**; egress 3; critical path 11; 143 logical
  tables (plus 3 for the selector = 140–143 depending on whether SR4's registers are counted with it).
- Element still over budget: **the OPERATE hold/release core** — the split `CLASS_ARM` OPERATE
  branch, the qid2 hold + qid3 reservoir admission/drain, the T0+J deadline comparator, the readiness
  gate, and the exactly-once OP_RELEASE pass. This is the **same 13-stage floor as the BOR core with
  all four aux features removed**, confirming the additive-probe prediction that "folding alone will
  not reach ≤12 because the core is +1."
- The consolidations that mattered: **SR1 alone recovered the one stage** (14→13, −13 tables). SR2 is
  table-positive but stage-neutral; SR3 is correctness-only and stage-neutral; SR4 is a required
  correctness cost (+6 tables). None of them, alone or combined, removes the 13th stage.
- **No invariant was traded away** to reach 13: exactly-once OP_RELEASE to the relay (single site),
  T0-anchored `reg_deadline`/`reg_tresp`/`reg_topj` arms, fail-open delivery (strengthened by SR4's
  fail-open-without-holding), and the RRC PRE carve are all present in the verdict source.

**Conclusion for the main session's gate:** one TF1 pipe cannot host RRC + faithful BOR; the deficit
is a hard **1 ingress stage** after maximal faithful consolidation. The two-pipe / two-pass split is
the remaining path — but that decision is gated on this verdict and is **not** built here.
