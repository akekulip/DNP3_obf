# RRC + BOR unified on ONE Tofino-1 pipe at ≤12 ingress stages — RESULT

**Verdict: YES — RRC + faithful-structured BOR fits ONE physical Tofino-1 pipe at 12 ingress
stages (4 egress), with a real `tofino.bin`.** The prior conclusion — that RRC + faithful BOR is
irreducibly 13 on one pipe and needs the two physical pipes — is **WITHDRAWN**. That negative was
an artifact of the *additive* approach (freeze the 125-table research kernel, bolt BOR on). This
work re-architected RRC around early packet-class dispatch, one outcome, one commit, and one
counter, which collapses the caseA "irreducible" 5-stage tail and frees exactly the headroom BOR
needs — on the same single pipe.

- Compiler: `bf-p4c` 9.13.1 (`~/bf-sde-9.13.1`), `--target tofino --arch tna -g`. **Compile-only;
  nothing loaded on hardware.**
- New file (frozen kernel **untouched**, `git diff` empty): `p4/defense4_rrc_bor_unified12.p4`.
  `-DU_BOR` turns BOR on; without it the file is the lean D4-only RRC.
- Frozen `p4/defense4_rrc_kernel.p4` is the behavioral **oracle** and was not modified.
- Evidence: `evidence/rrc_bor_unified12/<row>/` (per row: `compile.cmd` with src+bin SHAs,
  `compile.std{out,err}.log`, `table_summary.log`, `mau.resources.log`, `context.json`,
  `ANALYSIS.txt`).

---

## 1. The compile matrix

Ingress/egress are the **authoritative settled** counts (bf-p4c reports an INITIAL round then
re-places; the last `Number of stages` line in `table_summary.log`, cross-checked by whether a
`tofino.bin` was emitted). Every FITTING row emits a real binary.

| Row | Source / flags | ingress | egress | binary | fit | evidence |
|---|---|---:|---:|:--|:--|---|
| **A** | frozen RRC `defense4_rrc_kernel.p4` (reference) | **12** | 3 | yes | FITS | `A_frozen_rrc/` |
| **BC** | counter+commit collapse, full modes (`probes_snapshot_BC_commit_collapse.p4`) | **12** | 3 | yes | FITS | `BC_commit_collapse_fullrrc/` |
| **D** | D4-only + decision-table flatten (`unified12.p4`, no `-DU_BOR`) | **10** | 4 | yes | FITS | `D_d4only_decide/` |
| **F/G** | unified RRC + BOR + Random-J (`unified12.p4 -DU_BOR`) | **12** | 4 | yes | **FITS** | `F_unified_bor/` |

**F is also G:** the Row-F build already contains the leak-safe Random-J selector (the Tofino
`Random<bit<8>>` PRNG feeding a range-keyed `tbl_bor_codebook`), so there is no separate G row —
the "+ Random/range-J" step is included in F and costs +1 logical table / +0 stages.

Per-stage Logical-TableID occupancy (authoritative, fitting rows):

```
A  frozen  : s0:16 s1:16 s2:9 s3:3 s4:6 s5:2 s6:6 s7:16 s8:16 s9:16 s10:16 s11:3   (tail 7-11 = 5 stages)
BC collapse: s0:16 s1:16 s2:9 s3:3 s4:6 s5:2 s6:6 s7:16 s8:16 s9:16 s10:7  s11:1   (tail STILL 5 stages)
D  d4-only : s0:16 s1:16 s2:9 s3:4 s4:6 s5:2 s6:6 s7:3  s8:2  s9:1                 (10 stages; tail collapsed)
F  +BOR    : 12 ingress stages (decide s9-10, tbl_commit s11, BOR chain co-located with the RRC head)
```

---

## 2. Did the counter collapse move the tail 5→4? — NO. The decision-table flatten did.

The task's hypothesis was that collapsing the 36 scattered `ctr_fresh`/`ctr_deq` call sites into
one indexed counter (crossing the 64-LTID/4-stage threshold) would move the caseA tail from 5
stages to 4. **Measured, that is not what happens.**

- **Row BC** (counter collapse into one `tbl_commit` + `DirectCounter`, TM effects folded into it):
  the last two tail stages emptied (`s10: 16→7`, `s11: 3→1`) — capacity relaxed — but the tail
  **still occupies 5 stages** and total ingress **stays 12**. The reason: each ACT-block *leaf*
  still becomes its own anonymous logical table (`tbl_...l<line>`, one per `meta.outcome=` leaf),
  and the ~30 leaves + ~15 `cond-` gateways still fill stages 7/8/9 at 16/16 and force `tbl_commit`
  into a stage of its own. The collapse is a **capacity** relief, not a **depth** relief.

- **Row D** — the actual stage-shedder — is **change 1 fully realized**: the entire ACT branch
  tree is replaced by **two mutually-exclusive ternary decision tables** (`tbl_decide_fresh` /
  `tbl_decide_deq`, co-placed in ONE stage) whose `const entries` encode the disposition and feed
  the one `tbl_commit`. That removes the ~30 leaf tables + ~15 gateways, collapsing the 5-stage
  tail to **decide (1 stage) + commit (1 stage)** and taking lean D4-only RRC from **12 → 10**.

**Corrected finding:** the one-counter/one-commit collapse (change 2) is necessary but not
sufficient; the load-bearing lever is the **decision-table flatten (change 1)**. Stated plainly so
the record is not overclaimed.

---

## 3. What made BOR fit in the freed headroom

Row D leaves 2 ingress stages of headroom (10 of 12). BOR (`-DU_BOR`) consumes them and lands at
12 with a binary:

- **Separate BOR state domain (change 4).** Four registers — `reg_bor_epoch` (self-allocating:
  `epoch_prepare` increments, skipping 0, so a retired epoch is 0 and a DNP3 sequence wrap cannot
  revalidate stale readiness), `reg_bor_ready`, `reg_bor_gen`, `reg_bor_topj` — every access gated
  on a **single `bor_pc` byte**, so a qid3 OP token **never** reaches `reg_tag`/`reg_failopen`
  (the change-4 separation trap, made structural by the early class split).
- **`reg_topj` kept separate** (change 4/5): merging heavily-accessed deadline registers harms
  placement in this repo. `tbl_hold_ok` folds the T0+J arm (the RRC `do_shape` idiom).
- **Same one-outcome/one-commit path (change 2).** BOR dispositions (`OUT_OP_HOLD` qid2,
  `OUT_OP_ADMIT`/`OUT_OP_LOOP` qid3, `OUT_OP_RELAY` dp64, `OUT_OP_DUP`/`OUT_OP_TERM_*` drop) route
  through the same `tbl_commit` — no new terminal site.
- **Strict-priority ladder (change 6):** qid7 ACK-blk > qid6 ACK-hold > qid5 RESP-blk > qid4
  RESP-hold > **qid3 OP-blk > qid2 OP-hold**.
- **Leak-safe J (change 6/G):** `Random<bit<8>>` PRNG → range-keyed `tbl_bor_codebook`; J is never
  derived from a public DNP3 field.
- **No parser surgery:** the frozen parser already routes READ/SELECT/OPERATE to `ROLE_ARM`
  (distinguished by `func_code`), so SELECT→prepare and OPERATE→arm needed no new parser states.
- **Single-pipe simplification:** the epoch is allocated internally on SELECT (no cross-pipe carry
  that the two-pipe design required), and `T0` is the OPERATE's own ingress timestamp.

Each SALU limit hit during integration was resolved without weakening the mechanism:
`epoch_prepare`'s increment-skip-0 was rewritten as two mutually-exclusive writes; `epoch_read`'s
missing-OPERATE watchdog was folded to two comparisons via a precomputed `tok_spent` bit.

---

## 4. One-pipe verdict + resubmit

- **Fits ≤12 on one pipe: YES.** Row F/G = 12 ingress / 4 egress, real `tofino.bin`
  (`bin_sha` in `F_unified_bor/compile.cmd`).
- **Same-pipe resubmit fallback: NOT REACHED / NOT NEEDED.** The resubmit variant is required only
  if the *fully fused single-pass* build still needs 13. It fits at 12 in a single pass, so the
  two-pass split was not built. (The two *physical*-pipe split from the prior report also becomes
  unnecessary for this contract.)

---

## 5. Faithfulness — decision tables vs the frozen oracle (exhaustive)

The largest risk of change 1 is a wrong mask or priority in the decision-table `const entries`.
`offline/validate_decide_vs_oracle.py` transcribes the frozen kernel's ACT branch tree (restricted
to the kept modes OFF and D4) as a `(TM-effect, legacy-counter-slot)` function, transcribes the two
decision tables (priority-ordered), and enumerates the reachable per-packet state space.

```
enumerated 2,580,480 state tuples
FAITHFUL: decision tables reproduce the frozen ACT oracle on EVERY reachable tuple (D4/OFF). 0 mismatches.
```

The one initial divergence was the **structurally-unreachable** `mode=OFF & txn_active=1` RESP
state (OFF never arms, so `txn_active` is always 0 there); the matching OFF-RESP entry was added so
the table mirrors the oracle even on that unreachable state. Output:
`evidence/rrc_bor_unified12/emulator/decide_vs_oracle.out`.

## 6. Faithfulness — BOR lifecycle model + mutants

`offline/bor_unified_lifecycle.py` models the single-pipe BOR register semantics as written in the
P4 (self-allocating epoch, readiness confirm/read/clear, gen dedup, T0+J hold/release) with a
byte-level `relay_rx` ground truth.

```
CLEAN model: 10/10 invariants hold -> PASS
  (residency_before_operate, first_operate_held, operate_commit_exactly_once, retransmit_dropped,
   released_at_T0_plus_J, relay_gets_operate_once, no_source_copy, byte_identical_release,
   rrc_domain_untouched_by_qid3, stray_operate_fails_open)
mutants killed: 7/7
  retransmit_releases_second_copy, duplicate_release, source_copy_leaks_to_relay,
  qid3_touches_rrc_failopen, early_qid2_release, stale_ready_after_seq_wrap, ready_without_reservoir
```

Each mutant genuinely breaks its target invariant (non-vacuity was checked and two initially-vacuous
mutants were corrected). Output: `evidence/rrc_bor_unified12/emulator/bor_lifecycle.out`.

---

## 7. Honest boundary

- **Compile-fit ≠ silicon.** Rows A/BC/D/F place and emit binaries on bf-p4c 9.13.1; **nothing was
  loaded on hardware.** The cross-loopback timing, qid3 residency-continuity sizing (K vs J vs rate),
  strict-priority dequeue order, and the physical operation-time divergence floor all remain
  hardware-gated.
- **Behavioral model ≠ compile, and ≠ a full byte-precise PTF.** §5 exhaustively proves the
  *decision-table re-architecture* faithful to the frozen RRC oracle — that is the strong result.
  §6's BOR lifecycle is a **register-semantics model**, not a packet-level PTF against silicon: it
  validates the exactly-once / readiness / separation / T0+J invariants and kills the required
  mutants, but the fine wiring (e.g. seeding the OPERATE's own ACK/echo reservoir at release vs arm,
  and the precise pktgen `packet_id` ranges for the 2K/3K profiles) is compile-structured and would
  need the on-silicon campaign to confirm end-to-end. The BOR const-entry set for `tbl_commit` is
  control-plane-installed (like the frozen `tbl_session`/`tbl_state_decode`) and is modeled, not yet
  silicon-checked.
- **Invariants that would need re-silicon-validation if this replaced the shipped kernel:** the
  caseA exactly-once hold/release and blocker-termination behavior is now expressed through the
  decision tables + one commit rather than the original per-leaf tables. §5 shows the *disposition
  function* is identical, but a silicon regression of the caseA gates (as in the original bring-up)
  should be re-run before this build is considered a drop-in replacement.
- **Scope unchanged:** timing + OPERATE-hold shaping for a passive **upstream** observer; a
  downstream in-substation observer sees the released OPERATE directly (J cancels), out of scope, as
  in the prior reports. No DPI-parity, no multi-device claim.

## 8. Files

```
p4/defense4_rrc_bor_unified12.p4            the unified re-architecture (-DU_BOR = +BOR)
p4/probes_snapshot_BC_commit_collapse.p4    row BC snapshot (counter+commit collapse, full modes)
p4/defense4_rrc_kernel.p4                   FROZEN oracle (untouched, git diff empty)
offline/validate_decide_vs_oracle.py        exhaustive decide-vs-oracle equivalence (2.58M tuples)
offline/bor_unified_lifecycle.py            BOR lifecycle model + 7 mutants
evidence/rrc_bor_unified12/{A_frozen_rrc,BC_commit_collapse_fullrrc,D_d4only_decide,F_unified_bor}/
evidence/rrc_bor_unified12/emulator/        emulator outputs
```
