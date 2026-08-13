# Faithful two-pipe BOR — SELECT prepares a BOR epoch (COMPILE-PROVEN)

> **Scope.** This makes the two-pipe BOR split FAITHFUL: the FIRST OPERATE after a clean start is
> now **genuinely HELD and shaped**, not fail-opened. It supersedes the readiness caveat in
> `BOR_TWO_PIPE_PROPOSAL.md` (which carried the fail-open-first resource-probe behaviour on pipe 1).
> The reservoir is prepared **during the SELECT** (`BOR_RRC_DESIGN.md` §3), so qid3 is resident
> **before** the OPERATE. Compile-only on bf-p4c 9.13.1; nothing was loaded on hardware.

## Verdict — FEASIBLE and FAITHFUL

| program | role | ingress | egress | fit | bf-p4c |
|---|---|---:|---:|:--|:--|
| **pipe 0** `defense4_twopipe_pipe0_probe.p4` `-DPIPE0_SELECT_PREP` | frozen RRC + T0-admission + OPERATE handoff + **SELECT-prepare trigger** | **12** | 3 | **FITS** | 0 errors |
| **pipe 1** `defense4_twopipe_pipe1_faithful_probe.p4` | **faithful** BOR hold/release (SELECT-prepared readiness) | **10** | 0 | **FITS** | 0 errors |

Both compile clean and fit ≤ 12 ingress stages with the **first OPERATE genuinely held**. Real
`out/pipe/tofino.bin` produced for each (real placement, not just a table summary).

- **Pipe 0 stages: 12/3.** Adding the SELECT-detect + a fresh-epoch allocator (`reg_epoch`) + the
  cross-pipe SELECT-prepare crossing did **NOT** push pipe 0 over 12 — **no new fold was needed.**
  The `PIPE0_ARM_FOLD` headroom absorbed `reg_epoch` (a single SALU access at level 4, in parallel
  with `reg_deadline`/`reg_tresp`). Logical tables 137 → 143 (+6), stages unchanged. The
  `PIPE0_SELECT_PREP`-guarded additions are **inert with the flag off**: the baseline recipe
  (`-DTWO_PIPE_PIPE0 -DBOR_NO_TOPJ -DPIPE0_ARM_FOLD`, no `PIPE0_SELECT_PREP`) still places at exactly
  12/3 with 137 logical tables, byte-for-byte the pre-change control.
- **Pipe 1 stages: 10/0.** The faithful readiness is a real cost — it took the standalone BOR core
  from the fail-open-first **6** stages to **10** (see the honest negative below) — but 10 leaves
  two stages of margin under the 12-stage wall.

## The first OPERATE is now genuinely held (not fail-opened)

The sibling fail-open-first probe (`defense4_twopipe_pipe1_probe.p4`) reads an `op_ready` flag on the
OPERATE **before** the qid3 reservoir it depends on exists, so the FIRST real OPERATE always reads 0
and **fails open** (forwarded UNSHAPED); qid3 is armed asynchronously only *after*. That is safe
bypass, not a hold. The faithful design fixes this:

```
SELECT (func 0x03) crosses pipe 0 -> pipe 1  [carrying a FRESH BOR epoch, NOT the DNP3 generation]
  pipe 1:  reg_epoch := epoch  (BOR_PENDING, persists across SELECT completion)
           reg_ready := 0, reg_gen := 0        (a clean epoch)
           arm_clone()  -> seed the qid3 reservoir for THIS epoch (tokens stamped with the epoch)
           forward the SELECT byte-identically to the relay        (SBO needs it)
  qid3 tokens loop; a live (current-epoch) token confirms residency:  reg_ready := epoch   <- BEFORE the OPERATE
OPERATE (func 0x04) crosses pipe 0 -> pipe 1  [carrying T0 + the SAME epoch]
  pipe 1:  REQUIRE reg_epoch == epoch  AND  reg_ready == epoch
             match  -> select leak-safe J; arm reg_topj = T0+J; hold the byte-identical original in
                       qid2; release to the relay EXACTLY ONCE at T0+J.
             no match / unready -> forward the original once + ++CF_OP_FAILOPEN  (never enqueue).
```

Because SBO always sends SELECT before OPERATE, and the SELECT seeds+confirms qid3 first, the OPERATE
matches a **resident** reservoir on its **first** try. The offline model proves this directly:

```
first_operate_shaped(faithful select-prepared) = True
first_operate_shaped(SR4 fail-open-first)       = False   (correctly discriminated)
```

The epoch is an **internal monotonic id** allocated by pipe 0 (`reg_epoch`), never the 4-bit DNP3
application generation. A retired epoch is 0, so a **DNP3 sequence WRAP with no fresh SELECT** cannot
revalidate stale readiness — the epoch identity gates the hold, not the public sequence.

## Exactly-once + the full faithful lifecycle (offline proof)

`offline/bor_twopipe_faithful_emulator.py` models the faithful cross-pipe lifecycle with a byte-level
`relay_rx` ground truth (every frame the relay receives). Output: `evidence/.../faithful_emulator.out`.

**Clean model — 17/17 PASS**, including: `select_prepare_crosses_once`, `epoch_resident_before_operate`,
`first_operate_shaped`, `cross_pipe_operate_exactly_once`, `relay_receives_operate_exactly_once`,
`released_via_pipe1_hold`, `released_byte_identical`, `release_at_T0_plus_J`, `ack_echo_T0_anchored`
(ACK@T0+A / echo@T0+R, independent of J), `echo_carved_28_21`, `echo_byte_identical`,
`no_source_copy_to_relay`, `retransmit_operate_crosses_once`, `retransmit_relay_operate_once`,
`double_cross_backstopped_by_pipe1_dedup`, `fail_open_when_reservoir_not_ready`,
`seq_wrap_stray_fails_open`.

**Mutants — 8/8 KILLED** (each breaks the invariant it targets):
`first_operate_fail_open_mode` (SR4 → first OPERATE unshaped), `pipe0_cross_twice`,
`pipe1_duplicate_release`, `pipe1_no_dedup` (a cross-pipe **double-cross** doubles the relay only
without pipe-1's `reg_gen` backstop), `hold_when_reservoir_not_ready`, `stale_ready_after_seq_wrap`,
`source_copy_leaks_to_relay`, `reanchor_ack_to_release` (leaks J via response timing).

Nothing in the required contract was traded for the compile: exactly-once, T0-anchoring, leak-safe J
(codebook keyed on the relay-facing port, never on the DNP3 sequence or the epoch), fail-open-WITHOUT-
holding, and the RRC [28,21] echo carve are all present and mutation-tested.

## Cleanup / abort coverage (pipe 1)

- **retransmit while held** → `reg_gen` dedup → DROP (switch-level exactly-once; defence in depth for
  a pipe-0 dup-drop miss or a cross-pipe double-cross).
- **missing-OPERATE watchdog** → the qid3 reservoir exhausts its bounded budget; on that termination
  (`epoch_read` retires `reg_epoch := 0` for the live-epoch token) a late OPERATE fails open.
- **failed SELECT / connection replacement / new transaction** → the next SELECT-prepare resets
  `reg_epoch`/`reg_ready`/`reg_gen` (a clean epoch); a stray OPERATE with no live epoch fails open.
- **OPERATE release** → retire the whole transaction (`epoch_retire` + `ready_clear` + `gen_clear`).
- **unready reservoir / invalid match / concurrent generation / fail-open** → forward once + count,
  never enqueue; `reg_gen` armed so a retransmit still drops.

## The two placement levers (and one honest negative)

1. **`pclass` classifier (necessary).** The faithful pipe-1's first cut was **13 — NO-FIT**: compound
   three-field gateways (`dequeued && role && is_xpipe`, plus a 32-bit `ib.seq==0`) over-populated the
   `reg_epoch`/`reg_ready` stages and failed register co-location. One exact table `tbl_classify` folds
   `(role, is_xpipe, dequeued, is_pktgen)` into a single `pclass` byte, so **every** register access
   gates on one field. That fixed placement and brought it to **12**.
2. **topj-arm fold (the margin).** At 12 the critical path was 11 — a genuine serialized chain
   `epoch → blk_live → reg_ready → op_ready → hold_ok → topj-arm → topj → expiry`. Folding the
   `reg_topj` arm (`dl_val_topj := topj_cand`) **into** the `tbl_hold_ok` action (now keyed on
   `op_matched, op_ready, verdict`, the RRC `do_shape` idiom) removed the standalone arm stage →
   **12 → 10**, semantics-identical (the same `dl_val_topj` is written, one stage earlier).

**Honest negative (the readiness is NOT free).** The proposal anticipated pipe 1 would fit "well under
12" because the fail-open-first core was 6. The faithful readiness costs **+4 stages** (6 → 10): the
SELECT-prepared epoch introduces an inherent serialization — a qid3 token must compare its epoch to
`reg_epoch` (`blk_live`) *before* it may confirm residency into `reg_ready`, and the OPERATE's
`op_ready` then depends on `reg_ready`. That epoch → reg_ready → op_ready → hold_ok dependency is the
irreducible core of "SELECT prepares, OPERATE consumes". It still fits at 10/0 with margin, and pipe 0
stayed at 12/3, so the split is intact — but both pipes are now full-ish, not the wide-headroom picture
the fail-open-first probe suggested.

## Files

- `p4/defense4_twopipe_pipe0_probe.p4` — pipe 0; new `PIPE0_SELECT_PREP`-guarded SELECT trigger +
  `reg_epoch` + `xpipe.epoch`. Recipe: `-DTWO_PIPE_PIPE0 -DBOR_NO_TOPJ -DPIPE0_ARM_FOLD -DPIPE0_SELECT_PREP`.
- `p4/defense4_twopipe_pipe1_faithful_probe.p4` — **new**, the faithful pipe-1 (SELECT-prepared
  readiness, epoch-gated hold, `pclass` classifier, topj-arm fold). Standalone, no flags.
- `offline/bor_twopipe_faithful_emulator.py` — the faithful cross-pipe lifecycle model + mutation suite.
- `evidence/bor_two_pipe_faithful/` — `COMPILE_MATRIX.txt`, `pipe0/` + `pipe1/` (compile logs, table
  summaries, `mau.resources.log`, per-program `SUMMARY.txt`), `faithful_emulator.out`.
- Frozen and untouched: `p4/defense4_rrc_kernel.p4` (git diff 0 lines), the caseA files. The
  fail-open-first `p4/defense4_twopipe_pipe1_probe.p4` is kept unchanged as the 6-stage control.

## What is proven, and what is not

**Proven (compile + model):** both programs compile clean on bf-p4c 9.13.1 and fit ≤ 12 (pipe 0 = 12/3,
pipe 1 = 10/0), with real binaries; the first OPERATE is genuinely held (first_operate_shaped=True vs
SR4 False); exactly-once across the handoff / retransmit / cross-pipe double-cross; fail-open-on-unready;
stale-ready-after-wrap killed; no source copy to the relay; T0-anchored ACK/echo with the [28,21] carve.

**NOT proven (hardware-gated):** silicon behaviour (nothing loaded); the cross-pipe MAC-loopback timing;
the qid3 residency-continuity sizing (budget/rate vs J — a control-plane/hardware question); the physical
operation-time divergence floor (needs an authorized physical campaign); and the anti-subtraction claim
still requires a no-TCP-timestamp protected flow (`BOR_RRC_DESIGN.md` §2). A compile is not silicon.
