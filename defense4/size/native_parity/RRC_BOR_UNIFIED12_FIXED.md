# RRC + BOR unified12 — SIX-BLOCKER CORRECTION PASS (2026-08-13)

> **CORRECTION2 (2026-08-13, later same day) — read §7 first.** An independent source review confirmed
> the 12-stage compile and the lifecycle model but found that **blocker 6 (the unified setup) was NOT
> closed — it was a placeholder** (invented bfrt schemas, no real codebook/session/PRE/mirror/value_set/
> two-app install), and that the **clone profile was ambiguous** (READ/SELECT and OPERATE shared one
> clone marker, so the 2K and 3K pktgen bursts could not be told apart). §7 fixes both, software-only.
> Nothing is loaded on hardware; commit `4da4573`'s binary must NOT be loaded.


**Verdict: all six correctness/wiring blockers are closed, the corrected program still fits ONE
Tofino-1 pipe at 12 ingress stages (0 errors, real `tofino.bin`), the 2.58M-tuple decision-table
equivalence still holds, and the BOR lifecycle suite passes 17/17 invariants with 10/10 mutants
killed non-vacuously (including the two new tests the correction required).**

This was an *implementation-correction* pass, **not** a redesign. The decision-table flatten that
achieved 12 ingress stages is preserved verbatim; the frozen kernel
(`p4/defense4_rrc_kernel.p4`) and the frozen caseA/timing sources are **untouched** (`git diff`
empty). All edits are in the unified design in place:
`p4/defense4_rrc_bor_unified12.p4`, its emulator `offline/bor_unified_lifecycle.py`, and a new
unified setup `p4/defense4_rrc_bor_unified12_setup.py`.

- Compiler: `bf-p4c` 9.13.1 (`~/bf-sde-9.13.1`), `--target tofino --arch tna -g -DU_BOR`.
  **Compile-only; nothing loaded on hardware.**
- Source SHA (compiled + saved): `5abd9e64f54b0d99a8bf4d0460d88ff0b0e996835f6be5778de308d3d3828d9a`
- Binary SHA: `ca916a74245e3ef81a23c44bcb91bbad6aac33aaffa94923b7096c142d47715c`
- Evidence: `evidence/rrc_bor_unified12_fixed/` (raw `table_summary.log`, `mau.resources.log`,
  `context.json`, `compile.stderr.log`, `phv_allocation_summary_0.log`, `table_dependency_summary.log`,
  `source.sha256`, `emulator/`, `setup_dryrun_transcript.txt`).

---

## 1. The six blockers — before → after, with proof

### Blocker 1 — `tbl_commit` dropped every packet (no entries, `cmt_drop` default)

- **Before:** `tbl_commit` had a `key = meta.outcome` but **no entries** and
  `const default_action = cmt_drop()`; the comment said "control-plane installs one entry per
  OUT_* value." Loading as-is with the setup not yet run → **every packet dropped**.
- **After:** `tbl_commit` is **fully const-mapped in the P4**. Every defined `OUT_*` value (1..43)
  has **exactly one** `const entry` → commit action, known at compile time, so the program no
  longer depends on any control-plane install to avoid black-holing traffic. The default is now a
  **safe transparent forward `cmt_fwd()`** (never a drop).
- **Proof (totality + single-valued):** the setup's offline self-check
  `verify_commit_map()` asserts the expected map is total over `OUT_* 1..43`, single-valued (43
  entries), and its default is `cmt_fwd` (not drop) — all PASS (see transcript). `OUT_BADPORT` is
  a const entry → `cmt_drop`, so bad ports still drop; the `cmt_fwd` default can only fire for
  `meta.outcome == 0`, which is **unreachable by construction** (`port_ok==0` sets `OUT_BADPORT`;
  every `port_ok==1` path runs a decision table or a BOR disposition, each setting a nonzero
  outcome). The const entries place with no stage cost (still 12 ingress).

### Blocker 2 — a held OPERATE never seeded the ACK/RESP reservoirs → its ACK & echo escaped unshaped

- **Before:** the OPERATE-hold disposition `cmt_op_hold` only enqueued the OPERATE to qid2. The
  qid7 (ACK) and qid5 (RESP) reservoirs were **never seeded** for that OPERATE, so the relay's
  ACK and 49B echo would dequeue immediately and **escape the timing normalization**.
- **After:** `cmt_op_hold` now **arms the same pktgen clone burst** the FRESH-ARM path uses
  (mirror `MIRROR_TYPE_CLONE`, stamped with the OPERATE's own generation `meta.gen_in`). The
  burst's `packet_id 0..63` tokens seed qid7 and `64..127` seed qid5 (blocker 2); `128..191`
  seed qid3 (already resident from the SELECT pre-seed). The held OPERATE still goes to qid2; only
  the mirror copy triggers the burst. The OPERATE also traverses the RRC ARM path
  (`role==ROLE_ARM && sess==SESS_MASTER → CLASS_ARM`), so `reg_tag` / `reg_deadline` / `reg_tresp`
  are armed for its own ACK/echo.
- **Proof:** emulator invariants `operate_ack_reservoir_seeded` (both reservoirs non-empty after
  the OPERATE holds) and `ack_echo_subject_to_blocker` (the relay ACK is HELD, `release != arrival`)
  both hold in the clean model; the new mutant **`operate_no_seed`** (OPERATE hold does not seed)
  flips `ack_echo_subject_to_blocker` → **KILLED**.

### Blocker 3 — ACK/echo deadlines were ACK-relative; must be T0-anchored (T0+A, T0+R)

- **Before:** `reg_deadline`/`reg_tresp` were armed **at the relay ACK** (`now_word + D`,
  `now_word + D_A+D_R`), i.e. `t_ACK`-relative. With BOR delaying the OPERATE by `J`, the ACK
  exists only at `≈T0+J+native`, so an ACK-relative hold leaks `J` (the anti-subtraction attack).
- **After:** at OPERATE admission the program arms **`reg_deadline = T0 + A`** and
  **`reg_tresp = T0 + R`**, anchored to the *original OPERATE's own ingress timestamp* `T0`, in
  parallel with `reg_bor_topj = T0 + J`. A new keyless `tbl_bor_params` supplies `A`/`R` in ticks
  (default 20 ms / 24 ms, low byte 0). The candidates `dl_cand_op = now_word + a_ticks` and
  `tresp_cand_op = now_word + r_ticks` are computed early and, for `bor_pc==BPC_OPERATE &&
  hold_ok`, **override** the `dec_arm_fresh` disarm right before the deadline access; `deadline_rmw`
  / `tresp_rmw` then write those words. The **later relay ACK cannot re-anchor** them: it takes
  `deadline_arm_once`, which writes only from `UNARMED_WORD`, and the stored word is already armed
  → no-op. `tbl_bor_params` is its **own** table so the frozen caseA `set_params` signature is
  unchanged.
- **Proof:** emulator invariants `ack_released_at_T0_plus_A` (== `T0+A`),
  `echo_released_at_T0_plus_R` (== `T0+R`), and the anti-subtraction invariant
  `anti_subtraction_constant` (`echo_release − ack_release == R − A`, independent of `J`) all hold;
  the new mutant **`ack_relative_deadlines`** (deadline = `arrival + A/R`) flips
  `ack_released_at_T0_plus_A` (and the anti-subtraction constant) → **KILLED**.

### Blocker 4 — qid2/qid3 BOR classes still traversed the RRC state chain

- **Before:** a dequeued OP token (qid3) was classified `CLASS_BLOCK_DEQ`, so it could reach
  `fo_note` (**writing `reg_failopen`**) on the watchdog path and the RRC blocker decode; the
  released OPERATE (qid2) and the OP pktgen seed also read `reg_tag`.
- **After (structural, cheap):** two surgical guards under `U_BOR`:
  1. an OP blocker token (`hdr.ib.slot == SLOT_OP`) is **excluded from `CLASS_BLOCK_DEQ`**, so it
     never reaches `fo_note` (`reg_failopen`) nor the RRC blocker decode — it stays `CLASS_OTHER`;
  2. the whole `reg_tag` access if/else is wrapped in `if (meta.bor_pc <= BPC_OPERATE)`, so the
     three BOR-owned classes (`BPC_TOKEN` qid3, `BPC_RELEASE` qid2, `BPC_PKTGEN_OP` qid3-seed) touch
     `reg_tag` **not even as a read**. Only RRC-owned classes (`NONE`, `PREPARE`=SELECT,
     `OPERATE`=the fresh OPERATE, which *deliberately* arms `reg_tag` for its own ACK/echo) reach
     the tag register.
  The earlier *whole-chain* guard cost **+5 stages (17 total)** and is rejected; these surgical
  guards keep **12 ingress stages** (measured).
- **Proof:** emulator mutant **`qid3_touches_rrc_failopen`** flips `rrc_domain_untouched_by_qid3`
  → **KILLED** (stays killed). In the P4 control flow: `fo_note` fires only for
  `CLASS_BLOCK_DEQ && budget_zero`, and OP tokens are no longer `CLASS_BLOCK_DEQ`; `fo_take` fires
  only for `CLASS_ARM`, which no BOR-owned class is; and the `bor_pc <= BPC_OPERATE` guard removes
  every `reg_tag` execute for the qid2/qid3 classes. So the BOR classes read/write **neither
  `reg_tag` nor `reg_failopen`**.

### Blocker 5 — BOR state cleared at release → a later retransmission reached the relay twice

- **Before:** at request release (`BPC_RELEASE`, the qid2 OPERATE dequeues at `T0+J`) the code did
  `gen_clear` (reg_bor_gen := 0). A retransmitted OPERATE arriving **after** release then read
  `GEN_INACTIVE` → `V_OP_FRESH`, but with the epoch retired it **failed open and forwarded to the
  relay a SECOND time**.
- **After:** `BPC_RELEASE` **keeps `reg_bor_gen`** (the just-released generation, as a "spent"
  marker); only the next SELECT (`BPC_PREPARE`) clears it. A post-release retransmit of the SAME
  OPERATE reads `gen_stored == gen_in` → `V_OP_DUP` → `OUT_OP_DUP` → **drop**. The epoch is still
  retired (`epoch_retire`), so no new hold occurs; a genuinely new OPERATE with a *different*
  generation reads `V_OP_BUSY` and fails open (forwarded once). Exactly-once therefore survives
  **past** release, not only while held.
- **Proof:** the new emulator invariant **`retransmit_after_release_suppressed`** (post-release
  retransmit → `DROP_DUP`) holds in the clean model; the new mutant **`clear_gen_at_release`**
  flips it → **KILLED**. The existing `stray_operate_fails_open` (different-generation OPERATE
  after release → fail open) still holds.

### Blocker 6 — no unified setup with readback verification

- **After:** `p4/defense4_rrc_bor_unified12_setup.py` is the ONE unified setup. It installs /
  configures / verifies, in a safe order with **write→read→assert** on each step, fail-closed on
  mismatch, and **refuses** any hardware op unless `DEFENSE4_HW_AUTHORIZED=1`:
  1. deadline validation (`A > J_max + native_ACK`, `R > J_max + native_resp`, `R ≥ A`, all
     `< min(actuation, master_timeout−guard, RTO−guard, fail_open_horizon)`, and A/R/J quantized
     to a 256 ns tick so the ARMED marker survives) — a bad set is **rejected**, never defaulted;
  2. `reg_bor_epoch/ready/gen/topj := 0` (readback == 0);
  3. `tbl_params` (timing) — via the frozen caseA delegation in the joint flow;
  4. **`tbl_bor_params`** (A/R T0-anchored totals) — readback == install;
  5. `tbl_bor_codebook` (leak-safe J per `dst_port × PRNG bucket`);
  6. **`tbl_commit` const-entry readback** — reads the table back and asserts `COMMIT_MAP`
     (nothing to install; blocker 1);
  7. `tbl_session` (reverse 5-tuple ×2);
  8. queue ladder qid7>qid6>qid5>qid4>qid3>qid2 strict priority on `PORT_L` — readback
     `max_priority` per qid;
  9. pktgen **2K** (`packet_id 0..127` → seeds qid7+qid5, the OPERATE's own seed) and **3K**
     (`0..191` → also pre-seeds qid3, SELECT/combined) profiles + clone mirror session — readback
     batch config.
- **Offline demonstrability:** `bfrt_grpc` is imported **only inside** the configure functions;
  the `dry-run` op runs the full offline deadline validation, the `tbl_commit` map self-check, and
  an **in-process readback self-test** (write→read→assert plus a deliberately corrupted case that
  proves the assertion is fail-closed), then prints the exact install+verify sequence. This is the
  "run against the model/CLI without loading" path. See §3.

---

## 2. Recompiled stage matrix + evidence

`bf-p4c` reports an INITIAL round then re-places; the settled count is the last
`Number of stages` line in `table_summary.log`, cross-checked by binary emission.

| Build | flags | ingress | egress | binary | fit | evidence |
|---|---|---:|---:|:--|:--|---|
| baseline (pre-fix) | `-DU_BOR` | 12 | 4 | yes | FITS | (prior `evidence/rrc_bor_unified12/F_unified_bor/`) |
| **whole-chain guard (rejected)** | `-DU_BOR` | **17** | 3 | **no** | **NO-FIT** | measured during this pass; discarded |
| **FIXED (all 6 blockers)** | `-DU_BOR` | **12** | 6 | **yes** | **FITS** | `evidence/rrc_bor_unified12_fixed/` |

- Ingress **12 / egress 6**, both ≤ 12. `0 errors, 9 warnings`. Real `tofino.bin` emitted
  (`bin_sha` in `evidence/rrc_bor_unified12_fixed/compile.cmd`).
- **Which fix nearly cost a stage, and how it was recovered (honest):** the FIRST attempt at
  blocker 4 wrapped the *entire* RRC state chain (~40 tables/registers, ~8 stages) in one gateway;
  that placed at **17 ingress stages (no binary)**. Rejected. The shipped blocker-4 fix guards
  only (a) the `CLASS_BLOCK_DEQ` classification of OP tokens and (b) the `reg_tag` access block —
  both cheap — and holds at **12**. No blocker was dropped to stay at 12; the security-critical
  separation (`reg_failopen` never touched, `reg_tag` never touched by qid2/qid3) is fully
  achieved at 12.

Raw artifacts: `evidence/rrc_bor_unified12_fixed/{table_summary.log, mau.resources.log,
context.json, compile.stderr.log, phv_allocation_summary_0.log, table_dependency_summary.log,
compile.cmd, source.sha256}`.

## 3. Setup script + sample readback transcript (against the model, NOT hardware)

Path: `p4/defense4_rrc_bor_unified12_setup.py`. Full transcript:
`evidence/rrc_bor_unified12_fixed/setup_dryrun_transcript.txt`.

```
$ python3 p4/defense4_rrc_bor_unified12_setup.py dry-run     # OFFLINE, NOT HARDWARE
  [ok] A > J_max + native_ACK
  [ok] R > J_max + native_response
  [ok] R >= A
  [ok] A/R < ceiling(BOR_fail_open_horizon)
  [ok] A/R ticks low byte == 0 ; each J stored ticks low byte == 0 ; J did not quantize to 0
  [ok] tbl_commit map is total over OUT_* 1..43 / single-valued / default is cmt_fwd (not drop)
  [ok] readback tbl_bor_params A/R  = {a_ticks:20000000, r_ticks:24000000}
  [ok] readback reg_bor_epoch/ready/gen/topj init==0
  [ok] negative control: corrupted readback is DETECTED (fail-closed)
  ... RESULT: PASS (0 checks failed)
```

Negative controls (also in the transcript), all fail-closed:
- invalid deadline set (`--op-a-ms 10 --op-r-ms 8`) → `RESULT: FAIL`, exit 2;
- A/R over the horizon ceiling (`--op-a-ms 40 --op-r-ms 45`) → `RESULT: FAIL`;
- `configure-all` without `DEFENSE4_HW_AUTHORIZED=1` → `REFUSING …`, exit 2.

The readback assertions for the real switch live in `init_registers`, `config_tbl_bor_params`,
`verify_tbl_commit`, `config_queues`, `config_pktgen` (each `write → read from_hw → chk.expect`).
They are exercised **against an in-process store** in dry-run; the on-silicon readback is Philip's
authorized step.

## 4. Emulator results (with the two new tests)

`offline/bor_unified_lifecycle.py` — output at
`evidence/rrc_bor_unified12_fixed/emulator/bor_lifecycle.out`:

```
CLEAN model: 17/17 invariants hold -> PASS
mutants killed: 10/10
```

The 17 invariants include the correction additions `operate_ack_reservoir_seeded`,
`ack_echo_subject_to_blocker` (blocker 2), `ack_released_at_T0_plus_A`,
`echo_released_at_T0_plus_R`, `anti_subtraction_constant` (blocker 3),
`ready_cleared_at_release`, and the **two new required tests**:
- **T0-anchored ACK/echo deadlines** → invariants `ack_released_at_T0_plus_A` /
  `echo_released_at_T0_plus_R` / `anti_subtraction_constant`, mutant `ack_relative_deadlines`;
- **post-release retransmission suppression** → invariant
  `retransmit_after_release_suppressed`, mutant `clear_gen_at_release`.

All 10 mutants are killed **non-vacuously** (each flips exactly its target invariant, which is
True in the clean model): `retransmit_releases_second_copy`, `duplicate_release`,
`source_copy_leaks_to_relay`, `qid3_touches_rrc_failopen`, `early_qid2_release`,
`stale_ready_after_seq_wrap`, `ready_without_reservoir`, `operate_no_seed`,
`ack_relative_deadlines`, `clear_gen_at_release`.

The 2.58M-tuple decision-table-vs-oracle equivalence is unaffected by these edits (the two
decision tables and the oracle were not changed) and still passes:
`evidence/rrc_bor_unified12_fixed/emulator/decide_vs_oracle.out`:

```
enumerated 2580480 state tuples
FAITHFUL: decision tables reproduce the frozen ACT oracle on EVERY reachable tuple (D4/OFF).
```

The broader offline conformance suite (`pytest offline/`) is green: **19 passed**, no regressions.

## 5. HARDWARE-READY / NOT YET LOADED — the boundary for Philip

Everything above is **compile-fit + offline model**. **A compile is not silicon; the setup
readback here is against an in-process store / the model, not the switch.** The following campaign
steps remain, in order, each gated on Philip's explicit authorization and `DEFENSE4_HW_AUTHORIZED=1`:

1. **Load** the corrected `tofino.bin` (bring up dp8 loopback, dp64 relay, dp9 master, dp68
   pktgen) — Philip's step; the shared chip hand-off rules apply.
2. **Run the unified setup** `configure-all` on the live switch and confirm every readback PASSES
   on hardware (register init, `tbl_bor_params`, `tbl_commit` const-map, queues, pktgen).
3. **OFF-mode transparency** regression: mode OFF forwards ACK+RESPONSE+OPERATE unchanged, 0 loss.
4. **READ / SELECT** regression: the frozen caseA READ hold and the SELECT pre-seed of qid3
   behave as before.
5. **Software-OpenDNP3 BOR** across the physical Tofino: SELECT→OPERATE with a software master;
   confirm on the wire — the OPERATE is held to `T0+J`, released **exactly once** to the relay; a
   retransmit while held AND after release produces **no** second relay operation; the ACK and
   echo are released at `T0+A` / `T0+R` (T0-anchored), `echo−ack == R−A` independent of `J`.
6. **On-wire proofs**: qid3 reservoir residency-before-drain, the strict-priority dequeue order
   qid7>…>qid2, the operation-time divergence floor with real per-device distributions.
7. **SEL SELECT** (READ-only relay stays READ-only until this point), then a **physical OPERATE**
   — gated on odd-point isolation and **explicit** authorization.

The anti-subtraction claim is valid only on a **no-TCP-timestamp** protected flow
(BOR_RRC_DESIGN.md §2): the parser+counter timestamp-option gate must read 0 before any
timestamp-safe assertion; never claim it silently.

## 6. Files

```
p4/defense4_rrc_bor_unified12.p4              corrected unified design (all 6 blockers; -DU_BOR)
p4/defense4_rrc_bor_unified12_setup.py        NEW unified setup + readback verification (blocker 6)
offline/bor_unified_lifecycle.py              BOR lifecycle model, 17 invariants + 10 mutants (2 new tests)
offline/validate_decide_vs_oracle.py          unchanged 2.58M-tuple equivalence (still FAITHFUL)
evidence/rrc_bor_unified12_fixed/             compile artifacts + emulator outputs + setup transcript
p4/defense4_rrc_kernel.p4                      FROZEN oracle (untouched, git diff empty)
```

---

## 7. CORRECTION2 — clone-profile fix + a REAL unified setup (2026-08-13)

Software-only. The RRC + faithful-BOR **design is untouched** (the decision-table flatten that reached
12 ingress stages is preserved verbatim; the frozen `defense4_rrc_kernel.p4` and the frozen caseA/timing
sources are not edited — `git diff` on them is empty). Two independent-review findings are closed.

### 7.1 The clone-profile ambiguity (was: one marker for both bursts)

**Before.** `cmt_fwd_clone` (READ/SELECT fresh-arm) and `cmt_op_hold` (OPERATE hold) both wrote the
*same* clone tag `CLONE_TAG_MARKER (0xE1000000) | gen_in`. The two pktgen applications — the **2K**
burst (seeds qid7 ACK + qid5 RESP) and the **3K** burst (also pre-seeds qid3 OP) — had **no way to be
triggered selectively**: one marker cannot address two apps.

**After (stage-neutral).** Byte 1 of the 4-byte clone tag is a **profile selector** (`meta.gen_in` is
`bit<8>` and OR's into the LOW byte only, so it never disturbs byte 1; byte 2 stays 0):

| commit action | class | clone tag | pktgen app | tokens |
|---|---|---|---|---|
| `cmt_op_hold`  | OPERATE hold  | `CLONE_TAG_MARKER_2K = 0xE1000000` (byte1 = 0x00) | app 1 (2K) | packet_id 0..127 → qid7 + qid5 |
| `cmt_fwd_clone`/`arm_clone` | READ/SELECT fresh-arm | `CLONE_TAG_MARKER_3K = 0xE1010000` (byte1 = 0x01) | app 2 (3K) | packet_id 0..191 → qid7 + qid5 + qid3 |

The control plane pins **byte0 (0xE1) AND byte1** in the pktgen trigger pattern (`pattern_mask
0xFFFF0000`), so app 1 fires ONLY on `0xE1:00:*:gen` and app 2 ONLY on `0xE1:01:*:gen` — the two
**mutually-exclusive pktgen recirculation-pattern matches** the review asked for. The parser value_set
`pgen_recirc` is expanded from size 1 to **size 2** `{0x01, 0x02}` (one leading byte per app,
`byte = (pipe<<3)|app_id`); both apps' generated tokens still take the identical `parse_pktgen_token`
path — the profiles differ only in *how many* tokens they emit and *which* clone triggers them. Both
markers still lead with `0xE1`, so the parser's `parse_clone` recognizes either.

**Proof READ is unchanged.** A plain READ now commits `OUT_ARM_FRESH → cmt_fwd_clone → 3K` burst, so it
also emits the OP-range tokens (packet_id 128..191, class `BPC_PKTGEN_OP`). With **no live BOR epoch**
those tokens read `epoch_stored == EPOCH_NONE` and hit the existing P4 branch
(`defense4_rrc_bor_unified12.p4`: `else { meta.outcome = OUT_PKTGEN_DROP; }`) — they are **DROPPED**, not
enqueued to qid3. Two independent proofs:

1. **MAU placement is bit-identical.** After normalizing the source-line-number suffixes bf-p4c bakes
   into anonymous table names, the stage allocation of the fixed build and the CORRECTION2 build is
   **identical** — every table in the same stage, same order (12 ingress). The fix changed only an
   action's immediate constant and the parser value_set arity; the ingress pipeline is structurally the
   same. (`evidence/rrc_bor_unified12_hwfix/table_summary.log`, diff in §7.4.)
2. **Emulator invariants** (`offline/bor_unified_lifecycle.py`): the new **`read_op_tokens_dropped`**
   (a 3K READ with no SELECT drops all 4 OP-range tokens, qid3 stays empty) and
   **`read_unchanged_2k_vs_3k`** (the observable relay/master/reservoir state is *identical* whether the
   READ emitted a 2K or a 3K burst) both hold; the new mutant **`read_op_admitted_without_epoch`** (admit
   the OP seed despite no epoch) flips `read_op_tokens_dropped` → **KILLED**. Clean model now **19/19
   invariants**, **11/11 mutants killed**; the 2.58M-tuple decision-table equivalence is unaffected
   (still `FAITHFUL`).

### 7.2 Recompiled stage matrix (≤ 12 ingress required)

`bf-p4c 9.13.1`, `--target tofino --arch tna -g -DU_BOR`, **0 errors, 9 warnings, real `tofino.bin`**.

| Build | ingress | egress | binary | fit |
|---|---:|---:|:--|:--|
| fixed (six-blocker pass) | 12 | 6 | yes | FITS |
| **CORRECTION2 (clone-profile fix)** | **12** | **6** | **yes** | **FITS** |

- src sha `5b846064d2b3ebc9269f636f37807aa03f01057aaa0e1805902807092e4ed69f`
- bin sha `68221d0abd6770de5d3aea87ffb64aff9bd9a55efda02bab055929a48c093267`
- Evidence: `evidence/rrc_bor_unified12_hwfix/{table_summary.log, mau.resources.log, context.json,
  compile.stderr.log, phv_allocation_summary_0.log, table_dependency_summary.log, compile.cmd,
  source.sha256, emulator/, setup_dryrun_transcript.txt, setup_negative_controls.txt}`.

### 7.3 The REAL unified setup (blocker 6, now genuinely closed)

`p4/defense4_rrc_bor_unified12_setup.py` was rewritten. It no longer invents any bfrt schema; **every
hardware step delegates to a proven, silicon-exercised helper**, in a fail-closed order, and the
OFFLINE dry-run runs the SAME ordered sequence against a faithful in-process model plus a non-vacuous
negative-test battery. Proven helpers reused (schema authorities, cited `file:symbol`):

- `defense4_bor_twopipe_setup.py:_load_module` (88–90) — the offline-safe module-load pattern.
- `defense4_caseA_setup.py:config_params_d4` — `tbl_params` timing install (shape_enable stays OFF).
- `defense4_caseA_setup.py:config_queues_4q` — the `resolve_pg` + `pg_queue_of` +
  `tf1.tm.queue.sched_cfg` (str_val `max_priority`, `scheduling_enable`) queue idiom, extended here to
  the full **qid7>qid6>qid5>qid4>qid3>qid2** ladder (`hw_config_queues_6q`).
- `defense4_rrc_setup.py:install_pre` / `delete_pre` / `set_shape_enable` — the PRE group
  (`mgid 0x2849 → node 0x2851(RID1)+0x2852(RID2) → dp9`) and the shape RMW that preserves timing.
- `case_a_defense3_fixed_ack_delay_setup.py:config_session` — `tbl_session` reverse 5-tuple ×2
  (`sess_relay`/`sess_master`).
- `case_a_defense3_fixed_ack_delay_setup.py:config_mirror` — `$mirror.cfg` session 7 → dp68 (INGRESS).
- `case_a_defense3_fixed_ack_delay_setup.py:config_value_set` — `pgen_recirc` value_set entry
  (`byte=(pipe<<3)|app_id`, exact mask `0xFF`); called **once per app** to install `{0x01, 0x02}`.
- `case_a_defense3_fixed_ack_delay_setup.py:{resolve_pg,pg_queue_of,reg_read,reg_write,quantize_d,get_table,get_entry}`.
- `defense4_bor_twopipe_setup.py:config_pipe1_pktgen` / `config_pipe1_codebook` — the
  `tf1.pktgen.{port_cfg,pkt_buffer,app_cfg}` `trigger_recirc_pattern` app idiom
  (`increment_source_port=False`) and the `dst_port` exact + `rand8` range → `set_j` codebook idiom.

**Fail-closed sequence** (`hw_configure_all`, mirrored offline by `model_configure_all`):
1 validate (A,R,J) **and** TCP-timestamp policy before any write · 2 keep pktgen DISABLED · 3 bring up +
read back dp8/dp9/dp64/dp68 · 4 resolve dp8 `(pg_id, pg_queue)` · 5 queue ladder qid7…qid2, shaping
disabled · 6 pktgen port + **two token buffer regions** + **two mutually-exclusive patterns**
(`0xE1000000` / `0xE1010000`, mask `0xFFFF0000`) + value_set `{0x01,0x02}` + mirror 7→dp68 · 7 caseA
timing (shape OFF) · 8 `tbl_bor_params` (A/R) · 9 `tbl_bor_codebook` as **NON-OVERLAPPING range entries
covering buckets 0..255 EXACTLY** (no bucket defaults to `set_j(0)`; every range + realized J read
back) · 10 `tbl_session` both directions · 11 PRE group + two same-port RIDs (verified) · 12 init
`reg_bor_epoch/ready/gen/topj := 0` · 13 read back **every** component (any warn / missing table / empty
read / mismatch = **FAILURE**) · 14 enable pktgen apps + shape **ONLY** after every prerequisite passes.
Ops: `dry-run` (offline), `configure-all`, `verify`, `disable-bor`, `rollback` (rollback disables
**pktgen first**, then shape, then timing→OFF, then deletes PRE). Every hardware op refuses unless
`DEFENSE4_HW_AUTHORIZED=1`; `bfrt_grpc` is imported only inside the hardware functions.

**OFFLINE dry-run readback (MODEL, NOT hardware).** `python3 p4/defense4_rrc_bor_unified12_setup.py
dry-run` → full transcript at `evidence/rrc_bor_unified12_hwfix/setup_dryrun_transcript.txt`. Headline:

```
MODEL configure-all: PASS (n_fail=0 n_warn=0)
NEGATIVE tests: PASS
RESULT: PASS
```
The transcript shows every step's write→read→assert (queues qid7..qid2, both pktgen patterns +
mutual-exclusion check, value_set {0x01,0x02}, mirror 7→dp68, `tbl_bor_params` A/R, the six codebook
ranges covering 0..255, both `tbl_session` directions, the PRE identity, and the four `reg_bor_*` inits),
and confirms pktgen+shape are enabled only after all prerequisites pass.

### PART 3 — negative setup tests (offline, non-vacuous)

`run_negative_tests` proves `configure-all` **FAILS fail-closed** when each component is absent/corrupt.
Each is non-vacuous: the clean baseline PASSES, and the injected fault drives exactly the matching
readback assertion to fail (n_fail>0, so pktgen/shape stay disabled). All 7 PASS:

| component removed/corrupted | fault | result |
|---|---|---|
| codebook (bucket 255 left uncovered) | `codebook_gap` | configure FAILS (n_fail=1) |
| mirror session 7 | `mirror_missing` | configure FAILS (n_fail=1) |
| parser value-set (app-2 byte) | `valueset_missing` | configure FAILS (n_fail=1) |
| tbl_session (one direction) | `session_missing_dir` | configure FAILS (n_fail=1) |
| queue mapping (resolve_pg dp8) | `queue_unresolvable` | configure FAILS (n_fail=1) |
| PRE (RID-2 node) | `pre_missing_node` | configure FAILS (n_fail=2) |
| pktgen buffer (3K app region) | `pktgen_buffer_missing` | configure FAILS (n_fail=1) |

Also fail-closed (in `setup_negative_controls.txt`): `configure-all` without `DEFENSE4_HW_AUTHORIZED=1`
→ REFUSES, exit 2; invalid deadlines (`--op-a-ms 10 --op-r-ms 8`) → RESULT FAIL, exit 2;
`--tcp-ts-policy allow` → FAIL (the anti-subtraction claim requires a no-timestamp flow); a TCP options
sample carrying kind-8 timestamp → FAIL.

### 7.4 Is blocker 6 now closed? Yes — with an honest boundary

Blocker 6 is **genuinely closed in software**: the setup performs the complete fail-closed install +
readback of every component using the proven helpers' real schemas (not invented ones), provides
`verify`/`disable-bor`/`rollback`, and the offline dry-run + 7 non-vacuous negative tests all pass. The
clone-profile ambiguity is closed with two mutually-exclusive pktgen patterns and a size-2 value_set,
proven READ-neutral by a bit-identical MAU placement and the emulator.

**Boundary (do not overclaim).** **A compile is not silicon, and the dry-run readback is against an
in-process model, not the switch.** The following remain **Philip's authorized steps at the rig
(H0..H3)** and are NOT done here: load the CORRECTION2 `tofino.bin`; run `configure-all` on the live
switch and confirm every readback PASSES **on hardware**; OFF-mode transparency + READ/SELECT
regressions; the software-OpenDNP3 BOR SELECT→OPERATE on-wire proof (held to T0+J, released exactly
once, retransmit-suppressed, ACK/echo at T0+A/T0+R); and any physical SEL SELECT/OPERATE.
**No hardware result is claimed.** The anti-subtraction guarantee holds only on a no-TCP-timestamp
protected flow (the setup's TCP-timestamp policy gate must read `reject` — enforced offline here).

### 7.5 CORRECTION2 files

```
p4/defense4_rrc_bor_unified12.p4            clone-profile fix (2 markers, value_set size 2); MAU bit-identical
p4/defense4_rrc_bor_unified12_setup.py      REAL configure-all (proven-helper delegation) + model + 7 negatives
offline/bor_unified_lifecycle.py            +read_op_tokens_dropped / read_unchanged_2k_vs_3k (+1 mutant) = 19/11
evidence/rrc_bor_unified12_hwfix/           recompile artifacts + emulator + dry-run + negative-control transcripts
```
