# T's queue-resident timing role: source-level complete; whole file compiles for Tofino-1 (11/0 stages)

Status of `read_queue_timing.p4`, the blocker-queue-based replacement for T's heartbeat/recirculation
design (`read_timing.p4`), per `INTEGRATION_CONTRACT.md` §5's hard constraint that real ACKs/responses
stay queue-resident and only blocker tokens circulate.

## Current state (2026-10-09, latest): the whole file compiles on both SDKs, 11 ingress / 0 egress stages

**Whole-file compile** of `read_queue_timing.p4`, sha256 `b3470a690e89…`: **exit 0** on local 9.13.1
(`final7_full_local`) and on the switch's installed 9.13.2, compile-only (`final7_full_switch_9132`). Both
report 11 ingress / 0 egress stages, critical path 9, and 54 match + 5 action + 21 condition + 15 stateful
tables. The OPERATE slice compiles at 8 / 0 and the capture slice at 3 / 0. Tests:
`python3 -m pytest -q read/tests core/harness/tests` gives 195 passed (`final8_pytest.txt`; 193 at `final7`). Nothing has been
loaded or run on the switch.

**Local Tofino-1 model run of the whole compiled program** (`route_ab_01/model_t_queue_03`, driver
`read/model_drive_t_queue.py`, build `final7_full_local`): **20 of 20 checks pass**. Seven phases of real
packets on T_IN, with the mirror session bound locally, were compared against the interpreter (`QueueSim`)
replaying the same events at a scaled time base (`--predict` prints its prediction):
- A: READ request, ACK, response and a duplicate response.
- B: an ACK released by readiness fallback, then a late response.
- C: an OPERATE held and released.
- D: an OPERATE followed immediately by RESET (the clone-window case).
- E: a quarantined-epoch request and ACK.
- F: RESET while an ACK is held.
- G: policy off.

What matched in every phase: the released frames, in order, on the forward (9) and relay (64) ports; every
decision counter delta (`OUT_ACK_COMMIT`, `OUT_RESP_RELEASE`, `OUT_RESP_DUP_DROP`, `OUT_OP_RELEASE`,
`OUT_HELD_STALE_FLUSH`, `OUT_ACK_FALLBACK`, `OUT_RESP_FALLBACK`, `OUT_HELD_OFF_FLUSH`, `OUT_REQ_BYPASS`,
`OUT_UNMATCHED`); and the final generation registers (READ 5, OPERATE 4, quarantined epoch 2). In phases
A, B, C and F the held originals waited 9 to 28 recirculation laps on the model before release
(`OUT_HELD_REWAIT`), so the holds are real.

Limits of this run:
- **Functional only.** The model clock moves in about 1 ms quanta and one pass costs several ms, so no
  timing claim is made.
- **No packet generator.** Without it there are no READ blocker tokens, and token and re-wait counters are
  not compared. Strict-priority residency was not exercised.
- **Not exercised:** two response children, and pipe-local ports outside 324–327.
- `model_t_queue_01` stopped before phase G on a driver bug (passing `enabled` twice); `model_t_queue_02` is
  the same run before the lap check was added (16 of 16).

**The model run shows the try register actions return the value from BEFORE their write.** Each `*_try`
action returns `value ^ generation` and then writes the generation. If the compiled register unit
returned the just-written value instead, the result would always be 0 ("already done or duplicate"). The
run rules that out for each action separately:
- **`child_try*`:** the first response would read as a duplicate and be dropped. In phase A the first
  response (`a2`) was released and only the real duplicate was dropped (`OUT_RESP_DUP_DROP` = 1).
- **`ack_done_try`:** the commit-path writes are gated on `done_diff != 0`, so a_commit would never be
  recorded and the response would fall back. Phase A has `OUT_ACK_COMMIT` = 1, `OUT_RESP_RELEASE` = 1 and
  `OUT_RESP_FALLBACK` = 0.
- **`resp_done_try`:** a readiness-fallback commit would hit the `done == 0` row and be counted as a
  release. Phase B has `OUT_RESP_FALLBACK` = 1 and `OUT_RESP_RELEASE` = 0.
- **`op_done_try`:** the releasing pass would hit the `done == 0` row and re-wait indefinitely. Phase C
  has exactly one relay emission (`c0`) and `OUT_OP_RELEASE` = 1, after 10 laps held.

**Control-plane reset rule.** These registers reset to 0xffffffff, not 0, and any control-plane clear or
re-initialization must restore 0xffffffff:
- `child_seen0_reg`, `child_seen1_reg`, `child_seen2_reg`
- `ack_commit_gen_reg`
- `quarantine_reg`

Each is compared for equality with a live READ generation or epoch, and 0 is both the live generation
before the first request and a possible epoch. A zeroed `quarantine_reg` would quarantine epoch 0. In
generation 0 a zeroed child register cannot drop a response: `resp_done_reg` also resets to 0, so a
generation-0 response passes through as already released, before any duplicate check. Tests:
`K_ResetValues` pins the reset values (it fails on a zero-initialized variant) and that generation-0
behavior. The rule is also stated next to the child registers and `ack_commit_gen_reg` in
`read_queue_timing.p4`. `quarantine_reg` has no such comment yet; adding one would change the source bytes
that the compile and model evidence above are tied to, so it is left for the next source change. No
controller or core code reads or clears these registers today (checked by grep of `controller/*.py` and
`core/*.py`).

**What closed it** (rounds `b35`..`b40`; scripts `b35_verdict_tables/consolidate.py`, `child_regs.py`).
Every step is behavior-preserving at the source level, and the full suite passed after each one.
- **Per-port verdict tables (`b35`).** Each port's terminal decision is one const-entries ternary table
  (`tin_verdict`, `token_verdict`, `held_verdict`, `hb_verdict`) instead of a chain of gateways and
  one-action tables. Rows keep the original if/else priority.
  - Two-field equalities become "== 0" keys through XOR diffs: `lgen_diff`, plus `done_diff` returned by the
    done registers as `value ^ generation`.
  - "!= 0" is expressed by an earlier row that matches 0.
  - The `*_sign` tables are gone; deltas are keyed on their sign bit directly.
  - The go tables (`ack_go_check`, `resp_go_check`, new `op_go_check`) now include liveness, so each try
    register action runs for its whole role and writes only on a live pass.
  - Result: 116 → 49 tables and 32 → 18 gateways, and "too many tables total" disappeared.
- **No write-after-write between two call sites of one register (`b36`).** The RESET-path OPERATE
  generation bump no longer writes `md.op_gen`, and it is chained `else if` with the OPERATE arm.
- **Gateway chains ordered by stage (`b37`, `b38`).** bf-p4c places a gateway together with the first table
  it guards, so a late branch first in an else-if chain held every later branch back. The held-return role
  chain now runs held ACK, ACK blocker, held response, response blocker. The response-only reads of
  `ack_commit_at_reg` and `ack_commit_gen_reg` moved into the response branches. The N-input read of
  `resp_done_reg` has its own gateway.
- **Seed actions read `batch_id` before invalidating the timer header (`b38`).** The consolidation had
  briefly read it after `setInvalid()` (a compiler warning; the read value is undefined).
- **Per-child response registers (`b40`).** With placement solved, the assembler rejected the
  `{gen, mask}` pair's masked condition `(value.mask & BIT) != 0` ("Syntax error, expecting register
  slice"; swapping field order does not help, `b39`). It was replaced by `child_seen{0,1,2}_reg`, each
  holding the READ generation in which that child was last admitted. Same semantics. Initial value
  0xffffffff, which must be restored on any clear.

**Fit headroom.** 11 of 12 ingress stages, with egress unused. Any addition on the ingress critical path
must be checked against that one spare stage.

### Earlier on 2026-10-09 (superseded by the above)

**Whole-file compile** of `read_queue_timing.p4`, sha256 `323c5bc56bfa…`: exit 2 on both local 9.13.1
(`final5_full_local`) and the switch's installed 9.13.2, compile-only (`final5_full_switch_9132`): "Table
placement was not able to allocate tbl_read_gap_delta, tbl_mark_ack_commit_at in the same stage along with
Register Ingress.ack_commit_at_reg". No "Internal compiler error". The OPERATE slice compiles at 8 ingress /
0 egress stages; the capture slice at 3 / 0.

**What the crash was.** It hid ordinary errors. Stubbing whole top-level branches (`b6`), then pieces of the
generator-token branch (`b19`), exposed them:
1. The `~delta[31:31]` sign-bit slices (mitigation 2 below) split the whole now/t0/deadline chain,
   including `global_tstamp`, at bit 31 ("PHV allocation was not successful"). Fix: one-entry ternary
   `*_sign` tables (`b7`).
2. The generation counter's output was masked inside the action that receives it (IMPOSSIBLE_ALIGNMENT).
   Fix: a separate `make_request_tag` (`b8`).
3. **The crash trigger.** The generator-token staleness gateways compared two runtime fields with a mask on
   one side: `md.token_gen != (md.X_gen & 32w0xffff)`. Removing both (`p3`) gives readable errors; removing
   either alone still crashes. Fix: `tok_diff = batch_id ^ (bit<16>)gen`, then `tok_diff != 0`. This is the
   same test, because `token_gen` is the zero-extended 16-bit `batch_id` (`b20`).

**Behavior-preserving repairs.** Every one is source-checked, and tests stayed green after each.
- **One access per register per pass; read-then-dependent-write folded into one action.**
  - `op_done_try`, `ack_done_try` and `resp_done_try` return the old value and record the generation when a
    precomputed go flag is set (`b1`, `b4`).
  - `outcomes` is bumped by a single `outcome_count` table at the end of the pass (`b2`).
  - Quarantine has a read action and a RESET action, selected by a gateway on `hdr.tev.kind`. The read
    returns `q_diff = epoch ^ quarantine` (`b14`, `b26`).
  - `gen_alloc_reg`, `cur_epoch_reg` and `t0_reg` are each accessed by one ternary table (`gen_access`,
    `epoch_access`, `t0_access`), applied once after quarantine. The quarantine condition is decided inside
    the register action from `q_diff`. Rows are matched in order, so `enabled == 0` comes first and the rest
    mean `enabled != 0` exactly (`b17`, `b26`).
  - The ACK/response epoch gate is one register action, `epoch_check`. It returns 0 exactly when the epoch is
    current and not quarantined. The three-field gateway it replaces was split across stages by bf-p4c
    (`b27`).
  - The gap delta is read only on response-role passes, so a held ACK's commit pass no longer accesses
    `ack_commit_at_reg` twice (`b25`, code-review finding).
- **The resp_done → resp_mask → ack_done → resp_done ordering loop.** On T_IN, a response now marks its
  child in `resp_mask_reg` before reading `resp_done_reg`. The decision order is unchanged. The only new
  effect is a child bit set in a generation that has already released a response. That bit is not
  observable: the mask's only other consumer, the ACK gate, tests only "some child seen", which is already
  true there. Folding "released" into the mask would not break the loop (`b11`).
- **Shorter chains, exact mod 2^32.**
  - Deadline deltas are computed as `(now - X) - t0`.
  - The `ack_commit_at_reg` read returns the gap delta directly (`b13`).
  - `ack_go_check` and `resp_go_check` are single ternary tables. `ack_done_read` returns `value ^ cur_gen`,
    so "committed in cur_gen" is a match on 0 (`b18`, `b23`).

**Late 2026-10-09 changes** (each round recompiled, tests green after each):
- **`resp_deadline` removed (`b28`).** It was armed (only while zero, so once per RESET) and cleared, and no
  decision read it. Release is decided from `ack_commit_at_reg` plus the configured gap. The release decision
  has always used the gap configured at release time, not a gap frozen at a_commit; the frozen value existed
  only in this unread register. Its one test now checks `ack_commit_at_reg`
  (`test_duplicate_ack_records_a_commit_once`). Compile effect: none.
- **Generation-scoped a_commit (`b30`).** A genuine ACK commit writes `ack_commit_at_reg` (time) and the new
  `ack_commit_gen_reg` (READ generation). Response roles gate every gap use on `commit_diff == 0`, which means
  this generation had a genuine commit. There is no RESET-time clear.
  - A single `{gen, at}` pair register is not possible: a two-field stateful ALU may not return a computed
    value (`b29`).
  - **Intended counter change.** After a readiness-fallback ACK, or with a stale a_commit from an earlier
    generation, the response is now counted `OUT_RESP_FALLBACK`. The zero-clear design counted
    `OUT_RESP_RELEASE` from a zero or stale timestamp. Release times are unchanged
    (`b32/measure_reset.txt`).
- **RESET invalidates OPERATE by generation (`b32`).** RESET bumps `op_gen_alloc_reg` instead of zeroing
  `op_t0_reg`.
  - **Counter change.** A held OPERATE is flushed as stale: `OUT_HELD_STALE_FLUSH` instead of
    `OUT_OP_RELEASE`. Its blockers die stale (`OUT_TOKEN_STALE`).
  - **Flush time.** Unchanged at the tested offsets: 150,000 ns after a RESET 200 us after the OPERATE,
    and 180,000 ns at 20 us. This is not a general invariant. With a RESET 6 us after the OPERATE, the
    flush now comes 74,000 ns after the RESET, against 194,000 ns on the zero-clear `b28` source. It is earlier, and still
    a flush, not a timed release (`b34/reset_window.txt`).
  - **Bug found in review and fixed (`b34`).** `admit_operate_held` tagged the held original with a fresh
    `op_gen_peek()` instead of the generation the clone carries. A RESET landing between the OPERATE's
    admission and its clone's return (1–5 us in the simulator) therefore left the superseded OPERATE with
    a current tag. It was then released on its old deadline (about 625,000–629,000 ns after the RESET,
    counted `OUT_OP_RELEASE`). The tag now comes from `hdr.clone.tag`, whose low 16 bits are the admitted
    generation, and the PKTGEN branch no longer touches `op_gen_alloc_reg`. Test:
    `test_reset_just_after_an_operate_flushes_it_as_stale` (RESET at 1, 3 and 5 us). It fails on `b32` and
    passes now.
  - **A second pre-existing defect is fixed by the same change.** Before this fix, including at the
    committed HEAD, two OPERATEs 1–4 us apart (inside the first one's clone window) lost the first one. Its
    held original took the second's generation and was never released: one relay emission instead of
    two. Now the first is flushed as stale (at 770,000 ns) and the second is released on its own deadline
    (at 800,000 ns). Test: `test_two_operates_inside_the_clone_window_both_reach_the_relay`; it fails on
    HEAD `723bfd1ad` (`b34/two_ops.txt`).
  - **Tracked follow-up, not fixed (token path, not admission).** Once `op_gen` reaches 0x10000, its own
    bit 16 and above land in the 24-bit generator key, and the `| 0x10000` OPERATE marker no longer
    separates the OPERATE domain as intended. Each RESET now bumps `op_gen`, which brings that point
    closer.
  - **Defect fixed.** The RESET-near-clock-wrap defect, formerly the one expected failure, is fixed by this
    change. Its test now also checks the mechanism (`finished()`, `OUT_HELD_STALE_FLUSH` = 1,
    `OUT_OP_RELEASE` = 0) and covers the 0xC0000000 phase as well. It fails on the zero-clear `b28` source.
  - **Low-priority notes, not fixed.** Every RESET now bumps the OPERATE generation even when nothing is
    held, which uses up the 16-bit ladder generation field faster (wraparound is already a known
    follow-up). `ack_commit_gen_reg` depends on its 0xffffffff initial value: a clear to 0 would match
    generation 0. This is now stated in the source; a controller that clears registers must restore
    0xffffffff.
- **New tests**, class `J_GenerationScopedReset`:
  - a fallback ACK supplies no a_commit;
  - a stale a_commit from an earlier generation is not used;
  - RESET invalidates a held OPERATE by its own generation;
  - after RESET both domains start from their own anchors.

  All four pass on this tree and fail on the pre-redesign source (`b28`).

**What blocks the whole file now.**
- **Slack exists, but placement still fails.** The redesign gave `ack_commit_at_reg` two legal stages
  instead of one (dependency bounds: read 3..7, write 6..11; `b30`), but it still does not place.
- **The new limit is logical tables per stage.** The placement logs report "too many tables total" in the
  early stages (stages 2–4 full). This is the per-stage logical-table limit. Every bare action call and
  assignment in the apply block is its own table: 116 tables and 32 gateways (`b30`).
- **Two cheap tests did not resolve it.**
  - Merging the seven release+count pairs changed nothing, and was reverted (`b31`).
  - Removing whole early branches (port 0, PKTGEN, the policy-off block) lowers the pressure but still
    gives the same error (`b33_table_pressure_probe`).
- **Next options.** Consolidate the role and kind dispatch into decision tables with mutually exclusive
  actions, a substantial rewrite of the apply block. Or compose Route A's hardware-tested ingress with the
  new egress mapper.

**Tests:** `python3 -m pytest -q read/tests core/harness/tests` from `integration/`: 193 passed, 0 expected
failures (`final6_pytest.txt`; includes 10 tests in `read/tests/test_n_operate_handoff.py` added by another
workstream).

**Not done.** No model run of the regenerated capture slice. Nothing was loaded or run on the switch; the
9.13.2 build was compile-only.

## 2026-10-08 correction: "all 7 invariants established" was too broad

An external review of this file (audited at commit `5e848351c`) found, and this session independently
confirmed by direct source inspection plus live reproduction, three real gaps the original 18-test suite
did not catch: (F1) `IngressDeparser` sets `ig_dprsr_md.mirror_type`/`md.clone_tag` but never actually
emits a `Mirror()` clone — the interpreter's test simulator synthesizes the clone+blocker-token behavior
in Python, standing in for hardware behavior the file itself doesn't implement; (F2) `op_t0_arm` only
armed once per register lifetime, so a second OPERATE admitted without an intervening RESET inherited
the first operation's deadline (reproduced: released 399,808ns before its own earliest-permitted
release); (F3) `hdr.tev.wgen` was parsed and never read anywhere, flagged by the review as allowing a
stale response to satisfy a newer request's ACK gate.

**Investigation outcome, same day:**
- **F2 is fixed.** One-line change, see below.
- **F3 required no fix.** A deeper investigation (reading N's real implementation, `n.p4`/
  `native_binding.p4`, and replaying N's own real output bytes through `QueueSim` rather than injecting
  synthetic T_IN events) found the review's literal diagnosis was wrong: N allocates a new `wgen` per
  packet-processing operation, not per transaction, so a legitimate request/ACK/response can legitimately
  carry three *different* `wgen` values — an equality check against `wgen` would have rejected legitimate
  traffic. The real question (can a stale response reach T through the real N→T path) was answered
  empirically: **no.** N's own admission guarantees (single work slot; state-machine-gated READ admission;
  sequence/ack checks against live banks) already prevent a stale response from ever being forwarded to T
  in the real path. This boundary (T trusts N's filtering; T has no independent association check of its
  own) is now pinned by an explicit test (`H_NRealisticAssociation`, `test_t_queue_invariants.py`) rather
  than being an unstated assumption. OPERATE duplicate-detection was investigated for the same reason and
  found **not reachable today**: nothing in the real N implementation sends OPERATE events to T's input
  port at all (T's OPERATE path is exercised only by synthetic tests) — adding duplicate-detection now
  would mean designing against an interface that doesn't exist yet.
- **F1 is not yet fixed** — queued as the next step (Stream 1c), to be compiled and verified separately
  from F2 per this document's own standing discipline about isolating one new variable per compile attempt.
  *Update, same day: F1 is implemented and its mechanism is verified on the local model; see the next
  section. The whole file still does not compile.*

## 2026-10-08 (Stream 1c): F1 Mirror clone implemented; mechanism model-verified, whole file still crashes

**Change to `read_queue_timing.p4`.** `const MirrorId_t CLONE_SESSION_ID = 10w7` and `const bit<3>
MIRROR_TYPE_CLONE = 1`; a `MirrorId_t clone_ses` metadata field; `md.clone_ses = CLONE_SESSION_ID;` as its
own statement in `admit_request_gen()` and `hold_operate()`; `IngressDeparser` gains a no-arg `Mirror()
clone_mirror` and `if (ig_dprsr_md.mirror_type == MIRROR_TYPE_CLONE) clone_mirror.emit<clone_hdr_t>(md.clone_ses,
{ md.clone_tag });` before `pkt.emit(hdr)` (the `defense4_rrc_bor_unified12.p4` pattern). The empty egress
trio is unchanged. **One more change was forced by F1:** `hold_operate`'s tag went from `md.op_gen +
32w0x10000` to `md.op_gen | 32w0x10000`. Before the emit existed `clone_tag` was never read, so its write was
dead; once live, bf-p4c split `op_gen` over two 16-bit containers and rejected the carrying add ("requires too
many sources ... only one PHV source when action data/constant is present",
`evidence/mirror_f1_01/compile_slice_local/compile.log`). Same value while `op_gen < 0x10000`, the assumption
the action's comment already states. The harness interpreter (`core/harness/interp_ext.py`) learned
`MirrorId_t` (10 bits) the way it knows `PortId_t`; without it every test failed on the new constant.
Regression after all changes: read/tests 132 passed + 1 expected failure (unchanged); harness 42, binding 85,
controller 17, root 33 passed.

**Compile results** (all under `integration/evidence/mirror_f1_01/`):
- Standalone probe `read/mirror_probe.p4` (the new deparser + the unchanged empty egress trio + a stub
  ingress that rewrites a T_IN pass the way `hold_operate` does): **compiles, 0 errors**, SDK 9.13.1
  (`compile_probe_local`). The Mirror addition introduces no compiler complaint of its own.
- Whole `read_queue_timing.p4`, SDK 9.13.1 and the switch's installed 9.13.2 (compile-only), both before and
  after the `|` change (`compile_full_local`, `compile_full_switch_9132`, `..._02`): **the same unresolved
  crash** — exit 4, "Internal compiler error", `phv_allocation_0.log` zero bytes, dependency analysis max
  ingress stage 7. F1 did not change the signature. No further variant was attempted.

**Local-model results** (functional only, not timing, not silicon; mirror session bound on the local model only):
- `model_01` (probe, `read/model_drive_mirror_probe.py`), 15/15. Session 7 to a front port: exactly one
  clone, first 4 bytes = the tag (`0x00010005`), then the **pristine original as received** (tev + Ethernet +
  payload), not the ingress-modified image, while the original left once in its modified form. Session 7
  to 324 (`PKTGEN_RETURN`): nothing on the wire, the clone re-entered pipe 2 ingress on 324 exactly once,
  and `parse_clone` read tag `0x10005`, `tev.kind 12`, `epoch 5`. So the two assumptions `queue_sim.py`
  makes about the clone (arrives on 324; carries `tag + raw original`) hold on the model.
- `model_03` (`read/model_drive_operate_clone.py`), 21/21, on `read/operate_slice_capture.p4`, generated by
  `read/make_operate_slice.py --capture-hb`: the real prelude, parser, deparser, `hold_operate`,
  `admit_operate_held`, and the PKTGEN_RETURN and T_IN-OPERATE branches **copied verbatim** (the
  script checks each piece against this file); only HB_RETURN is replaced by an export to front ports. Two
  OPERATEs: each produced exactly one admitting blocker (role 13, its own generation, budget 240000, payload)
  and exactly one held original admitted from the clone (role 16, its own generation, followed by the pristine
  Ethernet + payload), with nothing on the relay. Policy off: one byte-identical passthrough to the relay,
  no clone, no blocker, generation not bumped. Negative control, mirror session removed: the blocker still
  appears and no held original does, so the held frames exist only because of the clone. `model_02` is
  the same run without that control (19/19).

**What this does not show.** The release itself (`mark_op_done`, exactly-once to the relay at the
deadline) was not model-run: the verbatim HB_RETURN branch does not place on its own (below). Generated
tokens (the packet generator's recirculation-pattern trigger on the clone) were not configured or tested;
nor was the request clone (`admit_request_gen`, kind 9, dropped by `drop_clone`); nor strict-priority queue
service. Nothing was configured or run on the physical switch.

**New lead on the whole-file crash (recorded, not acted on).** The full verbatim slice
(`read/operate_slice.p4`, `compile_slice_local_02`) gets past PHV allocation and then fails table
placement with a diagnosable error: "Table placement was not able to allocate ... `tbl_mark_op_done` in the
same stage along with Register `Ingress.op_done_reg`", and the same for the many tables bumping
`Ingress.outcomes`. `op_done_reg` is read into `md.op_done_g`, compared, and then written by a dependent
table; a Tofino register lives in one stage, so that read-then-dependent-write cannot place. The whole
file has the same shape for `ack_done_reg` and `resp_done_reg`. Note also that `table_dependency_graph.log`'s
"Maximum stage number according to dependences" is the dependency analysis, not a completed placement, so
the "placement succeeds at 8 stages" reading above may be stronger than that log supports. Inference, not
tested on the whole file: folding each read-compare-write into one RegisterAction (and the outcome bumps
into one table) is the next thing worth trying, ahead of register-count bisection.

**New, previously-undiscovered defect found as a byproduct of adding a timestamp-wrap test for F2's
fix**: RESET's fast-flush of a held OPERATE assumes a cleared `op_t0` register reads as "trivially
overdue." This breaks when the quantized 32-bit clock is in its upper half at the moment of the RESET:
`op_delta = now - OP_J` has its sign bit set in that range, so the flush is **late, not early** — measured
870µs to 1.56ms late near the wrap boundary, and up to ~2.15s late at worst. The release is always late,
never early (not a safety regression, but a real timing-accuracy defect). This is recorded as an
`expectedFailure` test (`test_reset_flush_near_the_clock_wrap`) rather than fixed — redesigning the RESET
path is a separate decision, out of scope for the bounded F2 fix.

## What is done and verified

**All 7 invariants from the integration prompt §4C, Phase C, are implemented and pass on the source-level
harness interpreter** (`integration/core/harness`, via `integration/read/tests/queue_sim.py` and
`test_t_queue_invariants.py`), now **133 tests, 132 passing + 1 expected failure** (up from the original
18, after today's F2/F3 investigation work added the `H_NRealisticAssociation` and
`I_OperateDeadlineAnchor` classes): residency (real ACK/response enqueue once, release once, under a
sufficient blocker reservoir; a degraded reservoir is detected and reported, not hidden); no early
response; both response children share one release decision; ACK/response/OPERATE have separate gates;
stale tokens and duplicate arrivals are rejected without disturbing a new transaction;
missing-response/missing-ACK/lost-blocker-service/budget-exhaustion fallback is bounded and
distinguishable from a normal completion; policy-off and reset both flush held originals and preserve
exactly-once delivery, with epoch quarantine correctly bypassing a superseded connection; the OPERATE
deadline is correctly anchored to the admitted operation's own generation; transaction association across
the real N→T path is explicitly tested, not assumed.

The full existing regression suite (root `tests`, `connection/binding/tests`,
`controller/tests`, `core/harness/tests`, `read/tests`) stays green with these changes — nothing
elsewhere in the tree was touched.

## What is not done: the local SDK 9.13.1 compile

Compiling against the real Tofino-1 target (`bf-p4c --target tofino --arch tna`) surfaced five
distinct classes of real hardware constraint. Four were fixed, with the fixes kept in the file
(they are real engineering, not reverted):

1. **Type mismatch** (`bit<4>` vs `bit<32>` constants) — fixed, cosmetic.
2. **One table may address at most one indirect extern** (a known constraint already recorded in
   project memory: "A Tofino table may access only ONE Register") — every action that bundled a
   state-register write with the `outcomes` counter bump, or that touched more than one state
   register, had to be split into separate single-register actions called as separate apply-block
   statements. Fixed across roughly a dozen actions (`release_ack`/`mark_ack_done`,
   `release_response`/`mark_resp_done`, `release_operate`/`mark_op_done`, `do_reset`,
   `admit_request`, `read_epoch_state`, and others).
3. **An action's ALU operations must fit in a single stage** — a combined mask-then-OR, and a plain
   add whose result fed directly into a stateful register call in the same action, both had to be
   split into separate single-operation actions (`hold_operate`'s clone-tag construction;
   `arm_resp_deadline`'s target computation split from `compute_resp_target`).
4. **A table cannot be `.apply()`'d from more than one place** (next-table propagation) — `gen_snapshot`,
   and later `da_check`/`readiness_check`/`gap_check`/`op_check`/`resp_seen_check`, all needed to move
   from being called inside several different branches to being applied exactly once, unconditionally,
   near the top of `apply{}` — harmless on passes that don't need the result, since each is a cheap
   register peek or deadline check.
5. **NOT CLOSED: a conditional/gateway complexity constraint, and what fixing it costs.**
   `if (md.now >= md.t0_v + md.da && ...) || md.now >= md.t0_v + md.readiness` failed with "condition
   too complex, limit of 4 bytes + 12 bits of PHV input exceeded" and "one operand ... must be
   constant" — Tofino's conditional-execution primitive (the apply-block `if`, compiled to a hardware
   gateway) cannot evaluate a live comparison between two fully dynamic values, especially not a
   compound `&&`/`||` of several. **The fix for this specific error is applied and is in the file**:
   `read_timing.p4` already solves exactly this, via its `deadline_deltas`/`heartbeat_eligibility`
   tables — compute `delta = now - deadline` as its own single-operation action, then turn the delta's
   sign bit into a 1-bit `*_ready` flag with a plain bit-slice assignment (`md.da_ready =
   (bit<8>)(~md.da_delta[31:31]);` — a pure data-plane ALU op, no table needed; see finding below for
   why this ended up simpler than a ternary-match table) for all five deadline checks (ACK `da`,
   shared `readiness`, response `gap`, OPERATE `op_j`), each then consumed by plain, narrow `== 1`
   comparisons.

   **This closed the specific diagnostic it targeted** (confirmed: stubbing the apply block down to
   just the unconditional top-of-pass computation, with no consuming branches, compiles with a
   *different*, later error — not this one). But the *fully assembled* file (every branch present)
   does not produce that later error either; it produces an **unhelpful internal compiler crash**
   ("Internal compiler error. Please submit a bug report with your code.", exit code 4, no file/line,
   no stack trace available — `ulimit -c` enabled and checked, no core dump; `--verbose 3` adds no
   useful detail) with no diagnosed cause after extensive bisection (stubbing each of T_IN's five
   sub-branches individually, both HELD_RETURN and HB_RETURN's four role branches individually, and
   the generator-token branch, one at a time — none of these in isolation reproduces a clean
   diagnostic in place of the crash; only stubbing enormous swaths, or the whole apply body, avoids
   it).

   **Follow-up evidence, confirmed on both local SDK 9.13.1 and the switch host's real installed SDK
   9.13.2** (compile-only, via `installed_sdk_build.py`, no activation — same authorized mechanism
   used throughout this effort): the crash is specifically and reproducibly in **PHV allocation, not
   table placement**. `out/pipe/logs/table_dependency_graph.log` on both SDK runs shows table
   placement actually succeeding, converging to **8 stages** (well inside the 12-stage budget) across
   two placement passes. `out/pipe/logs/phv_allocation_0.log` is **zero bytes** on both runs — the
   allocator crashes before writing anything, consistent with the crash happening at or immediately
   after PHV allocation starts.

   **Two independent mitigation attempts, both confirmed on both SDK versions, neither changed the
   crash at all:**
   1. Narrowing the `*_ready`/`resp_seen_mask`/`dup` fields from `bit<32>` to `bit<8>` and deleting six
      genuinely dead metadata fields left over from earlier iterations (`cap`, `child_bit`,
      `can_release`, `is_commit`, `stale`, `is_off`, `out_code`) — same crash, same signature (8
      stages placed, zero-byte PHV log), on both SDK versions.
   2. *(Superseded 2026-10-09: this bit-slice form was itself one of the hidden errors; the file now
      uses one-entry ternary `*_sign` tables again. See "Current state" above.)*
      **Eliminating all five ternary-match tables entirely** (`da_check`/`readiness_check`/
      `gap_check`/`op_check`/`resp_seen_check`), replacing each with a plain bit-slice assignment on
      the delta's sign bit (`md.da_ready = (bit<8>)(~md.da_delta[31:31]);`, a pure data-plane ALU
      operation, not a gateway/conditional construct at all) plus a direct `!= 0` comparison for
      `resp_seen_mask` (legal for a gateway on its own terms, since one operand is already the
      constant 0 — it never needed the sign-bit treatment). This removes the entire table-based
      mechanism the "gateway complexity" fix originally introduced, leaving only plain arithmetic and
      narrow flag comparisons. **Identical crash, identical signature, on both SDK versions.**

   Taken together, these two results rule out both of the obvious theories: it is not simply "too
   much live PHV data" (narrowing a third of the fields changed nothing), and it is not the
   ternary-match-table mechanism itself (removing all five tables changed nothing). Separately,
   re-examining the very first version of this file (before the gateway-complexity fix existed at
   all, using plain `if (md.now >= md.t0_v + md.da ...)` comparisons) confirms it hit the identical
   crash too — this is not something introduced by any of the fixes in this document; it was present
   from the first full compile attempt.

   3. **2026-10-08: the F2 fix (removing `op_t0_arm`'s `if (value == 0)` guard — a pure subtraction,
      zero new live metadata) also produced the identical crash signature on both SDKs** (table
      placement to 8 stages, zero-byte `phv_allocation_0.log`), confirmed by a direct compile of both
      the fixed and unfixed source on the same day. This is a third independent confirmation that small
      logic changes within existing registers do not move the needle at all — consistent with, and
      further supporting, the register-count bisection theory below rather than anything about this
      specific conditional.

   The true cause remains undiagnosed after five substantive, independent attempts to isolate or
   resolve it.

## Why this stops here rather than continuing

The dispatching task's own instructions named exactly this kind of outcome a legitimate stopping
point, not a failure to force past: "a partial, honestly reported result ... is a legitimate,
valuable stopping point." Here that is doubly true — the correctness of the design is fully
established at the level this phase actually needed (the interpreter is the authority the 18
invariant tests are written against, and nothing found in the real compile contradicts the logic; all
five findings above are hardware ALU/gateway/PHV resource constraints, not behavioral bugs the
interpreter missed). Four rounds of real, substantive fixes landed real progress (one-register-per-
table, single-stage ALU, table-applied-once, the gateway-complexity delta/sign-bit pattern — the last
of these confirmed correct in isolation and then shown, via two further independent mitigation
attempts, not to be the source of the remaining crash at all). Five separate things have now been
tried against the crash itself (bisection, cross-SDK confirmation, field narrowing, full table
elimination, the F2 register-guard removal) with no diagnostic information gained beyond "it happens
at the same point regardless."
Continuing to guess further structural variants with no new signal to act on is exactly the pattern
this project's own standing discipline (the M-mapper saga, `M_RECIRCULATION_VERDICT.md`) says to stop
rather than repeat. This crash is now a well-characterized, reproducible finding in its own right —
precisely where it happens (PHV allocation, after successful 8-stage table placement), what doesn't
cause it (table count, field width, the specific gateway-complexity fix), and that it is stable across
two SDK point releases — which is a legitimate basis for someone with access to the compiler's source
or Intel/Barefoot support to take further, rather than more blind source-level variation.

## Next concrete step (not performed here)

*Superseded 2026-10-09 by "Current state" above: the crash was diagnosed by branch bisection, not
register count, and the remaining blocker is stage budget on the ACK→response path.*

1. **Treat this as a compiler-level question, not a source-restructuring one.** Two independent,
   substantial restructuring attempts (narrower fields; zero tables, pure data-plane ops) produced
   the identical crash signature on two SDK point releases. That is evidence the remaining lever is
   not in this file's shape. A productive next step is bisecting by *register count* instead (this
   file declares roughly a dozen single-cell registers; try merging several into one wider struct
   register, or temporarily deleting whole domains' registers to see if the crash threshold is tied
   to total register count rather than anything examined here), or escalating to whoever maintains
   this SDK installation with the exact reproduction already assembled in this document.
2. Re-run the `bf-p4c` compile after each change on **both** SDK builds (local 9.13.1 via `bf-p4c`
   directly, and the switch's installed 9.13.2 via `installed_sdk_build.py`, compile-only) — every
   finding in this document held on both, so a fix should be confirmed on both too. The interpreter
   does not model any of the hardware constraints found in this session, so it cannot catch a
   regression here; only a real compile can.
3. Once it compiles, run it on the local Tofino-1 model (`integration/core/launch_model.sh`) with
   real packet inputs, per the original task.
