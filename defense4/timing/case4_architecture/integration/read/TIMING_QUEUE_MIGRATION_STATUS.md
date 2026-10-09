# T's queue-resident timing role: source-level complete, hardware compile not yet closed (placement, zero slack)

Status of `read_queue_timing.p4`, the blocker-queue-based replacement for T's heartbeat/recirculation
design (`read_timing.p4`), per `INTEGRATION_CONTRACT.md` §5's hard constraint that real ACKs/responses
stay queue-resident and only blocker tokens circulate.

## Current state (2026-10-09): crash gone; whole file fails placement with zero slack on the ACK->response chain

All evidence: `integration/evidence/route_ab_01/` (rounds `b1`..`b27`, `t_op_exactly_once/`, `final3_*`).
Everything below the "2026-10-08 correction" heading is history; where it disagrees with this section, this
section is current. (`final_*` and `final2_*` record earlier source versions of this same session.)

**Whole-file compile** of `read_queue_timing.p4`, sha256 `4cd8d25196d5…`: exit 2, an ordinary placement
error, on both local 9.13.1 (`final3_full_local`) and the switch's installed 9.13.2, compile-only
(`final3_full_switch_9132`): "Table placement was not able to allocate tbl_reset_clear_commit_at,
tbl_read_gap_delta, tbl_mark_ack_commit_at in the same stage along with Register Ingress.ack_commit_at_reg".
The "Internal compiler error" no longer occurs. The OPERATE slice compiles at 8 ingress / 0 egress stages
(`final3_slice_local`); the capture slice compiles at 3 / 0.

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

**What blocks the whole file now.** The ACK→response chain has zero slack.
- **Stages are earlier now.** With the prologue tables, `t0` is read at stage 2, `da_delta` is at 3 and the
  signs at 4 (`final3_full_local/.../table_placement_7.log`).
- **One legal stage.** The compiler's dependency bounds (`b26_qdiff_t0_access/.../table_dependency_summary.log`)
  put `tbl_read_gap_delta` at stages 3–6 and `tbl_mark_ack_commit_at` at 6–9. So `ack_commit_at_reg` can
  live in exactly one stage, 6, and everything behind it must place without slip.
- **The placer does not find that layout.** It places the RESET-arm clear and the gap read first, at other
  stages. A compile-only probe pinning all three users to 6, with `resp_done_reg` users at 9 and
  `resp_deadline` users at 10, still fails (`b24`, `b26`, `b27` `pins2`). In that probe the placer leaves the
  RESET clears and most of the response tables unplaced.
- **No placement option helps.** `--table-placement-in-order`, `--disable_backfill`, `--relax-phv-init` and
  `--auto-init-metadata` change nothing (`b21`). The source interpreter rejects `@stage` (`b22`: 27 failures),
  so pins could not be landed anyway.
- **More of the same is queued.** `op_t0_reg` and `resp_deadline` show the same "RESET clear placed early"
  pattern in the port-0-stubbed variant.

Conclusion: another local repair is unlikely to close this. It needs a structural idea that creates slack on
the ACK-commit → response path. Two options:
- Remove the RESET-arm clears of late registers (`ack_commit_at_reg`, `resp_deadline`, `op_t0_reg`), for
  example with generation-scoped values. This needs a decision, because the clears are observable today.
- Move part of the response gating off this pipeline.

`outcome_count` is not the limiting term: its bounds (8–11) are inside budget, and it does not gate any
decision.

**Tests.**
- `D_SeparateGates.test_same_generation_copy_is_not_released_while_its_generation_is_current`: a
  same-generation copy of a released OPERATE (generation read back from `op_gen_alloc_reg`, truncated to the
  16-bit ladder field) is not released while its generation is current.
- `..._is_flushed_to_the_relay_when_the_next_operate_arrives` pins the known, accepted behavior. A later
  OPERATE makes the copy stale and `flush_operate_stale` sends it to the relay: three relay emissions,
  `OUT_HELD_STALE_FLUSH` = 1, `OUT_OP_RELEASE` = 2. Exactly-once delivery is not claimed.
- Both pass on this tree and on HEAD, and both fail when `op_done_try`'s write is removed
  (`t_op_exactly_once/`).
- `python3 -m pytest -q read/tests core/harness/tests` from `integration/` gives 176 passed and 1 expected
  failure (134 + 42; `final3_pytest.txt`). The expected failure is the RESET-near-clock-wrap case below,
  still open.

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
