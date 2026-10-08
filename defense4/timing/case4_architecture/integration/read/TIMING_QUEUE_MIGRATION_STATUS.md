# T's queue-resident timing role: source-level complete, hardware compile not yet closed

Status of `read_queue_timing.p4`, the blocker-queue-based replacement for T's heartbeat/recirculation
design (`read_timing.p4`), per `INTEGRATION_CONTRACT.md` §5's hard constraint that real ACKs/responses
stay queue-resident and only blocker tokens circulate.

## What is done and verified

**All 7 invariants from the integration prompt §4C, Phase C, are implemented and pass, 18/18 tests,
on the source-level harness interpreter** (`integration/core/harness`, via `integration/read/tests/
queue_sim.py` and `test_t_queue_invariants.py`): residency (real ACK/response enqueue once, release
once, under a sufficient blocker reservoir; a degraded reservoir is detected and reported, not
hidden); no early response; both response children share one release decision; ACK/response/OPERATE
have separate gates; stale tokens and duplicate arrivals are rejected without disturbing a new
transaction; missing-response/missing-ACK/lost-blocker-service/budget-exhaustion fallback is bounded
and distinguishable from a normal completion; policy-off and reset both flush held originals and
preserve exactly-once delivery, with epoch quarantine correctly bypassing a superseded connection.

The full existing regression suite (root `tests`, `connection/binding/tests`,
`controller/tests`, `core/harness/tests`, `read/tests`) stays green with this file added — nothing
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
   2. **Eliminating all five ternary-match tables entirely** (`da_check`/`readiness_check`/
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
   from the first full compile attempt. The true cause remains undiagnosed after four substantive,
   independent attempts to isolate or resolve it.

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
attempts, not to be the source of the remaining crash at all). Four separate things have now been
tried against the crash itself (bisection, cross-SDK confirmation, field narrowing, full table
elimination) with no diagnostic information gained beyond "it happens at the same point regardless."
Continuing to guess further structural variants with no new signal to act on is exactly the pattern
this project's own standing discipline (the M-mapper saga, `M_RECIRCULATION_VERDICT.md`) says to stop
rather than repeat. This crash is now a well-characterized, reproducible finding in its own right —
precisely where it happens (PHV allocation, after successful 8-stage table placement), what doesn't
cause it (table count, field width, the specific gateway-complexity fix), and that it is stable across
two SDK point releases — which is a legitimate basis for someone with access to the compiler's source
or Intel/Barefoot support to take further, rather than more blind source-level variation.

## Next concrete step (not performed here)

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
