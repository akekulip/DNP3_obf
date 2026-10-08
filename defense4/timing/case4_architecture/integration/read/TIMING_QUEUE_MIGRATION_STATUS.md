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
   tables — compute `delta = now - deadline` as its own single-operation action, then use a table with
   a **ternary match on the delta's sign bit** instead of a live `>=`. This file now has that pattern
   for all five deadline checks (ACK `da`, shared `readiness`, response `gap`, OPERATE `op_j`), each
   reduced to a 1-bit `*_ready` flag consumed by plain, narrow `== 1` comparisons.

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
   it). **Separately, and more informatively**: stubbing the apply block to just the new unconditional
   top-of-pass block (no branches at all, so none of the newly-computed fields are ever consumed)
   fails PHV allocation outright — 18 field slices, mostly the 32-bit intermediate deltas/deadlines
   this fix introduces, could not be allocated simultaneously. That is real evidence, not a guess,
   that the delta/ternary-match fix is correct in shape but **expensive**: it adds roughly a dozen new
   always-live 32-bit metadata fields to a pipe that is already one of several sharing this switch's
   stage/PHV budget (the same resource pressure this session's M-mapper saga hit from a different
   angle). The crash on the full file is most plausibly this same pressure interacting badly with
   table-placement/dependency-graph construction in a way bf-p4c does not fail gracefully on, though
   that specific causal claim is not proven — only the PHV-pressure finding is.

## Why this stops here rather than continuing

The dispatching task's own instructions named exactly this kind of outcome a legitimate stopping
point, not a failure to force past: "a partial, honestly reported result ... is a legitimate,
valuable stopping point." Here that is doubly true — the correctness of the design is fully
established at the level this phase actually needed (the interpreter is the authority the 18
invariant tests are written against, and nothing found in the real compile contradicts the logic; all
five findings above are hardware ALU/gateway/PHV resource constraints, not behavioral bugs the
interpreter missed). Three rounds of real, substantive fixes landed real progress (one-register-per-
table, single-stage ALU, table-applied-once); a fourth (gateway complexity) has its fix in place and
independently confirmed correct in isolation; what remains is an un-diagnosed compiler crash on the
assembled whole, compounded by genuine PHV pressure that a narrower fix (not attempted here) would be
needed to relieve. Continuing to blindly retry variants against an unexplained ICE, with no new
diagnostic information available after a real bisection effort, is exactly the pattern this project's
own standing discipline (the M-mapper saga, `M_RECIRCULATION_VERDICT.md`) says to stop rather than
repeat.

## Next concrete step (not performed here)

1. **Reduce PHV pressure before fighting the crash further.** The five `*_ready` flags and their
   intermediate deltas/deadlines do not all need to be bit<32> or all computed unconditionally at the
   top of every pass. Narrowing them (the deltas only need their sign bit to survive past the
   ternary-match table; a `bit<8>` or even `bit<1>` flag is all any consumer needs) and/or computing
   each domain's checks only on the ports that actually need them (accepting the "applied in multiple
   places" duplication by giving HELD_RETURN and HB_RETURN their own private copies of the relevant
   tables, rather than one shared unconditional block) would directly address the PHV allocation
   failure found here, and may independently make the crash go away if it is in fact resource-pressure
   driven.
2. Re-run the `bf-p4c` compile after each change — the interpreter does not model any of the five
   hardware constraints found in this session, so it cannot be relied on to catch a regression here;
   only the real compiler can.
3. Once it compiles, run it on the local Tofino-1 model (`integration/core/launch_model.sh`) with
   real packet inputs, per the original task.
