# Repeat/lifecycle final independent review

**PASS — no blocking code/spec findings in the requested scope.** Reviewed the uncommitted changes against `68fcec059` on 2026-10-25, including the pre-fix reproducers in `repeat-review.md` and implementation evidence in `repeat-report.md`. This is the independent code/spec review lane; compiled-model validation and final integration remain with the parent. No source/test changes, model or hardware launches, commits, or child agents were made. This report is the only authored artifact.

## Reviewed identities

Paths are relative to `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments`.

```text
4d259036e3bd0e74a812b67c7fd8d770a52d95c436090c77bca685bc14a773bb  seg61_02/model_repeat.py
35e0d4444dfc12dec9a674f7ccb6a81099c5e5f6b7749f6b27d1049c6b1752d8  ctl_timing_01/model_select_lifecycle.py
2fd1fa2ed294d2d0043e419ae0f5b84594991dc6b09cabf75884aa61c3ff1fe4  seg61_02/tests/test_repeat_response_ready.py
```

## Requirement checks

- **Exact endpoint and pair:** [model_repeat.py:116](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/model_repeat.py:116) sends the genuine ACK and complete response consecutively, then requires exactly those two frames in order on the master endpoint and no frames on any other captured endpoint. Both owned callers provide the master port explicitly. Ordinary single-frame traffic also requires the destination endpoint and an aggregate count of exactly one at [model_repeat.py:245](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/model_repeat.py:245) and [model_select_lifecycle.py:115](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/model_select_lifecycle.py:115). Expected-drop cases still require zero captured output.
- **Full D:** [model_repeat.py:136](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/model_repeat.py:136) requires the ACK hold, response admission, ACK commit, and response release actions exactly once, and checks the modular commit-to-release interval against the actual written T-unit gap. The repeat caller reads that value at line 262; lifecycle does so at [model_select_lifecycle.py:171](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/model_select_lifecycle.py:171). Packet order is independently checked at the output endpoint. No additional J or tied-clock precision work was required or assessed.
- **Immediate failure propagation:** the common local assertion wrappers record the failed assertion before raising at [model_repeat.py:174](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/model_repeat.py:174) and [model_select_lifecycle.py:61](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/model_select_lifecycle.py:61). A failed request therefore exits before advancing its client TCP frontier, advancing the application sequence, manufacturing a reply, or entering a dependent exchange. The request gates precede those updates at repeat lines 281–284 and lifecycle lines 144–148. A failed response or timing proof exits before updating the server/growth frontiers or completed exchange counts at repeat lines 299–311 and lifecycle lines 165–180. The broad exception handlers only record the failure and finalize the report; they send no further traffic.
- **Failure evidence:** planned/completed counts and scenarios, the interrupted active scenario, precise failed assertion, stopped TCP frontier, remaining uncompleted counts, and later unexecuted scenarios survive failure at [model_repeat.py:429](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/model_repeat.py:429) and [model_select_lifecycle.py:299](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/model_select_lifecycle.py:299). The failed active scenario is deliberately separate from later unexecuted scenarios. Counts describe completed positive request/response exchanges; expected-drop probes are scenarios, not completed exchanges.
- **Legacy and successful scenarios:** the disabled-T and non-v2 response branches remain at repeat lines 285–287/306–308 and lifecycle lines 153–155/176–177. Review against the base found the existing wrap/growth checks, repeated READ/SBO cycles, release-count assertions, cancellation, replacement, retry, stale/unpaired authority, and reset/reconnect probes retained. Lifecycle normalizes `SELECT_retry` into its SELECT completion count at line 180. Source-bound repeat profile resolution and the profile-specific cancellation branch remain in place at repeat lines 102–113/183–195/413–421.

## Planned-count audit

Let `C=REPEAT_CYCLES` and `T=REPEAT_TIMED_CYCLES`. Repeat has `C+T+5` completed READ exchanges, plus one cancellation READ for milestones m4 through m10 including m9d; `C+T+1` SELECT exchanges; and `C+T` OPERATE exchanges. This agrees with the formulas at repeat lines 162–186 and the scenario calls at lines 333–424. With defaults, the totals are READ 72 for the legacy branch or 73 for the cancellation branch, SELECT 68, OPERATE 67.

Lifecycle has four READs, nine SELECTs (including one retry), and three OPERATEs per phase, plus one final reconnect READ: READ 9, SELECT 18, OPERATE 6. This agrees with [model_select_lifecycle.py:50](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/model_select_lifecycle.py:50) and the retained scenario bodies at lines 207–295. The planned case lists match the case transitions in both drivers.

## Fresh verification and coverage limits

Executed with bytecode generation and pytest cache disabled:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/tests/test_repeat_response_ready.py \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_rearm_response_ready.py \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_response_ready_stimulus.py \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_response_ready_profile.py

64 passed in 0.21s
```

The 11 repeat tests exercise production AST-extracted code. The original pair/order checks, D and clock-wrap checks, and the successful READ/SELECT/OPERATE × v2/non-v2 × enabled/disabled adapter matrix remain at [test_repeat_response_ready.py:26](/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/tests/test_repeat_response_ready.py:26), line 44, and line 63. Added pair tests reject wrong-port, split-port, and extra-output captures at line 101. The actual-main tests at line 209 inject both missing and wrong-port SELECT delivery in both drivers and require zero subsequent traffic, unchanged failed-request TCP frontiers, unchanged SELECT/OPERATE completion counts, and remaining-plan evidence. These are meaningful regressions for both pre-fix blockers; the main tests reach failure in the untimed phase.

To independently check the timed branch, I also ran **24 successful offline production-function probes**: both drivers × READ/SELECT/OPERATE × successful exchange, missing request, wrong-port ACK/response pair, and insufficient D. The probes execute the actual local assertion, request/step, response/exchange, pair, and timing-proof functions with deterministic packet/log boundaries. They verify failure status, traffic cutoff, application advancement, TCP/server/growth coordinates, and completion counts. No driver logic was edited. These probes supplement the committed-test coverage without purporting to validate model behavior.

`git diff --check` on the three scoped files passed. Source hashes match the implementation report. Compiled-model success coverage is still required from the parent against these exact identities; this review does not claim hardware or model timing results.
