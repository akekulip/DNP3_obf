# Contention01 first-failure diagnosis

**Finding: postcheck schema drift, high confidence.** The compiled-model driver passes **493/493**, then `reset_application_check.coverage_problems()` rejects four legitimate response-ready timing-proof case names. This postcheck failure changes the wrapper exit status from 0 to 1. No packet, data-plane, stimulus, or timing-observer failure precedes it in the retained result.

Evidence directory: `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/model_contention_m12p_c67_sdk9132_01/`.

## First causal failure

Paths below use `stage_experiments/ctl_timing_01/` as shorthand for the corresponding directory under `defense4/timing/case4_architecture/integration/core/response_only_rearm/`.

1. `contention_results.json` has `summary={"failed":[],"passed":493,"total":493}`. `session.log` ends with that passing summary and `driver exit code 0`.
2. Under the v2 contract, `model_contention.py:358`–375 emits a separate `_T_clock_response_ready_ACK_then_D` assertion for each judged recovery READ. Its ordinary restart code calls `judge('%s_new_READ' % tag, ...)` at line 898; the targeted restart code does the same at line 988.
3. `reset_application_check.py:204`–209 enumerates the allowed/required restart case suffixes. It includes the timestamp-options assertion conditionally but omits the v2 T-clock assertion. Lines 260–262 reject every restart-prefixed case outside that set.
4. The first rejected name is `restart_READ_new_READ_T_clock_response_ready_ACK_then_D`. The other three are the corresponding `restart_SELECT`, `restart_targeted_READ_1`, and `restart_targeted_SELECT_1` new-READ timing checks. All four have `ok=true`, `observed=true`, and `passed=true` in the result. These four names are the entirety of retained `_coverage_problems` and of an independent call to `coverage_problems()` over the unmodified evidence.
5. Every per-connection reset classification in `reset_application.json` is **PASS**; none has a release after reset application. The retained postcheck closure explicitly records checker `exit_code=1`. `run_model.py:129`–134 runs this postcheck and substitutes its exit code when the driver succeeded. `run_model.py:155` records the resulting launch exit code 1.

This is a production postcheck defect: its accepted case-name schema does not match the already-emitted response-ready driver schema. The strict unknown-case rejection itself remains useful; a blanket relaxation would hide missing or invented evidence.

## Earliest implicated packet/state trace

There is no failing packet to identify. I traced the earliest reset and the recovery READ whose valid assertion is first rejected, using the raw model log as well as the JSON observations.

For `restart_READ`, SYNACK attribution gives native server sequence **535001** (`000829d9`). The T ingress records are:

| Event | T ingress-pass wall time | Raw action log line |
| --- | --- | --- |
| Hold standalone ACK | 11:25:20.097798 | `model.out:5702644` |
| Admit whole response | 11:25:20.382542 | `model.out:5724762` |
| Commit ACK release | 11:25:20.391992 | `model.out:5725497` |
| Count response release | 11:25:20.439769 | `model.out:5729343` |
| Apply reset | 11:25:20.460471 | `model.out:5730535` / `5730603` |

The table uses ingress-pass timestamps, as the reset contract does; individual action lines occur slightly later within each pass. The raw reset pass seals `cur_epoch_reg` from `0x00000149` to `0x80000149` and advances `gen_alloc_reg` from `0xa3` to `0xa4`. The raw port-9 Tx record at `model.out:5730419` emits one 141-byte response payload with sequence 535001 and ACK 530026. This release precedes reset application. Independently parsing the retained log and calling `classify(conn, 1, 1)` reproduces PASS with one release before reset and none after it. The recorded restart counter increments once, one RST is relayed, and one response reaches the master.

The subsequent recovery READ uses native server sequence **545001** (`000850e9`). Its first rejected assertion contains:

```text
held_ack_units          = 1681713866
response_arrival_units  = 1682602538
ack_release_units       = 1682636718
response_release_units  = 1682861328
gap_units              = 195315
response - ACK          = 224610 >= 195315
```

Raw actions corroborate hold/admit/ACK-release/response-release order at `model.out:5757440`, `5772651`, `5773360`, and `5777276`. Raw Tx records at lines 5774342 and 5778342 show a standalone ACK followed by the 141-byte response, both sequence 545001 / ACK 540026. The driver's recovery observation records exactly those two frames, `ACK_COMMIT=1`, `RESP_RELEASE=1`, successful delivery without resend, and no fallback. The timing assertion is valid evidence rejected by the allowlist, not a false passing timing observer.

## Classification

- **Data-plane defect:** no evidence for one behind this exit. All 493 behavioral checks and all four reset-order classifications pass. This is bounded evidence, not proof against unrelated data-plane defects.
- **Stimulus/observer defect:** no evidence for one behind this exit. The first implicated timing proof reconciles with packet IDs, T actions, model-clock values, and raw emitted packet headers.
- **Postcheck defect:** confirmed by the exact allowlist/emitter mismatch and direct reproduction of its four errors.
- **Committed-precondition report:** correctly marks the older request-age/readiness check inapplicable to v2. It is not the failing gate.

## Validation and next minimal validation

Read-only validation completed:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_reset_application_check.py
```

Result: **31 passed in 3.94s**. Existing coverage tests use retained legacy `model_contention_m10_03_07`; they do not catch this v2 suffix mismatch. A read-only Python audit reproduced the four `coverage_problems` exactly, reparsed the raw log to confirm earliest reset ordering, and verified that current `model_contention.py` matches retained `driver_source.py` and launch SHA (`4f1e4d09fa4dd74501196b94baf477ef4291f68a298e2e49e16185070279563f`). The checker matches its retained postcheck dependency SHA (`caa3b11977628fcdaa0a6e5c79771148740bfcdfa25fa2e58723262011a2d1f2`).

Next minimal validation: add a regression using this retained v2 result/report that first reproduces the four unexpected-case errors; update the expected required suffixes conditionally for `response_ready_ack_d_v2`; prove the retained v2 evidence is accepted, a missing or failed v2 proof is rejected, unknown cases are still rejected, and the legacy fixture still passes. Then rerun only the reset postcheck offline against the retained contention01 evidence, writing any new checker report to a separate evidence artifact. A new 433-second model run is unnecessary to validate this cause or the bounded checker repair.

No code/assertion changes, model launches, hardware access, or child agents were used. Only this report was written.

## Follow-up review: fold the timing proof into the committed case

**Spec compliance: PASS. Code quality: PASS. No blocking findings in the pending diff.** The actual change at `model_contention.py:375`–376 removes the standalone proof case and uses `ok = ok and valid`. It retains the complete `response_ready_clock_proof` object in `row`. This is a sound alternative to expanding the reset-checker schema proposed above; the earlier cause diagnosis remains unchanged.

The proof is still mandatory at both acceptance layers:

- In the driver, `ok` already includes exact packet delivery/order, committed lane counts, retry counters, and no extended capture. The new conjunction additionally requires the actual held-ACK, whole-response arrival, ACK commit, and full-D response release proof. For v2, `readiness_first` remains false, so the existing `_delivered_once_committed` assertion at line 389 receives that combined verdict; the older readiness fallback branch cannot bypass it. The function also returns the combined verdict to callers that gate subsequent checks.
- The unchanged reset checker requires each recovery READ's `_delivered_once_committed` case and rejects nonpassing cases. Its finite case schema now agrees with the emitted names.
- Independently, `model_summary.py:552`–565 validates `response_ready_clock_proof` on every `_delivered_once_committed` case. It requires integer stamps/gap and `passed=true`, then recomputes ACK-after-both-prerequisites and the full-D interval. `summarize_v3()` invokes this validator for v2 contention/abort runs at lines 611–614. Thus deleting or falsifying the embedded proof cannot pass v3 merely by preserving a passing case label.

Coverage is preserved: retained contention01 has **40** standalone timing cases and **40** corresponding committed cases, with identical tag sets, and every committed case already carries its clock proof. The diff changes neither the `judge()` call sites nor the clock extraction or validity arithmetic. The expected case-count decrease from this diff is 40 (493 to 453 for an otherwise identical run); these are redundant assertions folded into their existing cases, not removed scenarios or timing requirements.

Read-only validation of the pending change:

1. Executed the actual nested `judge()` function extracted from its current AST with a deterministic mock exchange. A valid timing sequence passes. Missing each of the four prerequisite/release events, a D interval shorter than the configured gap, and an ACK before response arrival each fail the committed assertion and return false. Every emitted committed case retains its proof; no standalone clock case is emitted.
2. Called the actual v3 proof validator against copies of retained results. It accepts the valid embedded proofs and rejects missing proof, `None` timestamp, `passed=false`, short D, bad causal order, and a boolean timestamp masquerading as an integer.
3. In memory only, removed the 40 redundant standalone cases from a copy of contention01 and reconciled that copy's summary counts. The unmodified reset coverage checker and v3 clock validator both accept the resulting case/proof schema. Retained source/results/reports were not rewritten. This is a schema projection, not evidence of a new model run or overall v3 qualification.
4. Ran the existing reset-checker and summary suites. The first invocation without the repository's hardware-helper import path had 96 passing tests and four summary-fixture `ModuleNotFoundError: t_config` errors. Re-running with the existing helper directory on `PYTHONPATH` passed **100/100**:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only/hw python -m pytest -q -p no:cacheprovider defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_reset_application_check.py defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_model_summary.py
```

The remaining validation is the separately owned contention02 run with its new driver hash, fresh reset postcheck, and bound dependency evidence. Contention01 remains its original exit-1 artifact; this review does not relabel it or claim the complete model gate passes. No source/evidence edits, models, hardware, or children were used for this follow-up.
