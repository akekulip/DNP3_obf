# Repeat/lifecycle endpoint and prerequisite correction

Implemented after the parent confirmed source was safe to edit. Preserved the other session's existing v2 adapters and all legacy/Phase A branches. No model launches, hardware, network operations, commits, children, profile changes, P4 changes, J/tied-tick changes, or shared-helper edits.

## Changes

- `seg61_02/model_repeat.py`: the response-ready pair requires exactly ACK then complete response on the master port, with no output on any other observed port. Owned callers specify the master port; existing two-endpoint callers retain compatibility through unambiguous port inference. Ordinary request/response steps likewise require the expected destination port and zero additional output.
- `ctl_timing_01/model_select_lifecycle.py`: uses the explicit master-port pair contract and the same destination-port check for ordinary steps.
- Both drivers record each assertion before stopping immediately on failure. A missing or wrong-port SELECT cannot trigger simulated relay ACK/response, dependent OPERATE, subsequent scenarios, client/server/growth frontier changes, or completed exchange-count increments. Successful request application sequencing advances after confirmed request delivery.
- Both reports retain planned counts/scenarios, completed counts/scenarios, the active interrupted scenario, exact failed assertion name, stopped TCP frontier, remaining uncompleted exchange counts, and unexecuted later scenarios. Expected-drop probes still require zero frames on every observed port and continue when successful. Success paths retain their existing sequence-wrap, repeat, growth, authority, cancellation and reconnect checks.
- Expanded existing `seg61_02/tests/test_repeat_response_ready.py`; preserved all original test cases. Added wrong/split-port pair regressions and actual driver-main missing/wrong-port SELECT regressions, including no subsequent traffic, unchanged frontier/completed counts, and remaining-plan diagnostics.

## TDD and verification

1. Before source edits, existing focused test file plus new regressions: **4 failed, 5 passed**. Wrong/split-port captures were falsely accepted; actual repeat/lifecycle mains emitted respectively 44/91 further packets after a missing SELECT. The parent then sent the safe-to-edit signal.
2. Initial endpoint-pair and fail-stop correction: **9 passed**.
3. Before the additional ordinary-step endpoint fix, new actual-main wrong-port SELECT cases: **2 failed, 9 passed**. Repeat/lifecycle emitted respectively 21/1 further packets after the SELECT returned byte-exact on the master port.
4. Final focused plus existing relevant harness checks: **64 passed in 0.22s**, including **11** repeat regressions. Command:

```text
python3 -m pytest -q \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/tests/test_repeat_response_ready.py \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_rearm_response_ready.py \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_response_ready_stimulus.py \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_response_ready_profile.py
```

5. `git diff --check --` both changed driver paths: exit 0. Python `compile(...)` and `ast.parse(..., feature_version=(3, 8))` on both drivers and the focused tests: all pass. These are offline harness checks; compiled-model validation belongs to the parent and remains to be run against these final source identities.

## Final changed files and SHA-256

Paths below are relative to `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments`:

```text
4d259036e3bd0e74a812b67c7fd8d770a52d95c436090c77bca685bc14a773bb  seg61_02/model_repeat.py
35e0d4444dfc12dec9a674f7ccb6a81099c5e5f6b7749f6b27d1049c6b1752d8  ctl_timing_01/model_select_lifecycle.py
2fd1fa2ed294d2d0043e419ae0f5b84594991dc6b09cabf75884aa61c3ff1fe4  seg61_02/tests/test_repeat_response_ready.py
```

The additional authored artifact is `.superpowers/sdd/plan/repeat-report.md`. The earlier read-only `.superpowers/sdd/plan/repeat-review.md` remains a historical review bound to its recorded pre-repair hashes; its defect reproducer deliberately describes the old version.
