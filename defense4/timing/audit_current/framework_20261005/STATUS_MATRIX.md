# Implementation / evidence matrix — 2026-10-06

Status vocabulary (cumulative): implemented, offline-tested, compiled, loaded, configured, hardware-measured, unresolved.
Only what was checked this session is marked as such; "carried" means taken from a prior note and not re-derived.

| objective | historical implementation | current implementation | source / build | sim / rig / physical | tested workload | supported metric | unresolved gap | next acceptance test |
|---|---|---|---|---|---|---|---|---|
| Response-ready READ release (e_A = max(t_0+D_A, t_R, t_A), e_R = e_A + CLRT_new) | none (campaign_v1 D4 holds on absolute deadline) | `response_ready/src/defense4_response_ready.p4` | sha `cedded03…`; SDE 9.13.1 build 34, 7/0 stages; 9.13.2 rebuild pending | offline-tested; compiled (9.13.1); not loaded | 14 READ scenarios run through the independent model and through a pass simulator that executes the P4's own register actions and const tables (`framework/tests/test_model_vs_p4.py`): early, just-late, late, reversed, ACK after deadline, 32-bit clock wrap, never, after-watchdog, next transaction, back-to-back, busy, non-matching | release instants agree within one token loop (about 1.7 µs) | association registers are a match flag, not simulated; one token per slot stands for the 64-token ring; parser, clone-to-pktgen latency and queue service idealised; tokens not lost; two flows, hash collision, multi-segment not covered. Release instant is not wire departure. | extend to ACK-after-watchdog, two flows, token loss; then a bounded hardware smoke |
| Recovery (stale, wrap, busy, fallback) | frozen watchdog | same candidate; fixed timeout-note defect | as above | offline-tested | `test_p4_recovery` | none | tuple reuse, hash collision, two flows, TCP loss repair not covered | extend tests; code-review the 9-row change |
| ACK-focused (Case 1) | Defense 1 (hold ACK to response) | not separately selectable | n/a | unresolved | none | none | D1/D2/D3 declared but never arm in frozen build | Phase 3 |
| Response-focused (Case 2) | Defense 2 (60 ms target, ~107 ms measured, unexplained) | not separately selectable | n/a | unresolved | none | none | 47 ms offset uninvestigated | Phase 3 |
| Size split [28,21] | joint commit `9ffa9102d` | not in tree | archive revisions | unresolved | 30 READ + 30 SELECT, historical | historical only | reproduce original scope first | Phase 4 |
| BFRT control adapter | none | `active_control` verifier with injected Device, mock only | `active_control/` | offline-tested (98); no real adapter | mocks | none | no adapter against actual schema | Phase 5 |
| BMv2 artifact | none | `/usr/bin/simple_switch` present; no code | n/a | unresolved | none | none | whole phase | Phase 6 |
| Generated ACK (Case 3) | design reviews only | none | n/a | unresolved | none | none | transport responsibility undefined | Phase 7 |
| campaign_v1 reproduction | frozen | repro entry exists | `defense4/timing/reproduce.sh` | not rerun this session | — | — | rerun into new build dir | Phase 0.5 remainder |
