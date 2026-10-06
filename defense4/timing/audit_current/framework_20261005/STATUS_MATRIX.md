# Implementation / evidence matrix — 2026-10-06

Status vocabulary (cumulative): implemented, offline-tested, compiled, loaded, configured, hardware-measured, unresolved.
Only what was checked this session is marked as such; "carried" means taken from a prior note and not re-derived.

| objective | historical implementation | current implementation | source / build | sim / rig / physical | tested workload | supported metric | unresolved gap | next acceptance test |
|---|---|---|---|---|---|---|---|---|
| Response-ready READ release (e_A = max(t_A+D_A, t_R), e_R = e_A + CLRT_new) | none (campaign_v1 D4 holds on absolute deadline) | `response_ready/src/defense4_response_ready.p4` | sha `ceececa3…`; SDE 9.13.1 + 9.13.2, 7/0 stages | offline-tested (45 tests), compiled; not loaded | model/packet-level tests only | none yet (no traffic) | independent reference model not yet separate from the P4-mirroring tests; release instant vs ACK departure | Phase 2 trace matrix incl. late/fallback; then bounded READ smoke |
| Recovery (stale, wrap, busy, fallback) | frozen watchdog | same candidate; fixed timeout-note defect | as above | offline-tested | `test_p4_recovery` | none | tuple reuse, hash collision, two flows, TCP loss repair not covered | extend tests; code-review the 9-row change |
| ACK-focused (Case 1) | Defense 1 (hold ACK to response) | not separately selectable | n/a | unresolved | none | none | D1/D2/D3 declared but never arm in frozen build | Phase 3 |
| Response-focused (Case 2) | Defense 2 (60 ms target, ~107 ms measured, unexplained) | not separately selectable | n/a | unresolved | none | none | 47 ms offset uninvestigated | Phase 3 |
| Size split [28,21] | joint commit `9ffa9102d` | not in tree | archive revisions | unresolved | 30 READ + 30 SELECT, historical | historical only | reproduce original scope first | Phase 4 |
| BFRT control adapter | none | `active_control` verifier with injected Device, mock only | `active_control/` | offline-tested (98); no real adapter | mocks | none | no adapter against actual schema | Phase 5 |
| BMv2 artifact | none | `/usr/bin/simple_switch` present; no code | n/a | unresolved | none | none | whole phase | Phase 6 |
| Generated ACK (Case 3) | design reviews only | none | n/a | unresolved | none | none | transport responsibility undefined | Phase 7 |
| campaign_v1 reproduction | frozen | repro entry exists | `defense4/timing/reproduce.sh` | not rerun this session | — | — | rerun into new build dir | Phase 0.5 remainder |
