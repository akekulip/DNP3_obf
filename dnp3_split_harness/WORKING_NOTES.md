# WORKING NOTES — ACK/latency timing manipulation (ack_delay.md plan)

Task: execute /home/philip/Projects/DNP3/ack_delay.md — protocol-aware timing
manipulation for DNP3/TCP. Two phases. Priority order (from plan §12):
1. Characterize the 6 real traces.
2. Implement bounded normalization for the current COMBINED ACK-bearing response.
3. Validate safety + correctness.
4. Socket-level ACK separation experiment (Phase 2A).
5. Delay existing pure ACK + response independently (Phase 2B).
6. Attacker classification eval.
7. Only then assess P4.

## Key facts established this session
- Insertion point = split_server.py; send site is serve_once() line ~534 before
  `_send_chunks`. Response is a REPLAYED capture => response_ready ≈ request_arrival
  (no real processing), so holding until request_arrival+target_delay cleanly
  normalizes visible request->response time. Byte stream untouched (invariant OK).
- Codebase ALREADY does timing manip via --chunk-delay-ms (time.sleep between chunks),
  so response-hold timing is in-scope, precedent exists. NO byte/CRC/padding changes.
- Split harness is deliberately CONTROL-FREE (spec-clean). Do NOT add SELECT/OPERATE
  code here; control experiments belong to multicrob harness / real devices.
- Traces (verified earlier): SEL-751(10.0.0.1) SEPARATE ACK, CLRT≈11ms typical;
  AB1400(10.0.0.12)/ION7550(10.0.0.11)/reference(10.0.0.2) COMBINED (piggyback).
- Tools: tshark present; $RESEARCH_PYTHON has scapy 2.7; system py = 3.8.

## Plan / status
- [~] §1 trace characterization -> reports/ack_trace_characterization.{csv,json} + summary (SUBAGENT A running)
- [x] timing_policy.py (TimingProfile/TimingDecision/FlowTimingState/ReleaseScheduler/BypassReason)
- [x] unit tests tests/test_timing_policy.py -> 22/22 PASS (standalone + pytest)
- [x] integrate hold-until-target into split_server.py + CLI flags (native wire-identical)
- [x] loopback smoke tests/loopback_smoke.py: byte identity ALL PASS; native~0.3ms, fixed25->25.2, bounded20-30->23.1; full+split
- [~] profiles/*.json from characterization (SUBAGENT A)
- [~] rto_probe.py safety boundary (SUBAGENT B running)
- [~] Phase 2A ack_separation_probe.py (SUBAGENT C running)
- [ ] attacker_eval.py (§8) — depends on A's CSV; launch after A
- [ ] reports: repo assessment, run commands, validation, research report (§11)
- RIG-ONLY (document, can't autorun here): full 30-100 rep matrix on Vision/Hulk;
  authoritative RTO + real two-host ACK-separation. Loopback only here.

## Done so far (verified)
- timing_policy.py + 22/22 unit tests PASS; split_server integrated (native wire-identical).
- loopback_smoke: byte-identity ALL PASS; native~0.3ms, fixed25->25.2, bounded20-30->23.1.
- SUBAGENT A done: reports/ack_trace_characterization.{csv(22988 rows),json}, ack_trace_summary.md,
  profiles/*.json. SEL751 100% SEPARATE gap~12.9ms; AB1400/ION7550/ref COMBINED gap~0.
- SUBAGENT B done: rto_probe.py + reports/rto_probe_*. Measured RTO floor ~211ms (ss backend),
  safe hold ~105ms; 0 retrans/reset 0-100ms loopback.
- reports/ack_timing_implementation_report.md written (§11); experiment-matrix table pending.

## COMPLETE (all verified 2026-07-14)
- Matrix (run_timing_experiment): fixed-25 -> visible 25.17ms p95 25.19, 0 miss/bypass, bytes OK.
- Attacker eval (numpy; sklearn absent): native device-ID 0.897; timing defense closes timing
  channel only, size+ACK-mode residuals -> stays ~0.90; floor must exceed native ~16ms;
  constant-target detectable (AUC .99), bounded less (.887).
- Phase-2A probe: delay mechanism works, bytes OK 0-50ms; pure-ACK emission NEEDS privileged
  capture (unresolved here) -> honest 'unknown', rig command documented.
- Final verify: 9 scripts syntax OK, 22/22 tests, all deliverables present.
- Report ack_timing_implementation_report.md complete; memory + RESUME_STATE updated.

## GAP CLOSED (2026-07-14): real pydnp3 master integration
pydnp3 IS installed (system py3.8). tests/native_master_loopback.sh: real run_master
scan-all-classes vs timing-enabled split_server -> full integrity poll, DB decoded, 5/5
responses held ~24.5ms->25ms, byte-preservation PASS, 0 miss/bypass/reset, no DNP3 timeout.
ALL 7 checks PASS. Closes §10 "native OpenDNP3 transaction with delay" + "no retrans under
safe settings" with a REAL stack. Report §0 completion-audit table added.

## AUDIT VERDICT
Phase 1 (priorities 1-3): COMPLETE + real-stack validated. Phase 2 (4-5): logic built+unit-
tested, live measurement rig-deferred (pure-ACK needs privileged capture). §4 matrix PARTIAL
(loopback 20 reps; multi-CROB/SELECT-OPERATE/30-100reps need rig+control traffic). §8 SUBSTANTIAL
(no sklearn -> numpy logistic/nearest-centroid; simulated defense). §11 outputs COMPLETE.

## ONLY REMAINING = RIG (Vision/Hulk), documented not run here:
full 30-100 rep + multi-CROB matrix host-to-host; authoritative RTO; Phase-2A pure-ACK
detection w/ sudo capture; Phase-2B live ACK/response independent delay; then P4. Commands in
the report + reports/rto_probe_notes.md + reports/ack_separation_notes.md.
