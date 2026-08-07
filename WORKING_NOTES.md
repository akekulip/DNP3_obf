# WORKING NOTES — Defense 4 gated closeout (2026-08-07)

**Governing plan:** `defense4/Defense4_Completion_Experiment_Prompts.md` (Prompts 0-8, one gate at a
time). The ae2a802 TIMING EXPERIMENTS PASS verdict is **REOPENED / invalid** until Prompt 6 closes
it on a fail-closed pipeline with raw evidence. Branch `defense4-caseA-hw-integration`, do NOT merge
to main. Not ADTA/ADTD. Timing Defense 4 only, no size obfuscation. Physical SEL-751 READ-only;
hazardous/negative cases (missing-ACK/RESP, SELECT/OPERATE, combined, multi-segment, FIN/RST,
overlap, duplicate, identity) run ONLY on an isolated software outstation (Phase 2). Plain storyline
prose, no em dashes, never "optimal" (say selected/tested), never describe a distribution by median
or as an exact fixed value when a late tail exists.

## Standing charter (Prompt 0)
Every conclusion traces to committed raw evidence. Every experiment records attempted/sent/responded/
valid/invalid/excluded with reasons. A parser error, missing file, empty input, incomplete capture,
counter-read failure, scorer anomaly, or hash mismatch is a hard nonzero failure. No `|| true` on any
required op. Manifests generated only after every file is closed; `sha256sum -c` must pass. Never
delete failed trials. Keep pre-fix evidence separate from post-fix.

## Phase 1 (Prompt 1) — reopen the gate + make the evidence pipeline fail closed. OFFLINE, no live switch.
Reproduced failures recorded in `defense4/timing/evidence/NEXT_RUN_BASELINE_AUDIT.md`:
- F1 scorer exits 0 on a hard anomaly; F2 `run_campaign.sh` `|| true` on driver/scorer/copy/manifest;
  F3 malformed/empty/missing evidence read as clean; F4 byte_identity single observation point;
  F6 SHA256SUMS hashes run.log before on_exit appends (sha256sum -c FAILS on run.log).

### Phase 1 task tracker
- [x] Reopen gate: QUARANTINE.md reapplied, Introduction .tex header quarantined, claim-source matrix
      REOPENED, EXPERIMENTAL_EVIDENCE_FREEZE.md verdict WITHDRAWN, NEXT_RUN_BASELINE_AUDIT.md written.
- [x] score_campaign.py fail-closed + scenario/expectation schema (SCENARIOS). Exit 2 bad IO, 1 hard
      anomaly, 0 clean. Verified on real committed blocks (catches the D2 bypass; 5 clean modes pass).
- [x] run_campaign.sh: removed || true on required ops; aborts nonzero on driver/scorer/copy/dump
      failure; per-block PCAP validation; manifest built in on_exit AFTER run.log frozen; sha256sum -c.
      DRY_RUN path exercises the whole control flow offline.
- [x] pair_bytes.py paired ingress-vs-egress comparator. Catches a one-byte mutation (offset+app_seq),
      dropped, injected, reordered; handles MAC rewrite / offload / VLAN. byte_identity.py marked SUPERSEDED.
- [x] analyze_campaign.py fail-closed on malformed/skipped/FAIL blocks; session-aware bootstrap CI;
      full distributions min/p5/p25/p50/p75/p95/p99/max + IQR (exposes the D2/D4 late tails).
- [x] fixtures/build_fixtures.py + fixtures/run_tests.sh: 25/25 fail-closed assertions PASS.
      Immutable evidence root created at defense4/timing/evidence/final_run/ (README = policy).
- [ ] commit + push the Phase 1 checkpoint.

Phase 1 acceptance (met): all fail-closed tests pass (25/25); no required command suppressed; paired
byte comparison catches a one-byte mutation; a newly generated manifest verifies with sha256sum -c;
canonical docs REOPENED consistently; Introduction quarantined. Live switch untouched.

## After Phase 1
Prompt 2 controlled software outstation + negatives; Prompt 3 P4 audit/compile/deploy (D3 rollback is
emergency-only, keep D4 running); Prompt 4 recalibrate + physical campaigns; Prompt 5 before/after
classification; Prompt 6 independent acceptance + freeze; Prompt 7 explainer; Prompt 8 paper. Do NOT
combine 4-8.

## STATUS: Phase 1 in progress. Gate reopened. Rebuilding the fail-closed evidence pipeline (offline).
