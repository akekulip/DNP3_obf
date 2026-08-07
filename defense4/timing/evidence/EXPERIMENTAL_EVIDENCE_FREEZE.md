# Defense 4 experimental evidence freeze — REOPENED (no accepted verdict)

**Verdict: REOPENED. There is no accepted experimental verdict for Defense 4.**

The earlier "TIMING EXPERIMENTS PASS" freeze was withdrawn. Its full text is archived, verbatim and
clearly marked not-accepted, in `EXPERIMENTAL_EVIDENCE_FREEZE_ae2a802_ARCHIVED.md`. It was reopened
because the pipeline that produced it was not fail-closed and the mandatory controlled negatives were
never run. The independent adversarial audit and the reproduced failures are in
`PHASE1_INDEPENDENT_AUDIT.md` and `NEXT_RUN_BASELINE_AUDIT.md`.

## Current honest state

- **The P4 lifecycle CODE was repaired.** The mode-blind `tag_retire_if_unmarked` defect was fixed
  (fix commit `e47bcaa`, source sha256 `1242ca4d…`), and a corrected binary
  (`97175e7d…`, BF-SDE 9.13.2, 12/12 ingress) was compiled and deployed. This is a code and
  compile fact.
- **The repaired implementation has NOT been re-accepted experimentally.** No timing, byte-preservation,
  disposition, fail-open, negative-case, or classification claim from the archived freeze is accepted.
  Every such number must be re-derived from raw evidence by the repaired fail-closed pipeline and pass
  the Phase 6 independent gate before it counts.
- **The measurement-and-evidence pipeline was rebuilt to fail closed** (Phase 1). Its behavior is
  proven by `../control/deploy/fixtures/run_tests.sh`, which reports every test name with expected and
  actual exit codes. The pipeline being trustworthy is a precondition for evidence, not evidence
  itself.

## Outstanding gates before any verdict (from the completion plan)

1. Fail-closed scorer/harness proven by negative fixtures — **DONE (Phase 1)**.
2. Controlled software outstation + all negatives (missing-ACK/RESP, overlap, duplicate, identity
   mismatch, FIN/RST, combined-response, multi-segment, SELECT/OPERATE) — **NOT STARTED (Phase 2)**.
3. P4 audit/compile/deploy against the controlled evidence — **NOT STARTED (Phase 3)**.
4. Recalibrated physical + controlled campaigns, full distributions with tails, paired byte identity —
   **NOT STARTED (Phase 4)**.
5. Before/after timing-fingerprint classification — **NOT STARTED (Phase 5)**.
6. Independent acceptance + single verdict — **NOT STARTED (Phase 6)**.
7. R11 reservoir readiness: structural guard or explicit OPEN carry — **OPEN**.

## Scope and safety (unchanged)

One physical SEL-751, READ-only, CLRT observable only. Hazardous and negative cases run only on an
isolated software outstation. No size, cross-device, anonymity, or full-fingerprint claim. Not merged
to main. The Introduction stays quarantined until Phase 6 closes.

The only verdict recorded here is **REOPENED**. `EXPERIMENTAL_EVIDENCE_FREEZE.md` will carry a single
accepted verdict (`TIMING EXPERIMENTS PASS`, `… PARTIAL WITH CLOSED CLAIM BOUNDARY`, `… FAIL`, or
`… BLOCKED`) only when the Phase 6 gate closes.
