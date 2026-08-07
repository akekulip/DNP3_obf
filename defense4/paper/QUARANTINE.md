# Quarantine LIFTED (2026-08-07)

The Introduction quarantine is lifted. The D2/D4 lifecycle defect was fixed (P4 fix commit e47bcaa,
binary 97175e7d), the corrected campaigns proved the timing transformations, and the evidence freeze
(`../timing/evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md`) reached **TIMING EXPERIMENTS PASS**.

The Introduction claims now match the corrected-binary raw evidence: the response-deadline (D2) and
dual-deadline (D4) modes normalize the CLRT to a fixed value with zero RESPONSE bypass (D4 tight at
10 ms, p5-p95 within 0.05 ms; not the pre-fix mixture). The earlier "D2 is a boundary that does not
shape" wording is removed, because after the fix D2 shapes. Limits stand: one relay, READ, CLRT only;
no cover-traffic, size, cross-device, or full-fingerprint claim.
