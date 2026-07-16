# Phase 02 Research Reviewer — Overclaiming Audit

**Role:** Phase 02 Research Reviewer (read-only except this worklog).
**Date:** 2026-07-16
**Scope:** `reports/phases/phase_02/phase_02_combined_timing_normalization.md`,
`phase_status.json`, `tables/` (config_summary, decorrelation, projected_leakage,
transaction_log.csv), plus `phase02_normalize_experiment.py` and
`phase02_projected_leakage.py`.

## Verification performed (evidence)

All checks run this session against the shipped data files:

- **Row/aggregate recompute from `phase02_transaction_log.csv` (1050 data rows, 7 configs ×
  150):** byte-identical = 150/150 for **every** config; deadline_missed = 0 for every config;
  bypassed = 150/150 **only** for `fixed300-rto105`; big-READ (2407 B) median client-visible:
  native/full 0.5995, fixed25/full 25.3076, bounded20-30/full 23.3035, native/crc 0.7846,
  fixed25/crc 25.3067, bounded20-30/crc 23.2835, bypass 0.6364. **All match
  `phase02_config_summary.json` and the report Results table (lines 71–81) exactly.**
- **Decorrelation recompute from CSV:** native/full corr(vis,size)=−0.5496, corr(vis,native)=
  0.6813; bounded20-30/full corr(vis,size)=−0.1735, corr(vis,native)=0.0310 — **identical to
  `phase02_decorrelation.json`** and to the report's RQ1 headline numbers (−0.55→−0.17;
  +0.68→+0.03).
- **Projected leakage (`phase02_projected_leakage.json`) vs report:** fixed25 corr(vis,size)=
  0.0061, native corr(vis,size)=−0.0328 (report "0.03→0.006", line 37 ✓); fixed25
  deadline_miss/native-tail = 0.0022 = 0.22% (RQ4 ✓); bounded native-tail-over-20ms-floor =
  0.0095 = 0.95% (RQ4 ✓); corr(vis,native) 0.8696/0.3487 = "0.87 fixed / 0.35 bounded"
  (line 56 ✓); native median 16.039 = "~16 ms" (RQ5 ✓). Report↔table consistent.
- **Fail-open:** bypass rows all `bypass_reason=unsafe_target`, `added_hold_ms=0.0`,
  `selected_target=300.0`, byte-identical 100% — matches the fail-open claim (lines 66–69).
- **Test claim:** `python3 -m pytest tests/ -q` → **46 passed in 0.70s** (matches line 85 and
  `phase_status.json` `tests_executed`).
- **ACK / PCAP columns in the CSV:** `ack_mode_pcap` is uniformly `not_captured`;
  `retransmission_count` is uniformly `na_no_pcap` — i.e. no wire-timing or ACK-mode value is
  ever populated, consistent with the BLOCKED claim.

## Overclaiming flags

I checked all seven required categories. **No hard overclaims found.** Two soft items and one
cosmetic item are noted for tightening; none change the honesty of the phase.

### SOFT-1 (low severity) — "wire-equivalent" gate row marked PASS on loopback
- **File:line:** `phase_02_combined_timing_normalization.md:119`
- **Quote:** `| native mode is wire-equivalent | PASS on loopback (visible ~0.6 ms,
  byte-identical); wire PCAP pending |`
- **Why flagged:** the requirement literally names *wire* equivalence, and it is marked PASS,
  yet wire-equivalence cannot be demonstrated on loopback without a PCAP. This is the single
  place where a wire-named requirement shows PASS.
- **Mitigation already present:** the cell is qualified "PASS **on loopback** … **wire PCAP
  pending**", the adjacent row `actual wire timing verified by PCAP` is **BLOCKED** (line 121),
  and the Claim-discipline paragraph (lines 100–103) states loopback ≠ wire. So a reader is not
  misled. This is a wording tension, not a fabrication.
- **Fix:** rephrase to `PASS (loopback, application-level); wire equivalence PENDING PCAP` so
  the PASS token is not attached to the word "wire" without a qualifier.

### SOFT-2 (low severity) — one sentence mixes projected and loopback without an inline label
- **File:line:** `phase_02_combined_timing_normalization.md:60-62` (RQ5)
- **Quote:** "The deliberate hold is the dominant added latency (≈ target − native ≈ 9 ms at the
  ~16 ms native median for a 25 ms target)."
- **Why flagged:** the "~16 ms native median" is the **projected** real-device figure
  (projected_leakage native median 16.039), whereas the loopback added hold in this same report
  is ~24.4 ms (target 25 − native ~0.6). The sentence is grounded and arguably the *more*
  realistic overhead number, but it silently switches to the projected regime mid-RQ5.
- **Fix:** add "(projected real-device median)" after "~16 ms native median".

### COSMETIC — bypass_reason case
- **File:line:** `phase_02_combined_timing_normalization.md:68`
- **Quote:** "`bypass_reason = UNSAFE_TARGET`"
- **Actual value in CSV:** `unsafe_target` (lowercase). Purely cosmetic; no impact on meaning.

## Category-by-category verdict

1. **Loopback presented as wire?** NO (clean). Consistently labeled "loopback",
   "application-level", "client-observed": report lines 19–24, 71 (table header), 91–92,
   100–103; script docstrings `phase02_normalize_experiment.py:10-15`. Only tension is SOFT-1,
   which is qualified.
2. **Projected clearly labeled PROJECTED?** YES (clean). Lines 26–28, RQ1 (37), RQ4 (52), 93–94,
   the projected md header "PROJECTED / NOT WIRE-VALIDATED", and `projected_leakage.json` `note`.
3. **ACK-mode-after-normalization avoided / marked BLOCKED?** YES (clean). RQ3 lines 44–49
   ("Cannot be answered here — needs a PCAP"), gate line 122 BLOCKED, line 103 ("Nothing here
   claims the ACK mode after normalization"), status.json `combined_ack_after_normalization` =
   BLOCKED. CSV `ack_mode_pcap` never asserts separate/combined.
4. **Numeric claims match data?** YES. Independently recomputed byte-identity, deadline miss,
   bypass, medians, all decorrelation coefficients, projected corr/tail, and the 46-test count —
   all match (see Verification section).
5. **Native-tail leakage (RQ4) honest as residual?** YES (clean). Lines 51–58 report it openly
   and explain it is why projected corr(vis,native) stays positive; not hidden.
6. **Gate = CONDITIONAL PASS with PCAP/rig as blockers?** YES (clean). Report line 127
   CONDITIONAL PASS, gate table BLOCKED rows, `next_phase_allowed=false`, STOP line 134,
   status.json `status=CONDITIONAL_PASS`.
7. **Byte-preservation invariant stated correctly?** YES (clean). Line 42: `b"".join(chunks)
   == response` holds; no CRC recompute, no field edit — matches the project invariant.

## Residual limitation of this review

The projected-leakage JSON was cross-checked report↔table for internal consistency, and its
values are self-consistent; I did **not** re-run `phase01_reconstruct` over the raw PCAPs to
regenerate the projection from scratch (that depends on the Phase 01 reconstruction, out of
scope for a read-only spot-check). Everything derived from `phase02_transaction_log.csv` and the
summary/decorrelation tables was recomputed independently.

## Overall verdict

**The phase is honestly scoped.** Zero hard overclaims. The measured (loopback,
application-level), projected (shipped policy over captured timestamps), and blocked (PCAP wire
timing + ACK-mode-after-normalization) categories are cleanly and repeatedly separated; every
numeric claim I could recompute matches the data; the native tail is reported as residual
leakage rather than buried; and the gate is correctly CONDITIONAL PASS with the PCAP/rig items
as explicit blockers and `next_phase_allowed=false`. The only actionable items are two
low-severity wording tightenings (SOFT-1, SOFT-2) and one cosmetic case fix.
