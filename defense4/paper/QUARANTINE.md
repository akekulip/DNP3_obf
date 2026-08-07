# Quarantine REAPPLIED (2026-08-07)

The Introduction is quarantined again. The earlier "quarantine lifted" state rested on the
ae2a802 TIMING EXPERIMENTS PASS verdict, and that verdict has been reopened (see
`../timing/evidence/NEXT_RUN_BASELINE_AUDIT.md`). The evidence pipeline that produced it accepted
bad data as clean (scorer exited 0 on a hard anomaly; `|| true` swallowed required failures;
manifests failed their own `sha256sum -c`), and the mandatory controlled negatives were never run.

Until the final acceptance gate (Prompt 6) closes on a fail-closed pipeline with raw evidence, the
Introduction must not be treated as accepted. Two claims in particular are held:

- **Fixed-value normalization.** The draft says the response-deadline and dual-deadline modes
  normalize the CLRT "to a fixed value." The corrected-binary data has late-arrival tails. A
  RESPONSE that arrives after T_RESP is a late safe release, not deadline normalization. The full
  distribution may not be described by its median or as an exact fixed value.
- **Byte preservation.** The draft claims the original bytes are preserved. This was checked at one
  observation point (relay-facing framing/length), not by paired ingress-vs-egress byte comparison.
  The claim is not established until the paired comparator confirms it on real captures.

Do not edit the Introduction prose to match new evidence during Phases 1 through 5. It is rewritten
only in Phase 8, from the accepted freeze, after Phase 6 closes the gate.
