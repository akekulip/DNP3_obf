# Correction to ack_diag.md (2026-10-17, review af7bd434)

`ack_diag.md` and `ack_diag.json` are generated outputs and are left unchanged.

- **Denominator.** m9d ran 12 arms of 193 exchanges: 2,316 in all, all matched. The six timed arms hold
  **1,158 timed exchanges**. Timing statistics drawn from m9d refer to the 1,158 timed exchanges.
- **"downstream of the egress parser."** The tables' localization column means downstream of the switch's
  **egress-parser observation point**: after the final queue, but before the rest of egress, the deparser, the MAC,
  the link and the receiving host. It does not establish a host-only or NIC-only cause, and the diagnostic timestamp
  is not a wire transmit time.
- **Status of m9d.** m9d is a diagnostic build. Its model gate was unmet when these blocks ran
  (`ctl_timing_01/evidence/m9d_01/model_summary_v2.json`: blocked).

The full correction is in `ctl_timing_01/evidence/m9_01/ROUND2_DECISION_20261017.md`, section "Corrections".
