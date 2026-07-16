# Phase 01 — Data Quality Report

Run `20260716T103940Z_phase_01_real_trace_characterization_committed`. Total reconstructed transactions: **22988** (device-specific 11494, shared reference outstation 11494).

## Prior-count reproduction
- Prior reports stated ~22,988 reconstructed transactions. This isolated run reconstructed **22988** from the six raw PCAPs.
  REPRODUCED (matches 22,988).

## TCP / matching anomalies (whole run)
- transactions with retransmission: 93
- transactions with duplicate ACK: 93
- transactions with out-of-order: 0
- transactions with reset: 4
- transactions with missing response: 0
- OTHER_OR_AMBIGUOUS transactions: 0

## Classification confidence
- high: 22891   medium: 97   low: 0

## Shared reference outstation (10.0.0.2)
- The reference outstation appears in every capture and is EXCLUDED from device-specific analysis and profiles; it is reported here only for provenance. Reference transactions this run: 11494.

## Ambiguous handling
- OTHER_OR_AMBIGUOUS transactions are retained (not discarded) and enumerated in `tables/transaction_anomalies.csv` with their `ambiguity_reason`.

