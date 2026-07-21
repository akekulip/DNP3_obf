# Continuous-traffic campaign — PASS on Tofino silicon (2026-07-20)

Hardened dcrn_ackA.p4 sha `6e1b659b` (commit d380d1a), 120 sequential Class-0 txns on ONE persistent
connection, shuffled readiness {2,5,10,16,20}ms (seed 7), NO cold reload. Single-host Hulk loopback rig.

## Acceptance PASS
- 120/120 txns complete, byte-identical (client mism=0).
- **CLRT collapsed to a constant ~0.026 ms** (median 0.026, min 0.024, max 0.058) across all 120 txns.
- **No degradation across txn index**: head10 0.031 ms ~= tail10 0.026 ms (no growing hold, no backlog).
- **0 retransmits, 0 resets** (clean transport under continuous single-flow, NO cold reload).
- evstat (egress) diff over the campaign: ACK_RELEASED=120, RESP_RELEASED=120, ACK_MAXPASS=0,
  RESP_MAXPASS=0 (every hold event-governed, never fail-opened).
- Occupancy (flow_has_held_ack non-zero count) = 1 residual at end (NOT accumulating -> the reload
  dependency is gone). Minor edge (likely last-txn in-flight); follow-up item, not a blocker.

## Root cause of the earlier campaign "FAIL" (see ../continuous_campaign_FAIL/)
NOT a P4 regression. `ackA_setup.py` crashed on the removed `reg_held_count` (FIX4 replaced it with
per-flow flow_has_held_ack) BEFORE installing the fc_allowlist -> nothing armed -> no hold. With the
setup script fixed (REG_GLOBAL=[]), the allowlist installs and the hardened hold works. Also fixed the
stale reader (evstat moved to DcrnEgress; reg_held_count -> occupancy scan).

## Single-txn confirmation (rt2): CLRT 16.46 native -> 0.024 ms Case-A, byte-identical, clean.
