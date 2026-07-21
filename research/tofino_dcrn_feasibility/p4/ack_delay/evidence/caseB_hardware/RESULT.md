# Case B (response-delay) — hardware result on Tofino (2026-07-20)

dcrn_ackB.p4 sha 6387accb, loaded on the switch (9.13.2, 10 ingress stages), B1_FIXED G_i=60ms
(916 ticks), single-host Hulk loopback rig. 99 Class-0 txns/connection per profile, no cold reload.

## Result: device-INDEPENDENT constant CLRT (the Case-B objective)
| profile | native CLRT | Case-B CLRT |
|---|---|---|
| dev1 (17ms) | median 17.35 ms (IQR 15.9-18.7) | **median 106.99 ms (IQR 106.97-107.01)** |
| dev2 (35ms) | median 35.30 ms (IQR 33.3-37.3) | **median 107.00 ms (IQR 106.98-107.02)** |

Native CLRT is device-dependent (17 vs 35 ms — separable). Case-B fixes CLRT to a **device-independent
constant ~107 ms for BOTH devices** (medians 106.99 vs 107.00, IQR ±0.02 ms) -> a passive observer sees
the same CLRT regardless of device. Request->ACK unchanged; ACK forwarded immediately (single-txn ACK
hold 0.02 ms); response held to the ACK-relative deadline; response byte-identical (99/99); 0
retransmits/resets; occupancy (reg_held_count) returns to 0. Release is deadline-governed (CLRT 107 ms
<< MAX_PASS 65536 ticks -> not fail-open).

## The offset (constant 107 ms vs nominal G_i 60 ms)
The measured constant exceeds G_i by ~47 ms: a systematic recirc-drain/path offset under continuous load
(single-txn offset was ~21 ms; larger under load). It is CONSTANT and device-independent, so the defense
property (indistinguishability) holds; the target value is tunable (effective CLRT = G_i + offset). The
offset is the Case-B analogue of Case-A's guard delta and should be characterized under a load sweep
before B2/calibration. G_i must still exceed the readiness tail (40 ms) so the deadline governs (else the
response passes at readiness, device-dependent).

Both cases now normalize CLRT to device-independence: Case A COLLAPSES to ~0.026 ms; Case B FIXES to a
constant ~107 ms. Evidence: b_dev1/b_dev2/b1 pcaps + caseB_analysis.txt.
