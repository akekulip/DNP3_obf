# H3 physical-SEL BOR OPERATE — on-silicon result (2026-08-13)

Live: Vision master -> Tofino (defense4_rrc_bor_unified12, sha 33fa3a77, dp10 two-loopback) -> physical SEL-751.
Guarded {1,3} SELECT->OPERATE (RB02/RB04, audit-proven empty fanout). A=20ms, R=24ms, J-codebook {2,4,6,8,10,12}ms.
30 OPERATEs total (10 uncaptured + 20 captured). Master-facing capture: h3_operate_master_20.pcap (206 pkts, 20 txns).

## Result (from raw pcap, 20 OPERATE txns)
- ACK delay  T_ack - T0 : median 20.59 ms  (target A=20 ms)
- echo delay T_echo- T0 : median 24.60 ms  (target R=24 ms)
- echo - ACK            : median 4.00 ms, min 3.97, max 4.07, std 0.018 ms  (= R-A, INDEPENDENT of the switch's hidden random J)

The anti-subtraction invariant holds on silicon: the master observes ACK at ~T0+A and echo at ~T0+R,
and echo-ACK is a constant 4.00 ms regardless of the per-transaction randomized J -> J is not observable.

## Safety
Relay physical outputs (TRIP, OUT101/102/103/401/402/403 + all 32 BO points) read OPEN at baseline,
after the 10-txn batch, and after the 20-txn batch. Nothing actuated. Only indices {1,3} ever emitted
(hard guard; index 6 breaker-close refused). Config read-only except the authorized {1,3} OPERATEs.

## Honest bounds
- Master-facing observable proven (ACK@T0+A, echo@T0+R, echo-ACK=R-A const). The INTERNAL T0+J release
  (relay-facing) was not captured (dp68 mirror host not wired for capture) -- the internal release is
  inferred from the ~24.8ms OPERATE round-trip, not directly measured.
- 30 OPERATEs, randomized-J via codebook; a larger (1000+) run would tighten statistics but the
  invariant is already tight (std 0.018 ms). A few txns show +4-6ms absolute jitter on both ACK and echo
  together (echo-ACK stays 4.00ms), consistent with occasional master-side/scheduling jitter, not a J leak.
