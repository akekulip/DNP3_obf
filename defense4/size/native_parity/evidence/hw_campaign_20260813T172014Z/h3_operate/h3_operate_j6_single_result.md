# H3 single guarded OPERATE at fixed J=6 ms — result (2026-08-13, timestamps OFF)

Gated attended-session run (option 1: existing setup, master-facing capture; T0+J inferred).
Vision master -> Tofino (defense4_rrc_bor_unified12, sha 33fa3a77, dp10 two-loopback) -> physical SEL-751.
Guarded {1,3} SELECT->OPERATE at RB02/RB04 (empty-fanout decoys). A=20ms, R=24ms, fixed J=6ms. net.ipv4.tcp_timestamps=0.

## Gate results (from raw master-facing pcap h3_operate_j6_single_b.pcap, 19 pkts)
- TCP-timestamp gate: 2 SYN/SYN-ACK, 0 with TS option -> ABSENT (PASS, packet-level).
- Exactly ONE OPERATE (func 0x04, master->relay).
- T_ACK - T0  = 20.50 ms  (target A=20)
- T_echo - T0 = 24.48 ms  (target R=24)
- T_echo - T_ACK = 3.98 ms (target R-A=4)
- Echo carved [28,21] (28+21=49, valid func 0x81) -> byte-exact reassembly.
- RB02/RB04: 200ms PULSE (control code 0x01), drives nothing; ALL 32 physical outputs OPEN before AND after.
- Relay reachable throughout.

## Not measured (accepted limitation, option 1)
- T_OP,out = T0+J (relay-facing release at ~6ms): NOT captured. The existing setup has no host-capturable
  relay-facing tap (dp68 = internal pktgen/recirc/clone port, not a tap). T0+J is INFERRED, consistent with
  ACK@T0+A and echo@T0+R both anchored to T0. Direct T0+J would need a tap/mirror the existing setup lacks.
- J-independence: this is ONE transaction at J=6ms. Independence needs the (gated) multi-J batch.

## Per user's gate: STOPPED after the single transaction for review. No loop, no 30-txn batch.
