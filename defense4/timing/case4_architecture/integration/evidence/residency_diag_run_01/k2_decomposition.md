# Residency decomposition at K=2 (diag build, T-on 5 ms, 10 READs + 1 SBO, 2026-10-11)

Build residency_diag_01 (bfrt 8c687b72, p0 2855def3, p1 15d226e8), master port 54432. Correctness held:
master success, 10/10 READs match, 1 real SELECT + 1 real OPERATE 0 decoy, OUT_ACK_COMMIT=10, OUT_RESP_RELEASE=10,
OUT_OP_RELEASE=1, zero fallback.

Per-role HELD-ORIGINAL re-waits (originals circulating because the BLK queue emptied):
  ACK 59,833  |  RESP 8,988  |  OPERATE 2,999   (total ~71,820; ACK = 83%)

Per-domain BLOCKER laps (keep_blocking, previously uncounted):
  ACK 301,722  |  RESP 166,420  |  OP 14,996   (total ~483,138)

pktgen: READ 24 trig / 96 pkt, OPERATE 1 trig / 4 pkt (k=2 -> 2 ACK + 2 RESP blockers per READ trigger).
Queue peak watermark: ACK_BLOCK 324, RESP_BLOCK 318, OP_BLOCK 5; holds 1/2/2; zero drops.

Reading: internal traffic is dominated by BLOCKER laps (483k), ~5000 laps per generated blocker. Held ACK
originals still re-wait 59,833 times despite 301,722 ACK-blocker laps -> the 2 ACK blockers do not keep qid 7
continuously occupied: while a blocker is in flight on the ~20 us MAC-loopback loop, qid 7 is momentarily empty
and the held ACK original (qid 6) is serviced and re-waits. This is a scheduling/loop-latency gap, not a blocker
shortage. ACK dominates both originals and blocker laps (longest hold at 12 ms readiness). The K sweep tests
whether more resident blockers close the gap or merely add blocker traffic.
