# c74 on the physical SEL-751: connection-start fix confirmation (2026-10-30)

c74 is c72 plus const-entry rows only (`results/builds/c74/README.md`):
- a READ, SELECT or OPERATE that finds N's work cell held is retried within the existing budget instead of dropped;
- a late handshake ACK, proven by the connection's ISNs, is forwarded instead of aborted.

Resources are identical to c72.
- **Exact binary:** c74, source SHA-256 `c7e37eff…`.
- **Diagnostic build:** `c74_diag_mirror`, source SHA-256 `e46391d8…`. It is c74 plus the two existing relay-leg mirror
  sessions, and its blocks never qualify.
- **Procedure:** the design was registered before traffic in `DESIGN.json`. Every block ran as its own campaign with a
  fresh freeze, a dry-run of the exact command, timing and padding as stated, and guarded points {1, 3}.
- **Counting:** counts come from `scripts/analysis/confirmation_summary.py` and `recovery_e3.py`, beside the c72 results of
  the same blocks.

## Result

On both builds, c74 removes the connection-start loss in the trials run:

| Observable | c72 | c74 |
|---|---|---|
| Start frame received on dev9 and not forwarded (diagnostic build, combined arm, 32 starts) | 5 (3 handshake ACKs, 2 first requests) | 0 |
| Same, off arm (32 starts) | 5 (3 handshake ACKs, 2 first requests) | 0 |
| First request retransmitted by the master, diagnostic build (64 starts) | 4 | 0 |
| First request retransmitted by the master, exact binary (32 fresh connections in the strict, recovery and E4b blocks) | 1 (212.5 ms) | 0 |

Zero losses were observed in 64 mirror-observed starts, with mirror completeness 62 of 64 trials (each exception
accounted for on its own connection, below), and zero first-request retransmissions in 96 fresh connections. This
is not an unconditional loss-free claim. c74 is a hardware-tested checkpoint with open findings; no classifier or
evaluation campaign ran on c74, and those results belong to c72.

## Order, delivery, padding and timing (exact binary)

Strict workload: 4 cold trials of 32 cycles at each D, combined arm. The cycle is mixed READ → SELECT → OPERATE →
integrity READ.

| Check | c72 D = 20 / 5 ms | c74 D = 20 / 5 ms |
|---|---|---|
| Trials passing the strict gate and the recorded verdict | 4/4, 4/4 | 4/4, 4/4 |
| Transaction order equal to the strict cycle × 32 | 4/4, 4/4 | 4/4, 4/4 |
| Responses equal to the class images (141, 60, 60, 158 octets) | 512/512, 512/512 | 512/512, 512/512 |
| SELECT/OPERATE CROB SUCCESS on points 1 and 3 | 256/256, 256/256 | 256/256, 256/256 |
| Master TCP retransmissions | 1, 0 | 0, 0 |

CLRT by class under the response-ready ACK contract, median [p5, p95] in µs, 128 exchanges per class and D:

| Class | c74 D = 20 ms | c74 D = 5 ms | c72 D = 20 ms | c72 D = 5 ms |
|---|---|---|---|---|
| READ mixed | 19,995 [18,393, 21,632] | 5,048 [3,223, 6,840] | 20,005 [18,420, 21,597] | 4,930 [3,879, 6,857] |
| SELECT | 20,048 [18,371, 21,329] | 5,019 [3,793, 6,926] | 20,078.5 [18,695, 21,452] | 5,007 [3,599, 6,455] |
| OPERATE | 19,872 [18,166, 21,584] | 4,999.5 [3,537, 6,717] | 20,043 [18,420, 21,677] | 4,919.5 [3,385, 6,700] |
| READ integrity | 20,014.5 [18,269, 21,747] | 5,011 [3,401, 6,678] | 19,943.5 [18,408, 21,398] | 4,973 [3,631, 6,726] |

SELECT without OPERATE (E4b), 6 trials at D = 20 ms, the same on both builds:
- 24/24 SELECTs report CROB SUCCESS and no OPERATE is sent;
- 24/24 READs sent right after an abandoned SELECT are answered;
- all 120 READs match their class image and none is retransmitted.

The CLRT of those READs has a median of 20.08 ms on c74 and 19.66 ms on c72.

## The forwarded late handshake ACK (review finding H-1)

c74 forwards a late handshake ACK after the first request. The relay may answer that out-of-window segment with a
second ACK. The registered observable counts it per start, from the order of the mirror copies.

| | Combined arm | Off arm |
|---|---|---|
| Late handshake ACK forwarded | 4 of 32 (t4, t7, t12, t15) | 1 of 32 (t24) |
| Relay answered with a second ACK | 4 of 4 | 1 of 1 |
| Pure ACKs reaching the master before the first response | 1 in 32 of 32 | 2 in t24, 1 in the other 31 |

- **Combined arm:** with timing on, the timing hold absorbs the relay's second ACK. The master still sees one ACK, the
  first CLRT stays at D (18.6–20.0 ms) and every trial passes.
- **Off arm (the registered falsifier fired once):** with timing and padding off, t24's second relay ACK reaches the
  master as a duplicate pure ACK. That changes what the master receives, so by the registered definition it is a
  defect of the late-ACK rows. A duplicate pure ACK after delivered data is harmless to TCP, and the trial passed.
- **Not yet decided:** whether to keep forwarding these ACKs or to drop them as c72 did. c72 dropped them at no TCP cost:
  0 of 6 retransmitted.

## SELECT-response loss recovery (E3): a difference that stays open

Three conditions, 6 trials each, as in c72: D = 20 ms timing and padding, D = 20 ms padding only, and D = 5 ms timing
and padding.

| | c72 | c74 |
|---|---|---|
| OPERATE SUCCESS after a dropped padded SELECT response | 16/18 (r1 5, r2 6, r3 5) | 13/18 (r1 4, r2 5, r3 4) |
| OPERATE retransmitted by the master | 1 (r1 t3) | 0 |

The recovery path is the same in all 36 trials:
- the first padded SELECT response is dropped;
- the relay retransmits it 997.3–1,021.9 ms after the SELECT request (c74);
- the master sends OPERATE about 1.1 ms later;
- the relay acknowledges the OPERATE a few milliseconds after that.

The 5 c74 TIMEOUTs left the master at 1,004.8, 1,006.7, 1,014.3, 1,021.4 and 1,022.9 ms. In the same band, OPERATEs
succeeded from 998.4 to 1,022.5 ms; in r3, 1,022.5 ms succeeded while 1,022.9 ms timed out. The outcomes are not
ordered by departure time on either build, which points to the relay's selection window near 1.0 s. Its setting was
not read.

The count differs from c72, so by the registered falsifier it is reported as a c74 difference. Eighteen trials per
build cannot separate a c74 effect from that edge: 5/18 against 2/18 TIMEOUT, Fisher exact two-sided p ≈ 0.4. The
mechanism is not established.

The design said a failed trial would end its campaign. In these blocks the runner completed all 6 planned trials after
an application failure, as it did for c72. Every trial ran and is reported.

## Capture completeness and restoration

- **Mirror completeness:** 31/32 in each connection-start block.
  - t11 (combined): the switch emitted one copy fewer than the relay-leg frames.
  - t17 (off): it emitted one copy more.
  - In both, every frame of the trial's own connection has its copy and the master-host capture dropped nothing, so
    the start classification of those trials stands.
- **Restoration:** verified for 7 of the 8 blocks by the block itself.
- **The combined connection-start block** (`rc01_hw_c74diag_e2c_20261030_01`):
  - its final restore failed: `switch_swap.sh` sent SIGTERM and the candidate bf_switchd had not exited after 20 s;
  - the testbed was then restored by `scripts/hardware/switch_process_repair.py`. SIGTERM again did not finish in
    61 s, and SIGKILL to the verified process ended it in 0.76 s;
  - an independent re-verification followed, and reconcile cleared the unsafe flag (records under the campaign);
  - its runner result stays FAILED;
  - the cause of the stuck shutdown is not established;
  - the five later blocks ran as `_02` campaigns with fresh freezes.

## Limits

- 64 mirror-observed starts and 96 fresh connections are bounded counts, not rates.
- The mirror is used for packet presence, content and copy order only; its timing equivalence was not established.
- Diagnostic-build blocks qualify nothing about the exact binary. The exact-binary loss evidence is the master-side
  retransmission count.
- The relay's select-timeout setting remains unread.
- The SELECT/OPERATE transport wrap has no independent reassembly of its original 63→0 bytes: TShark decoded the
  wrap responses only on renumbered copies, and opendnp3 replayed only the READ wraps.
