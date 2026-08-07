# Methods and Results (accepted timing evidence)

This is the evidence write-up for the Defense 4 timing paper, grounded only in the committed,
fail-closed-scored campaigns on the corrected binary. It is deliberately bounded: it reports the
timing normalization that is proven, and it states plainly what is not yet done. The Introduction
stays quarantined until the acceptance gate closes; nothing here is a final verdict.

## Methods

### Testbed and implementation

One Intel Tofino-1 switch sits between a DNP3 master and a physical SEL-751 relay. The master (Vision,
`192.168.10.1`) reaches the relay (`192.168.10.7:20000`) through the switch. The relay is READ-only
throughout; no control command is ever sent to it.

The switch runs `defense4_caseA`, source sha256 `1242ca4d…`, compiled with BF-SDE 9.13.2
(`p4c 9.13.2 SHA 1baf055`) to binary sha256 `97175e7d…`. The running binary is verified from the
pipeline's loaded configuration, not from a file on disk. The program places at 12 of 12 ingress
stages.

### Mechanism and modes

The original acknowledgment and response wait in low-priority queues while higher-priority internal
blocker tokens (EtherType 0x88C1) recirculate to hold their place; the traffic manager releases the
held packets on a schedule the control plane sets. Four queues in strict priority order,
Q_ACK_BLOCK (qid7) > Q_ACK_HOLD (qid6) > Q_RESP_BLOCK (qid5) > Q_RESP_HOLD (qid4), guarantee the
acknowledgment is never released after the response. The design works with, not against, the fact
that a data-plane pipeline cannot recall an already-enqueued packet at an arbitrary later time.

Five modes are configurations of the one framework: OFF (native passthrough); D1, event (hold the
acknowledgment until the matching response event); D2, response deadline (D_A=0, hold the response to
T_RESP = t_A + D_R); D3, acknowledgment deadline (D_R=0, hold the acknowledgment to T_A = t_A + D_A);
D4, dual deadline (hold both). Deadlines are encoded as a delay word of ticks shifted left by eight
(1 tick ≈ 1 ns), with the low byte zero. The tested policy is D4 with D_A = 4 ms and D_R = 10 ms, a
budget of 18000, and a fail-open horizon of about 30.8 ms. These parameters are selected and tested,
not optimal.

### Measurement and the fail-closed pipeline

The observable is the cross-layer response time, the master-facing interval from the pure TCP
acknowledgment to the first byte of the matching DNP3 response. Each block is one sustained TCP
connection carrying 60 READs whose DNP3 application-control octet advances C0..CF and rolls over.

Every block is scored by a fail-closed pipeline. The scorer exits with an error on any hard anomaly
(a response bypassing a hold on a must-hold mode, an ordering inversion, a stale tag, a counter that
does not reconcile, a token on the wire, a queue or port drop, a missing capture, or an absent
counter) and passes only a fully valid block; it is mode-aware, so the D_R=0 mode's coincident
acknowledgment-and-response timestamps are not misread as an inversion. The analyzer requires one
passing score per expected block and reports full distributions with tails and a session-level
bootstrap, never a median alone. Manifests are generated only after every file is final and are
verified. The pipeline's fail-closed behavior is proven by 78 adversarial fixtures. Offloads at the
capture point are recorded; because the relay's responses are single 134-byte frames, GRO has nothing
to coalesce, so the first-byte CLRT timing is intact.

### Campaign design

Two campaigns on the corrected binary. Campaign A used fixed block order; Campaign B randomized the
block order with a recorded seed (20260807). Each ran OFF, D1, D2, D3, D4 with two sustained sessions
per mode and 60 READs per session: 120 valid transactions per mode per campaign, 600 per campaign,
1200 in total.

## Results

### Every block passed; the must-hold modes bypass nothing

All 20 blocks (10 per campaign) passed the fail-closed scorer. On D2 and D4 the switch held every
response: RESP_BYPASS = 0 across 240 transactions each. On the pre-fix binary the same modes bypassed
D2 240/240 and D4 80/240, so the lifecycle defect is closed on silicon. D3 forwards responses that
arrive after its acknowledgment deadline (D_R=0), which is its designed behavior, not a bypass.

### CLRT distributions (ms, n=120/mode per campaign)

| mode | campaign | p5 | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| OFF | A | 1.82 | 2.97 | 7.64 | 13.67 | 15.65 |
| OFF | B | 1.81 | 2.87 | 7.21 | — | 15.17 |
| D2  | A | 9.96 | 10.02 | 10.09 | 14.34 | 16.59 |
| D2  | B | 9.95 | 10.03 | 10.08 | — | 16.00 |
| D3  | A | 0.00 | 0.03 | 2.07 | 4.93 | 5.17 |
| D4  | A | 9.98 | 10.00 | 10.03 | 12.20 | 16.70 |
| D4  | B | 9.98 | 10.00 | 10.03 | — | 18.77 |
| D1  | A | 7.80 | 11.13 | 12.21 | 12.22 | 12.23 |

OFF is the wide native fingerprint: the middle 90 percent of responses spans about 1.8 to 7.6 ms.
D2 and D4 pull that middle 90 percent into a band of about 0.1 ms around a fixed 10 ms, roughly a
fifty-fold reduction in spread, and the two campaigns agree (D4 p5 to p95 is 9.98 to 10.03 ms in
both). D3 collapses the CLRT to about zero; D1 shapes it to about 11 ms. The empirical CDFs are in
`fig_clrt_ecdf` (source-data hash recorded alongside).

We report the whole distribution. D2 and D4 normalize the bulk, not every observation: a small
fraction of responses arrive after the deadline and are released late but safely (D2 max about
16.6 ms, D4 max 16.7 to 18.8 ms across campaigns). A response after T_RESP is a late safe release, not
deadline normalization, and we never describe the population by its median or as an exact fixed value.

### Targeted lifecycle cases

- **The response obligation survives the acknowledgment release.** Counter RESP_HOLD_LATE counts a
  response that arrived after the acknowledgment was released and was still held. Across both campaigns
  D2 (D_A=0, so the acknowledgment releases immediately) held all 240 after-release responses with 0
  bypass, and D4 held 60. This is the exact behavior the pre-fix binary got wrong, now confirmed by the
  counters.
- **Generation rollover on one connection.** Every 60-READ block is one connection advancing C0..CF and
  rolling over 3.8 times with no per-poll state clear.
- **Fail-open, bounded release, and re-arm.** Forcing the fail-open path with a small budget (horizon
  1.37 ms) still delivered all 30 responses (bounded release, never stranded), with 30 fail-open
  releases, 0 deadline releases, every transaction re-armed, and no stale tag.

### Resources

The program fits a single Tofino-1 ingress pipeline at 12 of 12 stages, 0 errors; the deployed build's
footprint is 12/12 ingress, SRAM 47, TCAM 10, 107 logical tables. A fresh reproducible compile of the
exact corrected source (`1242ca4d`) on BF-SDE 9.13.2 confirms the source-to-binary chain: 0 errors, the
same two benign parser-unroll warnings, and a binary of exactly the same size (1,418,611 bytes) placed
into the same stage tail; the sha differs only because bf-p4c embeds a build date and run id. Artifacts
in `../timing/evidence/compiler_9132_repro/`.

## Limitations and future work (stated, not hidden)

- **One physical device, CLRT only.** With a single separate-acknowledgment device we show timing
  normalization for that device, not cross-device fingerprint defeat. A classification claim needs at
  least two comparable devices or a clearly labeled controlled software-profile study; neither is done.
- **Controlled negatives not run live.** Missing acknowledgment, missing response, FIN/RST, combined
  response, multi-segment response, and SELECT/OPERATE are produced by a controlled software outstation
  that is built and unit-tested offline (58 checks), but not yet run live through the switch, because
  that requires repointing the P4's single shaped flow off the real relay.
- **Byte identity.** The paired ingress-versus-egress comparator is validated on crafted captures (it
  catches a one-byte change, a dropped or injected frame, a MAC change); a live dual capture on the
  software outstation is pending.
- **Capture offloads on, accounted.** GRO/GSO/TSO were on at the master capture point (no privilege to
  disable); recorded and accounted for single-segment CLRT. Byte-boundary work needs them off.
- **No final verdict.** The acceptance gate is not closed. The Introduction stays quarantined. This
  write-up reports proven timing normalization and an explicit boundary, nothing more.
