# Defense 4 Case-A — hardware bring-up result: **HARDWARE BRING-UP PASS**

The bounded, already-authorized short bring-up of the unified Defense 4 Case-A timing engine
ran on silicon against the physical SEL-751 relay on **2026-08-07**. All directive criteria
were met, no abort condition fired, and Defense 3 was restored to a forwarding state and
verified before the run was declared complete. **R11 remains OPEN** (the autonomous pktgen
bootstrap is not used; the proven harness-established reservoir is). No Case B, size
obfuscation, egress redistribution, two-pass, or statistical campaign was performed.

## Verdict

**HARDWARE BRING-UP PASS.** 34 transactions driven (1 OFF · 17 D1 · 5 D2 · 10 D4 · 1
FAIL_OPEN); **0 hard-aborts, 0 non-responded transactions, 0 TM drops/duplication/escape**;
the first protected READ passed every strict evidence check; the 17 D1 transactions crossed
the 16-generation rollover with every transaction answered; Defense 3 was restored and
forwarding verified. Evidence dir: `defense4/timing/evidence/bringup_live_20260807T014243Z/`.

## Deployment artifacts exercised

- P4: `defense4_caseA` compiled with **BF-SDE 9.13.2** (`p4c 9.13.2 SHA 1baf055`), tofino.bin
  sha256 `0ec4e452…e90e1242`, 1416979 bytes, staged at `/home/decps/d4_build/build9132/`
  (see `caseA_9132_deployment_compile.txt`), loaded via the proven `swap_generic.sh`.
- Host: switch `decps@10.10.54.81` (ufispace), master `decps@10.10.54.19` (Vision), physical
  SEL-751 at `192.168.10.7:20000` — **READ-only** throughout.

## The two-reservoir split — proven on silicon (first protected READ, txn 2)

One real relay READ seeded BOTH reservoirs from a single 2K=128-token pktgen burst, split in
the data plane by `hdr.pgen.packet_id`. Every strict check passed:

| check | result |
|---|---|
| pktgen `pkt_counter` delta == 128 | **true** |
| `CF_PKTGEN_ADMIT` delta == 128 | **true** |
| qid7 (Q_ACK_BLOCK) watermark increased | **true** (+43 cells) |
| qid5 (Q_RESP_BLOCK) watermark increased | **true** (+64 cells) — the previously-unseeded reservoir |
| qid4 (Q_RESP_HOLD) watermark increased (RESPONSE held) | **true** (+3 cells) |
| ACK not after RESPONSE on the wire | **true** |
| zero TM drops | **true** |

qid6 (Q_ACK_HOLD) also traversed (+1). The ACK-before-RESPONSE ordering is guaranteed
STRUCTURALLY by the setup-verified strict-priority ladder qid7>qid6>qid5>qid4; the master-side
pcap confirms it is never reversed.

## CLRT normalization by mode (master-side pcap, n as noted)

| mode | n | CLRT median (ms) | range (ms) | reading |
|---|---|---|---|---|
| OFF | 1 | 1.824 | — | true bypass; native separate-ACK CLRT |
| D1 (event) | 17 | **0.031** | [0.000, 0.049] | ACK dragged forward to coincide with the RESPONSE — native CLRT collapsed |
| D2 (RESP deadline) | 5 | **4.784** | [1.833, 5.999] | RESPONSE held to its deadline — CLRT lifted off native |
| D4 (dual deadline) | 10 | 2.900 | [1.804, 5.352] | both deadlines engaged |
| FAIL_OPEN | 1 | 2.977 | — | bypass; pktgen disabled |

Every transaction was answered (`responded=1`); pktgen was disabled in OFF and FAIL_OPEN
(delta 0), enabled only in D1–D4. The exact D_R magnitudes are NOT tuned here — CLRT
calibration is a statistical-campaign concern explicitly out of scope for this functional/
safety bring-up. What the bring-up establishes is that each mode's mechanism engages safely.

## Safety mechanism — exercised and proven in-situ

The disconnection-safe deployment support worked exactly as designed across the debugging
iterations that preceded the passing run:

- **Auto-abort → rollback**: the first two attempts hit configure defects (a wrong
  `disarm_port_shaper` argument shape; a `tbl_params` tuple-unwrap); the runner auto-aborted
  and rolled back to Defense 3 each time, and the scorer's first "RESP-before-ACK" flag was an
  over-strict ordering check (equal wire timestamps are inconclusive, not a reversal — the
  CLRT-obfuscation goal is a coincident ACK/RESP). Each was fixed and committed.
- **Rollback restores FORWARDING**, not just the program: a cold `bf_switchd` load leaves ports
  down, so the rollback also runs Defense 3's `setup --config --arm-blockers` (the proven
  live_r1 restore). Validated end-to-end on live hardware.
- **Independent detached watchdog** (setsid on the switch) armed at a 1200 s deadline, and on
  the passing run stood down on the completion marker — which is written ONLY after Defense 3
  is restored AND forwarding is verified. A shell trap cannot catch SIGKILL; the watchdog
  covers that case.

## Post-run state (verified, read-only)

`prog=case_a_defense3`, one `bf_switchd`; relay reachable through the switch (ping ~0.6 ms);
watchdog stood down on the marker; switch clean and on the production Defense 3 baseline.

## Not done / open

- R11 (autonomous pktgen bootstrap) OPEN — the harness-established reservoir was used.
- D_A/D_R magnitude calibration, the 22-trace adversarial suite, and any statistical CLRT
  campaign are out of scope and not performed.
- Size obfuscation (Priority 2) remains deferred behind this timing checkpoint.
