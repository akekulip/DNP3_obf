# Campaign A — corrected binary, physical SEL-751 (fresh, fail-closed pipeline)

This is a fresh physical campaign on the corrected Defense 4 binary, scored by the repaired
fail-closed pipeline. It is the first accepted-pipeline timing evidence on the corrected binary.

## What was run

- **Binary:** `97175e7dc1a77c3c…` (corrected), program `defense4_caseA`, BF-SDE 9.13.2, verified from
  the switch's loaded conf (not a disk file).
- **Testbed:** switch `ufispace`, master Vision `192.168.10.1`, physical SEL-751 `192.168.10.7:20000`,
  READ-only. Capture master-facing (`enp59s0f0np0`), `CAPTURE_MODE=master`.
- **Design:** OFF, D1, D2, D3, D4; two sustained TCP sessions per mode; 60 READs per session;
  **120 valid transactions per mode, 600 total.** One connection per block advancing C0..CF.
- **Scoring:** the fail-closed `score_campaign.py` (mode-aware). Every block re-scored from raw after a
  scorer correction (see "Scorer correction" below). `blocks.jsonl` = 10 records, all `PASS`.

## Result: the timing obfuscation holds, and 0 unplanned bypass

Every protected block held its responses as designed, confirmed by the fail-closed scorer and the
counters:

| mode | verdict | responded | RESP_BYPASS | reading |
|---|---|---|---|---|
| OFF | PASS | 120/120 | 120 | native passthrough (bypass = forwarded unshaped, expected) |
| D1 (event) | PASS | 120/120 | 0 | ACK held to the RESPONSE event |
| D2 (D_A=0, D_R=10) | PASS | 120/120 | **0** | response-deadline hold; every response held |
| D3 (D_A=4, D_R=0) | PASS | 120/120 | 22 | ACK-deadline; responses after the ACK deadline forward (by design, D_R=0) |
| D4 (D_A=4, D_R=10) | PASS | 120/120 | **0** | dual-deadline; every response held |

The lifecycle defect (which made the pre-fix binary bypass D2 240/240 and D4 80/240) is gone on
silicon: **D2 and D4 bypass 0** across 120 transactions each.

## CLRT distributions (master-facing ACK-to-RESPONSE, ms, n=120/mode)

| mode | p5 | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| OFF | 1.82 | 2.97 | 7.64 | 13.67 | 15.65 |
| D1  | 7.80 | 11.13 | 12.21 | 12.22 | 12.23 |
| D2  | 9.96 | 10.02 | 10.09 | 14.34 | 16.59 |
| D3  | 0.00 | 0.03 | 2.07 | 4.93 | 5.17 |
| D4  | 9.98 | 10.00 | 10.03 | 12.20 | 16.70 |

OFF is the wide native fingerprint (CLRT spread ~2 to ~16 ms). **D2 and D4 compress the p5-p95 CLRT
spread from OFF's ~5.8 ms to ~0.1 ms, normalizing the bulk to a fixed 10 ms.** Figure:
`fig_clrt_ecdf.pdf/.png` (ECDFs; source-data hash in `fig_clrt_ecdf.meta.json`).

**Honest limit — the late tail.** D2 and D4 do not put *every* response at exactly 10 ms. A small
fraction arrive after the deadline and are released late but safely (D2 p99 14.3, max 16.6; D4 p99
12.2, max 16.7). The distribution is normalized in its bulk, with a late tail; it is not a perfect
fixed value. This is reported as a distribution, never as a single median or an exact constant.

## Scorer correction applied here (mode-aware ordering)

The first scoring flagged both D3 blocks for "inconclusive ACK/RESPONSE ordering." Investigation showed
those polls had `clrt == 0` (t_ack == t_resp) with **zero** true inversions (`resp_before_ack = 0`):
with D_R=0, D3 releases the ACK and RESPONSE together, so their microsecond capture timestamps
coincide by design. The scorer was mode-blind. It is now mode-aware: inconclusive timestamps are hard
only for the must-hold modes D2/D4 (where CLRT must be D_R>0); a true inversion (`clrt<0`) stays hard
everywhere, and a must-hold mode that failed to hold still shows as RESP_BYPASS. Locked by fixtures in
both directions (D2 inconclusive fails, D3 inconclusive passes); suite 78/78.

## What this is NOT (boundary)

- **Not accepted as the final verdict.** This is Campaign A only. Campaign B (randomized order),
  the targeted lifecycle cases, the controlled negatives on the software outstation, paired byte
  identity, and the classification study are still pending. The Phase 6 gate is not closed.
- **Master-only, so no paired byte identity here.** The physical relay has no relay-facing capture
  point; byte identity is a software-outstation claim (Phase 2).
- **Offloads on at the capture point** (no sudo to disable), recorded and accounted: the relay's
  responses are single 134 B frames, so GRO has nothing to coalesce and the first-byte CLRT timing is
  intact. Byte-boundary work (dual capture) requires offloads off.
- One physical relay, CLRT observable only. No cross-device, size, anonymity, or full-fingerprint claim.
