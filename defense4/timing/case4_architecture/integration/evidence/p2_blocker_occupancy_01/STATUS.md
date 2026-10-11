# Precise release with low total work: shape BOTH hold and blocker queues (2026-10-11, diag build residency_diag_01)

Diagnostic build (bfrt 8c687b72, p0 2855def3, p1 15d226e8), T-on, 5 ms fixture, 10 READs + 1 SBO per block, fresh
cold bring-up each, master ports 54470-54474. n = 10 READs per block: a diagnostic comparison, not a distribution.
CLRT is `m_R - m_A` at the host capture point (microsecond pcap resolution); SD is reported as population and
sample (`clrt_check.py` now labels both). "Total counted passes" = held-original re-waits + blocker laps from the
diag counters (packets, not bytes; loop-port packet+byte counters landed in 4cc5952c5 after these runs).

## TM shaper realizes only a x4 ladder (measured, `shaper_quantization.txt`, `quant_probe.py`)

Requested -> achieved PPS (burst 1) on dev 182 qid 6: 100->58, 200->232, 300->232, 500->930, 750..1500->930,
2000..5000->3723, 7500..20000->14892, 30000..100000->59570, 200000->238281. Achievable set: 58, 232, 930, 3723,
14892, 59570, 238281 PPS = poll intervals 17.2 ms, 4.31 ms, 1.08 ms, 269 us, 67 us, 16.8 us, 4.2 us.

## Results

| config | READ CLRT median | pop SD | sample SD | req->ACK med | req->resp med | orig re-waits | blocker laps | total passes | fallback |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| unshaped (milestone ton5, K=2) | 803 | 11.9 | - | 5,468 | 6,265 | 71,820 | 483,138 | 554,958 | 0 |
| slow all-queue 232 PPS (comparison) | 4,293 | 1,043.4 | - | 7,494 | 11,753 | 58 | 531,889 | 531,947 | 0 |
| B1: ACK blocker queue only, 50,262 PPS | 814 | 13.4 | 14.1 | 5,474 | 6,292 | 75,476 | 363,654 | 439,130 | 0 |
| hold queues 3,723 PPS, blockers unshaped | 815 | 10.1 | 10.6 | 5,499 | 6,324 | 246 | 486,356 | 486,602 | 0 |
| hold queues 14,892 PPS, blockers unshaped | 811 | 21.8 | 23.0 | 5,499 | 6,314 | 883 | 485,119 | 486,002 | 0 |
| **hold + blocker queues 3,723 PPS** | 806 | 13.3 | 14.0 | 5,637 | 6,443 | 277 | 1,246 | **1,523** | 0 |
| **hold + blocker queues 14,892 PPS** | 811 | 13.2 | 13.9 | 5,483 | 6,297 | 977 | 2,335 | **3,312** | 0 |

Every row: master success, 10/10 READs match seed, one real SELECT + one real OPERATE, zero decoy,
OUT_ACK_COMMIT=10, OUT_RESP_RELEASE=10, OUT_OP_RELEASE=1.

## What it shows

1. **Precision is preserved at poll intervals well below the gap.** Median CLRT 806-815 us against the 800 us
   target (+6 to +15 us), SD 10-22 us, same as unshaped (11.9); only the slow 232-PPS poll (4.31 ms) breaks it.
2. **Added latency tracks half the poll interval.** Request->ACK +15 us at 14,892 PPS (67 us interval) and +169 us
   at 3,723 PPS (269 us interval); request->response +32 us and +178 us.
3. **Total work is set by the whole port, so only shaping both queue classes removes it.** The loop ports carry all
   six queues; shaping the hold queues alone leaves ~486k blocker laps, and shaping only the ACK blocker queue
   (B1) cut ACK blocker laps 301,722 -> 3,314 but ACK originals stayed at 63,548 and RESP blocker laps rose
   166k -> 345k (a rate-limited blocker queue is ineligible, so the hold queue is served in its gaps, and freed port
   capacity goes to the unshaped queues). Shaping hold and blocker queues together: 364x (3,723) and 168x (14,892)
   fewer counted passes than unshaped, with the same CLRT precision.
4. The original-recirculation count and the total-work count are different quantities: slow shaping lowered the
   first 1,238x and the second only 4%; this configuration lowers both.

## Limits and what is not yet shown

- n = 10 READs, one connection per block, one fixture delay (5 ms), one gap (0.8 ms): no distribution, no
  variation of fixture/spacing/start phase yet, and one SBO per block.
- Counts are laps (packets). Loop-port packet and byte totals need the 4cc5952c5 snapshot; to be measured on the
  production build.
- These runs use the diagnostic build; the production build has to confirm the same behaviour.
- Rates are the achieved readback values (exact ladder points); intervals are nominal, not measured service
  intervals. Release-delay distribution beyond n = 10 not measured.
