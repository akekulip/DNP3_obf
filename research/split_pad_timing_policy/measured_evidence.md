# Measured Evidence — Split / Size / Timing / Padding (rig, this session + prior)

_All numbers are **measured fact** from real Vision↔Hulk rig captures. Timing/size numbers
below were produced this session by running the existing `dnp3_split_harness/analyze_ack.py`
and scapy over existing PCAPs (no code changed); split/segmentation/padding numbers are from
prior rig reports, re-cited. Master = Vision `10.10.54.19`, Outstation = Hulk
`10.10.54.158:20000`, OpenDNP3 software, 1 G LAN. Cite these as "measured, this rig."_

## 1. TIMING channel — CROB count leaks in processing time
(from `research/ack_timing_normalization/measured_timing_data.md`)
- Baseline large READ: 9/9 piggyback, req→ACK 0.239 ms, req→response 1.014 ms, TCP opt sig
  `NOP-NOP-Timestamp`.
- CROB sweep: SELECT-resp **0.179 ms/CROB, R²=0.9985**; OPERATE-resp **0.214 ms/CROB, R²=0.9954**;
  OPERATE 1.62→4.90 ms over N=1→16. **Caveat: n=1 per N-level** (a clean 10-point line, not a
  replicated law); one device; CROB-count ≠ database-size.

## 2. SIZE channel — CROB count ALSO leaks in response size (this session, NEW)
Scapy over `dnp3_multicrob_harness/captures/sweep/multicrob_n{1..16}.pcapng`, outstation→master
payload sizes; the two large O→M payloads per capture are the SELECT-response and OPERATE-response
(equal size), the three 17 B ones are connect/disable-unsol/integrity setup.

| N | SELECT-resp = OPERATE-resp payload (B) |
|---|---|
| 1 | 37 | 2 | 52 | 3 | 67 | 4 | 80 | 5 | 95 | 6 | 110 | 8 | 140 | 10 | 168 | 12 | 198 | 16 | 256 |

- **Response size vs N: slope 14.6 B/CROB, intercept 22.5 B, R² = 0.9999**, 37→256 B over N=1→16.
- **Consequence (load-bearing for the whole study):** CROB count leaks on the **size** channel
  even more cleanly than on the timing channel. **Timing normalization alone cannot hide CROB
  count** — a passive observer reads it directly off response size. Hiding it on the size channel
  needs size normalization; but split preserves total bytes (§4) and no safe DNP3 padding exists
  (§5), so for these small control responses the size leak is currently a **residual** requiring a
  future protocol-modifying padding phase. Same n=1-per-N / one-device caveat as §1.

## 3. Response SIZE ∝ database point count (READ plane; measured, prior)
(from `dnp3_split_harness/reports/baseline_segmentation.md`)
- Range sweep g30v1 on a 200-analog DB: 10→50→100→200 points ⇒ **129→332→625→1211 B**
  (≈ **5.7 B/analog point**). Frames/segments: 4/3/4/6 link frames, 4/3/3/3 TCP segments.
- Large all-types READ (300-pt DB): **12,204 B** total O→M, **9** application fragments, **49**
  link frames (292 B DNP3 max frame), **20** TCP segments (MSS 1448). DNP3 frame and TCP segment
  boundaries do NOT align.
- So the **read-plane database-size leak is on the SIZE channel and is measured** (distinct from
  the *timing*↔DB-size relationship, which is still unmeasured).

## 4. SPLIT — CRC-boundary, byte-preserving; changes structure, NOT total bytes
(from `dnp3_split_harness/reports/split_aggressiveness_sweep.md`)
- A 2407 B READ response (9 link frames) split on existing DNP3 CRC block boundaries:
  `blocks_per_chunk` 1/2/4/8 ⇒ **141 / 71 / 36 / 18** chunks (⌈141/N⌉); total pkts 301/161/91/55.
- **All granularities: master reassembles identical bytes, delivers 800 measurements, sends DNP3
  CONFIRM, 0 TCP retransmits / 0 resets, no CRC recomputed.** Max fragmentation at bpc=1 (2407 B →
  141 ≤18 B segments vs native 9 frames). Cannot split *inside* a CRC block (out of phase).
- **Split changes per-packet size, packet count, and segmentation — but NOT total bytes.** Summing
  the chunks recovers the original size, so total-volume leakage survives splitting (a reviewer
  point and a design constraint).

## 5. PADDING — invalid-index CROB padding is a NEGATIVE result
(from `dnp3_multicrob_harness/reports/padding_candidates/padding_candidate_results.md`)
- Nonexistent G12V1 indexes (≥K) are rejected per-index in the SELECT response with
  **OUT_OF_RANGE (status 12)**, at any position (begin/middle/end); the op-count limit gives
  **TOO_MANY_OPS (status 8)** past `maxControlsPerRequest`. Both visible per-index on the wire.
- In OpenDNP3 SBO, a **partial SELECT failure prevents OPERATE**, so **invalid-index padding
  cannot be inserted into a real control transaction.** No byte-preserving, protocol-safe DNP3
  padding mechanism has been demonstrated. Not universal — this OpenDNP3 build/host/config only.

## Interpretation summary (measured, with limits)
CROB count leaks on **both** size (R²=0.9999) and timing (R²>0.99, n=1/N). Byte-preserving tools
available now: **split** (reshapes segmentation, not total bytes) and **timing normalization**
(removes the timing leak). Neither closes the **size** leak on small control responses; padding
that could is a **future** phase (invalid-index padding is a proven dead end). This asymmetry —
timing closeable now, size not — is the core of the combined-policy design and its honest
negative result.
