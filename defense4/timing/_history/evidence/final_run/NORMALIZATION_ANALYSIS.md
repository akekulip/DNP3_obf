# CLRT normalization, quantified (single device, corrected binary)

How much the CLRT observable collapses under each mode, pooled over Campaigns A + B (n = 240 per mode,
both campaigns). This is a **single-device** measure: it quantifies what an observer loses about the
SEL-751's own response-time signature. It is **not** a cross-device classification claim; a
fingerprint-defeat claim needs at least two comparable devices, which we do not have.

Source data hash `18407e17fa6c`. Entropy uses fixed 0.25 ms bins over 0..25 ms. Figure:
`../figures/normalization.png` (per-session medians + pooled p5/p95).

| mode | p5 | p50 | p95 | p5-p95 spread (ms) | IQR (ms) | spread reduction vs OFF | CLRT entropy (bits) | effective states 2^H | entropy reduction (bits) |
|---|---|---|---|---|---|---|---|---|---|
| OFF | 1.81 | 2.92 | 7.50 | 5.69 | 1.49 | 1.0x | 3.63 | 12.4 | 0.00 |
| D1  | 7.04 | 11.14 | 12.21 | 5.17 | 2.62 | 1.1x | 3.39 | 10.5 | 0.24 |
| D2  | 9.95 | 10.02 | 10.08 | **0.12** | 0.05 | **45.6x** | 1.23 | 2.3 | 2.40 |
| D3  | 0.00 | 0.03 | 1.05 | 1.05 | 0.01 | 5.4x | 0.76 | 1.7 | 2.87 |
| D4  | 9.98 | 10.00 | 10.03 | **0.05** | 0.01 | **118.2x** | 1.10 | 2.1 | 2.53 |

## Reading it

- **Native (OFF)** the CLRT spans a p5-p95 of 5.69 ms and carries 3.63 bits of entropy, about 12
  distinguishable timing states. That spread is the fingerprint.
- **D4** cuts the p5-p95 spread by **118 times** (to 0.05 ms) and the entropy to 1.10 bits, about 2
  effective states. **D2** cuts the spread 45.6 times to 0.12 ms, entropy 1.23 bits. The response-time
  observable an attacker can measure is collapsed from a dozen states to two.
- **D3** collapses the CLRT toward zero (its D_R=0 design), spread 1.05 ms, entropy 0.76 bits.
- **D1 (event)** is the weakest normalizer: it shifts the distribution up to about 11 ms but keeps a
  5.17 ms spread and 3.39 bits (only 0.24 bits less than OFF). Event-driven release tracks the response
  arrival, so it moves the timing without tightening it. This is an honest, expected limit of the
  event mode.
- **Per-session medians are tight** (the dots in the figure), so the D2/D4 normalization is stable
  across the four sessions per mode, not a pooled-data artifact.

## What this does and does not claim

It shows that D2 and D4 sharply reduce the information the CLRT observable carries about this device:
the residual entropy is about 2 bits (two states, essentially "shaped at ~10 ms" plus a small late
tail) versus about 12 states native. It does **not** claim that an attacker cannot tell this device
from another device, and it does not claim size, cover-traffic, or full-fingerprint concealment. With
one physical device this is timing normalization for that device, quantified; cross-device
classification remains future work needing a second comparable separate-acknowledgment device.
