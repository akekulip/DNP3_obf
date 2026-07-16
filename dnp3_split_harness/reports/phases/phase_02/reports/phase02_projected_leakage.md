# Phase 02 — Projected Timing-Leakage Reduction (RQ1/RQ4)

> **PROJECTED / NOT WIRE-VALIDATED.** The shipped `timing_policy` scheduler is applied to the captured native request→response times of the 7195 device-specific COMBINED transactions (AB1400 + ION7550). It shows what the *policy* does to the observable; enforcement on the wire is shown separately by the loopback experiment and requires the rig / PCAP to confirm at packet level.

| mode | n | visible med (ms) | corr(visible, resp size) | corr(visible, native) | deadline-miss | native>target |
|---|---:|---:|---:|---:|---:|---:|
| native | 7195 | 16.039 | -0.033 | 1.000 | 0.000 | n/a |
| fixed25 | 7195 | 25.000 | 0.006 | 0.870 | 0.002 | 0.002 |
| bounded20-30 | 7195 | 25.003 | 0.003 | 0.349 | 0.003 | 0.009 |

Interpretation: under `native` the visible time equals the native ready time (correlation with native = 1.0 by construction). Under `fixed`/`bounded` the visible time is pinned to the class-independent target for every transaction whose native time is below the target, dropping its dependence on the native time and response size. `deadline-miss` / `native>target` count the transactions whose native ready time already exceeds the target (the residual native tail that normalization cannot hide downward without dropping bytes).

> Note: the real device COMBINED traffic is homogeneous (Phase 01: median ~16 ms, response ~37 B), so native size/time spread is small; the loopback experiment (wide response sizes 17 B–2407 B) exercises decorrelation more strongly.

