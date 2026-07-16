# Phase 02 — Projected Timing-Leakage Reduction (RQ1/RQ4)

> **PROJECTED / NOT WIRE-VALIDATED.** The shipped `timing_policy` scheduler is applied to the captured native request→response times of the 7195 device-specific COMBINED transactions (AB1400 + ION7550). It shows what the *policy* does to the observable; enforcement on the wire is shown separately by the loopback experiment and requires the rig / PCAP to confirm at packet level.

| mode | n | visible med (ms) | corr(vis,size) | corr(vis,native) | deadline-miss (flag) | native>selected (direct) | native>lower | native>upper |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| native | 7195 | 16.039 | -0.0328 | 1.0000 | n/a | n/a | n/a | n/a |
| fixed25 | 7195 | 25.000 | 0.0061 | 0.8696 | 0.0022 | 0.0022 | 0.0022 | 0.0022 |
| bounded20-30 | 7195 | 25.003 | 0.0027 | 0.3487 | 0.0032 | 0.0032 | 0.0095 | 0.0006 |

Three tail metrics are reported separately (they are NOT the same thing):
- **deadline-miss** = native ready time > the transaction's OWN selected target (the scheduler's `deadline_missed`). This is the true residual: the response was already slower than the target, so normalization cannot hold it *down* without dropping bytes; its visible time stays = native.
- **native>lower bound** = native > `target_min` (20 ms for bounded, 25 ms for fixed).
- **native>upper bound** = native > `target_max` (30 ms for bounded, 25 ms for fixed).

Why the earlier bounded run reported deadline-miss 0.0032 (0.32%) and "native tail" 0.0095 (0.95%): the 0.95% figure counted native > **20 ms** (the lower bound) but was mislabeled "native > target". Because each bounded transaction's selected target sits between 20 and 30 ms, fewer transactions exceed their (higher) selected target (0.32%) than exceed the 20 ms lower bound (0.95%). The two are now reported as distinct columns; only `deadline-miss` is the true over-selected-target rate.

Interpretation: under `native` visible = native (correlation 1.0 by construction). Under `fixed`/`bounded` the visible time is pinned to the class-independent target for every transaction below the target, dropping its dependence on native time and size; the residual native correlation comes from the deadline-miss tail (visible = native there).

> Note: the real device COMBINED traffic is homogeneous (Phase 01: median ~16 ms, response ~37 B), so native size/time spread is small; the loopback experiment (wide response sizes 17 B–2407 B) exercises decorrelation more strongly.

