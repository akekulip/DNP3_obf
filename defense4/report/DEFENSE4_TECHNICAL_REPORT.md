---
title: "Defense 4: In-Network Normalization of a DNP3 Response-Time Fingerprint"
subtitle: "Corrected binary on silicon — accepted timing evidence"
date: 2026-08-07
---

# Summary

On one Intel Tofino-1 switch between a DNP3 master and a physical SEL-751 relay, Defense 4 holds the
relay's acknowledgment and response in the switch and releases them on a schedule, without changing any
byte. On the corrected switch program, verified from the loaded configuration (binary `97175e7d`), two
independent campaigns of 600 transactions each show that the response-deadline and dual-deadline modes
turn the relay's wide native response-time fingerprint into a fixed 10 ms value, holding every response,
with a small late tail reported honestly. Every result below is scored by a fail-closed pipeline
(78 adversarial self-tests) and reproduces across fixed and randomized block order.

# The observable and the mechanism

The cross-layer response time (CLRT) is the master-facing interval from the pure TCP acknowledgment to
the first byte of the matching DNP3 response. A passive observer measures it over many polls as a
device fingerprint. Defense 4 keeps the original acknowledgment and response queue-resident while
higher-priority internal blocker tokens recirculate, and the traffic manager releases them on schedule.
Four strict-priority queues guarantee the acknowledgment is never released after the response. Five
modes are configurations of the one framework: OFF (native), D1 (event), D2 (response deadline), D3
(acknowledgment deadline), D4 (dual deadline).

# Result: the CLRT is normalized, and the fingerprint information collapses

![Native (OFF) versus the Defense 4 modes: empirical CDF of the CLRT. OFF is the wide native curve; D2 and D4 are near-vertical steps at 10 ms with a short late tail; D3 collapses to ~0; D1 shifts to ~11 ms. n=120 per mode, Campaign A.](../timing/evidence/final_run/campaignA_corrected_binary/fig_clrt_ecdf.png){width=80%}

Across both campaigns (n = 240 per mode) the must-hold modes held every response (RESP_BYPASS = 0),
where the pre-fix binary bypassed D2 240/240 and D4 80/240. The CLRT dispersion and information collapse:

| mode | p5-p95 spread (ms) | spread reduction vs OFF | CLRT entropy (bits) | effective timing states |
|---|---|---|---|---|
| OFF | 5.69 | 1.0x | 3.63 | 12.4 |
| D2  | 0.12 | 45.6x | 1.23 | 2.3 |
| D4  | 0.05 | 118.2x | 1.10 | 2.1 |
| D3  | 1.05 | 5.4x | 0.76 | 1.7 |
| D1  | 5.17 | 1.1x | 3.39 | 10.5 |

![Per-session medians (dots) and pooled p5/p95 (bars) per mode. D2 and D4 are tight at 10 ms and stable across sessions; D1 (event) shifts the distribution but keeps its spread.](../timing/figures/normalization.png){width=80%}

D4 cuts the CLRT spread 118 times and the observable's entropy from about 12 effective timing states to
about 2. D1 (event) is the weakest normalizer: it moves the timing without tightening it.

# Honest boundary

We report the whole distribution: D2 and D4 normalize the bulk, not every observation (a small fraction
arrive late and are released safely, D4 max about 16.7 ms). This is timing normalization for one
separate-acknowledgment device, not a cross-device fingerprint-defeat claim, which needs a second
comparable device. The controlled negative-case tests are built and unit-tested offline but not yet run
live; the paired byte-identity comparator is validated on crafted captures; there is no final acceptance
verdict, and the paper Introduction stays quarantined.
