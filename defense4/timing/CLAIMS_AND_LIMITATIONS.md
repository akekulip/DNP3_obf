# Claims and limitations — timing

What the timing evidence supports, stated so that each claim can be checked against a named
artifact, and what it does not support, stated so that no reader has to infer the boundary.

**Active evidence: `evidence/campaign_v1/`.** One physical Tofino-1 between a DNP3 master and a
physical SEL-751A relay, all timestamps taken on the master-facing link. 22 grouped collection
runs in one approximately five-hour campaign, 132 captures, 63,360 DNP3 exchanges, plus a
19-point hardware sweep of 5,860 further exchanges. The size-shaping datapath is **off** in both
arms, so this is a timing-only measurement.

Every number below is regenerated from the raw captures by `evidence/campaign_v1/repro/reproduce.sh`
and is published in `paper/rewrite/figures/ndss/MANUSCRIPT_VALUES.json`, which is the single file
the manuscript quotes from. The retired `final_read_sbo` dataset and its claims are in
`history/CLAIMS_AND_LIMITATIONS_final_read_sbo.md` and are not current.

---

## Terminology: the two arms

* **Timing OFF** — the loaded switch binary with the timing mechanism disabled.
* **Obfuscated** — the same binary with the timing mechanism enabled.

They are deliberately not called "native" and "defended". In `campaign_v1` the size carve is off
in both arms, so the comparison isolates the timing-mode change and the Timing OFF arm is the
relay's own timing through an otherwise passive switch.

## The two lanes are never pooled

* **Read lane** — READ and the SELECT phase of SBO. Deadlines are anchored to the relay's own TCP
  acknowledgment: the switch releases the held ACK at `t_A + D_A` and the held response at
  `t_A + D_A + D_R`, with `D_A` = 20 ms and `D_R` = 4 ms. The observable CLRT is `D_R`. The
  release budget `D = D_A + D_R` = 24 ms governs this lane and only this lane.
* **Control lane** — OPERATE. Deadlines are anchored to the request: the ACK is released at
  `T0 + A` and the response at `T0 + R`, so the master-visible observable is `O = R - A`, in which
  the internal hold `J` does not appear. The read-path budget `D` is not a schedulability
  criterion here, and OPERATE never enters the read-lane coverage denominator.

---

## Claims

### C1 — Read-lane CLRT is replaced by the policy value

| arm and class | n | median | IQR | max |
|---|---|---|---|---|
| Timing OFF, READ | 26,400 | 2.116 ms | 2.778 ms | 83.458 ms |
| Timing OFF, SELECT | 2,640 | 2.050 ms | 2.697 ms | 24.831 ms |
| Obfuscated, READ | 26,400 | 4.000 ms | 0.006 ms | 57.182 ms |
| Obfuscated, SELECT | 2,640 | 4.000 ms | 0.006 ms | 5.150 ms |

The interquartile range falls by more than two orders of magnitude. The maxima are reported
because they are real: the tail is not clipped anywhere in the figures.

### C2 — The release policy is programmable over a bounded range

From the 19-point hardware sweep, whose 16 configured release policies are all in mode D4; its
other three points are native controls (`TIMING_ONLY_RERUN_PLAN.md` §2). At a fixed total
budget `D` = 24 ms, targets of
`D_R` = 1, 2, 4, 8, 12, 16, 20 and 22 ms produce measured CLRT medians of 0.998, 1.999, 3.999,
8.001, 12.001, 16.000, 20.001 and 22.001 ms, while the end-to-end response time stays between
25.30 and 25.34 ms. The leaking interval and the cost of the exchange are therefore set
independently. Ramping `D_A` at fixed `D_R` = 4 ms, the request-to-ACK interval tracks the target
to 30 ms (measured 30.571 ms, CLRT still 4.001 ms) and then saturates near 31.07 ms, beyond which
the CLRT rises to 5.503, 7.498 and 9.507 ms at `D_A` of 32, 34 and 36 ms. That is the operating
envelope closing from above.

### C3 — Read-lane coverage, and the residual it leaves

At `D` = 24 ms, 29 of 29,040 Timing OFF read-lane exchanges (0.0999 per cent) arrive too late to
be held, 28 READ and one SELECT; coverage is 99.900 per cent. Seen from the other side, 24 of
26,400 obfuscated READ exchanges depart from the scheduled release by more than 1 ms, and the
largest obfuscated READ interval is 57.182 ms. The residual is structural, not a defect of the
release logic: a response that arrives after its scheduled release cannot be moved backwards.

### C4 — The master-visible OPERATE interval sits at the policy value

The OPERATE median moves from 2.937 ms under Timing OFF to 4.000 ms under the mechanism, with the
interquartile range falling from 2.827 ms to 0.006 ms. Under the configured `J` codebook of
{2, 6, 12} ms, the master-visible OPERATE response-to-acknowledgment interval remained
concentrated near the
configured 4 ms policy value across all 22 grouped runs.

This is a statement about what the master sees. It is **not** a claim that the interval was shown
to be insensitive to the codebook, nor that a result was measured separately per `J`. See L4.

### C5 — Transaction-class timing leakage falls to chance for the evaluated attacker

Three-class problem over READ, SELECT and OPERATE; chance balanced accuracy is 1/3. Evaluation is
leave-one-grouped-run-out over all 22 runs, with a Random Forest (200 trees, min_samples_leaf 5).

| attacker | features | balanced accuracy |
|---|---|---|
| fixed, trained on Timing OFF, tested on Timing OFF | CLRT | 0.6515 |
| fixed, applied unchanged to Obfuscated | CLRT | 0.3332 |
| fixed, trained on Timing OFF, tested on Timing OFF | req-to-ACK + CLRT | 0.7328 |
| fixed, applied unchanged to Obfuscated | req-to-ACK + CLRT | 0.3337 |
| adaptive, retrained on Obfuscated | CLRT | 0.3333 |
| adaptive, retrained on Obfuscated | req-to-ACK + CLRT | 0.6510 |

Mutual information between the CLRT and the transaction class falls from 0.383 bits to 0.004
bits. Against a within-run permutation null over 1,000 permutations, the Timing OFF estimate lies
far above its null (empirical p = 0.001, the resolution floor) and the obfuscated estimate lies
inside its null (p = 0.096).

Spread across the 22 held-out runs is reported descriptively. It is **not** a confidence
interval: the folds share training data. No interval is placed on the MI point estimate. See L9.

### C6 — Residual leakage against an adaptive attacker

An attacker that retrains on obfuscated traffic stays at chance on the CLRT alone but recovers to
0.651 balanced accuracy when the request-to-ACK interval is added, because the read and control
lanes are anchored differently and their acknowledgment latencies therefore differ. This is a
result, not a failure to report: it bounds what the mechanism achieves.

### C7 — No added frames or bytes, and the workload completes

Every capture carries 1,448 frames and 130,708 captured bytes for 480 exchanges in both arms,
that is 3.017 frames and 272.308 bytes per exchange. The mechanism moves packets in time without
adding a frame or a byte to the master-facing link. Across all 63,360 exchanges every request was
answered with a well-formed response, and all 5,280 SELECT and OPERATE exchanges returned a
success status. Median response time rises by 22.657 ms for READ, 22.617 ms for SELECT and
21.185 ms for OPERATE.

---

## Limitations

These bound the claims above. None is a caveat added for form.

### L1 — One device, one switch, one campaign

One SEL-751A behind one Tofino-1, in one approximately five-hour campaign. Nothing here
establishes behaviour across days, devices, or deployments.

### L2 — The 22 grouped runs are not independent deployments

They are grouped collections within one session on one testbed. Run-to-run spread is
within-campaign variability. It is not cross-session, cross-day, longitudinal, or deployment
stability, and those words are not used of it.

### L3 — Only the master-facing link was captured

The relay-facing link is inside the switch and no host-capturable tap exists on it.

### L4 — The realized per-transaction `J` was never observed

`J` is the configured codebook value that sets the switch-internal release delay toward the
relay. The campaign records the codebook {2, 6, 12} ms, not the per-transaction draw, and the
relay-facing release at `T0 + J` is not on any captured link. C4 is a statement about what the
master sees. Nothing here shows that the relay-facing hold varied, and no result is reported per
`J`.

### L5 — Exactly-once release is not demonstrated

Release multiplicity toward the relay was not observable, for the same reason as L3. Nothing here
shows that exactly one OPERATE reached the relay.

### L6 — Physical actuation was not measured

No breaker motion, and no relay-facing timing, is evidence in this package.

### L7 — Transaction-class classification, not device identification

C5 concerns telling READ, SELECT and OPERATE apart for one device. With a single outstation,
nothing here shows that two devices become indistinguishable. This is not device fingerprinting
and not a device-model separation result.

### L8 — The attacker result is scoped to the classifier we evaluated

C5 characterises the fixed Random-Forest attacker and the two-interval feature set. It does not
generalise to all fingerprinting classifiers, and it is not a claim that no classifier can do
better.

### L9 — Two uncertainty estimates were withdrawn as indefensible

A grouped-run jackknife interval on the MI estimate was previously published. The pseudo-value
construction assumes a smooth estimator; a nearest-neighbour MI estimator near the
zero-information boundary is bounded, biased and non-smooth, and the resulting interval excluded
its own point estimate in both arms. A bootstrap over the 22 leave-one-run-out fold scores was
also published as a 95 per cent confidence interval; those folds share training data, so
resampling them does not estimate the sampling distribution of the mean. Both are withdrawn. MI
is reported against a permutation null with an empirical Monte Carlo p-value and no error bar,
and classifier scores carry a descriptive range. The rejected jackknife is retained as a
diagnostic in `leakage.json` under `rejected_estimators`.

### L10 — A fixed budget leaves a measurable tail

C3 quantifies it. The fail-open path bounds the tail rather than eliminating it.

### L11 — Configuration provenance is partial

Campaign parameters are corroborated by the wire and by the archived control-plane readback;
`shape_enable = 0` is established from the captures, where every response is a single 49-byte
payload and every capture holds exactly 1,448 frames and 130,708 bytes in both arms. For the
sweep, the per-point offsets are read from the archived `sweep_points.csv`; the driver logs record
the mode and the codebook but not `D_A`/`D_R`, and no per-point control-plane readback exists.
The fail-open horizon `H` = 30.8 ms is a control-plane quantity computed from the pass budget and
reservoir depth, not a bound the data plane enforces or that was measured directly.

### L12 — Scope

READ, the SELECT phase of SBO, and OPERATE, on one relay, master-facing. Size obfuscation is
outside the timing claims entirely: the mechanism changes no packet size, no size figure is
produced, and no size, padding, splitting or segmentation claim is made anywhere.
