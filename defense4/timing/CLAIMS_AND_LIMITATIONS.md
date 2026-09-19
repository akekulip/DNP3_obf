# Claims and limitations — timing

What the timing evidence supports, stated so that each claim can be checked against a named
artifact, and what it does not support, stated so that no reader has to infer the boundary.

**Active evidence: `evidence/campaign_v2/`**, collected on the request-anchored build. One physical
Tofino-1 between a DNP3 master and a physical SEL-751A relay, all timestamps taken on the
master-facing link. 22 grouped collection runs over 5.3 hours, 132 captures, 63,360 DNP3
exchanges, plus a 26-point hardware sweep of 9,360 further exchanges. The size-shaping datapath is
**off** in both arms, so this is a timing-only measurement.

Every number below is regenerated from the raw captures by `evidence/campaign_v2/repro/reproduce.sh`
and is published in `paper/rewrite/figures/ndss/MANUSCRIPT_VALUES.json`, which is the single file
the manuscript quotes from; the publication gate fails if a rebuild drifts from it. The attribution
numbers of C6 come from its step 5c, `repro/proof_analyses.py`. `campaign_v1` is the record of the
acknowledgment-anchored build that this one replaces; its claims are recoverable with
`git show d23fac67:defense4/timing/CLAIMS_AND_LIMITATIONS.md` and are not current.

---

## Terminology: the two arms

* **Timing OFF** — the loaded switch binary with the timing mechanism disabled.
* **Obfuscated** — the same binary with the timing mechanism enabled.

They are deliberately not called "native" and "defended". The size carve is off in both arms, so
the comparison isolates the timing-mode change and the Timing OFF arm is the relay's own timing
through an otherwise passive switch.

## The two lanes are never pooled

* **Read lane** — READ and the SELECT phase of SBO. Both deadlines are armed when the **request**
  reaches the switch, at `t_0`: the switch releases the held ACK at `t_0 + D_A` and the held
  response at `t_0 + D_A + CLRT_new`, with `D_A` = 20 ms and the configured `CLRT_new` = 8 ms
  (the field `D_R_ms`). The observable CLRT is the configured `CLRT_new`. The release budget
  `D = D_A + CLRT_new` = 28 ms governs this lane and only this lane, and because the deadlines hang
  off the request, `D` must cover the whole request-to-response time at the switch.
* **Control lane** — OPERATE. Its deadlines are also armed from the request, at `T0`, with the read
  lane's offsets, so the master-visible observable is `O = CLRT_new`, in which the command hold `J`
  does not appear. OPERATE never enters the read-lane coverage denominator, because its command is
  itself held for `J` before it reaches the relay, so its availability condition differs.

  **Measured 2026-09-18, on the acknowledgment-anchored build.** The control plane also carries `A`
  and `R`. A sweep that separated them from the read-lane pair found the master-facing OPERATE
  acknowledgment at 20.65 to 20.68 ms while `A` walked over 12, 16, 20 and 24 ms, and the
  response-to-ACK interval following `D_R_ms` while ignoring `R - A`
  (`evidence/tail_sweep_20260918/`). `A` and `R` gate what may be installed. `campaign_v2` sets
  `A` = `D_A` = 20 ms and `R` = 28 ms, so it cannot separate the two either, and no claim here
  depends on which of them sets the instants.

---

## Claims

### C1 — The read-lane CLRT is replaced by the policy value

| arm and class | n | median | IQR | max |
|---|---|---|---|---|
| Timing OFF, READ | 26,400 | 2.121 ms | 2.772 ms | 113.480 ms |
| Timing OFF, SELECT | 2,640 | 2.041 ms | 2.679 ms | 24.300 ms |
| Obfuscated, READ | 26,400 | 8.005 ms | 0.022 ms | 78.443 ms |
| Obfuscated, SELECT | 2,640 | 8.005 ms | 0.021 ms | 8.077 ms |

The interquartile range falls by two orders of magnitude. Shifting the Timing OFF READ series by a
constant keeps its standard deviation of 2.889 ms; the obfuscated series has 0.989 ms, and SELECT
falls from 2.267 to 0.017 ms (`replacement_stats.json`). 99.94 per cent of obfuscated READ lie
within 0.10 ms of 8 ms, and in 21 of the 22 runs the obfuscated READ variance is below that of every
Timing OFF run; the remaining run contains late responses (C3). The maxima are reported because
they are real: the tail is not clipped anywhere in the figures.

### C2 — The execution time of the relay does not reach the intervals the master sees

READ and SELECT follow the same lane and differ only in how long the relay takes to answer them.
Trained and tested within one arm, leave-one-grouped-run-out, the same Random Forest separates them
at 0.7847 balanced accuracy under Timing OFF and 0.5071 under the mechanism, against 0.5 chance
(both intervals; 0.7032 and 0.5068 on the CLRT alone). Obfuscated, their medians are identical:
8.005 ms CLRT and 20.101 ms request-to-acknowledgment.

### C3 — The release policy is programmable over a bounded range

From the 26-point sweep: 23 release policies in mode D4 and three controls (the two envelope modes
and Timing OFF). At a fixed budget `D` = 28 ms, configured `CLRT_new` of 2, 4, 8, 12, 16, 20, 24 and
26 ms produce measured CLRT medians of 1.9995, 4.0002, 8.0055, 12.0003, 16.001, 20.000, 24.0021 and
26.001 ms, within 6 µs of each setting, while the median request-to-response time stays between
28.106 and 28.108 ms. The interval the adversary measures and the cost of the exchange are set
independently. Ramping `D_A` at a configured `CLRT_new` of 4 ms, the request-to-acknowledgment
median tracks the setting to 30 ms (30.107 ms, CLRT still 3.999 ms) and then saturates at
31.07 ms, beyond which the CLRT rises to 5.034, 7.035 and 9.034 ms at `D_A` of 32, 34 and 36 ms.
That is the operating envelope closing from above.

### C4 — Read-lane coverage, and the residual it leaves

At `D` = 28 ms, 17 of 29,040 Timing OFF read-lane exchanges (0.0585 per cent) take longer than the
budget from request to response, all of them READ; coverage is 99.9415 per cent. Seen from the
other side, 15 of 26,400 obfuscated READ exchanges depart from the configured 8 ms by more than
1 ms, and the largest obfuscated READ interval is 78.443 ms. The residual is structural: a response
that arrives after its scheduled release cannot be moved backwards.

### C5 — The master-visible OPERATE interval sits at the policy value

The OPERATE median moves from 2.929 ms under Timing OFF to 8.000 ms under the mechanism, with the
interquartile range falling from 2.729 ms to 0.006 ms. Under the configured `J` codebook of
{2, 6, 12} ms, the master-visible OPERATE interval stays at the configured value. This is a
statement about what the master sees, not a result measured separately per `J`. See L4.

### C6 — What a fixed and an adaptive attacker learn

Three-class problem over READ, SELECT and OPERATE; chance balanced accuracy is 1/3. Evaluation is
leave-one-grouped-run-out over all 22 runs, with a class-balanced Random Forest (200 trees,
min_samples_leaf 5).

| attacker | features | balanced accuracy |
|---|---|---|
| fixed, trained on Timing OFF, tested on Timing OFF | CLRT | 0.7284 |
| fixed, applied unchanged to Obfuscated | CLRT | 0.3351 |
| fixed, trained on Timing OFF, tested on Timing OFF | req-to-ACK + CLRT | 0.8028 |
| fixed, applied unchanged to Obfuscated | req-to-ACK + CLRT | 0.3333 |
| adaptive, retrained on Obfuscated | CLRT | 0.4514 |
| adaptive, retrained on Obfuscated | req-to-ACK + CLRT | 0.4452 |

Pooling k exchanges of one class (both intervals) takes the adaptive attacker to 0.4470, 0.5281,
0.6151, 0.6318 and 0.6500 at k = 1, 2, 5, 10 and 20; under Timing OFF the same pooling reaches
0.8020 to 0.9388. Mutual information between the CLRT and the class falls from 0.35314 to
0.04279 bits; both estimates lie above their within-run permutation nulls (empirical p = 0.001,
the resolution floor).

**Where the adaptive attacker's accuracy comes from.** It recognises OPERATE in 0.689 of cases,
READ in 0.411 and SELECT in 0.235. Three measurements attribute it to the arrival of requests at
the switch rather than to the relay: execution time alone separates at chance (C2); READ alone,
split at the median of the gap that preceded each request (halves 31 µs apart), separates at 0.6284
obfuscated against 0.5361 Timing OFF; and OPERATE arrives 0.354 ms after its SELECT response where
READ follows its predecessor by 20.505 ms, with a release-tail median of 107 µs against 101 µs.
The attribution is argued from these within-device controls, not from a second device.

Spread across the 22 held-out runs is reported descriptively. It is **not** a confidence
interval: the folds share training data. No interval is placed on the MI point estimate. See L9.

### C7 — No added frames or bytes, bounded latency, no retransmission

Every capture carries 1,448 frames and 130,708 captured bytes for 480 exchanges in both arms, that
is 3.017 frames and 272.308 bytes per exchange. Across all 63,360 exchanges every request was
answered with a well-formed response, no capture contains a TCP retransmission, and all 5,280
SELECT and OPERATE exchanges returned a success status. The median request-to-response time rises
from 2.681 to 28.107 ms for READ, an added 25.426 ms, and by 25.482 ms for SELECT and 24.652 ms for
OPERATE. The longest obfuscated waits were 20.19 ms for an acknowledgment and 98.547 ms for a
response; the master's own retransmission timer fires at 200.8 ms
(`audit_current/master_rto_20260916/RESULT.md`).

### C8 — The release tail is small and does not depend on the hold

Measured on the master-facing link as the request-to-acknowledgment interval minus `D_A`, the
tail has a median of 0.101 ms for READ and SELECT and 0.107 ms for OPERATE, and its central 99 per
cent lies between 36 and 127 µs (`proof.json`). Across the `D_A` ramp from 4 to 30 ms its median
stays between 0.098 and 0.108 ms. This excess also contains the master-to-switch path, which is
not separated.

---

## Limitations

These bound the claims above. None is a caveat added for form.

### L1 — One device, one switch, one campaign

One SEL-751A behind one Tofino-1, in one 5.3-hour campaign. Nothing here establishes behaviour
across days, devices, or deployments.

### L2 — The 22 grouped runs are not independent deployments

They are grouped collections within one session on one testbed. Run-to-run spread is
within-campaign variability. It is not cross-session, cross-day, longitudinal, or deployment
stability, and those words are not used of it.

### L3 — Only the master-facing link was captured

The relay-facing link is inside the switch and no host-capturable tap exists on it.

### L4 — The realized per-transaction `J` was never observed

`J` is the configured codebook value that sets the switch-internal release delay toward the
relay. The campaign records the codebook {2, 6, 12} ms, not the per-transaction draw, and the
relay-facing release at `T0 + J` is not on any captured link. C5 is a statement about what the
master sees. Nothing here shows that the relay-facing hold varied, and no result is reported per
`J`.

### L5 — Exactly-once release is not demonstrated

Release multiplicity toward the relay was not observable, for the same reason as L3. Nothing here
shows that exactly one OPERATE reached the relay.

### L6 — Physical actuation was not measured

No breaker motion, and no relay-facing timing, is evidence in this package.

### L7 — Transaction-class classification, not device identification

C2 and C6 concern telling READ, SELECT and OPERATE apart for one device. With a single outstation,
nothing here shows that two devices become indistinguishable. The manuscript extends the result to
device types by the design argument, and says so; it reports no device-model separation result.

### L8 — The attacker result is scoped to the classifier we evaluated

C2 and C6 characterise the Random-Forest attacker and the two-interval feature set. They do not
generalise to all fingerprinting classifiers, and they are not a claim that no classifier can do
better.

### L9 — Two uncertainty estimates were withdrawn as indefensible

A grouped-run jackknife interval on the MI estimate was previously published. The pseudo-value
construction assumes a smooth estimator; a nearest-neighbour MI estimator near the
zero-information boundary is bounded, biased and non-smooth, and the resulting interval excluded
its own point estimate. A bootstrap over the 22 leave-one-run-out fold scores was also published as
a 95 per cent confidence interval; those folds share training data, so resampling them does not
estimate the sampling distribution of the mean. Both are withdrawn. MI is reported against a
permutation null with an empirical Monte Carlo p-value and no error bar, and classifier scores carry
a descriptive range. The rejected jackknife is retained as a diagnostic in `leakage.json` under
`rejected_estimators`.

### L10 — A fixed budget leaves a measurable tail

C4 quantifies it. The fail-open path bounds the tail rather than eliminating it.

### L11 — The adaptive residual is not removed

C6 shows an adaptive attacker above chance, rising with pooling. The evidence attributes it to the
arrival of requests at the switch, not to the relay, but the mechanism does not remove it: the
released intervals still depend on the state of the blocker queue that a request meets.

### L12 — Configuration provenance

Every campaign block archives a control-plane readback (`evidence/campaign_v2/provenance/`): all 66
Obfuscated blocks read back `anchor_req = 1`, mode 4, `shape_enable = 0`, `D_A` = 20 ms and a 28 ms
budget, and all 66 Timing OFF blocks read back mode 0 and `shape_enable = 0`. Every sweep point
archives a readback whose offsets match `sweep_points.csv` to within one 256 ns tick. Two
quantities remain unobserved: the per-transaction `J` (L4), and the fail-open horizon `H` =
30.8 ms, a control-plane quantity computed from the pass budget and reservoir depth, not a bound
the data plane enforces or that was measured directly.

### L13 — Scope

READ, the SELECT phase of SBO, and OPERATE, on one relay, master-facing. Size obfuscation is
outside the timing claims entirely: the mechanism changes no packet size, no size figure is
produced, and no size, padding, splitting or segmentation claim is made anywhere.
