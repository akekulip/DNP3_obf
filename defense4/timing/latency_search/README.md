# Lower-latency timing-policy search

User-authorized on 2026-09-26, including physical testbed acquisition and subsequent
figure/manuscript updates. Recovery commit: `a0be80f0`. This is a new experiment,
not a modification of campaign_v2 or a claim that the old campaign used seven stages.

## Preregistered objective

Minimize worst-operation median added response latency relative to interleaved
Timing OFF. Ties use worst-operation p99, then simpler policy. Report total latency
separately. A passing candidate requires a simultaneous 95% upper confidence bound
on balanced accuracy at most chance + 0.05 for fixed and adaptive attacks, all
declared features, and pools of 1, 5, and 20 exchanges. Three-class chance is 1/3;
READ/SELECT chance is 1/2. This is an empirical, testbed-specific acceptance rule.

Screen DA={5,10,15,20} ms x CLRT={1,2,4,6,8} ms, plus (4,4),(12,4).
References are OFF and (20,4),(20,8). Use five randomized blocks per setting,
100 READs and 100 guarded SELECT/OPERATE pairs, 400 ms inter-operation gap,
500 ms transaction deadline. Keep SELECT-to-OPERATE immediate as in the harness.
Do not hide request-cadence leakage if this makes the strict target unattainable.

Refine the three lowest-latency preliminary passing points at 1 ms steps within
2 ms; descend further on a passing lower boundary to DA=1 ms / CLRT=0.5 ms.
If fixed policies fail, evaluate bounded class-independent randomization, initially
on the gap then jointly on DA and gap, using symmetric offsets of 0.5,1,2,4 ms.
Only valid positive ordered deadlines within the holding range are admissible.
Any data-plane change must retain seven ingress stages and pass offline and hardware
validation. Random choices persist for the transaction and must be evidenced.

Freeze one finalist before 22 fresh paired confirmation blocks across two acquisition
sessions; each arm has 100 READs and 100 SBO pairs per block. Do not reuse confirmation
data for selection. No finalist means no claim of confirmed near-chance protection.

Use RF, standardized logistic regression, and RBF-SVM; fixed training uses OFF,
adaptive training uses protected traffic. Group by acquisition block, keep pools and
sessions within partitions, tune only within development data. Preserve raw timing,
outcomes, configurations, random seed, and program identity. Report late arrivals,
capture incompleteness, protocol failures, and request-spacing effects.

## Constraints found during preflight

- Live program is defense4_timing, seven ingress/zero egress, with dp8/dp10 loopbacks,
  dp9 master and dp64 relay, all UP. Snapshot: `evidence/preflight/switch.json`.
- Live DA=20 ms, response deadline=24 ms, anchor_req=1, budget=18000.
- Live codebook contains overlapping remnants of six-value and three-value J maps.
  A new trial must replace the whole codebook and verify exact coverage/no extras;
  old readbacks that merely checked requested keys did not establish this property.
- The historical J maximum of 12 ms is incompatible with DA=5 or 10 ms. Low-delay
  trials must identify their smaller command-hold codebook explicitly. Do not reduce
  claimed native bounds merely to pass a configuration guard.
- Hardware timestamps use a 256 ns grid; requested and realized values are separate.

## Safety and provenance

Retain DEFENSE4_HW_AUTHORIZED, frozen point allowlist {1,3}, successful SELECT gate,
CRC validation, and no automatic OPERATE retries. Stop a trial on failure; record
partial data. Snapshot and restore the starting configuration, retaining any discovered
inconsistency in the report rather than silently relabeling it. No sizing changes.
All commits belong solely to akekulip <akekulip@gmail.com>. Preserve unrelated edits.

## Reproducing the development analysis

The canonical fixed-policy acquisition is `screen_20260926T141505Z`. Select it
explicitly so that pilots, a failed earlier attempt, and a diagnostic repeat cannot
enter the screen. The summarizer checks capture drop statistics, TCP/DNP3 endpoint
matching, application outcomes, counts, and exact configuration readbacks before
admitting a block. Raw files are hashed in `measurements.json`.

```bash
python3 defense4/timing/latency_search/summarize.py \
  --campaign screen_20260926T141505Z \
  --out defense4/timing/latency_search/results/screen_20260926T141505Z
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
python3 defense4/timing/latency_search/evaluate.py \
  --input defense4/timing/latency_search/results/screen_20260926T141505Z/transactions.csv \
  --out defense4/timing/latency_search/results/screen_20260926T141505Z/attacks_development.json \
  --jobs 12
```

`--quick` evaluates one RF configuration on single-exchange ACK/CLRT features;
it is a diagnostic and cannot qualify a candidate. The full evaluator leaves one
paired acquisition repetition out, and tunes each model with grouped cross-validation
inside the other four repetitions. All scaling and imputation are fitted on training
data. Per-policy caches bind the exact paired rows, evaluator code, and library
version, so acquisition of an unrelated policy cannot invalidate or change a result.

Pooling forms non-overlapping groups of known same-operation samples within a block;
it does not represent arbitrary windows of an unlabeled packet stream. The largest
pool leaves only five test signatures per operation per held-out block. Five acquisition
repetitions support development comparisons, but their uncertainty can be too wide
to establish the chosen near-chance bound. Failure to pass is not itself proof of
reliable classification. Independent confirmation remains necessary for a positive claim.

The simultaneous bound uses the maximum centered bootstrap deviation over the
declared protected attacks, with the same repetition resample shared across attacks.
It uses 97.5% per task, allocating the 5% combined error budget across the three-class
and READ/SELECT tasks. This is approximate development uncertainty from five
same-session acquisition repetitions, not a guarantee against all timing attackers.
ACK/response results are reported separately from results including request spacing;
selection retains the stricter declared-feature criterion.

## Fixed-policy result

The canonical screen completed all 125 blocks and 37,500 primary exchanges. Each
block also captured both safety status polls. Capture logs report zero drops, and
an independent Wireshark retransmission analysis flags no frames in the 125 captures
(`results/screen_20260926T141505Z/tcp_audit.json`). All configuration and application
checks passed. The original program, process identity and configuration were retained
or restored, including the pre-existing overlapping codebook recorded in the snapshot;
each experimental block instead used exactly its three verified codebook entries.

The lowest tested median-delay setting, DA=5 ms and gap=1 ms, has a largest operation
median of 6.108599 ms, a largest operation p99 of 15.44554155 ms, and a largest
per-operation difference from the OFF median of 3.549428 ms. The repeated DA=20 ms,
gap=8 ms reference has a largest operation median of 28.109131 ms.

No protected policy passes the declared development bound. For DA=5 ms/gap=1 ms,
the maximum tested ACK/CLRT balanced accuracies are 0.493333 (three classes) and
0.600000 (READ/SELECT), with upper bounds 0.626667 and 0.820000. Request-spacing
features expose the acquisition workload, including immediate SELECT-to-OPERATE
versus 400 ms gaps between READs or SBO pairs. Their result is reported separately
from return-timing classification. These results do not identify a confirmed
near-chance low-delay policy. The conditional next phase is bounded class-independent
randomization, with selected deadlines verified from hardware digests.
