# DNP3 in-network timing obfuscation — final paper repository

This branch holds exactly what the timing-obfuscation paper needs and nothing else: the
program that ran on the switch, the captures it produced, the code that turns those captures
into figures, the manuscript, and the documents that bound what may be claimed.

**The active evidence is
[`defense4/timing/evidence/campaign_v1/`](defense4/timing/evidence/campaign_v1/)**: 22 grouped
collection runs in one approximately five-hour campaign, 132 captures, 63,360 DNP3 exchanges,
collected with the size carve disabled in both arms. Rebuild every published number and figure
from the raw captures with
[`campaign_v1/repro/reproduce.sh`](defense4/timing/evidence/campaign_v1/repro/reproduce.sh).

The earlier `final_read_sbo` evidence and its five figures are retained for provenance and are
**not** what the manuscript reports.

**Start at [`defense4/timing/README.md`](defense4/timing/README.md)** for the evidence and at
[`paper/rewrite/README.md`](paper/rewrite/README.md) for the manuscript. Everything below is
orientation for someone arriving at the reduced tree.

## What is here

```
CLAUDE.md                     repository instructions
FINAL_TIMING_ALLOWLIST.txt    every retained path, and the rules that produced the list
REMOVAL_MANIFEST.csv          every removed path: reason, replacement, how to recover it
REMOVAL_REPORT.md             what was kept, what was removed, and why
REPOSITORY_AUDIT.md           repository state at the start of the 2026-08-26 rewrite
CLEANUP_PLAN.md               disposition of every item touched by the rewrite
defense4/timing/              the canonical timing tree: evidence, analysis, figures
paper/rewrite/                the manuscript (main.tex, sections/, library.bib, pipeline/)
```

## Reproducing the results

```sh
cd defense4/timing
evidence/campaign_v1/repro/reproduce.sh   # verifies the manifests, rebuilds every table,
                                         # statistic and figure from the raw captures, runs
                                         # the 112 tests, then gates against what is published
```

No path outside this repository is hard-coded. The raw captures are immutable inputs; all
output goes to `defense4/timing/build/`.

## Building the paper

```sh
cd paper/rewrite && ./pipeline/build.sh      # tectonic + the manuscript gate -> pipeline/build/main.pdf
```

## What the paper claims, in one paragraph

With the in-network timing mechanism disabled, the cross-layer response time of a physical
SEL-751A varies with transaction type: median 2.116 ms for READ and 2.050 ms for the SELECT
phase of select-before-operate, with interquartile ranges near 2.8 ms. With it enabled, both
settle on the 4.000 ms policy value with an interquartile range of 0.006 ms. A measured
19-point hardware sweep shows the visible interval following the configured offset while the
end-to-end response time stays fixed. For the evaluated fixed Random-Forest attacker,
three-class transaction identification falls from 0.651 balanced accuracy to approximately
chance, and the mutual information between the interval and the class falls from 0.383 bits to
0.004 bits, inside a within-run permutation null. An attacker that retrains on obfuscated
traffic recovers to 0.651 using the acknowledgment interval, which bounds the result. The
master-visible OPERATE ACK-to-echo interval remained concentrated near the configured 4 ms
value across all 22 runs.

## Three things a reader must not misread

1. **The arms are timing modes of one binary.** In the active `campaign_v1` evidence the
   size-shaping datapath is off in both arms, so the measurement is timing only and the
   comparison isolates the timing-mode change. The arms are called *Timing OFF* and
   *Obfuscated*. The retired `final_read_sbo` dataset ran with shaping active in both arms;
   its Timing OFF arm is therefore not an unmodified relay baseline, which is one reason it is
   no longer the publication authority.
2. **Configuration provenance is PARTIAL.** One archived readback reports a failed assertion
   while showing none, and the failing check cannot be recovered. It is retained unedited and
   explained in the evidence audit.
3. **Relay-facing behaviour was never observed.** The relay-facing port is internal to the
   switch with no capturable tap, so the internal release timing and exactly-once delivery are
   not demonstrated.

All three are stated with their evidence in
[`defense4/timing/CLAIMS_AND_LIMITATIONS.md`](defense4/timing/CLAIMS_AND_LIMITATIONS.md).

## Size obfuscation is not part of this paper

No size claim, figure or analysis is in this tree. The size research remains in the
repository's history and on its own branches; `REMOVAL_REPORT.md` says where.

## What was removed, and how to get it back

6,395 of 6,480 tracked files were removed from this branch. Nothing was destroyed. Every
removed path is recoverable from the branch `cleanup/timing-read-sbo-20260824`, the tag
`archive/pre-final-timing-prune-20260824`, commit `2ea2daf`, or the bundle
`DNP3-before-final-timing-prune-20260824.bundle`. `REMOVAL_MANIFEST.csv` gives the recovery
reference for each path individually.

```sh
git show archive/pre-final-timing-prune-20260824:<path>     # read one removed file
```

## No licence file

This repository has never carried one. That is a gap to close before any public release, not
something this reduction removed.
