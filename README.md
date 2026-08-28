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
./reproduce.sh                # rebuilds every CSV, statistic and figure from the raw captures
python3 tests/test_timing.py  # 102 checks
```

No path outside this repository is hard-coded. The raw captures are immutable inputs; all
output goes to `defense4/timing/build/`.

## Building the paper

```sh
cd paper/rewrite && ./pipeline/build.sh      # tectonic + the manuscript gate -> pipeline/build/main.pdf
```

## What the paper claims, in one paragraph

With the in-network timing mechanism disabled, the command-to-link response time of a
physical SEL-751 varies with transaction type and spans roughly 1 to 18 ms. With it enabled,
READ and the SELECT phase of select-before-operate both settle on a 4.001 ms policy value
with a standard deviation near 0.02 ms, a READ-versus-SELECT classifier built on that feature
falls from 0.592 balanced accuracy to chance, and the master-visible echo-to-ACK interval of
an OPERATE stays at about 4.00 ms regardless of the configured hold.

## Three things a reader must not misread

1. **The baseline arm is not an unmodified relay.** Both arms ran the same unified switch
   binary with the size-shaping datapath active; only the timing mode differed. The arms are
   called *Timing OFF* and *Obfuscated* for that reason. Shaping is a held constant across the
   arms, so the comparison isolates the timing-mode change — but no measurement here is of an
   untouched SEL-751.
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
