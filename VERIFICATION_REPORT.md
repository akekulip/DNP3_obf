# Verification report — final timing-paper branch

Everything below was run **after** the prune, in a fresh worktree checked out from
`final/timing-paper-20260824` at `d6669ab42badd5c01227321badbcf834bc4aa317`, under the
**system Python** with no research virtual environment on the path.

```
python            3.8.10 (/usr/bin/python3)
platform          Linux-5.15.0-139-generic-x86_64-with-glibc2.29
numpy 1.24.4   scipy 1.10.1   scikit-learn 1.3.2   matplotlib 3.7.5
capture parsing   analysis/pcap_reader.py (no third-party dependency)
```

## 1. Reproduction from the retained captures

`./reproduce.sh` rebuilt every transaction CSV, every SBO CSV, the statistics and all four
figures from the six retained PCAPs. The pruned tree is self-sufficient: nothing it needs was
removed.

Regenerated CSVs against the frozen ones:

| file | rows | result |
|---|---|---|
| `native_txn.csv` | 1489 | values agree, max delta 0.001 ms |
| `defended_read_txn.csv` | 600 | values agree, max delta 0.001 ms |
| `defended_txn.csv` | 500 | values agree, max delta 0.001 ms |
| `sbo_j2.csv` | 30 | values agree, max delta 0.001 ms |
| `sbo_j6.csv` | 30 | values agree, max delta 0.001 ms |
| `sbo_j12.csv` | 30 | values agree, max delta 0.001 ms |

One microsecond is one unit in the last printed digit, and comes from integer-nanosecond
rather than float64-epoch arithmetic.

## 2. Test suite

`python3 tests/test_timing.py` — **102 checks, 0 failed.** Pairing, TCP direction and
endpoints, DNP3 function codes, monotonic timestamps, `T_req ≤ T_ack ≤ T_resp`, strictly
positive CLRT, cold-start handling, missing-ACK and missing-response detection, duplicate
prevention, deterministic sample counts, no silent clipping, Ethernet padding not counted as
payload, and the hard-coded-measurement check.

## 3. Sample counts and statistics unchanged

| series | n | median | std | max | above 12 ms |
|---|---|---|---|---|---|
| Timing OFF, READ | 999 | 1.272 ms | 1.354 ms | 12.274 ms | 2 |
| Timing OFF, SELECT | 488 | 2.107 ms | 2.530 ms | 18.178 ms | 11 |
| Timing ON, READ | 599 | 4.001 ms | 0.022 ms | 4.098 ms | 0 |
| Timing ON, SELECT | 499 | 4.001 ms | 0.021 ms | 4.124 ms | 0 |

Mutual information 0.424356 → 0.002085 bits, the Timing ON estimate inside its permutation
null (upper bound 0.003306). Classifier balanced accuracy 0.5921 → 0.5000. OPERATE
echo-to-ACK medians 4.001, 4.002 and 4.003 ms at J = 2, 6 and 12 ms, 30 transactions each.

Every expected value is unchanged by the prune.

## 4. No hard-coded results in the plotting scripts

All four figure sources parse clean under an AST check for published measurements appearing
as numeric literals. Numbers quoted in captions and docstrings are prose and are correctly
ignored; design constants such as the 4 ms reference line and the 0.5 chance baseline are
permitted, and the chance baseline is in any case read from `timing_stats.json`.

## 5. Figures: content reproduces, bytes do not

The four figure data CSVs — the numbers actually plotted — are **byte-identical** between the
regenerated and committed copies. The PDFs are not, for two reasons, and neither is a content
change:

* matplotlib stamps a `CreationDate` into every PDF, so byte-identity is impossible across
  runs regardless of environment;
* the committed publication PDFs were produced under matplotlib 3.11 and this verification
  ran under 3.7. Page geometry is identical (515.52 pt wide, the 7.16 in double-column
  measure) and T1 and T3 render identical text. T4 differs only in how many decades the log
  axis labels (3.7 labels 10⁰ through 10⁻⁴, 3.11 labels 10⁰ through 10⁻³), and T2 differs
  only in text-extraction ordering of shared tick labels. Both were inspected; the plotted
  content is the same.

`analysis/requirements.txt` pins `matplotlib>=3.7,<4`, so both versions are in specification.
The environment that produced the committed figures is recorded in
`figures/publication/ENVIRONMENT.txt`. If byte-stable figures are ever required, pin an exact
matplotlib version there and regenerate.

## 6. Claim boundaries survive the reduction

* **`shape_enable` was 1 in both arms** — stated in `README.md`, `PROVENANCE.md`,
  `REPOSITORY_AUDIT.md`, `CLAIMS_AND_LIMITATIONS.md`, the evidence audit, and per-capture in
  `CAPTURE_MANIFEST.csv`/`.json` with its supporting evidence.
* **Configuration provenance is PARTIAL** — recorded in five retained documents, and the
  readback file itself still reports `RESULT: FAIL (n_fail=1 n_warn=0)`, unedited.
* **The baseline is never called an unmodified native SEL baseline.** A search for that
  phrasing returns only negations and statements of what a clean baseline would require. The
  figure arm labels are `Timing OFF` and `Timing ON`.
* Relay-facing `T0+J` and exactly-once delivery are stated as unobserved; T1, T2 and T4 are
  stated as READ-versus-SELECT transaction timing, not device identification; SELECT is
  labelled as the SELECT phase of SBO.

## 7. The dirty worktrees are untouched

Both were hashed before the prune and again after.

| worktree | entries | file contents |
|---|---|---|
| `/home/philip/Projects/DNP3` | 13 (11 short-form) — identical list | 13 files, byte-for-byte identical |
| `/home/philip/Projects/DNP3-size-probe` | 68 (39 short-form) — identical list | 68 files, byte-for-byte identical |

Nothing was committed, stashed or modified in either.

## 8. Size of the result

| | tracked files | checkout |
|---|---|---|
| before (`2ea2daf`) | 6,480 | ~303 MB |
| after (`d6669ab`) | **90** | **6.6 MB** |

The remaining 6.6 MB is 2.1 MB of raw captures and derived CSVs, 1.6 MB of figures, 532 KB of
implementation, 2.2 MB of `REMOVAL_MANIFEST.csv`, and about 200 KB of code and documentation.

## What is not verified here

The control-plane chain cannot be exercised without Barefoot SDE 9.13 and the physical
testbed. What was verified is that it **imports offline** with the three retained Defense-3
modules co-located and `D4_CASEA_SETUP` set, which is the documented staging layout. Nothing
on the reproduction path imports it.
