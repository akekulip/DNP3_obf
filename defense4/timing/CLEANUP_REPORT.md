# Cleanup report — 2026-08-24

Machine-generated record of what this branch changed. Companion to `CLEANUP_PLAN.md`,
which says why.

Branch `cleanup/timing-read-sbo-20260824`, forked from `8a6896e`.

## Change summary

```
renames (git mv into _history) : 1106
added                          :   79
modified                       :    1   (defense4/timing/.gitignore — build_*/ kept, build/ added)
deleted                        :    0
```

Nothing was deleted and no pre-existing file had its content replaced. The one
modification extends an ignore file.

## `git diff --stat` (tail)

```
 .../implementation/control/defense4_caseA_setup.py |  667 ++++
 .../control/defense4_rrc_bor_unified12_setup.py    | 1126 +++++++
 .../implementation/control/defense4_rrc_setup.py   |  927 ++++++
 .../defense4_rrc_bor_unified12.p4                  | 3509 ++++++++++++++++++++
 .../timing/implementation/harness/dnp3_wire.py     |  179 +
 .../harness/relay_operate_guarded.py               |   82 +
 .../implementation/harness/relay_read_g10_23.py    |   98 +
 .../harness/relay_sbo_operate_guarded.py           |  163 +
 defense4/timing/pyproject.toml                     |   14 +
 defense4/timing/reproduce.sh                       |  116 +
 defense4/timing/tests/test_timing.py               |  277 ++
 1186 files changed, 16582 insertions(+)
```

## Repository tree, before and after

Before — `defense4/timing/` at `8a6896e`:

```
.gitignore
analysis
bootstrap
campaigns
control
evidence
figures
p4
probes
run
tests
```

After:

```
.gitignore
BRANCH_MAP.md
CLAIMS_AND_LIMITATIONS.md
CLEANUP_PLAN.md
PROVENANCE.md
README.md
REPOSITORY_AUDIT.md
_history
analysis
evidence
figures
implementation
pyproject.toml
reproduce.sh
tests
```

## Files moved to history

1,106 files, by `git mv`, from `defense4/timing/<subdir>` to
`defense4/timing/_history/<subdir>`. The mapping is mechanical: insert `_history/`
after `timing/`. Top-level directories moved:

- `analysis/` — 12 files
- `bootstrap/` — 29 files
- `campaigns/` — 10 files
- `control/` — 20 files
- `evidence/` — 1011 files
- `figures/` — 14 files
- `p4/` — 4 files
- `probes/` — 4 files
- `run/` — 1 files
- `tests/` — 1 files

## Files excluded from the active timing tree

Excluded means not carried into `defense4/timing/`. None was deleted; all remain in
`defense4/size/native_parity/evidence/E_FINAL/` on this branch, on
`origin/defense4-size-native-parity-crc-split`, in the archive tag, and in the bundle.

| file | reason |
|---|---|
| `raw_pcaps/off_probe.pcap` | 8 warm-up READs; no result depends on it |
| `raw_pcaps/e1_native_size_shapeoff.pcap` | size evidence; its CLRT is 4.000 ms, so the timing defense was active — not a timing baseline |
| `csv/size_verdict.csv` | size evidence |
| `scripts/size_analysis.py`, `scripts/size_reconstruct.py`, `scripts/fig5_segment_size.py` | size analysis |
| `figs/FIG-1 … FIG-10` | superseded by T1–T4; FIG-5 is a size figure |
| `scripts/clrt_extract.py`, `sbo_timing.py`, `e4e5_analysis.py`, `fig1–4,6,7`, `_figstyle.py` | superseded by the self-contained `analysis/` |
| `reproduce.sh` (frozen) | superseded; it hard-coded a user-specific interpreter and rebuilt size outputs |

## Test report

`tests/test_timing.py` — 102 checks, run under two independent environments:

| environment | result |
|---|---|
| Python 3.8.10, numpy 1.24.4, scipy 1.10.1, scikit-learn 1.3.2, matplotlib 3.7.5 | PASS (102/102) |
| Python 3.12.13, numpy 2.3.5, scipy 1.16.3, scikit-learn 1.9.0, matplotlib 3.11.0 | PASS (102/102) |

Coverage: request/ACK/response pairing, TCP direction and endpoints, DNP3 function codes
(READ 1, SELECT 3, OPERATE 4), monotonic timestamps, T_req ≤ T_ack ≤ T_resp, strictly
positive CLRT, cold-start handling, missing-ACK and missing-response detection, duplicate
transaction prevention, deterministic sample counts, no silent clipping, Ethernet padding
not counted as payload, and an AST check that no published measurement appears as a
numeric literal in figure code.

## Reproduction result

Every measured value regenerates from the raw captures and agrees with the frozen CSVs to
within one microsecond — one unit in the last printed digit — across 2,679 transaction
rows and 90 OPERATE rows. Statistics reproduce identically under both environments:

```
CLRT native   READ   n=999 med=1.272 std=1.354 max=12.274  >12ms=2
CLRT native   SELECT n=488 med=2.107 std=2.530 max=18.178  >12ms=11
CLRT defended READ   n=599 med=4.001 std=0.022
CLRT defended SELECT n=499 med=4.001 std=0.021
MI(class;CLRT) native=0.424356 -> defended=0.002085 bits (null 0.0000-0.0033)
classifier BA  native=0.5921  -> defended=0.5000 (chance 0.5)
echo-ACK median J=2: 4.001 ms   J=6: 4.002 ms   J=12: 4.003 ms   (n=30 each)
```

The raw captures verify against `MANIFEST.sha256` unchanged after every reproduction run:
24 of 24 files.

One number differs from the frozen record beyond rounding: the defended mutual information
is 0.002085 bits here against 0.001837 frozen. The cause is measured, not guessed — the
predeclared bin grid places an edge at exactly 4.000 ms and 199 of 1098 defended
observations lie within one microsecond of it. `EVIDENCE_AUDIT.md` §11.
