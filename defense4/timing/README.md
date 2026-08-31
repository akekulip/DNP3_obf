# Timing obfuscation — the active authority

This directory is the single source of truth for the timing work: what the paper evaluates,
the exact program that ran on the switch, the captures it produced, and the code that turns
those captures into the figures.

## 1. What the paper evaluates

In-network timing obfuscation for DNP3, on one Tofino-1 placed between a master and a
physical SEL-751A relay.

**The active evidence is `evidence/campaign_v1/`**: 22 grouped collection runs in one
approximately five-hour campaign, 132 captures, 63,360 DNP3 exchanges, plus a 19-point
hardware sweep of 5,860 further exchanges, with the size carve off in both arms. The earlier
`evidence/final_read_sbo/` tree is historical and is not the publication authority.

* **Read-lane timing** — the cross-layer response time, CLRT, of READ (function 1) and of the
  SELECT phase of select-before-operate (function 3). Medians move from 2.116 ms and 2.050 ms
  to 4.000 ms, with the interquartile range falling from about 2.8 ms to 0.006 ms.
* **Policy programmability** — a measured sweep in which the visible CLRT follows the
  configured `D_R` across a fixed-budget series while the response time stays near 25.3 ms,
  and the envelope closes near the fail-open horizon.
* **Control-lane timing** — the master-visible OPERATE ACK-to-echo interval remained
  concentrated near the configured 4 ms value across all 22 runs under the configured
  J codebook of {2, 6, 12} ms. The realized per-transaction draw was not observed.
* **Timing-feature suppression** — for the evaluated fixed Random-Forest attacker, three-class
  identification of READ, SELECT and OPERATE falls from 0.651 balanced accuracy to
  approximately chance, and mutual information falls from 0.383 bits to 0.004 bits, inside a
  permutation null. This is transaction-class suppression, not device identification.
* **Residual leakage** — an attacker retrained on obfuscated traffic recovers to 0.651 using
  the acknowledgment interval, because the two lanes are anchored differently.

Size obfuscation is **not** part of the paper's contribution. Section 7 below says exactly
how far size processing bears on these results, because it is not zero.

## Terminology: the two arms

The two experimental arms are named for what actually differed between them.

* **Timing OFF** (also written *Timing OFF, shaping active*) — the unified switch binary
  running with the timing mechanism disabled.
* **Obfuscated** (the public-facing name Dr. Lin asked for; the extractor and CSV file names keep the internal word "defended") — the same binary with the timing mechanism
  enabled.

They are deliberately **not** called "native" and "defended".

In the active `campaign_v1` evidence the size carve is **off in both arms**, established from the
captures themselves: every response is a single 49-byte payload and every capture holds exactly
1,448 frames and 130,708 bytes in both arms. That measurement is therefore timing only.

The paragraph that follows applies to the retired `final_read_sbo` tree only. There, both arms
ran the same unified binary with the size-shaping datapath active, so its Timing OFF arm is not
an unmodified SEL-751 baseline and must not be presented as one. Because shaping was on in both
arms it is a held constant rather than a difference between them, so that comparison still
isolates the timing-mode change within one binary. It is not a pure timing-only binary and not a
pure native-versus-defended experiment. An unmodified device baseline would require a separate
campaign with `shape_enable=0`.

## 2. Where the exact source is

`implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`

sha256 `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861`, from commit
`c18713840e8376c065909749d451a6bc9e6c5c4d`, compiled to the loaded binary
`33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa`.

This is the **combined** implementation: one program carrying both the timing mechanism and
the size carve, exactly as it ran. It has not been rewritten, and no rewritten program is
presented as having produced these captures. The copy of the same file at the branch tip has
a different hash — a documentation header was added the day after the campaign — so use this
one when the hash matters. `implementation/control/` and `implementation/harness/` hold the
control-plane chain and the drivers from the same commit.

## 3. Where the raw captures are

**Active.** `evidence/campaign_v1/sNN/raw_pcaps/` — 132 captures across 22 grouped runs, six per
run, plus `evidence/campaign_v1/sweep/raw_pcaps/` — 19 sweep captures (18 configured release
policies and one control). Per-run hashes are in each `sNN/provenance/DATASET.sha256` and the
sweep's in `sweep/SWEEP.sha256`; `repro/reproduce.sh` verifies all of them before any analysis
reads a capture.

**Historical.** The table below describes the retired `final_read_sbo` tree and its sample
counts. Those numbers describe that dataset and not the evidence the manuscript reports.

`evidence/final_read_sbo/raw_pcaps/` — six files, one session, 2026-08-13 19:53–19:57 local.

| file | contents |
|---|---|
| `e1_native.pcap` | Timing OFF: 1000 READ, 489 SELECT |
| `e2_def_read.pcap` | Obfuscated: 600 READ |
| `e2_def.pcap` | Obfuscated: 500 SELECT |
| `sbo_j2.pcap`, `sbo_j6.pcap`, `sbo_j12.pcap` | Obfuscated: 30 SELECT + 30 OPERATE each |

The file names are the original capture names and are kept unchanged for provenance; the
arm each belongs to is given above and in `CAPTURE_MANIFEST.csv`. `e1_native.pcap` is the
Timing OFF arm, not an unmodified device baseline.

Every request in all six has both an ACK and a response; there are no unmatched
transactions. Per-capture hashes, times, endpoints, configuration and per-field evidence are
in `evidence/final_read_sbo/CAPTURE_MANIFEST.csv` and `.json`. File hashes are in
`evidence/final_read_sbo/MANIFEST.sha256`.

These files are pcapng with nanosecond timestamps despite the `.pcap` extension. That
matters — see section 5.

## 4. How the figures are reproduced

```sh
cd defense4/timing
./reproduce.sh
```

Historical path for the `final_read_sbo` evidence, retained for provenance. The active
reproduction is `evidence/campaign_v1/repro/reproduce.sh`, which rebuilds the canonical
transaction table, the sweep tables, the statistics, the leakage analysis, the four NDSS
figures and their provenance, runs the tests, and then compares everything it rebuilt against
what the repository publishes. This historical script rebuilds that older tree's derived CSVs,
statistics and five figures from its raw captures into
`build/`, then compares against the frozen CSVs and prints the differences. The raw captures
are immutable inputs and are never written to.

The interpreter is resolved from `$TIMING_PYTHON`, then `uv` (pinned by `pyproject.toml`),
then a system Python that satisfies `analysis/requirements.txt`. No path outside this
repository is hard-coded, and no size artifact is produced.

The active test suite belongs to the campaign_v1 reproduction and runs as step 6 of
`evidence/campaign_v1/repro/reproduce.sh`:

```sh
cd evidence/campaign_v1/repro && CV1_OUT=<out> .venv/bin/python -m pytest tests -q   # 112 tests
```

The historical suite for the retired tree is:

```sh
python3 tests/test_timing.py     # 102 checks, final_read_sbo only
```

**The manuscript's figures are `paper/rewrite/figures/ndss/`**, regenerated only by
`evidence/campaign_v1/repro/reproduce.sh`. Each carries a vector PDF at an NDSS width, a 600-dpi
PNG, its exact figure data as CSV, a caption draft, a statistical-method note, a limitations
note, and a provenance sidecar naming every input by path and SHA-256.

`figures/publication/` holds the five earlier figures built from the retired `final_read_sbo`
evidence. They are kept for provenance and are **not** the manuscript's figures; their captions
quote that dataset's sample counts and its 4.001 ms medians, neither of which describes the
active evidence.

## 5. A note on parsing

`analysis/pcap_reader.py` parses the captures directly and carries integer nanoseconds end
to end. scapy is deliberately not a dependency: scapy 2.4.3 mis-scales pcapng timestamps by
a factor of 1000, which turns a 4 ms interval into 4000 ms without any error being
raised. Anyone re-deriving these numbers with an older scapy will get results that are wrong
by three orders of magnitude.

## 6. What the SELECT and OPERATE evidence prove

**SELECT.** In the active `campaign_v1` evidence there are 2,640 function-3 observations per
arm. They are the **SELECT phase** of select-before-operate, not complete SBO transactions, and
must be labelled that way in the manuscript. (The retired `final_read_sbo` tree had 489 Timing
OFF and 499 Obfuscated function-3 observations.)

**Two anchors.** READ and SELECT are held relative to the relay's own ACK (`t_A + D_A` for the
ACK, `t_A + D_A + D_R` for the response, so CLRT = `D_R` = 4 ms); OPERATE is held relative to
the request (`T0 + A`, `T0 + R`, so echo − ACK = `R − A` = 4 ms, with the OPERATE itself released
to the relay at `T0 + J`). The derivation from the source and the extractor is in
`paper/rewrite/pipeline/reports/EVENT_SEMANTICS_TRUTH_TABLE.md`.

**OPERATE.** In `campaign_v1` there are 2,640 OPERATE exchanges per arm, collected under the
configured codebook J in {2, 6, 12} ms; the realized per-transaction draw is **not** recorded, so
no result is reported per J. What the evidence supports is what the master sees: the
master-visible ACK-to-echo interval moves from a median of 2.937 ms under Timing OFF to 4.000 ms
under the mechanism and stays concentrated there across all 22 runs. It is not shown that the
interval is insensitive to the codebook, because the codebook was never observed to vary.

(The retired `final_read_sbo` tree ran 30 transactions per J condition and reported the interval
separately for each; that design is not reproduced in the active corpus.)

## 7. What remains unobserved

* **The relay-facing side.** dp68 is an internal pktgen/recirculation port with no
  host-capturable tap. Relay-facing timing at T0+J was never measured, and **exactly-once
  release is not demonstrated**.
* **The relay's unmodified CLRT.** The size carve was active during *every* timing capture,
  Timing OFF and Obfuscated alike — proved from the wire, not assumed. It was on in both
  arms, so it is a held constant rather than a confound, and the Timing OFF to Obfuscated
  change is attributable to the mode toggle. But the Timing OFF numbers are the relay's CLRT
  *through the shaping datapath*. No capture in this evidence has both interventions off.
* **Anything beyond one device and one campaign.** One SEL-751A, one Tofino-1, 22 grouped
  runs in one approximately five-hour campaign that are not independent deployments, and a
  transaction-disjoint rather than session-disjoint split. The result is signature
  replacement on this relay, not indistinguishability across devices.
* **One configuration assertion.** A readback reports one failure while showing none, and
  the failing check cannot be identified. The configuration proof is PARTIAL.

Each of these is stated with its evidence in `CLAIMS_AND_LIMITATIONS.md`.

## 8. Size is outside the current paper

No size claim, size figure, or size analysis lives in this tree. The size evidence, the size
scripts and the earlier size research remain where they were, under
`defense4/size/` and on the branches listed in `BRANCH_MAP.md`. The one place size touches
the timing result is section 7 above, and it is stated there rather than left implicit.

## 9. Layout

```
defense4/timing/
├── README.md                     this file
├── CLAIMS_AND_LIMITATIONS.md     what the evidence supports, and what bounds it
├── PROVENANCE.md                 silicon to figure, by hash and commit
├── REPOSITORY_AUDIT.md           repository state and safety steps
├── CLEANUP_PLAN.md               disposition of every candidate
├── BRANCH_MAP.md                 branches, tags, bundle
├── reproduce.sh                  rebuild everything from the raw captures
├── pyproject.toml                pinned environment
├── implementation/
│   ├── exact_experiment_source/  the P4 that ran, at its recorded hash
│   ├── control/                  control-plane chain at capture time
│   └── harness/                  READ and guarded SELECT/OPERATE drivers
├── evidence/final_read_sbo/
│   ├── MANIFEST.sha256           CAPTURE_MANIFEST.csv / .json
│   ├── raw_pcaps/                immutable inputs
│   ├── derived_csv/              transaction and SBO CSVs
│   ├── readbacks/                configuration provenance
│   └── audit/                    EVIDENCE_AUDIT.md and the frozen verdicts
├── analysis/                     extraction, statistics, figure style, manifest builder
├── figures/
│   ├── source/                   fig01 … fig05
│   └── publication/              PDF, PNG, data, captions, provenance
├── tests/                        test_timing.py
└── _history/                     superseded timing-core development
```
