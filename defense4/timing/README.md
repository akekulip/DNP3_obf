# Timing obfuscation — the active authority

This directory is the single source of truth for the timing work: what the paper evaluates,
the exact program that ran on the switch, the captures it produced, and the code that turns
those captures into the figures.

## 1. What the paper evaluates

In-network timing obfuscation for DNP3, on one Tofino-1 placed between a master and a
physical SEL-751 relay. Four things:

* **READ timing** — command-to-link response time, CLRT, for function 1.
* **SELECT timing** — CLRT for function 3, the SELECT phase of select-before-operate.
* **CLRT normalization** — with the timing mode off both span a variable 1–18 ms; with it on
  both collapse onto 4.001 ms ± 0.02 ms.
* **OPERATE timing** — the master-visible echo-to-ACK interval stays at about 4.00 ms across
  configured holds of J = 2, 6 and 12 ms.
* **Timing-feature suppression** — a READ-vs-SELECT classifier on CLRT falls from 0.592
  balanced accuracy to chance. This is transaction-class suppression, not device
  identification.

Size obfuscation is **not** part of the paper's contribution. Section 7 below says exactly
how far size processing bears on these results, because it is not zero.

## Terminology: the two arms

The two experimental arms are named for what actually differed between them.

* **Timing OFF** (also written *Timing OFF, shaping active*) — the unified switch binary
  running with the timing mechanism disabled.
* **Obfuscated** (the public-facing name Dr. Lin asked for; the extractor and CSV file names keep the internal word "defended") — the same binary with the timing mechanism
  enabled.

They are deliberately **not** called "native" and "defended". Both arms ran the same unified
binary with the size-shaping datapath active, so the Timing OFF arm is not an unmodified
SEL-751 baseline and must not be presented as one. Because shaping was on in both arms it is
a held constant rather than a difference between them, so the comparison isolates the
timing-mode change within one binary. It is not a pure timing-only binary and not a pure
native-versus-defended experiment. An unmodified device baseline would require a separate
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

Historical path for the `final_read_sbo` evidence. It rebuilds that tree's derived CSVs,
statistics and five figures from its raw captures into
`build/`, then compares against the frozen CSVs and prints the differences. The raw captures
are immutable inputs and are never written to.

The interpreter is resolved from `$TIMING_PYTHON`, then `uv` (pinned by `pyproject.toml`),
then a system Python that satisfies `analysis/requirements.txt`. No path outside this
repository is hard-coded, and no size artifact is produced.

```sh
python3 tests/test_timing.py     # 102 checks
```

Publication-ready figures are in `figures/publication/`: vector PDF at exactly 7.16 in with
embedded Times New Roman, 600 dpi PNG, and for each figure its data CSV, caption draft,
method note and hashes.

## 5. A note on parsing

`analysis/pcap_reader.py` parses the captures directly and carries integer nanoseconds end
to end. scapy is deliberately not a dependency: scapy 2.4.3 mis-scales pcapng timestamps by
a factor of 1000, which turns a 4.001 ms interval into 4001 ms without any error being
raised. Anyone re-deriving these numbers with an older scapy will get results that are wrong
by three orders of magnitude.

## 6. What the SELECT and OPERATE evidence prove

**SELECT.** The 489 Timing OFF and 499 Obfuscated function-3 observations are the
**SELECT phase**
of select-before-operate. They are SELECT transactions, not complete SBO transactions, and
should be labelled that way in the manuscript.

**Two anchors.** READ and SELECT are held relative to the relay's own ACK (`t_A + D_A` for the
ACK, `t_A + D_A + D_R` for the response, so CLRT = `D_R` = 4 ms); OPERATE is held relative to
the request (`T0 + A`, `T0 + R`, so echo − ACK = `R − A` = 4 ms, with the OPERATE itself released
to the relay at `T0 + J`). The derivation from the source and the extractor is in
`paper/rewrite/pipeline/reports/EVENT_SEMANTICS_TRUTH_TABLE.md`.

**OPERATE.** 30 transactions per J condition. What is proven is what the master sees: the
ACK arrives about 21 ms after the request, the echo about 25 ms, and the difference stays at
about 4.00 ms whether J is 2, 6 or 12 ms. An observer subtracting the two timestamps
available to it learns nothing about the configured hold.

## 7. What remains unobserved

* **The relay-facing side.** dp68 is an internal pktgen/recirculation port with no
  host-capturable tap. Relay-facing timing at T0+J was never measured, and **exactly-once
  release is not demonstrated**.
* **The relay's unmodified CLRT.** The size carve was active during *every* timing capture,
  Timing OFF and Obfuscated alike — proved from the wire, not assumed. It was on in both
  arms, so it is a held constant rather than a confound, and the Timing OFF to Obfuscated
  change is attributable to the mode toggle. But the Timing OFF numbers are the relay's CLRT
  *through the shaping datapath*. No capture in this evidence has both interventions off.
* **Anything beyond one device and one session.** One SEL-751, one capture session, and a
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
