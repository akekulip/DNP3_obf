# Timing figures — provenance

Four figures handed off for the manuscript, with everything needed to trace each back to the
captures it came from. Generated 2026-08-24.

Only the vector PDFs and preview PNGs were copied here. No raw capture, no P4 source, and no
part of the evidence package was copied into the manuscript tree.

---

## Source

| item | value |
|---|---|
| implementation repository | `https://github.com/akekulip/DNP3_obf` |
| source branch | `cleanup/timing-read-sbo-20260824` |
| source commit | `2ea2dafe4517b5893fac5e06fc5db2ae63ba13b8` |
| figures live at | `defense4/timing/figures/publication/` |
| full record | `defense4/timing/` — `README.md`, `CLAIMS_AND_LIMITATIONS.md`, `PROVENANCE.md`, `evidence/final_read_sbo/audit/EVIDENCE_AUDIT.md` |

Each figure also has, in the source tree, its own `*.provenance.json`, `*_data.csv` (the
numbers plotted), and `*.caption.md` (caption draft plus statistical-method note).

## Figures

| figure | file | sha256 (PDF) |
|---|---|---|
| T1 | `fig_T1_clrt_before_after.pdf` | `ddf9087f4303e307684e37d86103fed941831f2a7329e1c9433c17804622cca6` |
| T2 | `fig_T2_timing_feature_overlap.pdf` | `677d5fe74d6eb10742d9231100cd9fcb2f07d2625f2a4b0ca3c117443b9942c7` |
| T3 | `fig_T3_sbo_operate_across_J.pdf` | `76a9ff9cc8433a10033dbbf1acb7a2f34ceba2103b12fe17d633e0c4b49042fb` |
| T4 | `fig_T4_timing_leakage_summary.pdf` | `64dd3ab4305dec5cb12de3cbb37cb998b3dde0a8f6a30743b8c1493e6aee6c76` |

| preview | sha256 (PNG, 600 dpi) |
|---|---|
| `fig_T1_clrt_before_after.png` | `3e1487f24bd52020968f46abaf0ba43acd43d97aed11152534509b2a8dcb5fa2` |
| `fig_T2_timing_feature_overlap.png` | `0fc0e121228d2b84685ea38a419c3971de2d51d36689797f14a45b28568d718a` |
| `fig_T3_sbo_operate_across_J.png` | `f58cc9ec171332ff7fcf29ffc34d63d27da51000ab00d87e6c29bf5587208154` |
| `fig_T4_timing_leakage_summary.png` | `0c9b9a1bfb93967ae4c5a058325e2bc2c4c44eaf8f01bea235d0732b1d26417f` |

PDFs are 515.52 pt wide, exactly the 7.16 in IEEE double-column measure, with Times New
Roman embedded including mathtext, opaque white background, and no rasterized text.

## Input captures

Master-facing, physical SEL-751 behind one Tofino-1, one session on 2026-08-13.

| capture | sha256 | arm |
|---|---|---|
| `e1_native.pcap` | `4d0dc0c810124bb44624f2818918d7ac098a0d2d7995f32df68e8849ac9c97be` | Timing OFF |
| `e2_def_read.pcap` | `6e8e77dab757881c6b44aa20cbb9d6edc68fbbe968448cb27545a1a614b3d11a` | Timing ON |
| `e2_def.pcap` | `c550b549db46d717d5bdb27547892a64f2a3a94601483912c5a7f3d5fd619297` | Timing ON |
| `sbo_j2.pcap` | `66a4ba79688414562f3405d06b4bfb744514ff5139007d608ffc6a142893345b` | Timing ON |
| `sbo_j6.pcap` | `602769a5167f8a5c3ac581fc017f6d936bfec0eca295742a202a3d35869b8da2` | Timing ON |
| `sbo_j12.pcap` | `5d397de1e08dffdb5d0d44cdc23d4e18397db01b142c6d08ba6571cfa3040764` | Timing ON |

The file names are the original capture names, kept unchanged so provenance to the frozen
evidence package holds by hash. `e1_native.pcap` is the **Timing OFF** arm and is not an
unmodified device baseline — see "What the arms are" below.

## Analysis scripts

| script | sha256 |
|---|---|
| `analysis/pcap_reader.py` | `a44f10feef24ecb0d60282f5ac4556d83ce011bd24c82e854d0980cf7d301fa2` |
| `analysis/dnp3_timing.py` | `70d9b1c377bfe42ccd8f259286e1efb5aeca960ead225076ed03849c8804a07c` |
| `analysis/extract_clrt.py` | `d9c9e19529f86ea0057c615c72422b9b40684d3ecb0886dee9a7336b7d7b3554` |
| `analysis/extract_sbo.py` | `5134f61d60633487c8f4e656cd56b93953766af35dcf87950a11fdc65e51a4e9` |
| `analysis/timing_stats.py` | `a652bfd99db950ff0c86d2a5d2e7b20423ffe5f43ed88d3ad966b5a317ab33b0` |
| `analysis/figstyle.py` | `d3ad87323ba61b426ea0e43b16cb3e7aacacde83d2ea5bbfe917b86db980b448` |
| `analysis/compare_frozen.py` | `b4f8128bfd41816ba3af597d2f45723cc0b394640496f0f6d3f8dc7f4c40f894` |
| `figures/source/_common.py` | `0ed9903f9db93268f3ea9c2abe0e2e967b25379bc873821f685a0b50dc2afb6d` |
| `figures/source/fig_T1_clrt_before_after.py` | `d1dcb1af3a5af54075b955ceb743b2609fa9edb9fdfa07e65bc316552c6f6b47` |
| `figures/source/fig_T2_timing_feature_overlap.py` | `7d9e3c0c35f6eee27956ae4710cd22fe376cd8c8f759e4374dea83a233fdb14f` |
| `figures/source/fig_T3_sbo_operate_across_J.py` | `8b2df69047165613525ca1d33423d8845ca19f2730133b8c9279069382deec38` |
| `figures/source/fig_T4_timing_leakage_summary.py` | `4bfb6227d3dd053ed8fa1f46189872baf83fb92d7a6ea6c029310f7f8b118e27` |

---

## Verification status

**The packet-derived results reproduce identically across two independent Python
environments.** The full pipeline was rebuilt from the raw captures under Python 3.8.10
(numpy 1.24.4, scipy 1.10.1, scikit-learn 1.3.2, matplotlib 3.7.5) and under Python 3.12.13
(numpy 2.3.5, scipy 1.16.3, scikit-learn 1.9.0, matplotlib 3.11.0), producing the same
statistics in both. The test suite passes 102 of 102 checks under each.

**All input and output hashes passed.** The frozen evidence manifest verifies 63 of 63
files, the timing evidence manifest 24 of 24, and the raw captures verify unchanged after
every reproduction run. Regenerated CSVs agree with the frozen ones on every measured value
to within one microsecond — one unit in the last printed digit, arising from
integer-nanosecond rather than float64-epoch arithmetic.

**The saved `hw_config_readback.txt` is a hand-assembled excerpt ending in an unexplained
`RESULT: FAIL (n_fail=1 n_warn=0)`.** All 25 of its assertion rows read `[ok]`; there is no
`[FAIL]` row, although the checker that produces these transcripts prints every failing row.
21 of the 25 rows match a configure-all run that passed with zero failures, verbatim; the
other 4 are a later register readback; the run-transcript header is absent.

**The failing assertion cannot be recovered from archived evidence.** No archived log records
a run with `n_fail=1`, and the file was committed once and never edited. It has not been
modified here.

**Configuration provenance is therefore PARTIAL.** The parameters these figures depend on —
the A and R deadlines, their tick quantization, the J codebook entries, and the
TCP-timestamp policy — all appear as passing rows matched verbatim to a configure-all run
that reported zero failures, and `shape_enable` is established independently from the
captures rather than from any log. The unidentified failure is recorded rather than
explained away.

**The PCAP-derived timing measurements remain reproducible** regardless of the above: they
are derived from the capture files, which verify by hash and regenerate identically.

**A new `shape_enable=0` campaign would be required to establish a truly unmodified native
timing baseline.** None has been run, and no hardware action was taken in preparing this
handoff.

---

## What the arms are

Both arms ran the **same unified switch binary with the size-shaping datapath active**. They
differ only in the configured timing mode. The arms are therefore labelled:

* **Timing OFF** (equivalently *Timing OFF, shaping active*)
* **Timing ON** (equivalently *Defended timing*)

They must not be described as native versus defended, and the Timing OFF arm must not be
presented as an unmodified SEL-751 baseline. `shape_enable` was 1 in both arms, established
by direct observation: every relay response in every timing capture arrives as two TCP
payloads of 28 and 21 bytes, whereas a capture with the carve disabled shows a single
49-byte payload.

Because shaping was on in both arms it is a **held constant**, not a difference between them,
so the comparison isolates the timing-mode change within one binary. It is neither a pure
timing-only binary nor a pure native-versus-defended experiment.

## Claim boundaries to preserve in the text

* **T1 and T2 show READ-versus-SELECT transaction timing, not device identification.** The
  testbed has one relay; nothing here bears on telling one device from another.
* **SELECT means the SELECT phase of SBO** (function 3), not a complete select-before-operate
  transaction. Label it that way.
* **T3 reports only master-visible OPERATE ACK-to-echo invariance.** The valid statement is
  that the master-visible echo-to-ACK interval stayed at about 4.00 ms across J = 2, 6 and
  12 ms. J is the configured codebook value.
* **Relay-facing `T0+J` and exactly-once delivery remain unobserved.** The relay-facing port
  is an internal pktgen/recirculation port with no host-capturable tap. Do not claim either.
* One relay, one capture session, transaction-disjoint but not session-disjoint. The result
  is signature replacement on this device, not indistinguishability across devices.
* The Timing ON mutual-information point estimate is unstable at the fourth decimal because
  the predeclared bin grid has an edge at exactly 4.000 ms. Quote it as "below 0.003 bits and
  inside the permutation null", not to four significant figures.

## Regenerating

```sh
cd defense4/timing        # in the DNP3_obf repository, commit 2ea2daf
./reproduce.sh
```

Rebuilds every derived CSV, the statistics and all four figures from the raw captures, then
compares against the frozen CSVs and prints the differences. No path outside that repository
is hard-coded and the raw captures are never written to.
