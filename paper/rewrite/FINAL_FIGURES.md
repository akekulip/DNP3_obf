# FINAL_FIGURES.md — the five figures of the timing paper

All five live directly in `figures/timing/`. The vector PDF is the manuscript source; the PNG
is a 600 dpi preview. Every one is referenced from `evaluation_pipeline_v1.tex`, which
`main.tex` inputs, and every one is produced only by `defense4/timing/reproduce.sh` from the
six raw captures — no figure is hand-edited, and no plotting script contains a measured value
as a literal (checked by `defense4/timing/tests/test_timing.py`).

Generated 2026-08-24 from `defense4/timing` at commit `06f472c` under Python 3.8.10,
matplotlib 3.7.5. In-manuscript figure numbers are assigned by LaTeX at compile time and
currently follow the three diagrams (Figs. 1–3), so file `fig01` is manuscript Fig. 4, and
so on; the file numbers are the stable identifiers.

**The arms.** Every before/after figure compares *Timing OFF* with *Timing ON*. Both arms ran
the same unified switch binary with the size-shaping datapath active; the Timing OFF arm is
therefore **not** an unmodified native SEL-751 baseline, and the comparison isolates the
timing-mode change within one binary.

---

## Figure 1 — READ and SELECT CLRT before and after

| | |
|---|---|
| PDF | `paper/rewrite/figures/timing/fig01_clrt_read_select_before_after.pdf` |
| PNG | `paper/rewrite/figures/timing/fig01_clrt_read_select_before_after.png` |
| Manuscript section | Evaluation → Effectiveness in RO1 (read timing), `\label{fig:clrt-dist}` (currently Fig. 4) |
| Caption (short) | CLRT probability density for READ (func 1) and the SELECT phase of SBO (func 3), Timing OFF vs Timing ON; full tail shown to 12.27 ms and 18.18 ms; Timing ON collapses to 4.001 ms. |
| Source script | `defense4/timing/figures/source/fig01_clrt_read_select_before_after.py` — `9e0939678ce9ee2dd75d3b1af90ed20276a524011f5133149fce1d68b55de6a4` |
| Input CSVs | `native_txn.csv` `00d32b84…fbfca6f`, `defended_read_txn.csv` `3d4dbf38…9cc5316`, `defended_txn.csv` `8e197157…d026833c` |
| Input PCAPs | `e1_native.pcap`, `e2_def_read.pcap`, `e2_def.pcap` (hashes in FIGURE_PROVENANCE.md) |
| SHA-256 PDF | `cf9a4ae9a3828c09016839e871ae6f3eafb4acd95251ff6a65d53b6138edd234` |
| SHA-256 PNG | `a4ef4147b8e63f12b44081fa10e9800e75d12d40fc4c3330420047659e68443f` |
| Referenced by LaTeX | **yes** — `evaluation_pipeline_v1.tex` line 41 |
| Results shown | Timing OFF READ n=999, SELECT n=488; Timing ON READ n=599 (median 4.001 ms), SELECT n=499 (median 4.001 ms). |

## Figure 2 — READ and SELECT CLRT ECDF

| | |
|---|---|
| PDF | `paper/rewrite/figures/timing/fig02_clrt_ecdf_before_after.pdf` |
| PNG | `paper/rewrite/figures/timing/fig02_clrt_ecdf_before_after.png` |
| Manuscript section | Evaluation → RO1, `\label{fig:clrt-ecdf}` (currently Fig. 5) |
| Caption (short) | Four-series ECDF: Timing OFF READ, Timing OFF SELECT phase of SBO, Timing ON READ, Timing ON SELECT; full range to 18.18 ms, nothing truncated; Timing ON magnified in an inset. |
| Source script | `defense4/timing/figures/source/fig02_clrt_ecdf_before_after.py` — `e5afa2d00a49210a73991c82998b22bf7d84442ef4143d5d26f702b165cc39b0` |
| Input CSVs | as Figure 1 |
| Input PCAPs | as Figure 1 |
| SHA-256 PDF | `69a882a5d288d36f799a33ec2f249a3e9479a5eab120fa36cff59e410d208481` |
| SHA-256 PNG | `ffea6120f4bcdb2fad248c5700a243b5533f9efec8d5d1784d10d619d9d92cd8` |
| Referenced by LaTeX | **yes** — `evaluation_pipeline_v1.tex` line 58 |

## Figure 3 — Timing-feature overlap before and after

| | |
|---|---|
| PDF | `paper/rewrite/figures/timing/fig03_timing_feature_overlap_before_after.pdf` |
| PNG | `paper/rewrite/figures/timing/fig03_timing_feature_overlap_before_after.png` |
| Manuscript section | Evaluation → RO1, `\label{fig:overlap}` (currently Fig. 6) |
| Caption (short) | Request-to-ACK latency against ACK-to-response latency (CLRT), one point per transaction, READ and SELECT phase of SBO, Timing OFF vs Timing ON. Feature overlap, not clustering, not device identification. |
| Source script | `defense4/timing/figures/source/fig03_timing_feature_overlap_before_after.py` — `cdba06756f63c7295fffc0bbd66e5b183351e85734b9f7618b1dcb8b401e0333` |
| Input CSVs | as Figure 1 |
| Input PCAPs | as Figure 1 |
| SHA-256 PDF | `4de9993dc1e1991883435f8257c36cb2f290f53d595d5611a4f3924c1a898d21` |
| SHA-256 PNG | `6a13824574bc032fe613588ff1252ae7cfb07b603841ad7a115ff2c5b179f286` |
| Referenced by LaTeX | **yes** — `evaluation_pipeline_v1.tex` line 70 |

## Figure 4 — SBO OPERATE timing across J

| | |
|---|---|
| PDF | `paper/rewrite/figures/timing/fig04_sbo_operate_timing_by_j.pdf` |
| PNG | `paper/rewrite/figures/timing/fig04_sbo_operate_timing_by_j.png` |
| Manuscript section | Evaluation → Effectiveness in RO2 (control timing), `\label{fig:operate-j}` (currently Fig. 8) |
| Caption (short) | Master-visible request-to-ACK, request-to-echo and echo-minus-ACK for configured J = 2, 6, 12 ms; medians of 30 OPERATEs with bootstrap 95 % CIs; echo-minus-ACK stays ≈ 4.00 ms. J was not observed relay-facing; exactly-once delivery not demonstrated. |
| Source script | `defense4/timing/figures/source/fig04_sbo_operate_timing_by_j.py` — `0be5377ba652b37f5c86634158211abdf06874133951c29320fce03f2da2146b` |
| Input CSVs | `sbo_j2.csv` `d7c1c99d…a088c914`, `sbo_j6.csv` `10f631fd…29da264e`, `sbo_j12.csv` `62db1054…e23d4bf1` |
| Input PCAPs | `sbo_j2.pcap`, `sbo_j6.pcap`, `sbo_j12.pcap` |
| SHA-256 PDF | `0a2d515565d0c910f4b7c1cc9bad54ca0232f1a9b13a6b21c9667b39c290458a` |
| SHA-256 PNG | `584b49860981c0b02bfb8032a2378158b9d509b63c91aca72cc9ef02d83b3991` |
| Referenced by LaTeX | **yes** — `evaluation_pipeline_v1.tex` line 106 |
| Results shown | echo-minus-ACK medians 4.001 / 4.002 / 4.003 ms at J = 2 / 6 / 12 ms. |

## Figure 5 — Timing leakage summary

| | |
|---|---|
| PDF | `paper/rewrite/figures/timing/fig05_timing_leakage_summary.pdf` |
| PNG | `paper/rewrite/figures/timing/fig05_timing_leakage_summary.png` |
| Manuscript section | Evaluation → RO1, `\label{fig:leakage}` (currently Fig. 7) |
| Caption (short) | Mutual information I(class; CLRT) with permutation-null bands, and READ-vs-SELECT balanced accuracy with bootstrap CIs and the 0.5 chance line, Timing OFF vs Timing ON. Transaction-class feature suppression on one relay, not device identification. |
| Source script | `defense4/timing/figures/source/fig05_timing_leakage_summary.py` — `20e88cd75dfc01c929b03754ab5e6124cb7c00d80b5f2df4d7e8ec3e442f2590` |
| Input | `defense4/timing/evidence/final_read_sbo/timing_stats.json` (computed by `analysis/timing_stats.py` from the three CLRT CSVs) |
| Input PCAPs | as Figure 1 |
| SHA-256 PDF | `9751bf73843d4226afe03042e6cc03f6a68a76c33b68e1ccdf1ee3e41d8b9479` |
| SHA-256 PNG | `97ca4d486b64025e246b3f89eac200e3916e3d703e57896ad10b320a8c5b2207` |
| Referenced by LaTeX | **yes** — `evaluation_pipeline_v1.tex` line 84 |
| Results shown | MI 0.424356 → 0.002085 bits (Timing ON inside its permutation null, upper bound 0.0033; the frozen record's 0.001837 differs only by bin-edge rounding — quote as "below 0.003 bits and inside the null"); balanced accuracy 0.5921 → 0.5000, chance 0.5. Not the stale `0.223 → 0.018`. |

---

## Verification (2026-08-24)

* `main.tex` compiled from a clean temporary directory with tectonic, exit 0, 7 pages; every
  page rendered and inspected: all five figures appear, opaque white, no black or transparent
  region, no clipped tail.
* `grep includegraphics` over `main.tex` and its five section files finds exactly the five
  timing figures plus the three diagrams; no stale figure reference remains.
* `defense4/timing/tests/test_timing.py`: 102/102 under Python 3.8.10 and 3.12.13.
