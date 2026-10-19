# NOMAD paper: claims and the evidence behind each (2026-10-19)

Every claim the manuscript may make about the evaluation, and the figure or table that supports it.
A claim with no row here is not written. A row marked **open** is not written until it closes.

- **Outputs:** `../evidence/evaluation_campaigns/eval_m11_09_20261018_02_paper/`, produced by
  `../analysis/paper_evidence.py`. The `--check` mode rebuilds them in a temporary directory and
  compares all 130 file hashes in `OUTPUTS.sha256`. Hash prefixes below are from that file.
- **Inputs:**
  - the campaign's committed `results/` CSVs;
  - `release/rows.csv` (580 MB, uncommitted), checked against the hash in the committed
    `release/release_manifest.json`;
  - `../evidence/evaluation_campaigns/eval_m11_09_20261018_02_paper_inputs/`:
    - `conformance_trials.csv`, derived by `paper_conformance.py` from per-trial verdict files,
      each checked against `eval_m11_09_20261018_02_EVIDENCE.sha256`;
    - `motivation/`: device captures restored from git commit `7c4a5a7`;
  - the m11_09 compiler logs.
- **Environment:** the campaign's pinned one (Python 3.13.12, numpy 2.3.5, scikit-learn 1.7.2,
  matplotlib 3.10.7).
- **Not modified:** the campaign's own `results/` and its 39-output reproduction.
- **Tests:** `../tests/test_paper_evidence.py` (unittest in the pinned environment; also collected by the gated pytest suite, where the byte-identity test skips outside the pinned environment). Caption numbers are recomputed from the generated data by the tests.

Arm names used in the paper are No obfuscation, Timing, Size and Timing+Size. In the campaign
fields these are `off`, `timing_only`, `size_only` and `combined`.

| # | claim | output (hash) | what it shows | status |
|---|---|---|---|---|
| C1 | CLRT exists only when the IED acknowledges separately. The SEL-751 does (100/100), but the ION7550's delayed ACK hides CLRT (0/100), so a fixed CLRT method does not transfer and flexible obfuscation is needed. | `fig_motivation` (f6d7c68c) | SEL-751 CLRT median 2.785 ms; ION7550 request→response 2.92 ms with the ACK carried | closed (READ only, one unit per model; predates NOMAD) |
| C2 | Control units map to numeric indices; example SEL configuration | `table_point_map` (50ab0bf3) | 21 analog points of an SEL relay, indices 0–20 (currents, voltages, frequency, P/Q/S/PF, AI301–AI304) | closed for the Background example; relay model and source document still to record (`paper_inputs/sel_point_map/SOURCE.md`) |
| C3 | NOMAD fits one Tofino-1 | `table_resources` (f26305e8), stated in Appendix B text (no table, Philip 2026-10-19) | N 11 / E 12 / T 11 stages; p0 average SRAM 16.5%, TCAM 31.3% | closed |
| C4 | The Timing strategy replaces READ, SELECT and OPERATE CLRT with D | `fig_clrt_four_arm` (0bbfc404), `fig_precision_tail` (3e26cae0), `fig_precision_bias` (e20790f6) | timed-arm \|CLRT−D\| median 10–16 µs, p99 58–86 µs; 0.14–0.46% beyond 100 µs; max 1.93 ms. At D = 10 ms only, READ and SELECT sit 20–29 µs early while OPERATE stays within 5 µs (all five J); at D = 5/15/20 ms the operations agree within 3 µs | **open**: the cause of the D = 10 ms operation-dependent offset is not established; state it as measured, not explained |
| C4b | Schematics of the release rule and the components | `paper/rewrite/figures/nomad/fig_nomad_timeline`, `fig_nomad_components` (draw.io, `SCHEMATICS.sha256`) | placed at campaign medians (`table_timeline` (456cf9e5)); labels from `DESIGN_FACTS.md` | closed |
| C5 | Replacement, not a constant shift | `fig_replacement` (838487a8) | a shift keeps OPERATE ~60 µs from READ/SELECT, measured ≤25 µs at D = 10 ms; window variance ~3× lower; native SD 0.06–0.11 ms | closed (the remaining 25 µs is C4's D = 10 ms offset) |
| C6 | The OPERATE hold J is invisible on the master side | `fig_operate_hold` (86af91b1) | hold 2.52→20.12 ms follows J; master request→response 41.1 ms for every J | closed (software endpoint) |
| C7 | The Size strategy makes every response 61 B and stays conformant | `table_sizes` (de24bd2e), `table_conformance` (dc5103ae) | 49/37 → 61 B; 98,816/98,816 responses pass the checker; 0 CRC, unmatched, duplicate or reordered packets; 16,384 multi-segment SBO responses per size-normalized arm | closed (requests stay native) |
| C8 | The attacker of Formby et al. (multinomial NB on 200-bin CLRT histograms of K-transaction windows), trained before deployment, falls to chance under Timing and Timing+Size | `fig_formby_nb` (89bcd23b) | 0.333 at every K and setting; primary-setting reduction 0.271 [0.135, 0.396] (K=8), 0.271 [0.146, 0.396] (K=32), 0.292 [0.167, 0.417] (K=64) from `results/paired_reductions.csv` (attacker fixed, feature nb) | closed; Dr. Lin's choice (2026-10-19): the paper reports only Formby's attacker, so the pre-registered RF primary statistic (0.617) stays in the evidence and is not cited |
| C9 | Residual sources (post hoc RF field groups) | `fig_residual_sources`, `posthoc_attacks` (evidence only) | request alone 0.667; response 0.35–0.47; both 0.69–0.80 | evidence only, **not in the paper** (Formby attacker only) |
| C10 | READ vs SELECT and preceding-gap tasks (post hoc RF) | `fig_residual_sources` (b) (evidence only) | 0.48–0.55; 0.46–0.64 | evidence only, **not in the paper** |
| C11 | The same Formby classifier retrained on each configuration learns about as much as without NOMAD on the software outstation | `fig_formby_nb` (89bcd23b) | Timing+Size 0.454/0.531/0.557 vs No obfuscation 0.553/0.591/0.604 (means over settings, K=8/32/64); primary-setting reductions 0.130 [−0.016, 0.250], 0.000 [−0.146, 0.125], −0.042 [−0.167, 0.083]; 192/48/24 test windows per setting | closed (stated as a negative result) |
| C12 | RF reduction along D and J | `fig_dj_curves` (evidence only) | fixed 0.61–0.64, adaptive 0.50–0.61 | evidence only, **not in the paper** |
| C13 | The envelope covers response availability; no fallback | `fig_envelope` (c4da3db8), `table_outcomes` (2959c927) | all 12 arm/operation pairs below da = 31 ms: max 8.0 ms untimed, 26.45 ms OPERATE with J; 49,408 ACK commits, 0 fallbacks | closed (guards are not bounds) |
| C14 | Overhead is within the timers; no retransmission | `fig_latency` (579ec59e), `table_outcomes` | timed request→response 36.1–51.1 ms median, max 52.3 ms, versus 201 ms RTO and 500 ms timeout; 0 retransmissions, timeouts or capture drops | closed |
| C15 | Offline reproduction | campaign `reproduce_evaluation.py` (39/39) + `paper_evidence.py --check` (130/130) | byte-identical | closed |
| C16 | The ~1 ms precision tail is inherited, downstream of the switch | `fig_precision_tail` + RESULTS.md | 73 / 24,704 outside 100 µs | closed (localization inherited from m9d, not re-measured) |
| C17 | Plain text prevails: vendors document little DNP3 security | `table_crawler` (cec91cbe) | 55 devices from 5 vendors: 48 document no DNP3 security, 4 encryption+auth (2 of them CIP Security, not DNP3), 2 auth only, 1 unconfirmed; all 25 legacy/mature devices none | **open**: the draft's sentence cites 99 / 32 / 6 / 1, which this output does not reproduce; Dr. Lin to confirm which run the paper reports (`paper_inputs/crawler/SOURCE.md`); Barbieri et al. (ICCCN 2021) as independent support |

**Not claimed:**
- device identification;
- the restart path on silicon;
- physical-relay OPERATE;
- exactly-once delivery;
- generalization beyond the evaluated attackers;
- request-side normalization: requests stay native, so the request alone separates READ from SBO
  at 0.667.
