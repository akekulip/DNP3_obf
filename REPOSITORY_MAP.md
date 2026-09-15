# Repository map: which tree is authoritative for what

One page, six categories. Written 2026-09-15. If a statement anywhere else in this repository
disagrees with this file about *which path is authoritative*, this file is right and the other
one is stale; fix the other one rather than adding a third account.

## 1. Frozen record — what actually produced the paper's results

Byte-identical, never edited, not a working directory.

| path | what it is |
|---|---|
| `defense4/timing/implementation/` | the exact P4, control code and drivers that ran. Its README describes the state of that date and is **not** repaired in place; current interpretation belongs here in the map instead. |
| `defense4/timing/evidence/campaign_v1/s01…s22/raw_pcaps/` | the 132 captures |
| `defense4/timing/evidence/campaign_v1/s*/app_jsonl/`, `s*/provenance/` | per-block application logs, `MANIFEST.json` and `DATASET.sha256` |
| `defense4/timing/evidence/campaign_v1/sweep/raw_pcaps/` | the 20 policy-sweep captures, a **different workload** |
| `defense4/timing/evidence/final_read_sbo/` | the retired single-session corpus, provenance only |

The condition of a block is read from its `provenance/MANIFEST.json`, never from the filename.

## 2. Corrected code intended for future use, not yet measured on hardware

Nothing here produced any published number. Anything it emits is labelled a plan or a mock.

| path | what it is |
|---|---|
| `defense4/timing/active_harness/` | the corrected DNP3 drivers: framing and reassembly, CRC checks, monotonic transaction budgets, response association, SELECT-before-OPERATE validation, dry-run and live guards. Offline tests in `active_harness/tests/`. |

## 3. Current extraction, analysis and figure generation

| path | what it is |
|---|---|
| `defense4/timing/evidence/campaign_v1/repro/` | the campaign authority: `pcap_dnp3.py` (an independent reader), extraction, statistics, leakage, the five NDSS figures, the publication gate, and its own pinned environment |
| `defense4/timing/audit_current/tools/` | `clrt_distribution_and_variance.py` (READ CLRT histograms), `make_model_figures.py` (release timeline), `shift_vs_normalization.py`, `timeout_and_tcp_audit.py`, `make_campaign_manifest.py` |
| `defense4/timing/analysis/` | the shared extractor and `figstyle.py` used by the historical path |

**One reproduction entry point:** `defense4/timing/reproduce.sh` runs the active campaign and
dispatches to `campaign_v1/repro/reproduce.sh`. The retired corpus needs `--historical` and
prints a banner saying its output is not current paper evidence.

## 4. Current manuscript and published artifacts

| path | what it is |
|---|---|
| `paper/rewrite/` | `main.tex`, `sections/`, built by `pipeline/build.sh`, gated by `pipeline/lin_check.py` |
| `paper/rewrite/figures/` | `ndss/`, `clrt/`, `model/` and the three schematics. The figure table in `CLAUDE.md` names each family's single generator. |
| `paper/rewrite/pipeline/check_lin_intro_verbatim.py` | carries Dr. Lin's three Introduction paragraphs inside itself and checks them token by token |

## 5. Separate diagnostics that are not campaign evidence

| path | what it is |
|---|---|
| `relay_rto_20260915/` | the SEL-751A retransmission and blocker-drain diagnostics of 2026-09-15. A deliberate loss experiment. **No manuscript claim rests on it**, and it is excluded by name in the histogram source manifest. See `relay_rto_20260915/CORRECTION_20260915.md` for the configuration difference from the campaign. |

## 6. Historical context and recoverable retired artifacts

| path | what it is |
|---|---|
| `defense4/timing/PROVENANCE.md`, `defense4/timing/history/` | carry a Historical banner; they describe the `final_read_sbo` state and are read that way |
| `defense4/timing/figures/publication/` | the originals of the removed `figures/timing/fig01…fig05` |
| `README.md`, `FINAL_TIMING_ALLOWLIST.txt` at the root | how this tree was reduced from the full research repository |
| git history, tag `archive/pre-final-timing-prune-20260824`, the bundles | everything pruned, recoverable |

## Two distinctions that are easy to get wrong

**Shaping.** `campaign_v1` ran with `shape_enable = 0` in **both** arms, so its comparison is
timing only and every response is a single unsplit 49-byte payload. The retired `final_read_sbo`
corpus ran with shaping **active** in both arms, where responses are split 28+21. Segment length
is therefore a reliable tell for which configuration produced a capture.

**Notation.** `defense4/timing/NOTATION_MAPPING.md` is the authority, as fixed on 2026-09-09.
`D_A` is the ACK hold; `D_R` is the response latency `m_R - t_R`; the response hold `e_R - t_R`
has no symbol; the configured gap is the **configured `CLRT_new`**, carried in the code by the
field still named `D_R_ms`. `CLRT_target` is withdrawn. Archived field names are never renamed.
