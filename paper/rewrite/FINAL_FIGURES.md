> **Historical.** This describes the five-figure set built from the retired `final_read_sbo`
> evidence, which the manuscript stopped using at the campaign_v1 correction of 2026-08-28. It
> is kept as a record of that set, not as a description of the current paper.

# FINAL_FIGURES.md — the retired five-figure timing set

## Where these figures are now

They are **not** in `paper/rewrite/figures/`. On 2026-09-07 the ten files under
`paper/rewrite/figures/timing/` were removed, having been verified byte-identical to the
originals, which are retained at

* [`defense4/timing/figures/publication/`](../../defense4/timing/figures/publication/) — the five
  vector PDFs, their 600 dpi PNGs, figure data, captions and provenance sidecars.

Their generator, `pipeline/make_final_figures.py`, is retired to
[`defense4/timing/history/figures_campaign_superseded/`](../../defense4/timing/history/figures_campaign_superseded/)
and no longer runs: it read the copies under `figures/timing/` and grepped the LaTeX for
`\includegraphics{figures/timing/...}`, and neither exists. This file is therefore maintained by
hand from here on, and the instruction it used to carry not to hand-edit it no longer applies.

## What the manuscript uses instead

| what | where |
|---|---|
| the five data figures | `paper/rewrite/figures/ndss/` |
| the three schematics | `paper/rewrite/figures/fig_observation`, `fig_ladder`, `fig_design` |

Those are the only figures `main.tex` and the section files include. The NDSS set is regenerated
only by `defense4/timing/evidence/campaign_v1/repro/reproduce.sh` and is gated by its publication
gate; its provenance is
[`figures/ndss/FIGURE_PROVENANCE_campaign_v1.md`](figures/ndss/FIGURE_PROVENANCE_campaign_v1.md).

## What the retired set showed, and why it is retired

Five figures from the six-capture `final_read_sbo` dataset: READ and SELECT CLRT before and
after, their ECDFs, the timing-feature overlap, the SBO OPERATE interval by configured `J`, and
the leakage summary.

It is retired for three reasons, each recorded elsewhere in full:

1. **Its dataset was superseded.** `campaign_v1` has 132 captures across 22 grouped runs against
   `final_read_sbo`'s six in one session, and its headline values differ
   (`audit_current/REPOSITORY_AUDIT.md` §5).
2. **Its arms are not what the paper now reports.** Both arms of `final_read_sbo` ran with the
   size-shaping datapath active, so its Timing OFF arm is not an unmodified relay baseline. In
   `campaign_v1` the size carve is off in both arms, established from the wire
   (`audit_current/CONFIGURATION_EVIDENCE.md` §1).
3. **Its captions use retired labels.** They say *Timing ON*, which the current gate forbids; the
   arms are *Timing OFF* and *Obfuscated*.

Its claims are preserved separately at
[`defense4/timing/history/CLAIMS_AND_LIMITATIONS_final_read_sbo.md`](../../defense4/timing/history/CLAIMS_AND_LIMITATIONS_final_read_sbo.md).

## Figures added since, and not part of either set

* `defense4/timing/figures/model/` — two DRAFT diagrams: the release timeline and the timers that
  could end a held transaction.
* `defense4/timing/figures/shift/` — four DRAFT figures for the constant-shift versus CLRT
  normalization evaluation, over both corpora kept separate.

Neither is a manuscript figure. Adding any of them is item P11 of the proposed patch and needs
authorization.
