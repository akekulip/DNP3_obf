# What "reproducible" covers, and where byte-identity stops

Cross-review on 2026-09-07 ran the reproduction on a second machine and found it **does not**
fully pass: 130 of 131 tests passed, and the publication gate reported three problems, all from
`fig_feature_overlap.pdf` differing from the committed PDF. The decoded drawing stream differed
by roughly 1e-10 PDF points in **one coordinate**. The figure's statistics JSON matched exactly.

That is a real finding and this repository had overclaimed. This document states the boundary.

---

## 1. Three tiers, not one

| tier | artefacts | reproducible where | gated? |
|---|---|---|---|
| **The numbers** | `transactions_canonical.csv`, `per_capture.csv`, the sweep tables, `stats.json`, `replacement_stats.json`, `leakage.json`, every figure's `_data.csv` | **anywhere** the pinned environment installs. Integer nanosecond timestamps end to end, fixed seeds, no floating-point accumulation order that varies | yes, byte hash |
| **The renderings** | the figure `.pdf` files | **byte-identically on one machine**; across machines the plotted numbers agree but the last bits of a coordinate may not | yes, byte hash, **with a diagnostic** (§3) |
| **The previews** | the figure `.png` files | not guaranteed anywhere: the Agg raster depends on the interpreter build's FreeType and libpng | no, existence and size only |

The middle tier is the one that was described wrongly. `figstyle_ndss.py` marks the PDF
`"authoritative": True` and its comment says the PDF and the data CSV "are byte-reproducible
from the pinned environment". The first half of that is true only within a machine.

## 2. Why the PDF is not portable, and why that is not a result changing

A vector PDF stores coordinates. matplotlib computes them through a transform stack in double
precision, and the PDF backend prints them to fixed precision. Two hosts satisfying the same lock
file can still differ in the last bits of one intermediate, because the result depends on the
compiled maths library, on whether a fused multiply-add is used, and on vectorisation choices
the CPU makes. A difference of 1e-10 PDF points is roughly 1e-10 of 1/72 inch: about 3e-13
millimetres. It is not visible, not measurable and not a change in the figure's content.

The numbers behind the mark are carried by the data CSV, which **did** match. So the scientific
content reproduced across machines and the rendering did not reproduce bit for bit.

## 3. What was changed, and what deliberately was not

**Changed.** `publication_gate.py` now reports the data CSV's state alongside a PDF mismatch,
so an operator can see at once whether the summary statistics also moved. The wording stops at
what that supports and names inspection as the remaining step; §6 explains why it cannot say
more.

**Deliberately not changed: the check is still a failure.** The PDF is what goes into the
manuscript, so a silent tolerance would let a genuinely altered figure through. Whether a
rendering-only mismatch should be downgraded from a failure to a warning is a judgement about
published artefacts, and it is left to the authors rather than taken unilaterally. Verified on
this machine: the gate reports 0 problems on an unmodified rebuild, and when a single byte of a
regenerated PDF is flipped it still fails, with the new diagnostic naming the data CSV as intact.

## 4. Corrected claims

Where this repository said the reproduction is byte-identical, it should say, and now says:

* **The analysis is reproducible anywhere** the pinned environment installs: manifests, canonical
  tables, statistics, leakage results and every figure's plotted data.
* **Byte-identity of the rendered PDFs is verified within one machine**, and is not guaranteed
  across machines.
* **The PNG previews are not byte-reproducible anywhere** and are not gated.

Statements elsewhere about two runs agreeing "byte for byte on all 14 artefacts" describe **two
runs on this machine**, which is what was measured; they are not cross-machine claims and are
scoped accordingly in `SESSION_20260907.md` gate row 19.

## 5. The failing test, identified

Cross-review reported **130 passed, 1 failed** on the second machine and named the test:

```
test_regenerated_figure_matches_committed[fig_feature_overlap]

committed:    e6dd10b0d6c64b3a918ee9c0ff3cab426fb69aadd634e366d10bb71a9df23173
regenerated:  5710e0b3c76296fe46831fb60b5c762b49e4347f5a3e5df7c51605ddf48aafad
```

So this is a **known, reproducible failure on that host**, not a hypothesis. It is the same
`fig_feature_overlap.pdf` that produces the three publication-gate problems, reaching the test
suite through the same hash comparison. It does not reproduce on this machine, where the
committed hash `e6dd10b0…` is regenerated exactly and all 131 tests pass.

**Cross-machine test parity is therefore FAILING, not unresolved**, and the count to quote for
that host is 130 of 131. The single failure is confined to a rendered PDF's bytes; the figure's
plotted data and the statistics behind it match on both machines.

## 6. Why a matching data CSV does not prove the figures are equivalent

The gate's diagnostic reports whether the figure's data CSV matched alongside a PDF mismatch.
That narrows the search. It does **not** establish visual or content equivalence, and the
diagnostic no longer says it does.

`fig_feature_overlap` is the worked example. Its `_data.csv` holds **six rows**, one per arm and
transaction class, carrying medians and 5th/95th percentiles. The figure itself draws **900
sampled points per arm per class**, along with axes, ticks, labels, a legend and an inset. The
CSV certifies the summary statistics behind the marks and says nothing about the 900 drawn
coordinates, the sampling seed's effect on which points were drawn, or any label or axis setting.
A CSV match is consistent with a rendering difference and also with a real difference the CSV
does not cover.

The gate therefore now says exactly this:

> `fig_feature_overlap.pdf: PDF differs; summary CSV matches; visual/content equivalence
> requires inspection (see REPRODUCIBILITY_SCOPE.md)`

Closing it properly means one of: comparing the decoded drawing streams numerically with a
stated tolerance, or rendering both to raster at fixed resolution and comparing within a stated
pixel tolerance, or a human comparison of the two PDFs at printed size. None has been done, so
equivalence for that figure is **asserted by nobody** and the strict gate stands.
