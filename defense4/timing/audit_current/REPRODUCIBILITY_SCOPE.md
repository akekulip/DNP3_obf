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

**Changed.** `publication_gate.py` now distinguishes the two cases. When a regenerated PDF's
hash differs, the gate checks that figure's data CSV and, if the CSV is byte-identical, says so
in the problem text: the plotted numbers agree and the difference is in the rendering only. An
operator seeing a failure on another machine can now tell a portability artefact from a real
change without decoding a PDF stream by hand.

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

## 5. What is still open

The second machine's run also reported **130 passed, 1 failed** in the test suite. The failing
test is not identified in the review, and it is not reproducible here, where all 131 pass. It is
plausibly the same coordinate difference reaching a test that compares a figure hash, but that
is a hypothesis and is recorded as one. Identifying it needs the failure output from that
machine, and until then cross-machine test parity is **UNRESOLVED**, not passing.

The residual risk is small and bounded: the numbers agree on both machines, and the disagreement
is confined to rendered bytes. But "the reproduction passes everywhere" is not a claim this
evidence supports, and it is not made.
