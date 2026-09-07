# Shift versus replacement, finished honestly

What the comparison rests on, what the two non-D4 sweep points are, and what the replacement
claim is and is not allowed to say.

---

## 1. The D2 and D3 sweep points were inactive controls

**Confirmed, three ways.**

*From the program.* `tbl_decide_fresh` admits a transaction only for `MODE_D4_DUAL`. Frozen
source line 2846 gives `(… CLASS_ARM, V_ARM_FRESH, … MODE_D4_DUAL …) : dec_o(OUT_ARM_FRESH)`;
line 2847 gives `MODE_OFF → OUT_ARM_BUSY`; and the catch-all at line 2849 sends **every other
mode** to `OUT_ARM_BUSY`. `MODE_D1_EVENT`, `MODE_D2_RESP` and `MODE_D3_ACK` are declared at lines
633 to 635 and are unreachable in this build: no deadline is written and both packets are
forwarded.

*From the wire.*

| point | configured mode | `D_A` | `D_R` | measured CLRT | measured request-to-ACK |
|---|---|---|---|---|---|
| `sw_off` | OFF | — | — | 2.093 ms | 0.558 ms |
| `sw_D2_0_24` | D2 | 0 | 24 | 2.108 ms | 0.550 ms |
| `sw_D3_20_0` | D3 | 20 | 0 | 2.098 ms | 0.558 ms |
| `sw_D4_20_4` | D4 | 20 | 4 | 3.999 ms | 21.318 ms |

D2 with `D_R` = 24 ms should have held the response about 24 ms. D3 with `D_A` = 20 ms should
have held the acknowledgment 20 ms. Neither did: both sit on the OFF control's values.

*From the control plane.* It is not the cause. Imported offline with no SDE it exposes all six
modes and accepts `--mode D2` and `--mode D3` without complaint. The configuration was accepted
and the data plane ignored it.

## 2. The analysis already had this right; the prose did not

`repro/validate_sweep.py` line 42 declares

```python
CONTROL_POINTS = {"sw_off", "sw_D2_0_24", "sw_D3_20_0"}
# Points that establish the operating envelope rather than a release policy.
```

and emits `is_control_point` per point. The published figure filters on it: both panels of
`fig_policy_coverage_cost` select `mode == "D4" and not is_control_point`, so panel (b) plots 8
points and panel (c) plots 9, and **the three controls are plotted nowhere**. Its figure-data
CSV confirms it: every plotted row is a `sw_D4_*` point.

So nothing in the analysis or the figures ever depicted D2 or D3 as a measured defense. The
error was confined to prose, in four places:

| where | said | should say | status |
|---|---|---|---|
| `defense4/timing/README.md` §3 | "18 configured release policies and one control" | 16 policies, all D4, and three native controls | **corrected** |
| `CLAIMS_AND_LIMITATIONS.md` C2 | "the 19-point hardware sweep" without composition | same, with the composition named | **corrected** |
| `CLAIM_EVIDENCE_MATRIX_CORRECTED.md` | "18-point hardware sweep" | 16 D4 policy points of 19 | **corrected** |
| `paper/rewrite/figures/ndss/fig_policy_coverage_cost.method.md` | "Panels (b) and (c) are the measured 19-point hardware sweep: each point is one capture under one installed release policy" | panels (b) and (c) plot the 16 D4 policy points, 8 and 9 of them respectively; the sweep's other three points are native controls | **queued as patch item P10**, because it is a published artefact the publication gate hashes |
| `paper/rewrite/sections/06_evaluation.tex`, twice | "18 configured release policies", "18 release policies" | 16 | **queued as patch items P1a and P1b** |

The two queued items are not applied here: publishing a corrected figure sidecar rewrites
`FIGURES.sha256` and the sidecar's provenance, which the gate compares, and editing the section
prose is a manuscript change. Both wait for authorization. Until then the gate stays green and
the defect is recorded here.

## 3. There is no measured fixed-shift arm, and there cannot be one on this binary

**Correcting an error in an earlier version of this section.** It said a constant shift
"requires both instants delayed by the same amount". That is wrong, and `TIMING_MODEL.md` §4 has
it right. With each packet delayed from its own arrival,

```
e_a = t_a + d_a      e_r = t_r + d_r      so   e_r - e_a = X + (d_r - d_a)
```

what a constant translation requires is that the **difference** `d_r - d_a` be a constant, not
that the two delays be equal. Equal delays are the special case `d_r - d_a = 0`, which leaves
the interval unchanged: the identity translation. Any fixed difference translates the
distribution by that amount and preserves its variance.

**The conclusion stands, for a different reason than the one given.** What makes a shift
unreachable here is not the size of the delays but their **anchor**. A translation requires each
release instant to be computed from *that packet's own arrival*. Every implemented mode computes
release instants from absolute deadlines instead: D4 arms both from the single anchor `t_a`,
which removes the native term rather than translating it, and D2 and D3 would each have armed one
instant from a deadline as well. No reachable mode delays a packet relative to its own arrival,
so no reachable mode produces a translation, whatever its offsets. And in any case D2 and D3
never arm.

So the constant-shift comparison in `EVIDENCE_AUDIT.md` §3 is an **analytical reference computed
from the Timing OFF samples**: the native distribution translated so its median lands on the
protected median. It is the only shift comparison obtainable without a new program, and it must
be labelled analytical wherever it appears. It is **not** a hardware condition, not an arm, and
not a measured defense. Where a figure or a table shows it, the label must say so; where the
manuscript describes it, patch item P5 supplies the wording.

## 4. What the replacement claim is tied to

Three things, in this order.

**The implemented schedule.** Both read-lane release instants are armed from the single anchor
`t_a`: `reg_deadline` holds `t_a + D_A` and `reg_tresp` holds `t_a + D_A + D_R`, each armed once
as an absolute 32-bit word (frozen lines 1676 to 1719, and the comment at 1705). Their difference
is `D_R` and the outstation's own interval is absent from it algebraically, not merely reduced.
The control lane does the same from `t_0`, and line 3140's comment says why the later relay
acknowledgment cannot re-anchor it.

**The response-availability boundary.** A deadline cannot emit a packet that has not arrived. The
program takes the `expired` branch to `to_fwd()` when the response arrives after its deadline, so
those transactions become an upper tail rather than being pinned. The explanatory model is
`e_r = max(t_r + ε, e_r,target)`, and it is labelled a model, not a line of the program.

**The measured residual.** Release accuracy against the configured target, over all 31,680
obfuscated exchanges:

| class | n | median error | 99th percentile absolute error | over 1 ms | worst |
|---|---|---|---|---|---|
| READ | 26,400 | −0.0001 ms | 0.031 ms | 24 | 53.182 ms |
| SELECT | 2,640 | +0.0002 ms | 0.031 ms | 1 | 1.150 ms |
| OPERATE | 2,640 | −0.0001 ms | 0.029 ms | 1 | 1.662 ms |

with a stated envelope: the target is followed from `D_R` = 1 ms to 22 ms at fixed budget, and on
the `D_A` ramp to 30 ms, after which the released interval rises above target.

## 5. What it is not allowed to say

* **Not physical-operation-time replacement.** `t_P` was never measured, and
  `audit_current/FORMBY_REVIEW.md` shows the physical-operation-time fingerprint as actually
  reported rests on an application-layer SER timestamp, which this mechanism does not touch.
* **Not independence from native timing, on variance alone.** A variance ratio of 0.058 for READ
  and 0.0001 for SELECT against a reference that retains the native spread exactly is enough to
  **reject a constant-shift explanation** under comparable conditions. It is not enough to
  establish that the output is independent of the native interval. That needs paired ingress and
  egress measurement, which this evidence does not contain and which the loaded binary cannot
  provide (`INSTRUMENTATION_AUDIT.md`).
* **Not the absence of leakage.** An attacker retrained on obfuscated traffic recovers to 0.651
  balanced accuracy from the acknowledgment interval, because the two lanes are anchored
  differently. That is reported as a result, not a caveat.
* **Not a claim about queue correctness.** Reduced variance is consistent with the queues working
  as designed and with several other mechanisms producing the same output. The program's own
  reservoir check, which would have distinguished them, cannot be run.
