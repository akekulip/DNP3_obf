# Selected common size pattern — Phase B decision

This is the Phase B decision the plan calls for: not a survey, a choice. It synthesizes two independent
analyses (`DISTRIBUTION_AND_PATTERN_ANALYSIS.md`, statistical/leakage; `HARDWARE_FEASIBILITY_ANALYSIS.md`,
ASIC cost), which converged closely despite working independently (the second was written first and the
first corrected its own early guess to match it after reading it — see that document's §2.3). All sizes
below are **TCP-payload bytes** unless marked Ethernet-frame bytes (`INTEGRATION_CONTRACT.md` §2).

## The decision

**Selected: Option A — converge READ and SELECT/OPERATE on a shared 49-byte pre-carve TCP payload, split
`[28, 21]` via the Release-Replicate-Carve (RRC) mechanism already proven on real Tofino-1 silicon.**

| Role | Native request | Native response | Transform | Final response vector |
|---|---:|---:|---|---|
| READ (23-point G10V2) | 20 B | 49 B | none — already at target | `[28, 21]` |
| SELECT (2-CROB, single shared G12V1 header, qualifier `0x17`, count=2) | 45 B | 49 B | request: rewrite the native 1-CROB object's qualifier `0x28`→`0x17` and count 1→2, in place | `[28, 21]` |
| OPERATE (same construction as SELECT) | 45 B (expected) | 49 B (expected) | same as SELECT | `[28, 21]` (expected, **not yet measured — see "What this decision does not close"**) |

Both analyses independently scored this at or near the top. The carve side needs **no new P4 mechanism** —
it reuses the exact `defense4_rrc_kernel.p4` RID1/RID2 construction, already hardware-proven for both READ
and SELECT at 49B (`RRC_HW_RESULTS.md` R1–R6). The request-side transform is new: a codec that rewrites an
existing native command object's qualifier and count fields in place, rather than appending a separate
object (the current `case4_padding.expand_control()` approach, which can only reach 52–57B, never exactly
49B — `HARDWARE_FEASIBILITY_ANALYSIS.md` §1.3).

## Why this option over the alternatives, honestly

**Option A′** (converge on the native 37B response, no switch-side transform at all, by choosing a READ
poll that also yields 37B) scored *cheaper* on hardware cost in both analyses — it needs no mapper and no
new codec. It is not selected because:
1. It depends on an operator/master-side READ poll configuration decision that neither analysis could
   verify is acceptable, and that is outside this repository's and this task's authorization to decide or
   test (no live master access).
2. It would mean the switch performs **no padding or transformation at all** for this flow. The integration
   prompt frames padding as a required capability of the framework, not an optional one to skip when a
   cheaper non-mechanism is available (§1: "Pad supported smaller packets and split supported larger
   packets into the selected pattern"), and `INTEGRATION_CONTRACT.md` §5 already settled that the historical
   "no in-switch insertion defeats a parsing observer" finding is not a reason to avoid building the padding
   mechanism this effort asks for. Choosing the option that builds nothing would under-deliver on that
   requirement even though it would "work" numerically.

Option A′ is not discarded — it is recorded below as a candidate worth raising with whoever controls the
production master's poll configuration, pursued in parallel without blocking Phase D on it (§"What Phase D
should also do").

**Option B** (uniform 58B pad, no split at all) has the cleanest measured leakage result of any option
(MI = 0 exactly, not just statistically indistinguishable from zero) and is the documented fallback if
Option A's request-side codec fails its correctness/endpoint-compliance validation (see gate below). It
ranks second, not first, because: it pads every transaction by a flat 9B regardless of native size (a
real, if small, bandwidth cost Option A's exact-fit carve avoids for the 49B-native case), and because
Option A already has direct hardware proof for the carve mechanism on two of the three protected roles,
where Option B's 58B pad target has never been compiled or loaded.

**Option D** (49B uniform pad, no split) is dominated by both A and B — it buys nothing neither already
has while introducing an unhidden exception class (the 58B background state-read, which must bypass
natively and is therefore trivially identifiable). **Option C** (a different fixed cut point) is not a
separate option — mutual information is invariant to a bijective relabeling of the cut, so it is Option A
with an unproven cut instead of the proven `cut28`; `RRC_DESIGN.md` §6 explicitly hard-codes `RRC_49_CUT28`
and rejects a runtime-configurable cut, so a different cut is a recompile, not a free choice, and there is
no reason to pay that cost. **Option E** (keep READ and control on separate size profiles) is rejected: it
is cheap but is the status quo the project exists to fix, and would reintroduce the exact size-channel
leak (READ `[28,21]` vs control `[28,29]`, deterministically separable from the second segment alone —
`DISTRIBUTION_AND_PATTERN_ANALYSIS.md` §4.1).

## What this decision does not close (explicit, falsifiable gates for Phase D)

1. **The qualifier-rewrite codec (`0x28`→`0x17`, count 1→2) does not exist yet.** It must be built and
   tested off-switch first, same pattern as `case4_padding.py`'s existing suite, and validated against the
   production-software `endpoint_gate` semantic harness (does a `0x17`-qualifier, count-2 SELECT/OPERATE get
   accepted and correctly echoed by real OpenDNP3 master/outstation code, not just a parser that tolerates
   the bytes). This is a correctness/protocol-compliance gate, not an ASIC question, and it must pass before
   this pattern is wired into the P4 data plane. If it fails, fall back to Option B.
2. **OPERATE's 49B landing is inferred, not measured.** Every cardinality that was physically captured
   shows OPERATE byte-identical to SELECT (35/37, 50/52 — `DISTRIBUTION_AND_PATTERN_ANALYSIS.md` §2.4), which
   supports expecting the same 45B/49B construction to work for OPERATE, but physical OPERATE has never run
   through the RRC kernel. Phase D's first-milestone demonstration must exercise OPERATE through this exact
   path on the local model (not just assume symmetry with SELECT) before this pattern is called complete for
   all three protected roles.
3. **Request-direction size is not addressed by this pattern.** READ's request stays 20B; SELECT/OPERATE's
   request becomes 45B under the qualifier-rewrite codec. This is a known, named residual
   (`READSBO_NORMALIZATION_RESULT.md`'s own "honest residual") that response-direction convergence alone does
   not close. State this plainly in any claim of operation-indistinguishability — do not let it go unstated.
4. **The combined pipe-0 egress compile has not been run.** `HARDWARE_FEASIBILITY_ANALYSIS.md` §3: the
   carve must share egress of pipe 0 with the existing final-emitter program (`installed_nf_05`), which has
   only 2 of 64 32-bit PHV containers free. The carve's own PHV cost (~392 bits for the 49B case) is small,
   but "fits standalone" and "fits next to the real program" are different claims — the prompt explicitly
   forbids assuming the latter from the former. This is Phase D's first required compile.
5. **Arrival-order reversal is unexplained and inherited, not resolved.** Historical captures recorded wire
   arrival `[21,28]` against TCP sequence order `[28,21]` (prompt §2.5). This pattern does not change that
   open question; Phase E must check it on whatever final build results, not assume it away.

## What Phase D should also do, without blocking on it

Raise Option A′ (37B shared native size, no padding, no mapper) with whoever controls the production
master's poll configuration, independent of and not blocking the Option A implementation above. If an
operator-acceptable 13-point READ poll turns out to be available, it is strictly cheaper than Option A (no
codec, no mapper) and should replace Option A's request-side work — but Phase D does not wait for that
answer to start building the Option A codec and carve integration.

## Byte-precise mapping table (final, machine-readable companion: `selected_pattern.json`)

| Input class | Eligibility test | Transform | Output (TCP-payload bytes) |
|---|---|---|---|
| READ response, 49B native | `(dofs,total_len)` matches the payload49 table (`RRC_DESIGN.md` §3) | none | `[28, 21]`, RID1/RID2 |
| SELECT response, after qualifier-rewrite | same 49B eligibility match, post-transform | request-side qualifier rewrite applied before the response is generated | `[28, 21]`, RID1/RID2 |
| OPERATE response, after qualifier-rewrite | same | same as SELECT | `[28, 21]`, RID1/RID2 (expected, unmeasured) |
| All-points state-read response, 58B native | does not match 49B eligibility | **none — correctly excluded, passes through unsplit** | `[58]` unchanged |
| Any other unsupported size/role | does not match 49B eligibility | none (pass-through, per `INTEGRATION_CONTRACT.md` invariant 7) | unchanged |

## Feasibility/overhead comparison (carried forward from both source analyses, not re-derived)

- **Carve cost**: ~3 egress stages, ~392 PHV bits, 1 PRE multicast group with 2 same-port L1 nodes — already
  proven on silicon for the READ/SELECT case (`RRC_HW_RESULTS.md`), to be re-verified for OPERATE and for
  the combined pipe-0 placement (gate 4 above).
- **Wire cost of the split**: a 49B payload split into 28/21 produces 181 total frame bytes before FCS
  versus 115 for one unsplit 49B frame — a 66-byte-per-transaction increase, the same arithmetic the
  integration prompt itself worked through as its reference example.
- **Security evidence**: MI = 0.0162 bits (Miller-Madow 0.0132), flow-grouped bootstrap 95% CI
  `[0.0, 0.206]` (spans zero), permutation p = 0.166 — not significant at conventional thresholds, but
  measured on only 4 flow-groups (2 READ runs, 2 SBO runs); not yet flow-generalizable at scale. This is
  the honest, current state of the evidence, not a final security claim.

## Provenance

Synthesizes `DISTRIBUTION_AND_PATTERN_ANALYSIS.md` (research-scientist pass, statistical/leakage scoring,
recovered and independently re-verified the extraction/evaluation tooling and all four RRC hardware PCAPs)
and `HARDWARE_FEASIBILITY_ANALYSIS.md` (p4-dataplane-engineer pass, ASIC cost/feasibility scoring, local
compile probes at `/tmp/claude-1002/.../scratchpad/carve_probe/`, not committed). Both ran in parallel
against the same candidate option set defined from `INTEGRATION_CONTRACT.md` and
`DNP3_Timing_Size_Integration_Prompt.md` §4B. This document is the single decision they both feed; neither
source document picks a final answer on its own, by design.
