# Selected common size pattern — Phase B decision

**UPDATE 2026-10-08, still later the same day: Option B′ is built, validated against the real pinned
OpenDNP3 master/outstation, and CLEARED. This is now the active pattern.** Read this update first; it
supersedes both updates below, which are kept for the record of why A and B each failed.

**What Option B′ is:** a filler restricted to the pinned library's seven implemented qualifier codes
(`0x00, 0x01, 0x06, 0x07, 0x08, 0x17, 0x28`), built as a new sibling codec
`defense4/timing/framework/size/case4_pad58b.py`. **CONTROL** (SELECT/OPERATE, 19-byte gap): one G41V3
(32-bit float Analog Output Block) object at qualifier `0x28`, 2 points — header 5B + 2×7B = 19B exactly;
the only whitelisted single-object construction that reaches 19 with real point data. **READ** (9-byte gap):
three `ALL_OBJECTS` (qualifier `0x06`) headers — G41V1, G41V2, G41V3, each a bare 3-byte group+variation+
qualifier header, no count field, no point data — 3+3+3 = 9B exactly.

**The arithmetic-only candidate this document itself proposed for READ (two header-only, count=0 objects,
4+5=9) is wrong, caught only empirically, not by source review alone**: `NumParser::ParseCount`
(`cpp/lib/src/app/parsing/NumParser.cpp`) rejects a parsed count of zero outright
(`ParseResult::COUNT_OF_ZERO`), which — exactly like Option B's `UNKNOWN_QUALIFIER` on `0x27` — aborts the
whole two-pass `APDUParser::Parse` before dispatch, losing the real 23-point READ data too (confirmed:
`points_received_after_padded=0` on that first construction). The `ALL_OBJECTS`/`0x06` qualifier avoids
`NumParser` entirely (`APDUParser::ParseQualifier` routes it straight to `HandleAllObjectsHeader`, which
consumes only the 3-byte header), so it cannot hit that failure. Also newly found: `0x07`/`0x08` are
whitelisted qualifier codes in general, but `CountParser::ParseCountOfObjects` only recognizes Group50/51/52
for them under default parse settings — G41Vx/G12V1 fillers under `0x07`/`0x08` hit `INVALID_OBJECT_QUALIFIER`
and fail exactly like `0x27` did. They are unusable for this filler at all, not a corner case.

**Empirical result, independently re-run and confirmed twice** (once by the dispatching agent, once
independently re-run in this session against the same pinned commit with a fresh output directory):
`All tests passed (62 assertions in 7 test cases)`. CONTROL: the real master accepts the padded SELECT echo,
emits a genuine OPERATE, and completes a real SBO actuation (`master_emitted_operate=1`,
`physicalActuations=1`). READ: all 23 real points are delivered through the padded response
(`points_received_after_padded=23`). A subsequent native, unpadded transaction on the same connection
recovers cleanly on both roles. This is a strictly better result than either prior candidate — no partial or
total data loss on either protected role. Full trace: `endpoint_gate/TestCase4Pad58B.cpp`,
`emit_vectors_pad58b.py`, `case4_pad58b.py`'s own module docstring (which documents the failed first design
honestly, not just the final one).

**What remains open:** this clears the size-pattern *software model*. It does not yet exist in P4 — Phase D's
data-plane realization of this exact filler construction is the next concrete step, and per the standing
lesson from this same day (twice), nothing about a software-correct construction guarantees it fits the
ASIC's own constraints; that is a separate, unstarted check.

---

**Prior update 2026-10-08, after Option B's own codec was gated: Option B as coded is dead.** (Superseded by
the update above — a third candidate, Option B′, has now cleared the same gate.) Kept for the record.

**What happened:** `case4_pad58.py` (the G41V2/qualifier-`0x27` uniform-58-byte filler) was built, tested
byte-exact (18/18 new unit tests, independently re-verified), and run against the real pinned OpenDNP3
production master/outstation (`endpoint_gate`, commit `4648fcb898`) on both protected roles. **It failed, and
failed more severely than Option A's qualifier-rewrite codec did.** The pinned library implements exactly
seven qualifier codes (`QualifierCode.cpp`: `0x00, 0x01, 0x06, 0x07, 0x08, 0x17, 0x28`); `0x27` is not one of
them and decodes to `QualifierCode::UNDEFINED`. `APDUParser::ParseQualifier`'s `default:` branch returns
`ParseResult::UNKNOWN_QUALIFIER` for it, and `APDUParser::Parse`'s two-pass design means a non-`OK` result
anywhere in the fragment aborts the **entire parse** before pass 2 (the dispatch-to-handler pass) ever runs —
so the real, well-formed native data that precedes the filler in the same fragment is never delivered either.
Measured: a padded READ response carrying all 23 real points plus the filler delivered **zero** points to the
master's SOE handler (`points_received_after_padded=0`); a padded SELECT/OPERATE echo left every command
point at `CommandStatus::UNDEFINED` (127) — the master never even reached `TypedCommandHeader`'s per-point
logic, because `CommandSetOps::IsAllowed`'s whitelist (`{0x17, 0x28}`) already rejected the qualifier in pass
1. A subsequent, unpadded READ on the same connection recovered all 23 points cleanly, confirming the loss
was specific to the padded fragment. Where Option A's failure silently withheld OPERATE but still let the
master's app-layer read of the SELECT echo succeed, Option B's construction destroys the legitimate payload
on every transaction it touches. Full trace: `endpoint_gate/TestCase4Pad58.cpp`,
`endpoint_gate/emit_vectors_pad58.py`, and the source citations above.

**What this means:** any filler object's qualifier byte must be one of the library's seven implemented codes.
Of those, only `0x17` (1-byte index prefix, 1-byte count; header 4B, point 4B for G41V2) and `0x28` (2-byte
index prefix, 2-byte count; header 5B, point 5B) carry a per-point index, matching this project's own default
gate's already-proven-transparent construction (`TestCase4.cpp`, a G12V1/qualifier-`0x28` trailing object,
46/46). `0x07`/`0x08` (no index prefix, sequential points) are also whitelisted and usable for an object whose
points don't need individual addresses. Byte arithmetic for a **whitelisted-qualifier replacement filler**
(not yet built or tested — a candidate, from this document's own author doing the arithmetic directly, not a
dispatched result):

- **READ** needs filler = 9 bytes (33→42 user bytes, same 58B TCP target). No single whitelisted-qualifier
  object hits 9 exactly with real point data (`0x17`: 4+4k; `0x28`: 5+5k; `0x07`: 4+3k; `0x08`: 5+3k — none
  solve for an integer k≥1 at 9). The only exact fit is **two header-only objects, each count=0, no point
  data at all**: a 4-byte-header qualifier (`0x17` or `0x07`) plus a 5-byte-header qualifier (`0x28` or
  `0x08`), both empty, 4+5=9. This needs its own validation: whether a real master's parser/dispatcher
  tolerates a declared-empty object group cleanly, same rigor this gate already applied twice.
- **CONTROL** needs filler = 19 bytes (23→42). This one has a clean single-object solution with real point
  data: **one `0x07`-qualified (no index prefix) G41V2 object, 5 points, header 4B + 5×3B = 19B exactly**
  (value+status only per point, no index octets).

This is a new candidate (call it **Option B′**), not yet built, not yet endpoint-gate-tested. It must clear
the same gate that killed both A and B before being treated as more than arithmetic. The empty-object-group
piece of READ's construction in particular is untested territory this project hasn't touched before.

---

**Prior update 2026-10-08, earlier the same day, after Gate 1 was tested: Option A is dead. Option B is now
the active pattern.** (Superseded by the update above — Option B's own codec has now also failed its gate.)
Kept for the record, same reasoning as before.

**What happened:** the qualifier-rewrite codec (`0x28`→`0x17`, count 1→2) that Option A depended on for
SELECT/OPERATE was built, tested byte-exact, and then run against the real pinned OpenDNP3 production
master (`endpoint_gate`, commit `4648fcb898`) — exactly the validation gate this document itself required
before Option A could be called complete (see "What this decision does not close," item 1, below). It
failed: `TypedCommandHeader::ApplySelectResponse` in the real master silently declines to select any point
when the response header carries more indexed objects (2) than the master's own request header held (1)
— `if (commands.Count() > this->records.size()) return;`. A live master never issues OPERATE after seeing
the rewritten echo. This is not a hardware limit and not a bug in the codec; it is the real production
client correctly refusing a wire construction that doesn't match what it sent. There is no variant of the
in-place qualifier rewrite that gets around this guard without changing what the master itself sends, which
is outside this project's control. Full trace: the codec's own report, kept at
`defense4/timing/framework/size/case4_qualifier_rewrite.py` and
`defense4/timing/framework/size/endpoint_gate/context_evidence_qualifier_01/`.

**What this means for Option B, now that it is live rather than a documented fallback:** Option A let READ
stay completely untouched (it was already native at 49B) and only needed insertion on SELECT/OPERATE
(37B→49B gap, 12 bytes). Option B's uniform 58B target needs insertion on **all three roles**, including
READ (49B→58B, a gap neither this document nor the hardware-feasibility analysis separately costed, since
READ was assumed free under the option that was actually picked at the time). This is a real, newly
surfaced increase in scope, not a free substitution — Option B is not simply "the fallback," it is "the
fallback, now revealed to need insertion on the one role that previously needed none." A follow-up
hardware-feasibility check on this specific point is in progress; this document will be updated again when
it reports.

**Why proceeding with B now, rather than pausing on it:** `SELECTED_PATTERN.md`'s "Why this option over the
alternatives" section already pre-committed, in writing, before this result was known, that a validation
failure on Option A's codec falls through to Option B — precisely so this moment wouldn't need to re-litigate
the whole Phase B choice from scratch. Option A′ (native 37B, no padding) was rejected for reasons unrelated
to this failure (operator poll dependency outside this project's access; builds no padding mechanism at all)
and those reasons are unchanged by today's result, so A′ is not reconsidered here either. Options C/D/E were
already dominated or rejected on their own terms and remain so.

## The original decision (superseded above; kept for the record)

This was the Phase B decision the plan called for: not a survey, a choice. It synthesizes two independent
analyses (`DISTRIBUTION_AND_PATTERN_ANALYSIS.md`, statistical/leakage; `HARDWARE_FEASIBILITY_ANALYSIS.md`,
ASIC cost), which converged closely despite working independently (the second was written first and the
first corrected its own early guess to match it after reading it — see that document's §2.3). All sizes
below are **TCP-payload bytes** unless marked Ethernet-frame bytes (`INTEGRATION_CONTRACT.md` §2).

**Selected at the time: Option A — converge READ and SELECT/OPERATE on a shared 49-byte pre-carve TCP
payload, split `[28, 21]` via the Release-Replicate-Carve (RRC) mechanism already proven on real Tofino-1
silicon. Superseded by the update above — kept here only so the reasoning for rejecting A′/B/C/D/E at the
time remains legible.**

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
