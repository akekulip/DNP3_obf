# Post-meeting review handoff

Prepared 2026-09-08 for the revision requested in
`meeting/CLAUDE_Timing_Paper_Revision_and_GitHub_Handoff.md` and
`meeting/DNP3_Post_Meeting_Research_and_Writing_Instructions.md`.

## 0. A correction to the handoff's premise

The handoff names `/home/philip/Projects/DNP3-size-probe/paper/rewrite/` as the working
directory. **That path does not exist.** It was a git worktree of this same repository and was
removed; `DNP3_obf` is the remote's name, not a directory. The live manuscript is
`/home/philip/Projects/DNP3/paper/rewrite/main.tex`, which was verified present and is what
this revision edits.

The handoff also gives `d895d53` as the last inspected remote commit. That is correct for the
remote, but the local branch was already **five commits ahead** of it, carrying CLRT-figure work
from the session immediately before the meeting. Those commits were preserved, not discarded.

## 1. Branch and commits

| | |
|---|---|
| Started from | `paper/campaign-v1-ndss-corrections-20260828` at `fe42ada` |
| Review branch | `paper/lin-post-meeting-revision-20260908` |
| Remote at start | `origin/paper/campaign-v1-ndss-corrections-20260828` = `d895d53` |

Changed files are listed in section 10.

## 2. Argument map

| Link | Content | Where |
|---|---|---|
| Problem | Device fingerprinting is reconnaissance; in ICS the attacker's interest moves to device models and control operations | Intro ¶1 (Dr. Lin, verbatim) |
| Prior work | Traffic obfuscation reshapes packet size and inter-packet timing; recent work offloads it to programmable switches | Intro ¶2 (Dr. Lin, verbatim) |
| Scope-specific gap | Two reasons it does not transfer: ICS fingerprinting uses device behaviour, not network-layer features; and existing obfuscation assumes an encrypted channel that this plaintext setting does not have | Intro ¶3 (Dr. Lin, verbatim) |
| Design response | Schedule the release of real protocol packets from one anchor so a selected interval becomes a configured value; endpoints and bytes untouched | Intro ¶4, Section IV |
| Evidence | Released interval reaches its target; supported range; cost; residual leakage | Section VI |
| Boundary | Function codes still visible; acknowledgment latency still leaks; one relay, one campaign; switch-side release instants never observed | Section IV-D, VI limitations |

## 3. Dr. Lin's prose: verification and concerns

**Verification.** `pipeline/check_lin_intro_verbatim.py` compares the installed paragraphs
against his supplied text token by token, after stripping citation commands. Result:

```
  paragraph 1: VERBATIM (123 words)
  paragraph 2: VERBATIM (101 words)
  paragraph 3: VERBATIM (165 words)
LIN INTRO VERBATIM CHECK: PASS  (3 paragraphs word-for-word)
```

Not one word was changed. Only the bracketed reference numbers were mapped to bibliography keys.

**Concerns for author review — recorded, not corrected.**

| # | Location | Observation |
|---|---|---|
| 1 | ¶3 | "the latency between the TCP acknowledge packets" — likely "acknowledgment" |
| 2 | ¶3 | "Since each vendors may choose" — number agreement |
| 3 | ¶3 | "exposing the the underlying traffic pattern" — duplicated "the" |
| 4 | ¶3 | "despite ICS network protocols may provide security features" — "despite" takes a noun phrase or "although" |
| 5 | ¶3 | "this time can be accurate in fingerprinting" — the antecedent of "this time" is the estimated execution time; a reader may attach it to the latency instead |
| 6 | ¶3 | "estimate execution time there" — "there" means on the device; worth making explicit |
| 7 | ¶1 | The six-month dwell claim is attached to both Ukraine and Stuxnet. Reference [1] is mapped to two keys because Lee et al. document the Ukraine intrusion and not Stuxnet; whether either source supports "at least 6 months" for **both** incidents is **unverified**. |
| 8 | ¶3, second reason | The encrypted-channel statement is written generally. Our Related Work scopes it to the specific techniques cited, which is the defensible form. If ¶3 is read as a claim about all obfuscation research it would be too strong. |
| 9 | ¶3, first reason | "different materials or algorithms" is well supported for physical actuation. For a READ, the interval reflects firmware and processing rather than materials. The paper does not repeat the materials claim for polls. |

**Removed non-Lin text, and the evidence it was superseded.** The previous Introduction ¶3 began
"First, the leaked features are different" and argued from DNP3 framing and CRC. Its status:

* At `3b9a812` (2026-08-26) it was installed as author-supplied text; `LIN_TEXT_CHANGELOG.md`
  records that the supplied Introduction then had four paragraphs and that no word was changed.
* At `4e2d105` ("bound the claim about adding bytes to ICS traffic") an assistant **rewrote its
  second half** into the CRC, framing and relay-firmware argument that stood until today. The
  current file header admitted this: "apart from added citations and the corrected DNP3
  framing/CRC explanation".
* Dr. Lin has now supplied a **new** ¶3 filling the same "two main reasons" slot with different
  reasons, and the meeting record explicitly rejects the CRC and no-flexibility arguments as the
  motivation for a timing-only paper.

So the removed block was part author-supplied and part assistant-written, and is superseded in
both halves by newer authored text. It remains in git history at `3b9a812` and `4e2d105`.

## 4. Notation mapping

Full table: `defense4/timing/NOTATION_MAPPING.md`. The load-bearing change:

| Symbol | Meeting / paper meaning | Code and archived evidence |
|---|---|---|
| `D_A` | ACK hold, `e_A - t_A` | same |
| `D_R` | **RESPONSE hold**, `e_R - t_R`, per transaction, never recorded | **the configured target gap**, `D_R_ms = 4.0` |
| `CLRT_target` | the configured gap | appears as `D_R_ms` / `scheduled_release_interval_ms` |
| `D` | `D_A + CLRT_target` | `release_budget_D_ms = 24.0`, `da_dr` in the P4 |

No archived CSV column, configuration field or control-plane parameter was renamed. Prose,
equations and figure labels were moved to the paper convention.

**Remaining inconsistency:** none in the manuscript body. The Introduction, Design,
Implementation and Evaluation all use the paper convention, and the two figures that carried the
old label were regenerated.

## 5. Parameter selection

**ACK delay** — `defense4/timing/audit_current/ACK_DELAY_SELECTION.md`.
The finding overturns the assumption the paper previously carried. TCP is **not** the binding
constraint here. The mechanism's own admissibility policy computes a horizon
`H = B*K/rate = 18000*64/37.4e6 = 30.802 ms` and an admissible budget
`D_max = 24.797 ms` (`implementation/control/parameter_policy.py`), which at a 4 ms target
admits `D_A <= 20.797 ms`; the tested 20 ms sits 0.8 ms inside its own ceiling. The hardware
sweep confirms the ceiling independently: the acknowledgment tracks `D_A` to 30.571 ms and then
saturates at ~31.07 ms, with the released interval losing its pin (CLRT median 5.503 / 7.498 /
9.507 ms at `D_A` 32 / 34 / 36 ms). I re-derived both the policy arithmetic and the sweep rows
myself rather than taking them on report. RFC 6298 supplies a second argument: because the timer
is computed from observed round-trip samples, a *uniform* hold inflates the sender's RTO rather
than racing it (§2.3, and §6 notes the same effect as an attack). The residual risk is a
*variable* hold. **Unresolved:** the master's realized RTO was never read back;
`ss -tin` on the master during a session would settle it.

**Response latency** — `defense4/timing/audit_current/RESPONSE_LATENCY_BUDGET.md`.
**No standard could be verified that bounds the added response latency** for a DNP3 poll or SBO
on this device. The only numeric, device-enforced deadline verified from primary documentation is
the SEL-751A's `STIMEO1` select/operate timeout, default 1.0 s, from the instruction manual.
IEC 61850-5 message classes govern 61850 messaging and do not transfer to a DNP3 poll — and the
informal "about 100 ms" from the meeting coincides with 61850 Type 2, which is exactly why it
must not be imported. IEEE 1815 interior clauses and IEEE C37.1 are paywalled and remain
**unverified**, not "no requirement". The paper therefore states the target as a deployment
choice, not a compliance claim.

## 6. Release measurement status: UNAVAILABLE

`defense4/timing/audit_current/RELEASE_MEASUREMENT_STATUS.md`. Verified in the P4 source today:
the ten `ts_*_w` timestamp actions are each declared exactly once as a `RegisterAction` and
**every further occurrence is inside a comment** — none has an execute site, so none ever runs.
Four more sit behind `D3_SYNTH_EVENTS`, undefined in the evaluated build. Every declared write
would take an *ingress* timestamp, which is not a wire departure. A control-plane readback
therefore cannot be presented as a release measurement.

What the master-facing capture does carry is a **net signed residual**, the response release
delay minus the acknowledgment release delay plus differential path effects — not a queue delay,
and not attributable to draining. Concrete remaining work, neither executed: external
synchronized capture of both switch links on one clock (preserves the evaluated binary, bounds
the residual from above), or one egress-timestamp write at a real execute site (observes it
directly, but needs a new binary and a new hash, and its evidence must stay out of
`campaign_v1`).

## 7. Figures, data provenance and exclusions

**Data.** All manuscript numbers come from `campaign_v1`: 22 grouped collection runs in one
approximately five-hour window, 132 captures, 63,360 exchanges, one SEL-751A behind one
Tofino-1, size shaping off in both arms. The retired `final_read_sbo` corpus is kept separate
and contributes nothing to the manuscript. The 22 runs are described as grouped collections and
not as independent deployments, in the text and in every caption that reports across them.

**Exclusions.** None in `campaign_v1`: every one of the 52,800 READ rows enters the histogram
figure, the dataset rollup reports zero anomalies and zero incomplete sessions, and no tail is
trimmed. The 36 obfuscated READ transactions that land more than 0.5 ms from the target, the
farthest at 57.2 ms, are plotted and named in the caption.

**Regenerated, and why.**

| Artefact | Change | Reason |
|---|---|---|
| `figures/ndss/fig_policy_coverage_cost.*` | axis labels `Target $D_R$` to `Target CLRT $C_{\rm target}$` | the notation change; regenerated through `campaign_v1/repro/reproduce.sh`, not edited |
| `figures/model/fig_m01_release_timeline.*` | relabelled to the new convention, and now also draws the response hold `D_R` | makes visible that `D_R` is implied by the schedule, not configured |
| `figures/clrt/fig_clrt_distributions.*` | legend and caption target symbol | same notation change |

**No plotted value changed in any of these.** Only labels, and in the timeline one added bar.
The reproduction pipeline confirms it: the rebuild differed from the published copy in exactly
one figure, the one whose labels I changed, and after publishing the rebuild the gate reports
`0 problems` and `131 passed`.

**Figure decisions taken, for the reviewer to confirm.**

* The before/after histograms are now the primary spread explanation in RO1, as the meeting
  asked, placed ahead of the per-class summary.
* The run-level variance dot plot built before the meeting is **not** in the manuscript. The
  meeting said to keep it only if it answers a necessary additional question, and
  `fig_stability` already reports per-run behaviour. Its artefacts stay in
  `paper/rewrite/figures/clrt/` for reference.
* The constant-shift figure is **retained** as one figure. The meeting permits a short analytical
  clarification and warns only against expanding it. It was not expanded, but its prominence is a
  judgement call worth a second opinion.

## 8. Build and validation

| Check | Result |
|---|---|
| `paper/rewrite/pipeline/build.sh` | **PASS**, `compile rc=0 gate rc=0` |
| Undefined references or citations | none |
| `??` placeholders in the PDF | 0 |
| Figures after References | 0 |
| Pages | 16 |
| `pipeline/check_lin_intro_verbatim.py` | **PASS**, 3 paragraphs word-for-word |
| `campaign_v1/repro/reproduce.sh` full run | completed; **131 passed** after publishing the relabelled figure |
| `campaign_v1/repro/publication_gate.py` | **0 problems**, regenerated outputs match every published artefact |
| Visual inspection | pages 4 to 6 rendered and read: timeline figure, equations (1) to (6), and the parameter argument all correct |

The gate's remaining warnings are `contribution_grammar`, `sentence_health`, `acronyms` and
`readability`. They are advisory, were warnings before this revision, and no hard check was
weakened or disabled to reach PASS.

Note also that `test_regenerated_figure_matches_committed[fig_feature_overlap]`, which a previous
cross-review reported failing, passes here: 131 of 131.

## 9. Remaining substantive issues

Ordered by what a reviewer should look at first.

1. **The release residual is unmeasured, and this is the one gap the meeting asked to close.**
   `defense4/timing/audit_current/RELEASE_MEASUREMENT_STATUS.md`. The loaded program cannot
   supply a release instant; closing it needs external synchronized capture or a new binary,
   neither of which this handoff authorizes. The paper says the switch-side instants were not
   captured and does not attribute the observed spread to queue draining. **Effect on claims:**
   the paper can say the released interval concentrates at its target, and cannot say why the
   residual has the width it has.

2. **The master's realized retransmission timeout was never read back.**
   `defense4/timing/audit_current/ACK_DELAY_SELECTION.md`. The transport margin rests on a
   reference value, not a measurement of this host. The paper now argues the mechanism's own
   horizon binds first, which is measured, so the claim does not depend on the unmeasured number.
   **Effect:** no claim that 20 ms is universally safe; one `ss -tin` reading would close it.

3. **No verifiable standard for the response-latency budget.**
   `defense4/timing/audit_current/RESPONSE_LATENCY_BUDGET.md`. IEEE 1815 interior clauses and
   IEEE C37.1 are paywalled and were not read; the DNP Users Group application note downloaded
   only in part. The paper states the target as a deployment choice. **Effect:** no compliance
   claim anywhere; obtaining IEEE C37.1 is the highest-value next step.

4. **Reference [1] in the Introduction is unverified for the Stuxnet half of its claim**
   (section 3, concern 7). Dr. Lin's prose is preserved; the citation maps to two keys. An author
   should confirm the six-month dwell for both incidents or narrow the sentence.

5. **`sections/02_background.tex` and `sections/03_threat_model.tex` were not rewritten.**
   They compile, they do not contradict the new Design, and the threat model's RO1-RO5 still
   match the Evaluation headings. They were left alone because the meeting directed effort at the
   Introduction, Design, Implementation and Evaluation. A reader-level pass over them for voice
   is still outstanding.

6. **`fig_design` is no longer referenced by Design.** The schematic is still in
   `paper/rewrite/figures/` and is referenced from the threat-model side. If it should return to
   Design, it needs a caption in the new notation.

## 10. Changed files

See `git diff --stat fe42ada..HEAD`. Summary: 44 files, +1721 / -509.

Manuscript sources: `00_abstract`, `01_introduction`, `04_design`, `05_implementation`,
`06_evaluation`, `library.bib`, `main.pdf`.
Guides and gates: `pipeline/DR_LIN_WRITING_GUIDE.md`, `pipeline/check_lin_intro_verbatim.py`,
this report.
Notes: `defense4/timing/NOTATION_MAPPING.md`, `audit_current/ACK_DELAY_SELECTION.md`,
`audit_current/RESPONSE_LATENCY_BUDGET.md`, `audit_current/RELEASE_MEASUREMENT_STATUS.md`.
Figure sources and artefacts: `make_model_figures.py`, `make_ndss_figures.py`,
`clrt_distribution_and_variance.py`, and the regenerated figures listed in section 7.

Nothing under `defense4/timing/implementation/` and no raw capture was modified.
