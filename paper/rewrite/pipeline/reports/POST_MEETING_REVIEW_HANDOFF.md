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
| Commits on it | `44603d9` Introduction and Design; `dd0fbc8` Implementation and Evaluation; `453a181` writing-philosophy pass; plus the audit commit that carries this section |
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

5. **Related Work was reviewed and left unchanged.** It already follows the meeting's
   fair-treatment template and scopes the encrypted-channel assumption to the techniques that
   make it. Nothing was found that needed correcting, which is a finding rather than an omission.

## 10. Changed files

See `git diff --stat fe42ada..HEAD` for the authoritative list; the count grew with each commit and is not restated here so it cannot go stale.

Manuscript sources: `00_abstract`, `01_introduction`, `04_design`, `05_implementation`,
`06_evaluation`, `library.bib`, `main.pdf`.
Guides and gates: `pipeline/DR_LIN_WRITING_GUIDE.md`, `pipeline/check_lin_intro_verbatim.py`,
this report.
Notes: `defense4/timing/NOTATION_MAPPING.md`, `audit_current/ACK_DELAY_SELECTION.md`,
`audit_current/RESPONSE_LATENCY_BUDGET.md`, `audit_current/RELEASE_MEASUREMENT_STATUS.md`.
Figure sources and artefacts: `make_model_figures.py`, `make_ndss_figures.py`,
`clrt_distribution_and_variance.py`, and the regenerated figures listed in section 7.

Nothing under `defense4/timing/implementation/` and no raw capture was modified.

## 11. Second pass: writing philosophy applied to Background, Threat Model, Design, Implementation

Added 2026-09-08 after the first push. This pass applied the meeting's writing philosophy, not
only its register: one purpose per paragraph, the reason before the mechanism, general to
concrete, adjacent sentences that connect, stable terms, and each section leaving a question for
the next.

**One substantive correction, in the Threat Model.** The section previously read: "The CLRT
reflects the outstation's internal processing, while the second reflects the physical device
behind a control command." The "second" is our master-visible OPERATE response-to-ACK interval,
so that sentence called a packet-timing feature a physical-actuation measurement. That is one of
the self-defeating moves the meeting lists by name. It is replaced by a paragraph that states
what Formby et al.\ actually did (a sequence-of-events timestamp inside the application payload,
with their packet-arrival alternative producing no usable result), states that our interval is a
packet-timing feature of the solicited control response, and says plainly that we measure no
physical actuation time anywhere.

**Structural changes.**

| Section | Change |
|---|---|
| Background | Opens by saying what the section establishes and why, rather than listing what it contains. The fingerprint paragraph now gives the reason first (two answers come from different parts of the device), then the general claim, then Formby, then our own numbers. Ends by handing the observer question to Section III. |
| Threat Model | Reordered to adversary, what it wants, what our evaluation actually separates, two adversaries, objectives, scope. The duplicated "not device identification" material, previously in two paragraphs, is stated once. Ends by handing the feasibility question to Section IV. |
| Design | Opening no longer restates Background; it inherits the requirement from the objectives. The argument for why the interval is a fingerprint is made once, in Background, and referenced here. |
| Implementation | Ends by naming the three questions Section VI answers, in the order it answers them. |

**Mechanical consistency.** British and American spellings were mixed across the manuscript
(`defence`/`defense`, `characterise`/`characterize`, `realise`/`realize`, `behaviour`/`behavior`).
All are now American, which was already the majority. **Dr. Lin's three paragraphs were excluded
from this sweep** and the verbatim gate still passes.

**Checked and left alone.** Two phrasings flagged by an overclaim sweep are correct in context:
"what the mechanism guarantees" introduces the distinction between a count-based and a
deadline-based hold, and "we do not claim the tested hold is universally safe" is an explicit
disclaimer. Related Work was reviewed against the fair-treatment rule and needed no change: it
already gives each work's objective before the assumption that differs, and it scopes the
encrypted-channel assumption to the techniques that make it rather than to the field.

**Re-verified after this pass:** build PASS, no undefined references, 16 pages, verbatim gate
PASS.

## 12. Self-audit against the two meeting documents

Added 2026-09-08. I re-read the handoff's required package (its section 8, items 1 to 9) and the
synthesis's ordered execution list (its section 12, items 1 to 10) and checked each mechanically
rather than from memory. **Six defects were found in my own work.** All six are fixed; they are
listed here because the fix matters less than the fact that they existed.

| # | Defect | How it was found | Fix |
|---|---|---|---|
| 1 | **Four provenance sidecars claimed a script hash that no longer exists.** I changed `make_ndss_figures.py` to relabel one figure, but hand-copied only that figure's artefacts. The other four NDSS figures are produced by the same script, so their `analysis_script.sha256` was stale. | Ran the sanctioned `publication_gate.py --update` and diffed | All five refreshed through the gate's own update path |
| 2 | **I hand-edited a gated manifest.** `paper/rewrite/figures/ndss/FIGURES.sha256` was rewritten by an ad-hoc script, which is the manual sidecar edit the handoff warns against; `publication_gate.py --update` writes it, and also writes `MANUSCRIPT_VALUES.json`, which I had not considered. | Read `publication_gate.py` | Re-run through `--update`. My hand-edit turned out byte-identical, and `MANUSCRIPT_VALUES.json` was unchanged because no plotted value changed, so nothing downstream was wrong. The process was, and that is what defect 1 came from. |
| 3 | **`fig_design` was orphaned.** The Design rewrite dropped the architecture schematic and never re-placed it, so Implementation explained the queues with no figure at all. | Grep for `\ref{fig:design}` returned nothing | Relabelled the SVG to the paper convention, re-exported PDF and PNG, and placed it in Implementation where the meeting wants the queue explanation |
| 4 | **`SCHEMATICS.sha256` went stale** the moment I re-exported that schematic. | `sha256sum -c` | Manifest refreshed; all nine entries verify |
| 5 | **Two stale guide statements the meeting names explicitly survived my banner.** The guide still said "size shaping active in both arms" (the current campaign has it off) and still prescribed the pre-meeting Evaluation order with "RO1, RO2, RO3" (the draft has five). A supersession banner is not a correction. | Grep for the phrases the meeting names | Both rows and the order paragraph corrected in place |
| 6 | **This report named the starting commit but not the final one**, item 1 of the required package, and carried a file count that went stale on the next commit. | Re-reading item 1 | Commit list added; the count is now a pointer to `git diff --stat` |

**Checked and confirmed correct, not assumed:**

* Every number in Design traces to its source. `H = 30.802 ms` and `D_max = 24.797 ms` were
  recomputed from `parameter_policy.py`; `D_A = 20`, target `4`, budget `24` read from
  `policy_config.json`; the "1 ms to 22 ms" sweep is exactly the eight D4 points at `D = 24 ms`.
* Notation: no old-sense `D_R` survives anywhere in the manuscript, and `C_obs`, `X_off` and
  `X_shift` appear nowhere.
* Citation spacing: zero bare `` \cite{`` or `` \ref{`` in any section, so item 10's
  nonbreaking-space requirement holds throughout.
* Nothing improper is committed: no build intermediates, no credentials, no third-party trees.
* A side-finding that supports a claim already in the paper: the `D = 24 ms` sweep contains a
  **mode D2** point at `D_A = 0` whose measured CLRT is 2.108 ms, essentially the Timing OFF
  median of 2.116 ms. That is direct evidence for the Implementation sentence saying the
  non-dual-deadline modes forwarded both packets unheld.

**The one process weakness has since been closed.** `fig_m01_release_timeline` was generated
into `defense4/timing/figures/model/` and *copied* into `paper/rewrite/figures/model/` by hand,
and that copy had already drifted in its provenance sidecar with nothing detecting it.
`make_model_figures.py` now publishes into the manuscript tree itself and writes that directory's
`FIGURES.sha256` in the same run, so there is no manual step to forget. It also carries a
`--check` mode that recomputes the manifest and compares the published bytes against the
generating tree, and the generating run applies that check to its own output and refuses to
finish quietly if it fails.

The check was tested against real failures rather than assumed to work: appending a byte to a
published caption produced two problems and exit 1, deleting the published PDF produced one
problem and exit 1, and restoring both returned it to 0 problems and exit 0. Only figures the
manuscript actually includes are published; `fig_m02_timeout_model` is a working diagram and
stays in the generating tree.

## 13. Review of Abstract, Related Work and Conclusion

Added 2026-09-08. Every number was checked against
`paper/rewrite/figures/ndss/MANUSCRIPT_VALUES.json`, and every Related Work characterization
against `pipeline/reports/CLAIM_CITATION_MATRIX.md`. Six corrections, one of them a
prior-work accuracy problem.

**Verified correct, and left alone.** Abstract: IQR 2.8 to 0.006 ms (2.7781, 0.006); fixed
attacker 0.651 to chance (0.6515, 0.3332 against a chance of 0.3333); mutual information
0.383 bits to inside the null (0.38315, `inside_null` true); added latency about 21 to 23 ms
(22.657 / 22.617 / 21.185); 22 runs, 63,360 exchanges, 132 captures. Conclusion: the same
figures, consistently stated. All 30 Related Work citations resolve, and every title matches
how the text describes the work.

**Corrections made.**

| # | Where | Problem | Fix |
|---|---|---|---|
| 1 | Related Work | Securitas described as mixing fragmentation and insertion "under a learned policy". The citation matrix records fragmentation and insertion across Tofino, FPGA, eBPF and BMv2, and says nothing about learning. The qualifier was unsupported. | Dropped; the text now states what the record verifies |
| 2 | Related Work | Minos described as morphing "encrypted traffic". The record says switch-based morphing and scheduling; the encryption assumption is not in it. | Dropped |
| 3 | Conclusion | It enumerates four bounds and omitted the one gap the advisor asked to close: the switch's own release instants were never captured. | The bound is now stated, including that what the distribution shows near the target is a net residual and not a delay attributable to one stage |
| 4 | Abstract | The adaptive attacker was described qualitatively where the number exists, and the number is the point: it returns to **0.651**, the fixed attacker's undefended accuracy. | Stated |
| 5 | Abstract | "A fixed release budget leaves a small tail" was vague where the measurement is known. | Replaced with 29 of 29,040 undefended read-lane exchanges too late to schedule, and 24 of 26,400 protected READ exchanges more than 1 ms from target, farthest 57 ms |
| 6 | Abstract | "the behavior of the physical device" blurred device processing and physical actuation, which Section III now separates carefully. | Reworded to "how the device itself behaves" |

**A defect in my own earlier fix.** The spelling sweep of the previous pass matched `characterise`
and `characterised` but not the third-person `characterises`, so two occurrences survived in the
Evaluation and the Conclusion, along with one `normalised` in a caption. A broader search over
`-ise`, `-ises`, `-ised`, `-ising` and `-isation` found and fixed all three, and now returns only
legitimate words (`raises`, `rises`).

**The Abstract was far too long, and I raised it as a question instead of fixing it.** At that
point it ran to **604 words in 19 sentences**. Dr. Lin's own DefRec abstract, the copy in this
repository, is **223 words in 9 sentences**, so the draft was 2.7 times the length of the model
it is meant to be written against. The cause was accumulation: each review pass appended its
caveat to the abstract rather than trusting the body, and by the end the closing paragraph
carried five separate boundary statements.

It is now **270 words in 11 sentences**, following DefRec's shape: problem, why existing work
does not transfer, the mechanism and the one idea that makes it work, what was implemented and
measured, and the headline numbers with the single bound that actually limits them. Everything
removed is still in the paper. Campaign scope and the single-outstation caveat are in the threat
model and the limitations, the tail counts are in the evaluation, and the added latency and
protocol-preservation results are in the cost subsection. Nothing that remains is unsourced: the
six numbers in it were re-checked against `MANUSCRIPT_VALUES.json` after the rewrite.

## 14. Figure layout, measured against the model

Added 2026-09-08 after the criticism that figures were placed without following the structure the
meeting defines. Measured rather than argued: DefRec uses **24 figures** in a comparable page
count, most of them column width, and it pairs two small figures side by side in one row. This
draft had **11 figures, 7 spanning the text block**, each about 4.3 in tall, which is roughly
half a page each.

| | Before | Now |
|---|---|---|
| Figures | 11 | 10 |
| Text-block width | 7 | **3** |
| Figure area | 4.6 text pages | **3.3** |

**Converted to a single column, as stacked panels:** `fig_clrt_distributions` (4x1),
`fig_distributions` (4x1), `fig_policy_coverage_cost` (4x1). The three NDSS figures were changed
in `make_ndss_figures.py` and regenerated through `campaign_v1/repro/reproduce.sh`, never edited
in place; the 2x2 index is preserved by a two-line wrapper so no panel code moved.

**Removed:** the constant-shift figure, which the meeting says twice not to have at that size.

**Tried and reverted, with the reason recorded in the source:** `fig_leakage`. Its panels (c) and
(d) are confusion matrices drawn with equal aspect, so at column width each takes its own width
in height and strands the two result panels above in whitespace. The regenerated column version
was rendered and inspected before the revert, and the pipeline test that then flagged only
`fig_distributions` and `fig_policy_coverage_cost` confirmed the revert restored it byte for byte.

**The release timeline was converted too, after being kept once on the assumption that its time
axis needed the width.** That assumption was wrong, and the fix was to remove content rather than
shrink it: the two deadline expressions above the master lifeline duplicated what the duration
bars below already name, and the end-to-end bar duplicated the abscissa. With those gone the
timeline reads cleanly at 3.5 in, and the expressions moved into the caption where there is room
to state them properly.

**Left at text-block width:** `fig_feature_overlap`, whose source already carries a note from an
earlier session that a stacked version forced the inset into the ordinate labels, and
`fig_leakage` for the equal-aspect reason above. Both reasons are content-driven and recorded in
the generating source.

**Final position: 10 figures, 2 at text-block width, 3.0 text pages of figure area against 4.6
when this started, and the paper is 14 pages rather than 15.**

**Still open.** The Evaluation carries six figures. Each currently answers a question the others
do not, but `fig:hist` and `fig:dist` overlap on READ, and that pair has not been put to the
meeting's test of whether both are necessary.

## 15. Voice and density, measured against Dr. Lin's own papers

Added 2026-09-08. Five of his papers were converted to text and measured, so the targets are
observations rather than adjectives: DefRec (NDSS 2020), RAINCOAT (IEEE TSG), the SDN in-network
honeypot paper, "Adapting Bro into SCADA", and "Safety-Critical Cyber-Physical Attacks". The
bands are the observed minimum and maximum across those five, so a draft sitting anywhere inside
his own range passes.

**How the prose sounds. Three axes failed; all now pass.**

| axis | Lin band | before | after |
|---|---|---|---|
| mean sentence words | 20.5 to 25.4 | 23.3 | 20.6 |
| sentences over 35 words | at most 16% | **17.9%** | 7.4% |
| connective-led sentences | at least 8.5% | **3.5%** | 9.0% |
| median paragraph words | 70 to 100 | **110** | 96 |
| sentences with "we" | 15 to 40% | 23.2% | 21.6% |
| passive | 9 to 26% | 18.2% | 16.1% |

The connective result corrects an error made earlier in this session. After the philosophy pass I
recorded that the rate had fallen from 8.9% to 5.0% and treated that as an improvement. It was
not. Dr. Lin chains his logic explicitly at about 11%, and a rate of 3.5% in our own sections
meant the prose asserted where his explains. Sentences were not padded to reach the band: each
change promotes a real consequence or contrast that was hiding behind a comma, which shortens the
sentence at the same time, which is why both axes moved together.

**How much the prose carries. Density is not word count, and this is where the draft is still
short.**

| axis | Lin band | before | now |
|---|---|---|---|
| numerals per 1000 words | 31.9 to 74.1 | 29.6 | 31.3 |
| sentences carrying a number | 33.6 to 53.0% | 26.8% | 28.1% |
| median paragraph words | 72 to 98 | 110 | 104.5 |

The clearest instance was the Conclusion, which measured **zero** numerals and zero sentences
carrying a number. His conclusions put a number in a quarter to a third of their sentences. Ours
had been stripped during the shortening pass, because numbers are the easiest words to cut. It is
now 189 words in 8 sentences with 2 carrying a number, which is his shape, and every value traces
to `MANUSCRIPT_VALUES.json`.

Other restorations, each a magnitude the paper had already measured and left qualitative: the
Timing OFF tail is 83~ms rather than "a long tail"; the request-to-acknowledgment median is
0.56~ms; the coverage boundary is 29 of 29,040 exchanges; the budget covers 99.9% for about 23~ms
of added latency; the tested settings are stated as $D_A = 20$~ms and a 4~ms target; the
reservoir is 64 blockers.

**Still short, and reported rather than papered over.** Numeric density is 31.3 against a floor
of 31.9, and sentences carrying a number are 28.1% against a floor of 33.6%. Closing the second
means roughly nineteen more sentences carrying a magnitude, in a 342-sentence paper, and each one
has to be a quantity that genuinely belongs. The thinnest sections are the threat model and
design. This was not closed by inserting numbers to move a metric, because that is the same
failure as padding connectives.

The abstract is deliberately excluded from that judgement. It measures low on numerals by direct
instruction: interpretation of the numbers rather than the numbers themselves.

**The measurement is now a skill.** `~/.claude/skills/paper-voice` was updated to version 2.0.0
rather than duplicated. It already carried a fingerprint mined from the same five papers, and
adding a second, competing skill would have left two sources of truth. What it lacked was any
measure of density, so `scripts/density_check.py` is new, the corpus profile carries a `density`
block with both full-corpus and two-column-only paragraph bands, and the structural and figure
discipline from this meeting is recorded there.

## 16. Density in the threat model and design, and a correction to section 15

Added 2026-09-08.

**A broken sentence, found and fixed.** An earlier edit in this session had produced "A response
that arrives after it has nothing to wait for", losing the words "its deadline". A scan for
doubled words, lost objects, doubled verbs and connectives without their comma now runs over
every section and reports zero issues. The two hits it raises in the Introduction are in Dr.
Lin's protected paragraphs and are left untouched.

**Magnitudes restored where they belong.** The threat model and design named constraints without
their size. Now stated, each traced to the gated values: the poll and control medians differ by
0.9 ms while their acknowledgment intervals differ by 0.003 ms, which is where the separation
lives; chance for the three-class task is 0.333; the adaptive adversary recovers 0.651; the
per-transaction hold is drawn from 2, 6 and 12 ms; RFC 6298 floors the retransmission timer at
1 s; the admissible budget is at most 24.8 ms; the tested target is 4 ms at about 23 ms of added
latency. Background recovered the DNP3 function codes, 1, 3, 4 and 0x81, which an earlier pass
had removed as clutter and which are the opposite of clutter.

**The measurement in section 15 was wrong, and the corrected figure is worse.** The density tool
had three defects: it did not strip citation keys or macro names, so those counted as words and
deflated every per-word density; it counted section titles as sentences; and its paragraph floor
of 25 words moved when other parts of the tool changed. All three are fixed, the corpus bands
were re-derived, and the tool now records in its own source why bold run-in heads are
deliberately kept.

Position with the corrected tool:

| axis | corpus band | now |
|---|---|---|
| median paragraph words | 67 to 98 | **97** |
| sentences per paragraph | 3.3 to 5.1 | **4.5** |
| numerals per 1000 words | 31.9 to 74.1 | 26.7 |
| sentences carrying a number | 33.6 to 53.0% | 19.2% |

Paragraph density now passes. Numeric density does not, and the gap is larger than section 15
reported, because that section trusted a tool that was over-counting words. Reporting the worse
number is the point: the earlier figure would have let the draft look finished.

The sound axes were re-checked after all of this and none regressed.

**What closing the rest would take.** Roughly fifty more sentences would have to carry a
magnitude. The evaluation is already at 40.5% and inside the band; the shortfall is concentrated
in the abstract, introduction and threat model, which are argumentative rather than quantitative
sections. Two of those are constrained: the abstract is deliberately interpretive by direct
instruction, and the introduction is protected text. That leaves less room than the whole-paper
number suggests, and the remaining honest work is in the threat model and the design.

## 17. Section-by-section and paragraph-by-paragraph pass

Added 2026-09-08, using the `paper-voice` skill. The Introduction was excluded throughout as
protected text.

**Two stale rules in the skill were corrected before it was applied.** It carried a rule marked
mandatory: "every paper carries exactly one 'To the best of our knowledge, this is the first ...'
claim. A draft with zero first-ness claims fails." That is wrong on three counts, each verified:
the corpus uses the phrase in one of five papers; the meeting says not to force novelty language
and that documents making it mandatory are superseded; and this project's own
`pipeline/lin_check.py` flags firstness as a defect. Applying the skill as written would have
introduced a claim the gate rejects. The skill also cited a contract under a `DNP3-size-probe`
path that does not exist. Both fixed; skill at 2.4.0.

**One self-defeating argument found and repaired.** The threat model put the master-visible
OPERATE interval in scope, then explained that Formby's actual physical-operation-time feature
came from an application-layer timestamp our mechanism cannot touch. Both statements are true and
both must stay, but together they left RO2 looking pointless. A paragraph now states what the
interval is still good for: the control lane answers 0.8 ms slower than the read lane, that
difference separates the classes on its own, and Section VI-F shows an adversary recovering 0.651
balanced accuracy from exactly that kind of difference. RO2 asks whether the interval becomes a
policy value, not whether physical timing is concealed.

**Consistency checked mechanically, not by eye.** Every numeral appearing in more than one
section was compared across sections; all agree. Every phrase the meeting forbids was searched
for; each of the ten hits is a *denial* of the forbidden claim rather than the claim itself. The
abstract's and the conclusion's headline statements were compared against the body and match.

**Wording.** Two corpus frames were absent from our prose and are now used where they genuinely
fit: `For example,` instantiating a general claim with a measured number, and purpose-first
`To <goal>, we <verb>` for design decisions. No banned corpus word appears outside the protected
Introduction.

**Density.** Two more tool defects surfaced during the pass. The checker counted publisher
boilerplate, the IEEE copyright line and DOI stamped on every page, as prose; that alone made one
corpus paper's Related Work look number-dense when its prose carries no numbers at all, and it
had inflated the bands. It also revealed that our Related Work carrying zero numerals is
*consistent* with his, not a defect, so no numbers were forced into it. Bands re-derived with
boilerplate and bibliographies excluded.

| axis | corpus band | before pass | after |
|---|---|---|---|
| numerals per 1000 words | 18.7 to 49.8 | 26.7 | **29.1** |
| median paragraph words | 67 to 95.5 | 97.0 | **85.5** |
| sentences per paragraph | 3.1 to 4.6 | 4.6 | **4.2** |
| sentences carrying a number | 29.9 to 47.5% | 19.0% | 20.2% |

Three axes pass. The fourth is closer and still short, and it is the honest remainder: the
sections that carry it are the abstract, which is interpretive by instruction, and the
introduction, which is protected.

Build PASS, verbatim gate PASS, prose scan zero issues, 15 pages.

## 18. Evaluation pass

Added 2026-09-08.

**Every number verified against the gate.** Eighteen values quoted in the Evaluation were checked
against `MANUSCRIPT_VALUES.json`: medians, interquartile ranges, standard deviations, both
classifier accuracies, both mutual-information figures, the acknowledgment median, the added
latency and the coverage percentage. Zero mismatches.

**Each objective now states its verdict.** Every RO opened with a condition, "We achieve RO1 if
...", and then reported results without ever answering it. The corpus closes an experiment with a
scoped takeaway, so each objective now ends with one, in its own terms: RO1 holds for the
exchanges the budget can schedule, RO2 for the interval the master sees, RO3 against the fixed
adversary and not against one that retrains, RO4 over a 1 to 22 ms range bounded by the
outstation below and 31.07 ms saturation above, RO5 at about 23 ms per exchange with no added
frame or byte.

**Limitations rewritten to Dr. Lin's scope rule.** His instruction is that a caveat bounds our own
result, and that an unrelated research problem does not belong in the argument merely because
mentioning it sounds careful. The block now opens by saying each limitation bounds one of the
results above, and each is titled by the claim it bounds: What RO3 Establishes, What RO2 Rests On,
What RO4 Observes, What RO5 Counts, The Residual Is Not Attributed, The Tail Is Not Eliminated.

Two disclaimers were removed as out of scope rather than as inconvenient. "Size obfuscation is
outside this paper: the mechanism changes no packet size, and we make no size, padding, splitting
or segmentation claim" defends against a claim no reader of a timing paper would attribute to us,
and the Design section already states that the switch changes no bytes. "Nothing here shows that
exactly one OPERATE reached the relay" disclaims exactly-once delivery, which the paper never
asserts. What was kept, and sharpened, is every caveat that genuinely bounds a result: the
relay-facing release behind RO2, the control-plane horizon behind RO4, the unattributed residual,
the master-facing-only overhead behind RO5, and the late tail behind RO1.

The retransmission caveat was kept but re-scoped. It reads as a bound on our own
zero-retransmission result rather than as a general disclaimer: because the program suppresses a
response retransmission matching an already-seen transport position, a relay-side retransmission
of a held response would not reach a master-facing capture.

**Result.** The Evaluation now measures 63.5 numerals per 1000 words, 38.8 per cent of sentences
carrying a number, 70.5 words a paragraph and 3.8 sentences a paragraph, inside the corpus band
on all four. Whole-document numeric density rose to 30.2 and paragraph density to 84.0, both
inside band. Sentences carrying a number remain at 21.0 against a floor of 29.9, concentrated in
the abstract and the protected Introduction.

Build PASS, verbatim gate PASS, prose scan zero issues, 15 pages.

## 19. Related Work pass

Added 2026-09-08.

**One digression removed on the scope rule.** The general-obfuscation paragraph carried the web
fingerprinting arms race, that deep-learning attacks defeat several padding defenses and that
their accuracy at Internet scale is contested. Both statements are true and both are about their
field, but neither leads to a design response here and this paper makes no size claim, so under
Dr. Lin's scope rule they were decoration. The sentence now states what those defenses achieve
against the features they target and cites the same two works for the attacks that followed,
which is the fair-treatment form: objective first, then the assumption that limits transfer.

**A duplicated argument removed.** Related Work restated at length why our master-visible OPERATE
interval is not Formby's payload-timestamp estimate of physical operation time. Section III
already makes that case carefully, and repeating it invited the two versions to drift. Related
Work now states the contrast in one sentence and points back.

**Three paragraphs were doing two jobs each** and are split at the change of subject:
fingerprinting work from the defenses that answer it, and web-scale shaping from cloud shaping.
Median paragraph length in the section falls from 119 to 65 words and sentences per paragraph
from 5.2 to 3.6.

**A finding the pass produced, reported rather than fixed by padding.** Citations concentrate
almost entirely in the Introduction and Related Work: before this pass, Design cited 1.0 per 1000
words and Implementation and Evaluation cited nothing at all, against a corpus that cites at 9.7
to 14.0 throughout. Five body citations were added where a claim genuinely rests on someone
else's work: P4 and SP-PIFO for the pipeline and the strict-priority primitive in Implementation,
Formby for the feature in Design and for the relay class and the attacker model. That moves the
whole paper from 4.6 to 5.1 per 1000 words, still under the corpus floor.

Closing the rest would take roughly forty more citations. Our Evaluation is 3,308 words reporting
our own measurements and has little that a citation would support, whereas the corpus's
evaluations cite simulators, datasets and testbed components. Adding citations to reach the band
would be padding, so the miss is left standing and reported. The checker marks this axis soft for
that reason.

**Section state after the pass.** Related Work: 65 words a paragraph, 3.6 sentences a paragraph,
both in band. Whole document: numeric density 30.2 and paragraph density 80.0, both in band;
sentences carrying a number 21.1 against a floor of 29.9.

Build PASS, verbatim gate PASS, prose scan zero issues, 15 pages.

## 20. Abstract and Conclusion pass

Added 2026-09-08, completing the section-by-section pass. Both were measured against the two
corpus papers that have comparable abstracts and conclusions, DefRec and RAINCOAT.

**The conclusion was missing the corpus's closing move.** Both corpus conclusions end with
exactly one future-work sentence, "In future work, we will provide formal coverage analysis ..."
and "In future work, we plan to use Raincoat in other implementation scenarios ...". Ours had
none: the sentence was cut during an earlier shortening pass. It is restored in that form and
names the two things that would actually close the open gaps, other vendors' outstations and
direct measurement of the release instants with synchronized capture.

**Both now follow the corpus's reporting frames.** The conclusion opens "This paper presents ..."
and reports with "Evaluations on a physical relay ... show that", which are RAINCOAT's forms. The
abstract reports with "The experimental results show that", which is DefRec's. The abstract also
gained the short blunt sentence the corpus uses to set a topic, "Hiding that timing is
challenging", against DefRec's "Disrupting reconnaissance is challenging."

**Fair treatment applied to the abstract's gap sentence.** It had read that existing traffic
obfuscation "does not help", which states a verdict on other people's work. It now says the work
"was built for a different feature" and names which, which is the same argument without the
dismissal.

**Structure.** The conclusion is now three paragraphs, recap, result, bounds and future work,
rather than two paragraphs with the bounds trailing the result inside one. The abstract keeps its
three, with the first split so the two reasons prior work does not transfer are separate
sentences rather than one three-clause chain.

**Length.** Abstract 257 words against DefRec's 223; conclusion 223 against DefRec's 178. Both
are longer than his and shorter than they were, and both were trimmed once after the first
rewrite ran over.

**A deliberate difference, recorded rather than fixed.** The abstract carries no digits, and
measures 8.3 per cent of sentences carrying a number against a corpus floor of 29.9. That is on
instruction: the abstract states the interpretation of the results rather than the results
themselves, so "a spread more than two orders of magnitude smaller" appears where the conclusion
gives 2.61 and 0.63 ms. The conclusion is inside the band at 27.3 per cent. The two agree on
every claim; they differ only in whether the magnitude is spelled or written as a figure.

Whole document after the full pass: numeric density 30.0 and paragraph density 82.0, both in
band; sentences per paragraph 4.2, in band; sentences carrying a number 21.1 against 29.9;
citations 5.0 against 9.7, reported in section 19 rather than padded.

Build PASS, verbatim gate PASS, prose scan zero issues, no banned corpus word outside the
protected Introduction, 15 pages.
