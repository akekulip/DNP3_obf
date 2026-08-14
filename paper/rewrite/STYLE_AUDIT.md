# Style Audit — NDSS Rewrite (four sections vs. STYLE_PROFILE.md, Lin-priority)

Read-only structure/style pass over `sec_introduction.tex`, `sec_relatedwork.tex`,
`sec_threatmodel.tex`, `sec_implementation.tex` against `STYLE_PROFILE.md` and the DefRec /
RAINCOAT / Testbed target extracts. This is an **edit list to apply**, not a rewrite.

**Overall:** the four sections are already close to the Lin model — no adjective-led paragraph
openings, no banned discourse markers, no promotional register (`novel/powerful/seamless`), the
defense stays unnamed with no leftover proper name, and ports/queues/`T0/A/R/J`/CLRT are used
consistently across all four files. The remaining work is (a) splitting a handful of stacked
long sentences, (b) two structural fidelity gaps against the DefRec 8-step intro arc, (c) one
mislabeled security goal, (d) one unsubstantiated "at line rate" claim, and (e) minor monotony
in the Related Work contrast lines.

---

## Edit table

| file:line | issue | suggested fix |
|---|---|---|
| `sec_introduction.tex:36` | **Unsubstantiated success claim** — "in the network, at line rate" states a throughput property the paper never measures; the profile bans "at line rate" as an unsubstantiated slogan (it is fine only when attributed to Ditto, as at `sec_relatedwork.tex:45`). | Drop "at line rate" here, or replace with what is actually shown — "entirely in the switch data plane" / "with no added application bytes". Do not assert line-rate without a throughput number+bound. |
| `sec_introduction.tex:23-33` (¶3) + `:35` | **Structural divergence from the DefRec 8-step arc** — ¶3 delivers the prior-art *drawbacks* (First/Second/Third/Last) and the gap follows, but the distinct **"why the in-network angle is desirable" (First,… Second,…)** step is missing. DefRec keeps desirability and drawbacks as two separate First/Second lists (extract L13-23 desirability, L34-43 drawbacks). | Add one short desirability paragraph before ¶3 or fold a two-clause "Normalizing in the network is desirable because *First*, it needs no endpoint change; *Second*, it preempts fingerprinting before an attack executes." Keep the existing drawbacks list as the separate step. |
| `sec_introduction.tex:18-21` | **Stacked-"and" sentence (~55 words), two ideas fused** — the SEL-751 timing reading is joined by `;` + `and` to a separate encrypted-session claim (`sirinam2018`), which reads as a bolted-on non-sequitur. | Split: end the device reading at "…separable by timing alone." Start a new sentence for the encrypted-session point ("Prior traffic-analysis work shows such size-and-timing side channels recover content even on encrypted sessions [sirinam2018].") |
| `sec_introduction.tex:38-43` | **Long two-clause mechanism sentence (~65 words)** joined by `;` — holds/releases *and* replicates/carves in one breath. | Split at the semicolon into two sentences: one for the timing hold→fixed-CLRT, one for the replicate-and-carve→byte-preserving reassembly. |
| `sec_introduction.tex:50-58` (¶6) | **Intro paragraph carries implementation depth that duplicates `sec_implementation.tex:117-123`** — strict-priority queue ladder, reservoir starvation, two scheduling domains belong in Implementation §4.8; the intro needs only the conceptual claim. | Compress to the conceptual point (control-command mode hides operation timing by anchoring ACK/echo to arrival; the two mechanisms need independent scheduling domains) and move the starvation mechanics to §4.8. |
| `sec_introduction.tex:62-67` | **Very long results sentence (~90 words, four `;`-chained clauses)** — at the extreme end even for Lin's enumerative style. | Optional but recommended: break into two sentences (CLRT+segment-vector reconstruction results, then control-gap+classifier results), or convert to a short in-line list. |
| `sec_introduction.tex:87-90` | **First-ness claim buried inside the control-command bullet** — "To the best of our knowledge, this is the first…" describes the whole system but sits in bullet 3. | Move the "first…" sentence to lead the contributions list or make it its own summative line, so the novelty claim covers the whole defense, not just the control-command mode. |
| `sec_relatedwork.tex:4-7` | **Stacked-"and" sentence fusing two works** — Formby and GTID joined by `and` in one ~40-word sentence. | Split into two sentences (one per citation) so each work gets its own predicate. |
| `sec_relatedwork.tex:9,18,27,37,48` | **Monotony in the closing contrast lines** — four of five groups open the contrast with the identical "The defense differs in …;". Profile wants a crisp contrast per group (present ✓) but RAINCOAT varies its phrasing. | Vary two of the five (e.g., "Unlike these approaches, the defense …" / "Our mechanism instead …") while keeping the contrast content. |
| `sec_relatedwork.tex:9` | **Choppy/redundant sentence** — "It is an attacker capability rather than a defense." restates the prior sentence's point in a short fragment. | Fold into the preceding sentence ("…identify an outstation — an attacker capability, not a defense.") |
| `sec_threatmodel.tex:58-59` | **G5 is mislabeled as a security goal** — "testbed preservation" (native/defended differ only by a runtime mode) is an evaluation-validity control, not a security property, yet it sits in the "Security goals" G1–G6 list. | Move G5 out of the Security-goals list into the evaluation methodology, or relabel the list "Goals and evaluation properties." Keep G1–G4 (security) and G6 (safety) as the testable security goals. |
| `sec_threatmodel.tex:19-21` | **Long `as…so…that` chain (~40 words)** in the unencrypted-traffic assumption. | Minor: split after "…substation and utility networks." into a second sentence for the foothold consequence. |
| `sec_implementation.tex:11-12` | **Grammar/wording** — "The program places in one ingress pipe within the twelve-stage budget" (missing reflexive/verb). | "The program fits in one ingress pipe within the twelve-stage match-action budget." (matches `:150`). |
| `sec_implementation.tex:85-87` | **Long sentence (~50 words)** — byte-28 design-choice clause runs `;` + `so…and` fusing "design choice not requirement" with "reassembled response remains 49 bytes". | Split at the semicolon; keep "Byte 28 is a selected existing DNP3 CRC-block boundary…" separate from the TCP-segmentation-is-a-design-choice point. |
| `sec_implementation.tex:72,101` | **Mechanism heads skip the problem they close** — §4.6 opens "Response shaping normalizes…" and §4.7 opens "The control-command hold governs the one control command", neither restating the leak (segment-shape/CLRT fingerprint; SBO operation-timing fingerprint) per the profile's problem→state→…→evidence order. | Add one problem sentence at each head naming the fingerprint being suppressed, then proceed to state/decision/effect. (Low priority — threat model already establishes both.) |
| `sec_implementation.tex:154` | **Only one `Repeatability.` run-in** — Testbed template attaches it per reproducibility-sensitive part; here it appears once at the very end. | Optional: add a short `Repeatability.` note to the response-shaping (§4.6) and control-plane (§4.9) parts, or leave as-is if length is a concern (single note is acceptable). |
| `sec_introduction.tex:23` | **Transition slightly off allow-list** — the drawbacks list runs First/Second/**Third**/Last (four items); the Lin allow-list and DefRec use First/Second/Last (three). | Minor: fold to three items (First/Second/Last) or accept; "Third" is not banned, only off-model. |

---

## Checklist verdicts (per prompt)

- **Adjective/qualifier-led paragraph openings:** none found — clean across all four files.
- **Banned discourse markers (Importantly/Notably/Interestingly/Crucially/Fundamentally):** none (grep-confirmed).
- **Unquantified success claims:** intro is well quantified (1.3/2.1/4.001 ms, σ0.02, 1,280, 0.59→0.50); the one exception is the unsubstantiated "at line rate" (`intro:36`).
- **Paragraph restates heading / lacks one function:** subsections add function, not restatement; the two issues are the mislabeled G5 and the intro ¶6 duplication of §4.8.
- **Sentence-length outliers:** 5 clear splits (`intro:18-21`, `intro:38-43`, `relwork:4-7`, `impl:85-87`, plus optional `intro:62-67`); 2 borderline (`threat:19-21`, `impl:106-108`).
- **Transitions vs. Lin allow-list:** compliant; only "Third" (`intro:23`) is off-model.
- **Related Work contrast sentences:** all five groups close with a contrast (none missing); only monotony of "The defense differs in…" to vary.
- **Threat Model — testable properties + explicit non-goals:** goals stated as testable master-facing properties ✓; non-goals given their own subsection with five explicit carve-outs ✓; only defect is G5 being a methodology property inside the security-goal list.
- **Implementation — mechanism sequence + honest pros/cons/negatives:** honest throughout (relay-facing unobserved `:115`/`:66`, mutant-kill evidence `:61`, shared-tag negative `:70`, fail-open `:134`, bounded limitations `:149-156`); rejected-alternative cons are qualitative (correctness, not perf) which is acceptable; only gap is the missing problem sentence at the §4.6/§4.7 heads.
- **Terminology consistency:** defense unnamed everywhere; no leftover proper name; `dp8/dp10/dp9/dp64/dp68`, `qid7–qid4`/`qid3,qid2`, `T0/A/R/J`, CLRT=R−A used identically across figure captions and body; "response shaping" and "the control-command hold/mode" carry no acronyms. Clean.

---

## Top 10 most impactful (ranked)

1. `intro:36` — remove the unsubstantiated **"at line rate"** claim (profile-banned, unmeasured).
2. `intro:23-33/:35` — add the missing **desirability step** to restore the DefRec 8-step arc.
3. `threat:58-59` — move/relabel **G5**; it is not a security goal and weakens the goals list.
4. `intro:50-58` — trim intro **¶6** implementation depth that duplicates §4.8.
5. `intro:18-21` — split the fused **device-timing + encrypted-session** sentence.
6. `intro:38-43` — split the **65-word mechanism** sentence at the semicolon.
7. `impl:11-12` — fix "**The program places in**" → "fits in".
8. `relwork:9,18,27,37,48` — vary the repeated "**The defense differs in…**" contrast openings.
9. `impl:85-87` — split the long **byte-28 design-choice** sentence.
10. `intro:87-90` — surface the **"first…" novelty claim** out of the control-command bullet.
