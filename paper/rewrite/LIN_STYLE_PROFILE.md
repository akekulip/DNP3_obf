# Dr. Hui Lin — Structure + Style Profile, and Divergence Map of the Current Draft

Read-only assessment. Groundwork for aligning `dnp3_obfuscation_paper_readerfirst.tex` to the
advisor's writing. No manuscript file was edited.

**Sources characterized (style model):** DefRec (NDSS 2020, Lin et al.), RAINCOAT (IEEE TSG
2018, Lin et al.), the Cyber-Physical Testbed paper (Lin et al.) — the three Hui-Lin-group
papers. Formby "Who's in Control" (NDSS 2016) and Ditto (NDSS 2022) are venue/topic
comparators only, not the voice model.

**Method:** direct reading of the corpus text dumps in
`~/.claude/skills/paper-voice/corpus/` (same PDFs as `paper/target/`), the paper-voice mining
notes, and a `voice_check.py` run + targeted greps on the current draft. Every quoted phrase
below is verbatim from a Lin paper.

---

## PART A — The Dr. Lin structure + style profile

### A1. Section anatomy and order (measured from DefRec and RAINCOAT)

**DefRec (NDSS conference):**
I. Introduction (incl. `A. Contributions`) → II. Design Objectives (background w/ formal
Definitions + **threat model and named objectives RO1–RO3**) → III. Design Overview →
IV–V. the two mechanism sections → VI. Implementation → VII. Evaluation → VIII. Related Work →
IX. Conclusion → Appendices.

**RAINCOAT (IEEE Transactions):**
I. Introduction → **II. Background & Threat Model** → III. Raincoat Approach → IV. mechanism
(craft decoy measurements) → V. Evaluation → VI. Discussion → VII. Related Work →
VIII. Conclusions.

Load-bearing invariants shared by both:
1. **Threat model comes EARLY** — inside/adjacent to Background, *before* the design/approach
   section, so the design can reference it. DefRec: threat model is §II-B, before the §III
   design overview. RAINCOAT: §II, before the §III approach.
2. **Named objectives are declared once, then used as labels everywhere after.** DefRec
   declares RO1–RO3 in §II and organizes the *entire* evaluation 1:1 against them
   (`Effectiveness in RO1.`, `Effectiveness in RO2.`). The objective labels are the spine.
3. **A distinct conceptual Design/Approach section sits between Background and Implementation**
   (DefRec §III "Design Overview"; RAINCOAT §III "Approach"). Implementation is a *separate,
   shorter, concrete* section.
4. **Related Work is late** (second-to-last), immediately before the Conclusion, in both.
5. **Conclusion is a compressed restatement** of mechanism + the same headline numbers from
   the abstract + exactly one future-work sentence.

### A2. Introduction pattern

Both papers build the intro as an **incident-led reconnaissance-to-defense arc**, and the
*first sentence is a plain declarative problem statement*, not an aphorism:

- DefRec ¶1: *"Reconnaissance is crucial to an adversary's preparation for an attack on
  industrial control systems like smart power grids (ICS) [77]."*
- RAINCOAT ¶1: *"CYBER-attacks on SCADA ... systems used by industrial control systems
  (ICSes), e.g., power grids, can cause severe damage. In December 2015, remote intruders
  penetrated a Ukrainian power grid and caused a blackout that affected 225,000 residents [1]."*

Paragraph progression (RAINCOAT is the cleanest template):
1. Impact statement (one sentence) → 2. Real incident with citation and a quoted line from the
incident analysis (*"the strongest capability of the attackers is their capability to perform
long-term reconnaissance ..."*) → 3. a **staged attack model** (penetration → preparation →
execution) keyed to Figure 1 → 4. prior work, *merit granted first then faulted*: *"These
approaches are effective against specific malicious activities. However, ..."* → 5. the pivot,
verbatim shape *"Instead of focusing on the execution stage, we detect attacks in their
'preparation' stage."* → 6. benefits enumerated *"two major benefits ... First, ... Second,
..."* → 7. *"To obfuscate attackers' knowledge, we propose Raincoat, a technique that ..."* →
8. an MTD contrast paragraph → 9. `Specifically, Raincoat makes the following contributions:`

**Contribution list phrasing (the signature to match):**
- Items open with a **bold verb-first headline ending in a period**, then 2–4 sentences.
  RAINCOAT: *"1) Disrupts attacks at the preparation stage. ..."*, *"2) Mitigates damage by
  misleading attackers. ..."*, *"3) Has little overhead on control networks. ..."*. DefRec's
  capability bullets are gerund-led: *"Increasing reconnaissance efforts."*, *"Regaining
  computational advantages for defense mechanisms."*
- **A first-ness claim is mandatory**, in the exact frame *"To the best of our knowledge, this
  is the first work to ..."* (DefRec uses it twice; RAINCOAT once, folded into contribution 1).
- DefRec follows the capability bullets with a **second, separate bullet list previewing the
  quantitative results** (the (i)/(ii)/(iii) testbed list, then "Our experimental results show
  that ...").

### A3. Argument and evidence style

- **Claim → mechanism → consequence → rationale, every time.** Mechanism sentences are
  followed by `Consequently, ...`; design choices are justified with a *fronted* `Because ...,`
  clause: *"Because a substation tends to deploy devices from the same vendors ..., we expect
  to profile a small number of models."*
- **Results carry a figure pointer, then a mechanistic explanation, then a scoped takeaway.**
  *"As shown in Figure 16, we observed a negligible impact on the RTT ..., variations are
  within ±3% ..."*; explanations open *"This is because ..."* / *"The reason is that ..."*.
- **Quantify instead of praise** — effects always carry a number and a bound (*"by at least
  three orders of magnitude"*, *"delay passive attacks for 100 years"*, *"less than 3%"*).
- **Limitations are volunteered inline and immediately deferred:** *"cannot perfectly follow
  every aspect ... without formal coverage analysis (which we leave to future work)."*
- **Hedging is done through the modal "can" and pragmatic grading**, not epistemic adverbs:
  *"challenging, if not impossible"*, *"computationally expensive, if not impossible"*.
  Boosters are near-zero; `significantly` appears only with a measured number attached.

### A4. Sentence-level voice

- Mean ~23 words/sentence, FK grade ~16, Flesch reading ease ~15–29 (dense but from long noun
  phrases and subordination, *not* rare words). Rhythm: mostly medium (12–27 w) sentences with
  one long chained sentence per paragraph and an occasional blunt short verdict
  (*"Disrupting reconnaissance is challenging."*).
- **Heavily agentive first-person plural** (~29% of sentences contain "we"), alternating with
  the system as agent (*"Raincoat spoofs measurements"* ↔ *"we spoof the measurements"*).
- **Connective spine:** `Consequently,` is the causal glue (~1/paragraph); `However,` for
  pivots; `For example,` + inline `e.g.,`/`i.e.,` at very high density to instantiate every
  general claim; `Based on X, we ...`; `First, ... Second, ... Last,` (DefRec says "Last," not
  "Finally,"). **Absent:** `Moreover`, `Notably`, sentence-initial `Thus`; `Furthermore` at
  most once.
- **Signature long-sentence tic:** main clause + trailing present-participial result clause —
  *"..., significantly increasing the time for adversaries to stealthily identify real
  devices"*, *"..., making it info-theoretically challenging for an adversary to ..."*.
- **Terms are introduced by description first, then named** with `i.e.,` (*"a subset of
  randomly selected devices, i.e., online devices"*), and the noun phrase is then repeated
  verbatim with zero elegant variation (`virtual nodes`, `decoy data`, `real devices`).
- **Figure/table referencing:** locative-first *"In Figure N, we show/present ..."* or
  evidential *"As shown in Figure N, ..."*, always followed by a reading; never a bare ref.

### A5. Structural signatures (recurring moves)

- **Bold run-in paragraph headers ending in a period** structure design/impl/eval subsections
  (`DefRec's Objective.`, `Packet Hooking.`, `Security Argument.`, `Repeatability.`), and
  parallel subsections recycle the same header template verbatim. Occasional **question-form
  headers** (*"Is it Possible for FDIAs to Bypass DefRec (False Negative)?"*).
- **Named-label anchors** (RO1–RO3; passive/proactive/active; Scenario 1/2/3) declared once and
  reused as shorthand for the rest of the paper.
- **Threat-model moves:** `Assumptions on Adversaries' Capability. We assume that ...`, a typed
  attacker taxonomy, an explicit TCB statement, and **preemptive out-of-scope carve-outs** each
  with a bold run-in and a future-work deferral (*"For Attacks on Data Privacy. ... We leave ...
  to future work."*). Each retained assumption is defended: *"We argue that this is a
  reasonable assumption, as ..."* (criterion word: *practical*).
- **Implementation cadence:** *"To evaluate ..., we implemented ..."* → name the N major parts
  → one subsection per part with concrete facts (LOC counts, exact hardware `SEL 751A relay`,
  `HP ProCurve 3500yl`, library/version names) → honest pros/cons and negatives kept in.
- **Related Work:** themed bold-headed paragraphs, each closing with an objective/mechanism-cost
  contrast, never a dominance claim: *"This approach can significantly increase the amount of
  network traffic by at least 50%. DefRec, on the other hand, relies on a small amount of decoy
  data ..."*; *"PFV is not a honeypot for ICSs: ..."*.

---

## PART B — What paper-voice already captures vs. what is missing

The `paper-voice` skill (`~/.claude/skills/paper-voice/`) was mined from **exactly this
corpus** (all five papers, Lin group + Formby/Ditto). It already captures, well and
quantitatively, most of the *sentence- and lexicon-level* profile — do not re-derive these:

**Already captured (rely on it, don't rebuild):**
- The full **Voice Card**: connective spine (`Consequently,`/`However,`/`For example,`,
  no `Moreover`), purpose-fronted `To <goal>, we ...` sentences, participial result-clause tic,
  the `can`-modal hedging, near-zero boosters, banned-word list, verbatim-repetition of terms.
- The **quantitative fingerprint** (`style-fingerprint.md` + `corpus_profile.json`): 22.8
  w/sentence, 13/58/25/4 short/med/long/verylong split, hedges 14.4/1k, boosters 1.1/1k,
  citations 7.1/1k, "we" in 29% of sentences, opener-class distribution — and a runnable
  `voice_check.py` that scores any draft against it (used in Part C).
- **Section blueprints** (`section-blueprints.md`) and **per-paper mining notes**
  (`paper-notes/defrec-ndss.md`, `raincoat-tsg.md`) covering the abstract/intro/threat/design/
  impl/eval/related/conclusion anatomy, incident-led motivation, RO-label anchoring, bold
  run-in headers, and the "grant merit then contrast" related-work move.
- The critical caveat that a STYLE PASS is **not** evidence of readability or detector-safety.

**Missing / thin in paper-voice (this document adds):**
- A **side-by-side section-ORDER contract** (threat-model-early, separate Design section,
  RO-labels threaded into Evaluation) as a checklist — the skill describes each section but
  does not flag the *ordering* dependency the current draft breaks.
- The **contribution-headline grammar** (verb-first `Disrupts.../Mitigates.../Has little
  overhead.` vs. noun-phrase) as an explicit rule; the skill notes bold bullets but not the
  verb-first form.
- A concrete **divergence map against this specific draft** (Part C) — the skill has the model
  but was never run as a gap analysis on `dnp3_obfuscation_paper_readerfirst.tex`.

Also note the sibling `paper/rewrite/STYLE_PROFILE.md` already contains a strong Lin-priority
matrix and argument-order templates; it is consistent with this document and with paper-voice.
The gap it does not close is, again, applying the profile *back onto the live draft*.

---

## PART C — Divergence map of the current draft (ranked)

Draft: `paper/dnp3_obfuscation_paper_readerfirst.tex`. `voice_check.py` result:
**11 deviations** (234 sentences, 5769 words). Highlights: `pct_medium` LOW, `pct_verylong`
HIGH, `sentence_len_stdev`/`cv`/`burstiness`/`rhythm_jaggedness` all HIGH,
`flesch_reading_ease` HIGH (33.3 vs corpus max 29.5), `hedges` LOW (5.2 vs 7.7–20.9),
`citations` HIGH (11 vs 5–8). Grep: `Consequently` 0, `For example` 0, `Based on` 0,
`In addition` 0, `Specifically` 0, `To the best of our knowledge` 0; banned words all 0;
em dashes 0; bold run-ins 27; "we" 43 (≈15/100 sentences, corpus floor).

Ranked by how strongly each reads as "not his structure / not as good as his writing":

**1 — No first-ness claim in the contributions (structure + voice).**
Lin *always* carries `To the best of our knowledge, this is the first ...`; DefRec twice.
The draft's contribution list has none. For an advisor reading, the missing "first" claim is
the most conspicuous absence — it is both a positioning move and a house tic. **Highest-value
fix.**

**2 — Contribution headlines are noun phrases, not verb-first.**
Draft: *"A statement of the DNP3 timing-and-shape leak ..."*, *"An in-network timing
normalization."*, *"A byte-preserving shape normalization."* Lin: *"Disrupts attacks at the
preparation stage."*, *"Mitigates damage ..."*, *"Has little overhead ..."* The noun-phrase
form reads as catalog labels; Lin's verb-first form reads as claims. Direct structural tell.

**3 — The connective spine is essentially absent.**
`Consequently,` = 0 in the whole draft (corpus ~0.8/1k, ~1 per paragraph); `For example,` = 0;
`Based on X, we ...` = 0; inline `e.g.,`/`i.e.,` density far below corpus. The draft carries
causation with bare juxtaposition and semicolons rather than Lin's `Consequently,` +
fronted `Because ...,`. This is the single most pervasive voice divergence and touches every
section.

**4 — Threat model placed AFTER the full design overview; named goals not threaded.**
Draft order: Intro → §II Background **and Design Overview** → §III Threat Model → §IV
Implementation. Lin puts the threat model *before* the design (DefRec §II before §III;
RAINCOAT §II before §III) and declares RO1–RO3 there. The draft *defines* G1–G5 in §III but
then **does not reference them by label** in the Evaluation, which instead uses ad-hoc run-ins
(`Timing (measured).`, `Shape and reconstruction.`). Lin's signature is
`Effectiveness in RO1.`-style label-anchored evaluation. Re-threading G1–G5 through the
evaluation (and moving the threat model earlier, or at least the goals) is a structural
alignment, not cosmetics.

**5 — No distinct conceptual Design/Approach section.**
Lin keeps Design Overview (§III) and Implementation (§VI) as separate blocks. The draft folds
the conceptual design into "Background and Design Overview" and jumps to Implementation. The
content exists, but the two-column-paper shape an advisor expects (Background → **Design** →
Implementation) is collapsed to Background → Implementation.

**6 — Rhythm is too jagged; the abstract over-runs.**
`burstiness`/`stdev`/`cv`/`rhythm_jaggedness` all HIGH, `pct_verylong` HIGH, `pct_medium` LOW:
the draft swings between very short punchy sentences and 45+-word run-ons, with too few of
Lin's steady 12–27-word sentences. The **abstract is one ~110-word semicolon-chained
sentence**; Lin's abstracts are separate sentences (problem → limitation → proposal → venue →
numbers). Splitting the abstract and adding medium-length connective sentences moves this.

**7 — Opening sentence is an aphorism, not Lin's plain problem statement.**
Draft ¶1: *"The grid runs on old protocols, and an attacker learns them before it breaks it."*
This is the plain-storyline register, more readable but not Lin's. Lin opens with a flat
declarative (*"Reconnaissance is crucial to an adversary's preparation ..."* /
*"...can cause severe damage."*). Reads as a different, more journalistic voice on line one —
where an advisor first calibrates "is this ours?".

**8 — Under-hedged and under-agentive relative to Lin.**
`hedges` LOW (5.2 vs 7.7–20.9) and "we" at the corpus floor (~15/100 vs mean 29). The draft
often uses the observer/system as agent (*"An observer does not need to read the payload"*)
where Lin would write *"we"* and hedge capability with *"can"*. Milder, but it accumulates.

**9 — Prior-work enumeration uses semicolon lists, not `First, ... Second, ... Last,`.**
Draft intro lists obfuscation defenses as a semicolon run (*"Padding hides ...; morphing
transforms ...; adaptive padding inserts ...; and constant-rate ... force ..."*). Lin
enumerates drawbacks/benefits as `First, ... Second, ... Last,`. Easy, localized fix.

**10 — Assumptions are stated but not defended in Lin's frame.**
The draft lists deployment assumptions (no TCP timestamp, eligible class) and backs the
timestamp one with a preflight check, but never uses `We argue that this is a reasonable
assumption, as <practical argument>`. The defense-of-assumption move and the criterion word
*practical* are missing.

**Strong matches already in place (do not disturb):** Related Work is late and themed with
bold run-ins each closing on an objective/mechanism contrast (RAINCOAT-faithful); bold run-in
headers are used heavily (27) in Implementation/Evaluation; the Conclusion recaps mechanism +
headline numbers + one future-work sentence; every result carries measured/modeled/unobserved
status; banned AI vocabulary and em dashes are absent (0). The draft is clean at the lexical
layer — the divergences are almost all at the **structure / connective-spine / contribution-
grammar** layer, not word choice.
