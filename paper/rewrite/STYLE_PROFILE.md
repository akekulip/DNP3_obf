# Target-Style Profile for the NDSS Rewrite

Derived from close reading of the extracted target papers. Priority order for
prose modeling: the three **Hui Lin** papers (DefRec, Testbed, RAINCOAT). Formby is used
**only** for technical terminology and threat accuracy; Ditto only as a programmable-switch
traffic-shaping related-work reference. Short quoted phrases below are illustrative of a
pattern — never full sentences to lift.

Source files (in `target_extract/`):
- `10139606.txt` = **DefRec** (Lin et al., NDSS 2020) — primary style model for Introduction, threat framing, contribution structure, claim discipline.
- `10336809.txt` = **Testbed** (Lin et al., LASER/NDSS 2020) — primary for implementation explanation, testbed description, tradeoffs, limitations.
- `raincoat.txt` = **RAINCOAT** (Lin et al., IEEE TSG 2018) — primary for threat progression, defense motivation, assumptions, mechanism-to-goal reasoning.
- `who-control-...txt` = **Formby** et al. (NDSS 2016) — terminology/threat accuracy only.
- `ditto.txt` = **Ditto** (Meier et al., NDSS 2022) — related-work / switch-shaping reference only.

---

## 1. Target-Style Matrix (one row per paper)

| Dimension | **DefRec** (10139606) | **Testbed** (10336809) | **RAINCOAT** (raincoat) | **Formby + Ditto** (reference only) |
|---|---|---|---|---|
| **Introduction argument order** | (1) problem centrality — *"Reconnaissance is crucial to an adversary's preparation…"*; (2) real-incident anchor — Ukraine blackout, *"225,000 residents"*, with a direct quoted line from a security analysis; (3) why the preemptive angle is desirable (*First,… Second,…*); (4) research gap — *"there exists a big research gap"*; (5) drawbacks of prior art (*First,… Second,… Last,…*); (6) proposed concept (PFV→DefRec); (7) enumerated benefit bullets; (8) explicit *"main contributions of the paper are:"* list. | Structured abstract (Background/Aim/Method/Result/Discussion). Intro re-uses the DefRec problem framing, then pivots to a **requirements list** the artifact must satisfy (*Close to Realistic Environments / Reasonable Scalability / Integration of both cyber and physical…*), then a contributions list scoped to the testbed. | (1) impact — *"CYBER-attacks on SCADA … can cause severe damage"*; (2) incident (Ukraine, Dec 2015); (3) a **three-stage attack model** (penetration→preparation→execution) tied to Figure 1; (4) prior work targets the execution stage + its two drawbacks; (5) the pivot — *"Instead of focusing on the execution stage, we detect attacks in their 'preparation' stage"*; (6) *First,/Second,* benefits; (7) *"we propose Raincoat"*; (8) contrast vs MTD; (9) numbered contributions. | Formby: problem → infeasibility of crypto/patching on legacy ICS → gap in existing fingerprinting → *"This paper presents…"* → bulleted contributions. Ditto: problem (WAN traffic analysis) → encryption-not-enough → prior techniques and why unsuited → *"This paper presents ditto…"* → contributions. Same skeleton; **do not** copy their prose voice. |
| **Paragraph purpose & typical length** | One idea per paragraph, ~6–12 lines. Many paragraphs open with a **bold run-in label** (*"PFV's Role."*, *"DefRec's Objective."*). Motivation paragraphs are longer; mechanism paragraphs shorter. | Component-descriptive paragraphs, ~8–14 lines, most ending with a **"Repeatability."** run-in that states how others can reproduce that piece. Explicitly pairs pros then cons in the same or adjacent paragraph. | Motivation paragraphs longer; assumption/mechanism paragraphs are itemized. Related-work paragraphs are one-category-each, each closing with a *"Raincoat differs…"* sentence. | Formby/Ditto paragraphs are longer and more discursive; not a length model to follow. |
| **Sentence length / clause structure** | Moderate, ~20–35 words, 1–2 clauses. Heavy use of *"such that"*, *"based on which"*, *"e.g.,"*, *"i.e.,"*. Purpose clauses ride on the main clause rather than starting new sentences. | Same register; slightly more enumerative (*"three implementation options"*, *"four implementation aspects"*). Trade-off sentences use *"However, major disadvantages stem from…"*. | Same register; a bit more formal (journal). Frequent *"we argue that this is a reasonable assumption as…"*. | Formby/Ditto run longer and more compound; not the target rhythm. |
| **Preferred transition patterns** | *First, / Second, / Last,*; *However,*; *Consequently,*; *In addition,*; *Specifically,*; *For example,*; *Compared to …,*; *Based on …,*; *Even though …*. | Same set, plus explicit contrast framing *"Each category has its own pros and cons"*, *"The major advantage… However,…"*, *"Instead of …,"*. | Same set, plus *"Meanwhile,"*, *"Instead of focusing on …, we…"*, *"To be stealthy (i.e., …),"*. | Ditto uses *"However,"*, *"As a result,"*, *"More generally,"*; acceptable but generic. |
| **How limitations are introduced** | Inline, mid-flow, immediately hedged and deferred: *"cannot perfectly follow every aspect … without formal coverage analysis (which we leave to future work). However, …"*. Scope exclusions get a bold run-in (*"For Attacks Requiring Little or No Reconnaissance. DefRec does not focus on…"*). | Dedicated **Discussion** admits the gap plainly: *"the testbed still lacks dynamic coupling … We will leave such implementation in future development."* Frames alternatives as *"both negative and positive experiences for future research."* | Threat-model scoping ("we assume attackers do not have physical access…") plus a conclusion future-work paragraph. Assumptions are defended, not hidden. | Not a model. |
| **How contributions are stated** | Explicit list after *"The main contributions of the paper are:"*; novelty via *"To the best of our knowledge, this is the first work to…"*; separate **quantified** results bullets (*"delaying adversaries for at least 100 years…"*, *"less than 3% overhead"*). | Contribution bullets scoped to the artifact (*Network Communication / Power Grid Simulation / SDN Implementation*), each = what was explored + what was compared. | Numbered list *"Raincoat makes the following contributions: 1) Disrupts attacks at the preparation stage. To the best of our knowledge, Raincoat is the first technique to…"*. Each item = capability + first-ness or quantified effect. | Formby: bulleted "Two novel … approaches / A new class …". Ditto: "Our main contributions are:". Structure OK; avoid their adjective load ("novel"). |
| **How figures are introduced / interpreted** | *"In Figure X, we show/present …"* then an interpretive sentence *"We can see that…"* / *"We observed negligible differences, with less than 0.1%."* Figure captions carry setup detail (delay distribution, CIs). Never a bare figure reference without a reading. | Same *"In Figure X, we present …"*; results labeled *"primitive"* and explicitly walked through option-by-option. Tables introduced with what the columns mean (*"we include the number of nodes … in parentheses"*). | Same *"In Figure X, we show …"*; step figures narrated with *"Step ⑥: We use the edge switch…"*. Equations introduced then explained clause-by-clause. | Ditto: *"Fig. 1: ditto adds padding and chaff packets such that…"* — caption states the mechanism. Same discipline, good to mirror. |
| **How threat models & assumptions are ordered** | *"Assumptions on Adversaries' Capability. We assume that…"* → classify capability into **three types** (Passive / Proactive / Active) → *"DefRec's Objective."* → numbered objectives **RO1/RO2/RO3** → TCB definition → out-of-scope carve-outs. | Inherits DefRec's threat model near-verbatim (background section), lighter touch. | *"we consider the remote insider threat model. We assume that…"* → per-zone assumptions (*In control networks… In substations… In the control center…*) → each defended with *"We argue that this is a reasonable assumption…"* → then attacker goal (FDIA vs CRA) with a targets table. | Formby: adversary framed by capability (active vs passive fingerprinting; *"prior access"* vs none). Use for **accuracy** of attacker terms, not ordering. |
| **Implementation: architecture → components → workflow** | *"To evaluate …, we implemented …"* → subsections *Communication Networks / Implementation of PFV & DefRec / Physical Devices* → concrete facts (LOC counts *"~1,500 LOC"*, exact hardware *"four Intel Xeon 2.8 GHz … 16 GB RAM"*, library names). Workflow traced through the figure (network-flow letters ⓒ–ⓕ). | Strongest model: *"the testbed includes four major parts…"* → one subsection per part → each ends *"Repeatability."*. Pros/cons of each option enumerated (emulation vs cloud vs hardware switches) with concrete cost/scale numbers. Data-collection method spelled out (*"500 times with and without … Tcpdump … Zeek"*). | *"High-level procedure."* run-in → k-round algorithm → numbered Steps → parameter definitions (T, k, p). Mechanism is walked as a procedure, then formalized. | Ditto: mechanism = three operations (padding / chaff / …) at line rate on programmable switches — cite as the switch-shaping comparator. |
| **Citation density & placement** | Dense in Intro & Related Work (clustered brackets *"[37], [38]"* at clause/sentence end), sparse in Method/Eval. Numeric IEEE/NDSS style. Named-author attributions rare, mostly in related work. | Similar; many tool/dataset citations inline (ONOS [8], Mininet [37], MATPOWER [59], TopologyZoo [30]). | Dense; journal numeric style *[1][3][9][10]*; incident and prior-defense citations clustered. | Formby/Ditto similar numeric style; fine for accuracy checks. |
| **Words / constructions to avoid** | No adjective-led hype openings; no *"Importantly/Notably/Interestingly"*; sparing on *"novel/powerful/seamless"*. Prefers **quantified** claims (*"less than 0.5% false negatives"*) over qualitative praise. Hedges with *can/may/usually*. | Avoid overstating the testbed — it deliberately reports negatives. Don't call primitive results "final". | Avoid unbounded superlatives; defend each assumption instead of asserting it. | Formby/Ditto lean harder on *"novel"/"uniquely well"/"line rate"* marketing — **do not** import that register. |

---

## 2. Unified Style Profile (derived, Lin-priority)

### Voice, sentence, and paragraph rules
- **First-person plural, active voice** throughout: *"we propose"*, *"we implemented"*, *"we can see that"*. No passive-agentless constructions where an actor exists.
- **One idea per paragraph.** Open motivation/design paragraphs with a **bold run-in label** ending in a period (*"DefRec's Objective."*, *"Repeatability."*, *"High-level procedure."*), then elaborate.
- **Sentence length 20–35 words**, at most two clauses. Attach purpose with *"such that"*, *"based on which"*, *"so that"* rather than starting a new sentence. Use *"e.g.,"* and *"i.e.,"* for inline examples and restatements.
- **Quantify instead of praise.** Every effectiveness/overhead claim carries a number and a bound (*"less than 3% overhead"*, *"at least three orders of magnitude"*). Replace adjectives with measurements.
- **Hedge honestly.** Use *can / may / usually* for capabilities not universally guaranteed; state the limiting condition and defer it (*"…which we leave to future work"*).
- **Novelty via** *"To the best of our knowledge, this is the first … to …"* — used at most once or twice, always tied to a concrete capability.

### Transition vocabulary the Lin papers actually use (allow-list)
`First, / Second, / Last,` · `However,` · `Consequently,` · `In addition,` · `Specifically,` · `For example,` · `Based on …,` · `Compared to …,` · `Even though …` · `Instead of …, we …` · `Meanwhile,` · `To be … (i.e., …),`

### Argument-order templates

**Introduction (follow DefRec/RAINCOAT):**
1. State the problem's centrality in one sentence (what the adversary needs / what the leak is).
2. Anchor with a concrete real-world referent (incident, standard, or measured device behavior) — one direct quote or one hard number is enough.
3. Explain why the chosen defense angle is desirable — *First,… Second,…* (coverage, earliness, low disruption).
4. Name the research gap in one sentence.
5. Enumerate prior-art drawbacks — *First,… Second,… Last,…* — each a distinct failure mode, each cited.
6. Introduce the mechanism by name and its one-line operating principle.
7. Bulleted benefits (qualitative capability + quantified effect).
8. Explicit *"The main contributions of this paper are:"* list, with a first-ness claim and quantified evaluation bullets.

**Related Work (follow RAINCOAT):** group by category with a run-in label per group (e.g., *"Honeypots for ICS."*, *"Traffic obfuscation on programmable switches."*); summarize each line of work in 2–4 sentences; **close every group with one contrast sentence** stating how our work differs in objective or mechanism. Cite Ditto here as the line-rate switch-shaping comparator; cite Formby as the fingerprinting threat we defeat.

**Threat Model (follow DefRec then RAINCOAT):**
1. *"Assumptions on the adversary's capability. We assume that…"* — what they can and cannot do.
2. Classify capability into named types (e.g., passive / active observation) with a one-line definition each.
3. State the defender/system objective, then break it into **numbered objectives (O1/O2/…)**.
4. Define the trusted computing base explicitly.
5. Carve out what is **out of scope** with a bold run-in, and defend each retained assumption (*"We argue that this is a reasonable assumption as…"*). Use Formby's terms precisely (active vs passive fingerprinting, cross-layer response-time / physical-operation-time fingerprints, data-acquisition vs control functions, SCADA protocols DNP3/Modbus/IEC 61850).

**Implementation (follow Testbed then DefRec):**
1. One sentence stating what was built and why (*"To evaluate …, we implemented …"*).
2. Name the **major parts** up front (*"the system includes N major parts…"*).
3. One subsection per part; give concrete facts — LOC, exact hardware/library/versions, dataset names, measurement counts.
4. Where a design choice had alternatives, present **pros then cons** with numbers; say which was chosen and why.
5. Trace the runtime workflow through the architecture figure (label the flows/steps).
6. Close reproducibility-sensitive parts with a *"Repeatability."* note; report negative/abandoned options honestly.

### Concrete "avoid" list
- **No adjective-led openings** ("Powerful new…", "Remarkably,…"). Lead with the subject and the claim.
- **Banned discourse markers:** *Importantly, Notably, Interestingly, Crucially, Fundamentally.* State the fact; let it be important on its own.
- **Promotional terms to cut:** *novel, powerful, seamless(ly), cutting-edge, state-of-the-art (as self-praise), robustly, significantly (unless followed by a number).*
- **No bare figure references** — every *"Figure X"* is followed by a reading of what it shows.
- **No unquantified success claims** — pair each with a number and a bound.
- **Do not import the Formby/Ditto marketing register** ("uniquely well", "at line rate" as a slogan). Borrow their terminology and mechanism facts, not their voice.

---

## 3. How each Lin paper should drive each of our four sections

| Our section | Primary Lin driver | What to borrow specifically |
|---|---|---|
| **Introduction** | **DefRec**, with **RAINCOAT** for the attack-stage framing | DefRec's 8-step order (centrality → incident anchor → *First/Second* desirability → gap → *First/Second/Last* prior-art drawbacks → mechanism → benefit bullets → contributions). Use RAINCOAT's *"Instead of focusing on X, we do Y at stage Z"* pivot to position size/segmentation obfuscation against fingerprinting reconnaissance. Novelty via a single *"To the best of our knowledge…"*. |
| **Related Work** | **RAINCOAT** | Category-per-group structure, each group closed by a one-line *"our work differs in objective/mechanism"* contrast. Slot Ditto under programmable-switch traffic shaping (padding/chaff at line rate, end-host-free) and contrast our byte-preserving, DNP3-boundary approach; slot Formby under device fingerprinting as the threat we suppress. |
| **Threat Model** | **DefRec** (ordering) + **RAINCOAT** (assumption defense) + **Formby** (terminology) | DefRec's *"Assumptions on the adversary's capability… We assume…"* opener, capability typing, numbered objectives, explicit TCB, and out-of-scope carve-outs. RAINCOAT's per-zone assumption listing each defended as *"a reasonable assumption as…"*. Formby's exact fingerprinting vocabulary and the passive-observer model so the threat is technically accurate. |
| **Implementation** | **Testbed** (structure) + **DefRec** (concrete facts) | Testbed's "N major parts → subsection each → *Repeatability.* → honest pros/cons with numbers → report negatives" template. DefRec's habit of citing exact LOC, hardware, libraries, versions, dataset names, and measurement repetition counts, and tracing the workflow through the architecture figure with labeled flows. |
