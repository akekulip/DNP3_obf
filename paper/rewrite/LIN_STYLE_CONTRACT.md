# Dr. Lin Writing Contract — the single source of truth

Consolidates every key from the transcript (`LIN_WRITING_GUIDANCE.md`), his papers
(`LIN_STYLE_PROFILE.md`), the annotated intro diff (`LIN_VS_PHILIP_DIFF.md`), and the
completeness pass (7 gaps folded in, ★ = load-bearing). This is the spec the pipeline enforces
(`paper/pipeline/lin_check.py`) and the reference for every drafting/revision pass. 2026-08-19.

---

## 1. Scope & contribution framing

- **Timing-focused paper.** The RRC+BOR timing framework covers *both* of Formby's techniques —
  CLRT *and* the physical/control (breaker-operate) fingerprinting. Size is **out of scope as a
  contribution**; it appears only as related-work context (one of the two obfuscation directions).
- **★ The FRAMEWORK is the rich technical contribution; CLRT and physical fingerprinting are two
  CASE STUDIES**, chosen for continuity with the prior (Formby) work. Contributions must be worded
  so the *framework leads* and the two techniques are its instantiations — not two co-equal
  results. ("our framework is what we propose as a rich technical contribution… CLRT and physical
  fingerprinting is just 2 case study… why we choose it… because of this previous work.")
- **Do NOT frame the paper as "anti-reconnaissance"** — too broad; invites "the measurement itself
  can be used for good," a different topic. Stay focused on **device fingerprinting** as the
  specific application.
- **Say "industrial control system," not "power system."** Naming power narrows the impact
  ("reviewers say limited"); use power system only as the *understandable example*.

## 2. Paper structure contract

- **Section order** (his papers): Introduction (+ Contributions) → Background **with threat model
  and named objectives stated EARLY** → a **distinct Design/Approach section** → Implementation
  (separate, concrete) → Evaluation organized **1:1 against the named objectives** (label them,
  reuse the labels: "Effectiveness in RO1.") → Related Work **second-to-last** → Conclusion
  (mechanism recap + the same headline numbers + one future-work sentence).
- **★ Section placement is a rule, not a preference.** "Some of your content is better put into
  the **Design** part, not the intro." Design/mechanism detail belongs in the Design section. The
  current draft has **no distinct Design section** and the intro carries design content — both must
  be fixed.
- **Comment out, don't delete** misplaced or leftover content (keep it for its right section).
- **Intro paragraph roles are fixed:** ¶1 = the funnel; ¶2 = leftover (commented/moved to Design);
  ¶3 = research-area trend + gap that pre-loads the contributions.

## 3. Introduction blueprint

**¶1 — a 4-sentence funnel, each sentence one job, ZERO domain jargon** (a general
computer-engineering reader must follow with no background):
1. Device fingerprinting is an essential step in cyber reconnaissance (+ one line on what it is +
   that it's critical).
2. Narrow to ICS — these techniques are increasingly critical in industrial control systems.
3. Why ICS is unique — cyber components cause **physical disruption**.
4. **A bridging sentence led by "Consequently,"** that summarizes ¶1–2 and pivots from
   website/botnet fingerprinting to device-model/control-operation fingerprinting.
5. **An example that serves the thesis** — Stuxnet + Ukraine 2015, pointed at **reconnaissance**
   (the ~6-month dwell), NOT at "attacks are bad." Well-known examples: **do not belabor impact**
   (and space is tight).

**Intro techniques:**
- **★ It is fine to use an unspecified general term in the intro** ("unique features") and defer
  the concrete definition — the reader continues; you name the specifics (packet size, latency)
  later. This is deliberate, distinct from "no jargon."
- **No domain-specific jargon** in the intro.

**¶3 — trend → overhead → gap → pre-map to contributions:**
- Trend: fingerprint defense is done by traffic obfuscation, which disrupts the two fingerprint
  features — **padding/splitting change packet SIZE; delay/dummy change LATENCY** (legible to a
  non-expert).
- **★ The "why it matters" content = ML classifiers consume these features.** (Put this in the
  motivation chain.)
- Overhead → P4: host-side manipulation has overhead, "that is why I use a programmable switch."
- Gap: "**Unfortunately, it is challenging, if not impossible,** to apply these methods to device
  fingerprinting in ICS," for two reasons — **(a) the features are different, (b) the messages are
  unencrypted**. **★ Generalize the wording** of the first reason (don't name a too-specific
  feature). These two gaps **pre-map to the two things the paper does** → the reader connects the
  dots, so the contributions later feel like the natural design.

## 4. Contribution grammar

- **Verb-first bold headline** per contribution, ending in a period ("Disrupts…", "Mitigates…",
  "Has little overhead…"), each + 2–4 sentences.
- **★ Mandatory** "To the best of our knowledge, this is the first…" first-ness claim (his papers
  always have one; the draft has zero).
- **Framework leads** the contribution list; the two fingerprinting techniques are its case-study
  instantiations (§1).
- Contributions **echo the ¶3 gap** so they read as inevitable.
- Optionally a second bullet list previewing the headline numbers.

## 5. Sentence-level style

- **Lead pivotal sentences with the connective** that names the logical relation — the "connective
  spine": **Consequently, / Because …, / Since …, / However, / Unfortunately, / For example,**.
  This is the single biggest fix (Philip's named weak spot: linking sentences).
- **One idea per sentence; every sentence has a subject–verb main clause.** Kill the fragment
  class ("By learning X…, because Y…" with no main clause).
- **Plain language on purpose** — "fancy language can be done by ChatGPT; the human job is
  structure and logic." No paper is rejected for plain prose.
- **Short/simple words** — use > "exploit"/"leverage"; word variety doesn't matter, can be
  interchangeable.
- **Consistent terminology** — the same term for the same thing, every time.
- **Balanced, finished enumerations** — "(i) …, and (ii) …".
- **Motivation-first — WHY before WHAT.** When stuck: write what you did, but write *why* first;
  always "why do people want to do this?"; then step by step.
- **★ Verify factual claims yourself** (dates, facts) before relying on them — prevents the exact
  Ukraine date slip (2015, not 2025) and duplicate-example error found in the draft.
- Use each marquee fact **once**, pointed at the thesis.

## 6. Threat-model contract

- Define three attacker scenarios and **use the terms consistently**: **passive** (eavesdrop →
  record → classify), **proactive** (attacker selectively *sends probing* — use "proactive," NOT
  "active"), **active** (changes the network). "If we use it, define it specifically and use it
  consistently."
- **This paper focuses on the passive fingerprinting attacker.** Whether to address proactive
  probing is undecided (most obfuscation work ignores it) — but the taxonomy is defined regardless.
- **Distinguish from intrusion detection** — the paper is specifically about fingerprinting.
- Position against prior obfuscation work (e.g. Ditto) that considered only the passive eavesdropper.

## 7. Frozen technical facts (write these consistently)

- **RRC and BOR are two SEPARATE mechanisms.** RRC = the read request–response hold; BOR =
  "Blocking the Operate Response" (his coinage). The operate-hold delay = **G** (a.k.a. **J**),
  analogous to the read's **A** (ACK delay) and **R** (response delay).
- **A, R, G are configurable, set by the system administrator.** The master-visible observable is
  **R − A** (e.g. 25 − 21 = **4 ms**; defended CLRT = **4.001 ms**, near-zero variation).
- Figure label for the defended curve = **"obfuscated"** (native vs obfuscated); read and select
  overlay to the same observation.
- The timing framework covers **both** of Formby's techniques (completeness claim for the eval).

## 8. Process / freeze directives (current phase)

- **Stop P4 implementation; no new mechanisms** — "don't try different things… waste of time."
- **★ Keep the fail-open safety exactly as-is** — an unmatched transaction now **passes through**
  (not dropped). "keep it this way." Do not change it.
- **Next work = writing + "a little bit more evaluation,"** not more mechanism.
- **Future eval-strengthening (not now):** multi-platform — P4 switch + NVIDIA DPU on NSF FABRIC +
  BMv2 (Alex can help; possibly NCSA).

## 9. What the reproducible check enforces (maps to `lin_check.py`)

| Rule | Checkable signal |
|---|---|
| Connective spine (§5) | density of leading connectives per paragraph ≥ target |
| Contribution grammar (§4) | verb-first bold headlines; a "to the best of our knowledge" first-ness claim present |
| Structure (§2) | threat model appears in/before Background; a distinct Design section exists; RO/goal labels defined and reused in Evaluation |
| Readability (§5) | flesch_reading_ease / fk_grade within band (the "too dense" guard) |
| Sentence health (§5) | flag sentences with no main clause / fragments |
| Fact hygiene (§5) | duplicate marquee examples; obvious date inconsistencies (warn) |
| Voice fingerprint | `paper-voice/voice_check.py` (sentence length, "we"-agency, hedges, banned AI words, em-dashes = 0) |

## 10. Aug-31 quarterly review (separate deliverable)

Prepare slides describing what's done, **general, not deep technical**; arc = define the problem →
what fingerprinting does → the threat model → what we do + some results. (Per the full transcript:
< 10 slides, delivered over Zoom, student/Philip presents — the sponsor audience lacks P4
expertise, so keep it high-level; may say "programmable networks.")

---

*Provenance: `LIN_WRITING_GUIDANCE.md` (transcript), `LIN_STYLE_PROFILE.md` (his papers +
paper-voice), `LIN_VS_PHILIP_DIFF.md` (annotated intro), completeness pass 2026-08-19. This
contract supersedes those as the working reference; they remain the evidence trail.*
