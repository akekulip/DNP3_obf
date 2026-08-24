# Dr. Lin's writing guidance — extracted from the 2026-08-19 meeting transcript

Source: the recording where Dr. Lin reads through the Introduction he added on top of Philip's
draft and explains his method. Transcript is noisy (auto-captioned); garbled terms are repaired
from context and marked ⟨inferred⟩ — confirm the flagged ones. This complements
`LIN_STYLE_PROFILE.md` (mined from his papers). Assessment/extraction only — no manuscript edits.

---

## 0. Scope, confirmed from his own words

- **The paper is TIMING-focused.** The timing mechanism "covers both of the techniques" that
  Formby ⟨"for me people, the Georgia Tech paper" = Formby et al., Georgia Tech⟩ present — the
  CLRT *and* the control/physical fingerprinting (via the breaker/operate response time). So one
  timing framework subsumes both.
- **Stop implementation.** "I don't want you to go into the first implementation on the P4 switch
  … don't complicate any further implementation … follow this structure." The timing work is "in
  good shape"; the next work is **writing + a bit more evaluation**, not more P4. (This confirms
  parking the size/hardware push.)
- **Size is context, not a co-contribution.** Size ("padding and splitting") appears in the
  Introduction only as one of the two *directions of prior obfuscation work* (size vs latency);
  it is likely **out of scope** as its own contribution. → the old "two-part size+timing" plan is
  superseded; size lives in framing/related-work.
- **Naming:** the defended curve is labelled **"obfuscated"** (he corrected the figure label);
  CLRT defended = **4.001 ms**. His mechanism names: **RRC** = the read request–response hold;
  **BOR** = "Blocking the Operate Response" (his coinage); the operate-hold delay he calls **G**
  (also **J**) — analogous to the read's A (ACK delay) and R (response delay).

## 1. His Introduction architecture (paragraph by paragraph, as he walked it)

**Paragraph 1 — a 4-sentence funnel, every sentence with a job, ZERO jargon.** "Only 4 sentences,
but each sentence serves a purpose." A general computer-engineering reader must follow it with no
background:
1. **Fingerprinting is an essential step in cyber reconnaissance** — state it's critical + a
   one-line "what fingerprinting is." (He deliberately does NOT frame the paper as
   "anti-reconnaissance" — too big a scope; it invites "measurement can also be used for good,"
   a different topic. **Stay focused on device fingerprinting**, the specific application.)
2. **Narrow to ICS** — "these techniques have become increasingly efficient in industrial control
   systems." Say **"industrial control system," not "power system"** (naming power narrows impact
   → reviewers say "limited"); use power system only as the *understandable example*.
3. **Why ICS is unique** — cyber components cause **physical disruption**. Still no jargon; a
   reader with no background still understands.
4. **A bridging summary sentence** — "fingerprinting shifts focus from identifying visited
   websites / botnet behavior to revealing device models and types of control operation critical
   to ICS." One sentence that summarizes the first two and pivots general→ICS.
5. **An example that serves the paper's argument** — Stuxnet (nuclear facility) and Ukraine 2015.
   These are **well-known, so do NOT belabor how impactful they are** (you would only emphasize
   impact if they were obscure). Instead point the example at **reconnaissance**: "it is widely
   believed the adversary stayed in the system for at least 6 months to perform cyber
   reconnaissance." The example exists to argue *reconnaissance matters*, not "attacks are bad."
   Rule: **"whenever you present an example, present the fact that helps our argument."**

**Paragraph 2 — leftover, commented out not deleted.** "Some of your content is actually better
put into the design part, not here." → **move content to the section where it belongs; comment
out rather than delete** (keep it for reuse).

**Paragraph 3 — the research-area + gap paragraph (sets up the contributions).** Three moves:
1. **The trend, in plain terms:** many works do fingerprinting defense via traffic obfuscation,
   which disrupts the two fingerprint features — **padding/splitting change packet SIZE; delay
   changes LATENCY.** A non-expert now sees the two directions of the field.
2. **The overhead → P4 motivation:** "manipulating [traffic on the host] has overhead, that is
   why I want to use P4." One clause motivates the whole in-network choice.
3. **Why existing measures don't transfer to ICS** (the gap): "unfortunately it is challenging;
   there is no [ready] policy to apply these defenses to device fingerprinting in the ICS
   environment," for two reasons — **(a) the features are different, (b) the messages are
   unencrypted.** Crucially, **these two gaps pre-map to the two things the paper does**, so
   "even without talking about our approach, these two [points] already correspond to what we are
   going to do." The reader **connects the dots**, and the contributions then feel like the
   natural design.

## 2. His sentence-level style rules

- **Plain language, deliberately.** "You don't have to use fancy language — fancy language can be
  done by ChatGPT. Use very plain language." The human job is **structure and logic**; polish can
  come later/automatically. "No paper is rejected for this kind of language."
- **Short, simple words.** use > "exploit"/"leverage" ("just use *use*, it's shorter"); word
  variety doesn't matter, can be interchangeable — don't agonize over it.
- **Consistent terminology.** Use the **same term for the same thing** across sentences ("you put
  it in the same [words]"). Do not vary vocabulary for variety.
- **Every sentence serves a purpose; short paragraphs** (his para 1 = 4 sentences).
- **Motivation-first — WHY before WHAT.** "Whenever you don't know what to write: write what you
  did — but write *why* first. Always think about why people want to do it." Then step by step.
- **Connect the dots.** Engineer the setup (problem, field trend, gaps) so the contributions read
  as the natural, inevitable solution.
- **Right content in the right section.** Design detail belongs in Design, not the Intro.

## 3. Philip's specific gaps (his direct feedback)

- **Linking sentences / logical flow is the weak spot** — Philip: "your understanding of how you
  link the sentences together, I think that's where I'm lacking." Dr. Lin agrees this is the
  thing to fix; his fix = the purpose-per-sentence + consistent-terminology + why-first method
  above. ("You still have some to learn in writing, but it's not too difficult to catch up.")
- **Beat the blank-page freeze** by writing *what you did + why*, in plain ordered sentences.

## 4. Threat-model guidance (affects the Threat Model section)

- He wants the **attacker model defined carefully and used consistently.** Distinguish scenarios:
  **passive** (eavesdrop → record traffic → classify), **"proactive"** (attacker selectively
  *sends probing* to elicit responses — he calls it "proactive," reserving "active" for
  attackers who *change the network*, since "active" is used inconsistently in the literature),
  and a third he alludes to. "This is not critical, but **if we use it we must define it
  specifically and use it consistently.**"
- **This paper focuses on the passive fingerprinting attacker** (observe + record + classify).
  Whether to address proactive probing is undecided — most traffic-obfuscation work ignores it.
- **Distinguish from intrusion detection** — this paper is specifically about fingerprinting (as
  he did in his NDSS paper), not IDS.
- Prior traffic-obfuscation work (e.g. **Ditto** ⟨"the diesel paper"⟩) only considered the
  passive eavesdropper — a point to position against.

## 5. Transcription repairs — CONFIRM these

| Transcript garble | Inferred meaning | Confidence |
|---|---|---|
| "for me people, the Georgia Tech paper" | **Formby et al.** (Georgia Tech CLRT fingerprinting) | high |
| "the diesel paper" | **Ditto** (NDSS'22 traffic obfuscation) | medium |
| "SVU" / "celebrity flow operate" | **SBO** / Select-Before-Operate control path | medium |
| "break operating time" | **breaker operating time** (control operate→response) | high |
| "CORT" / "CRT" | **CLRT** (cross-layer response time) | high |
| "G" / "J" | the **operate-hold delay** (same quantity, two labels) | high |
| "off bascade" / "fuscated" | **obfuscated** (defended curve label) | high |
| "Robert" / "Robbie" appearing in the draft | a leftover **placeholder author name** to remove ⟨and a co-author's given name he recognized⟩ | low |
| "Ohans" / "who and our" project, Aug 31 | the **funded project's quarterly review** (owner/sponsor name uncertain) | low |

## 6. Non-writing action items from the meeting

- **Aug 31 quarterly review (Zoom):** prepare **< 10 slides**, **general** (not deep technical) —
  define the problem, what fingerprinting is, the threat model, then what we do + some results.
  You may say "programmable networks" / mention the P4 switch, but the audience lacks that
  expertise, so keep it high-level. **Philip presents.** (Audience = program/sponsor stakeholders,
  hence the non-technical framing.)
- **Stop P4 implementation / no new mechanisms** — follow the current structure.
- **Later eval-strengthening (not now):** multi-platform implementation to strengthen evaluation —
  P4 switch + **NVIDIA DPU on NSF FABRIC** + **BMv2** (Alex can help with specific implementation;
  possibly NCSA compute). Future work, not the current push.

## 7. What I still need to align precisely

Dr. Lin's **actual added Introduction text** (his version alongside Philip's original). The above
reconstructs his intent from him reading it aloud; the real text lets me (a) diff his edits vs
Philip's original for exact phrasing/structure, and (b) extend his 4-sentence-funnel method to the
rest of the paper in his voice.
