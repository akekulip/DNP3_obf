# Notes on Dr. Lin's draft text for author review (2026-10-19)

His non-[Archive] paragraphs from `lin_draft/main_20261019.tex` are installed word for word, and
`pipeline/check_lin_verbatim.py` enforces it. None of the points below is corrected in the
manuscript; each is for him to decide. Only empty cross-references were filled: Fig.~\ref{} became
the motivation, PSA and components figures, and Appendix~\ref{app} became the crawler appendix.

## Facts that disagree with the evidence

1. **The crawler numbers (III-B).** The text says "a stratified sample of 99 catalogued entries, 32 …
   DNP3 support, … encryption for six entries, and one had DNP3 authentication."
   - The crawler output Philip supplied on 2026-10-19 has 55 devices: 4 encryption with
     authentication, 2 authentication only, 1 unconfirmed option, 48 none.
   - Two of the four encrypted devices secure EtherNet/IP rather than DNP3.
   - Appendix A reports the 55-device data, so the text and the appendix currently disagree.
   - Source: `…/eval_m11_09_20261018_02_paper_inputs/crawler/SOURCE.md`; `CLAIM_EVIDENCE_MATRIX.md`
     row C17.
2. **PSA pipelines (II-C).** "It can feature up to four ingress and four egress pipelines [PSA spec]."
   The PSA v1.2 specification defines one logical ingress and one logical egress pipeline. Four
   pipes is a property of Tofino-1, and the evaluated chip exposes two. Either cite Tofino
   documentation or reword (`CITATION_AUDIT_20261019.md`).
3. **Two components or three (III-C).** "NOMAD includes two components: (i) Obfuscation
   infrastructure … and (ii) obfuscation objectives/constraints." The post-meeting structure lists
   three: infrastructure, strategies, and objectives and constraints. The manuscript follows the
   structure, with Sections IV, V and VI and Fig. 5.
4. **The trace in III-B.** The text refers to "a sample network trace collected from IEDs from two
   different vendors". Fig. 4 is built from the 2026-08-03 READ captures of the SEL-751A and the
   ION7550 (git `7c4a5a7`); it shows READ only, with no select-before-operate.
5. **The threat model (III-A).** "We also assume that the adversary knows the existence of the
   framework and the intervals it obfuscates." Only the retrained classifier (Sec. VII-D) fits this
   assumption; the one trained before deployment does not.
7. **The attacker's task (VII), for his decision.** By his choice, the paper uses only Formby's
   classifier, applied to READ/SELECT/OPERATE windows. A reviewer pass on 2026-10-19 raised two
   points, and the evidence confirms both:
   - The function codes are readable, so the label is already visible to the adversary. The
     Limitations now say that the task measures how much operation information CLRT carries.
   - The classifier trained before deployment also falls to chance under a constant delay of 1 ms
     (post hoc, claim C8b), because its threshold H is set from unobfuscated training data. The
     paper now states this next to the headline, and the abstract no longer leads with "falls to
     chance". Against the retrained classifier, NOMAD's effect is not significant on the software
     outstation.
   Options for him: classify devices rather than operations (needs a second device), or keep the
   current framing with these caveats.

6. **PRT (II-B, l.123) and Figure 1.** His sentence defines PRT "between unsolicited responses
   (indicating the start of a control operation) and the corresponding application-layer response".
   Formby et al. (NDSS 2016, Sec. IV-B; they call it "operation time") measure from the operate
   command seen at the tap to the unsolicited response reporting the change (m = t3 - t1), or to its
   SER timestamp. Philip chose the verified definition for Figure 1 (2026-10-19): PRT runs from
   OPERATE (0x04) to UNSOLICITED RESPONSE (0x82). His sentence is unchanged; the Fig. 1 caption's
   "(b) … its master-visible interval $O$" now reads "(b) … its PRT".

## Wording he may want to revisit (not changed)

- "Unfortunately, these methods cannot be directly applied…": his own note on that paragraph reads
  "it seems that this paragraphs contains inaccurate arguments".
- "and configure the DNP3 protocol with different parameters." is a sentence fragment in III-B ¶2.
- "Despite ICS network protocols are gradually enhanced…" and "obfuscation directly
  protocol-conformance" are grammar slips in the design-goal bullets.
- "Device fingerprinting … These device fingerprinting presents different features…" is a
  number-agreement slip.
- PRT in II-B is called "Physical Response Time"; Formby et al. call it physical operation time.

## Citation fixes applied to References.bib (his keys kept)

- **`securitas2026`:** the official title has no "Securitas:" prefix; the entry now carries the full
  author list and pages from usenix.org.
- **`minos2025`:** now carries the full author list and pages from usenix.org.
- **`CISA2026SecureOT`, `p42022psa`, `seion7550`:** added from their sources of record.
- **`lincps2016`:** his archived Related Work cited it for the anti-reconnaissance testbed. The
  rewritten section cites `lintestbed2020`.
- **`jeon2016passive`:** exists only on arXiv and is no longer cited.
