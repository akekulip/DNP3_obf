# Corrective Prompt for Claude Code: Reader-First NDSS Rewrite

Paste the text below into Claude Code. Do not combine it with the previous broad rewrite prompt. This prompt supersedes the previous writing instructions where they conflict.

---

Stop the current rewrite. The generated eight-page paper does not follow the required narrative, reader model, literature depth, or technical verification standard. Do not continue polishing the current text. Repair the manuscript from the author-written base.

## 1. Immediate instruction

Use the selected `*_desmoothed.tex` manuscript as the canonical base. Archive the current Claude-generated version without deleting it. Diff the canonical base, the other original manuscript, and the Claude-generated version before editing.

The author-written Introduction is the narrative anchor. Preserve its intended story:

```text
reconnaissance is required before a damaging attack
-> fingerprinting converts passive traffic observations into system knowledge
-> general traffic-analysis defenses reshape observable traffic
-> those defenses rely on assumptions that do not transfer cleanly to ICS and DNP3
-> DNP3 exposes a specific cross-layer timing and response-shape fingerprint
-> the endpoints and protocol correctness constrain what a defense can change
-> the defense must therefore operate in the network
-> Defense 4 normalizes the evaluated timing and segment-shape features
-> implementation challenges, results, and bounded contributions
```

Do not replace this story with a condensed mechanism summary.

## 2. The central reader-model failure

Write for an NDSS reviewer who understands security and networks but has never seen this project, this repository, the testbed, or the Defense 4 terminology.

The reader must not be expected to know:

- what DNP3 is;
- what a master or outstation is;
- what READ, SELECT, OPERATE, select-before-operate, ACK, response, or echo mean;
- which two packets define CLRT in this implementation;
- why CLRT can fingerprint a device or transaction;
- what a TCP segment vector is;
- why a 49-byte response matters;
- why `[49]` and `[28,21]` expose different shapes even though both total 49 bytes;
- what a DNP3 CRC block is;
- why modifying or fabricating DNP3 bytes is constrained;
- what P4, Tofino, PRE, pktgen, recirculation, or a strict-priority queue does;
- why a queue reservoir can act as a timer;
- what RRC or BOR means;
- why dp8 and dp10 are needed;
- what is measured on the master-facing link and what is not captured on the relay-facing link.

Every project-specific term must be introduced in plain language before its acronym, symbol, port, queue, register, or code name appears.

Use this explanation order:

```text
concept -> concrete DNP3 example -> security consequence -> design requirement
-> high-level mechanism -> exact implementation -> evidence and limitation
```

Do not use this order:

```text
mechanism name -> port IDs -> queue IDs -> registers -> unexplained result
```

## 3. Mandatory checkpoint: do not edit LaTeX yet

Your next response must contain only the following pre-rewrite artifacts. Do not modify the manuscript until I approve them.

### 3.1 Failure audit

Create `REWRITE_REPAIR_AUDIT.md` with a paragraph-by-paragraph audit of the Claude-generated Introduction, Threat Model, Implementation, and Related Work. For every paragraph, identify:

- its intended function;
- knowledge it assumes without explanation;
- unsupported or overly broad claims;
- terminology introduced too early;
- missing citations;
- contradictions with the final evidence or P4 code;
- whether it should be retained, rewritten, moved, split, or removed.

### 3.2 Reader knowledge ladder

Create `READER_KNOWLEDGE_LADDER.md`. List the concepts in the exact order a new reader must learn them. For each concept, provide:

```text
concept | one-sentence explanation | why it matters | first section where it appears
| prerequisite concept | supporting citation or repository evidence
```

### 3.3 Narrative storyboard

Create `NDSS_STORYBOARD.md` with the proposed section and paragraph sequence. Give each paragraph one purpose sentence. Show how the last sentence of each paragraph creates the reason for the next paragraph.

### 3.4 Literature gap matrix

Create `LITERATURE_GAP_MATRIX.md`, organized by research category. It must identify the current weak coverage, candidate primary sources, quality/venue, exact claim supported, and intended citation location.

### 3.5 Fact-conflict report

Create `FACT_CONFLICTS.md` for statements in the Claude-generated paper that conflict with, exceed, or are not traceable to the final code and evidence.

Stop after producing these five artifacts. Show me the proposed story and citation expansion before changing the paper.

## 4. Problems already identified in the Claude-generated PDF

Treat these as mandatory audit targets, not optional suggestions.

### 4.1 Structural problems

- The paper is compressed to eight pages and reads like a project summary rather than a developed NDSS systems-security paper.
- Related Work appears after the Conclusion. The Conclusion must be the final argumentative section before acknowledgments/references.
- The Introduction jumps from the Ukraine incident to CLRT and switch implementation without teaching the DNP3 transaction.
- The Introduction contains queueing, scheduler, and mechanism details before the reader understands the problem.
- The Threat Model repeats mechanism facts instead of first establishing the system, observation point, attacker, and protected properties.
- The Implementation begins with six internal components before presenting a simple end-to-end transaction or design overview.
- Figures show internal topology and pipeline details but do not first teach the native leak or the before/after transaction.

### 4.2 Reader-assumption problems

- “Outstation,” “master,” “READ,” “SELECT,” “OPERATE,” “echo,” “eligible response,” and “segment vector” appear without sufficient introduction.
- RRC and BOR are not explained through a concrete transaction before internal port and queue names appear.
- The paper assumes that the reader understands why an ACK-to-response interval carries processing information.
- The paper assumes that the reader understands why fixed segmentation is useful even though reassembly still yields 49 bytes.
- The paper states the two scheduling domains before showing the failure caused by the shared scheduler.

### 4.3 Technical statements requiring correction or proof

Verify each statement directly against the final P4, setup code, analysis scripts, PCAP-derived CSVs, claim matrix, and evidence package.

1. **CLRT packet semantics.** Determine the exact two captured packets used by `clrt_extract.py`. Do not alternate between a DNP3 link ACK, a DNP3 transport concept, and a TCP ACK. Define the layer and packet role exactly once and use it consistently.
2. **“Without decoding the payload.”** Unencrypted DNP3 is parseable. If the threat does not depend on application semantics, say that. Do not imply that the payload is unavailable when the packet is unencrypted.
3. **“Identical response.”** Remove this from the abstract, Introduction, body, and captions unless a paired source-side oracle proves it. The hardware evidence supports sequence-contiguous, CRC-valid, checksum-valid 49-byte reconstruction, not byte identity to a captured source frame.
4. **DNP3-byte preservation.** Separate design intent from measured evidence. The code may be designed not to edit DNP3 bytes, but the hardware claim must remain bounded by the available oracle.
5. **Commit-table default.** The generated paper says the terminal default forwards unmodified traffic. Verify the final `tbl_commit` default and every fail-open outcome from the actual P4. Do not infer the default from desired behavior.
6. **Rollback.** The paper says no configuration snapshot exists. Verify this against the final rollback and snapshot tooling.
7. **TCP timestamps.** Verify whether the P4 pipeline rejects/gates timestamped flows or whether timestamps were disabled and checked by host/preflight configuration. State only the implemented behavior.
8. **BOR secrecy.** Do not call J secret unless the threat model, codebook exposure, and observation model establish that property. J-independence of the master-visible gap is not automatically secrecy.
9. **Exactly-once release.** Do not state or imply a measured single relay-facing release. The relay-facing timestamp and multiplicity were not captured.
10. **“Hides operation timing.”** Narrow this to the measured master-facing property. The hardware evidence shows a J-invariant ACK-to-echo interval at the master-facing observation point.
11. **Segment determinism.** Do not generalize from one SEL-751 and one eligible response class to all DNP3 outstations.
12. **CRC-boundary claims.** Verify the exact 49-byte layout and the byte-28 cut. TCP can segment anywhere. Explain that the boundary is a design and verification choice, not a TCP requirement.
13. **Fail-open behavior.** Distinguish explicit fail-open dispositions for recognized unsupported/ineligible traffic from the terminal default for unknown outcomes.
14. **Production claims.** Remove “production representative,” “deployment ready,” or similar language unless the evidence and deployment assumptions support it.

## 5. Required story for the Introduction

The rewritten Introduction should be approximately 1.5 to 2.5 NDSS two-column pages, depending on the paper's total page budget. Use eight to ten developed paragraphs rather than compressed mini-paragraphs.

### Paragraph 1: reconnaissance before physical damage

Explain that an attacker must learn the target before choosing effective actions. Connect reconnaissance to real ICS consequences and use one authoritative incident source. Do not begin with the solution.

### Paragraph 2: fingerprinting as passive reconnaissance

Explain fingerprinting in ordinary language: repeated timing, size, direction, and protocol behavior allow an observer to infer device or transaction properties. Distinguish device identity, device type, and transaction-class inference.

### Paragraph 3: existing network fingerprinting and traffic-analysis evidence

Establish that timing and size remain informative even when payload semantics are unavailable or encrypted. Introduce high-quality foundational and modern sources.

### Paragraph 4: existing obfuscation defenses

Explain padding, morphing, adaptive padding, constant-rate shaping, differential privacy, and in-network shaping at the level needed to understand their assumptions. Do not merely list papers.

### Paragraph 5: why ICS and DNP3 are different

Introduce the DNP3 setting before discussing the leak:

- a control center/master periodically requests data from a field device/outstation;
- the exchange produces the specific acknowledgment and response observed by the extractor;
- devices are long lived, stable, and repeatedly polled;
- endpoint firmware and protocol behavior are difficult to change;
- correctness and timing constraints matter.

### Paragraph 6: the concrete fingerprint

Use one running transaction. Show the request, the exact acknowledgment event, and the response. Define CLRT from the correct captured packets. Then explain the eligible 49-byte native response and segment vector `[49]`. Explain how these features can distinguish the evaluated READ and SELECT transactions and how they relate to Formby et al.

### Paragraph 7: why existing defenses do not directly solve this problem

Derive the requirements rather than asserting them:

- padding or dummy exchanges can violate or complicate observable protocol behavior;
- endpoint changes are unavailable;
- a controller fast path adds timing variability and deployment assumptions;
- size-only shaping leaves the timing feature;
- timing-only shaping leaves the segment-shape feature;
- the defense must preserve a valid ordered DNP3/TCP exchange.

Avoid the absolute claim that all general defenses “will not work.” State the exact assumption mismatch.

### Paragraph 8: key insight and design

Introduce the switch as the enforcement point. Explain in one sentence what timing normalization does and in one sentence what segment shaping does. Only then name RRC. Introduce BOR after explaining why an outbound OPERATE request creates a different causal problem.

### Paragraph 9: implementation challenges

State the real systems challenges:

- implementing delayed release without a controller timer;
- anchoring multiple events to one request timestamp;
- splitting a valid response without claiming unsupported byte identity;
- separating RRC and BOR scheduling to prevent queue interference;
- fitting the design into one Tofino pipeline;
- operating safely on a physical relay.

### Paragraph 10: results, boundaries, and contributions

Preview the strongest measured results, then state the single-device and missing relay-facing-tap limitations. Contribution bullets must map to verified artifacts, not aspirations.

Use Dr. Lin's recurring argument pattern:

```text
problem and consequence -> limitations of present approaches
-> “To overcome these limitations” -> concrete design
-> implementation -> results -> bounded contributions
```

Do not copy Dr. Lin's sentences or distinctive wording.

## 6. Add a reader-first Background or Design Overview

The manuscript needs a short conceptual bridge before low-level Implementation. Either add a dedicated `Background and Design Overview` section or place equivalent subsections before implementation details.

It must explain:

1. the native READ transaction;
2. the native SELECT-before-OPERATE transaction;
3. the master-facing observation point;
4. the two leaked features;
5. the desired defended timeline;
6. the desired `[49] -> [28,21]` transformation;
7. the high-level role of RRC and BOR;
8. why the two internal scheduling domains exist.

Use one consistent running example throughout the paper.

The first architecture figure must be understandable without knowing any port or queue number. Put dp8, dp10, dp68, qid7, and register names in the detailed implementation figure, not the first explanatory figure.

## 7. Threat Model rewrite

Order the section as follows:

1. system model and native transaction;
2. observation point;
3. adversary objective;
4. adversary capabilities and knowledge;
5. trusted components;
6. deployment assumptions;
7. security goals;
8. non-goals and evidence limitations.

Do not repeat the complete implementation in the Threat Model.

Define whether the claim concerns:

- a passive master-facing observer;
- transaction-class inference;
- device fingerprinting evidence from prior work;
- the evaluated single-device signature;
- encrypted versus unencrypted traffic;
- application semantics versus metadata-only features.

Do not state that active adversaries are covered. Explain what changes if the observer can see the relay-facing link.

## 8. Implementation rewrite

Begin with a one-page high-level walkthrough before code symbols.

For each mechanism use this structure:

```text
problem -> packet entering the switch -> state recorded -> queue decision
-> release event -> packet seen by master or relay -> failure behavior
```

Use this subsection order:

1. physical topology and packet paths;
2. end-to-end READ example;
3. RRC timing mechanism;
4. response replication and `[28,21]` carving;
5. SELECT-before-OPERATE example;
6. BOR state lifecycle;
7. shared-scheduler failure and two-domain correction;
8. P4 pipeline and one-outcome/one-commit implementation;
9. control-plane, pktgen, PRE, traffic-manager, and readback setup;
10. retransmissions, stale state, watchdog, ineligible traffic, and failure behavior;
11. safety guard and restoration;
12. compiler/resource fit and limitations.

Introduce a code symbol only after the concept it implements has been explained. Do not write a paragraph around a symbol merely because it exists in the code.

Every subsection should answer:

- What problem does this component solve?
- What exact packet or state triggers it?
- What observable effect does it produce?
- What could go wrong?
- What evidence verifies it?

## 9. Related Work rewrite and literature expansion

The current bibliography of 16 references is inadequate for the requested paper. Expand the literature based on relevance and quality, not citation count alone. A developed NDSS submission in this area will normally need substantially broader coverage. An expected range is roughly 35 to 60 verified sources if that many directly support the paper; do not add irrelevant citations to meet a quota.

Top security conferences are archival primary venues in this field. Treat NDSS, IEEE Symposium on Security and Privacy, USENIX Security, and ACM CCS as high-quality sources, not as inferior to journals. Add strong journal work where the topic naturally appears, including relevant papers from venues such as:

- IEEE Transactions on Dependable and Secure Computing;
- IEEE Transactions on Information Forensics and Security;
- IEEE Transactions on Industrial Informatics;
- IEEE Transactions on Smart Grid;
- IEEE Transactions on Network and Service Management;
- IEEE/ACM Transactions on Networking;
- ACM Transactions on Privacy and Security;
- ACM Transactions on Cyber-Physical Systems.

Use Semantic Scholar for discovery, then verify each item against DOI/publisher/proceedings metadata before adding it to Zotero.

### Required research categories

1. remote and passive device fingerprinting;
2. ICS and cyber-physical device fingerprinting;
3. cross-layer timing and response-time fingerprints;
4. website and encrypted-traffic fingerprinting;
5. traffic morphing and packet-size defenses;
6. adaptive padding and constant-rate defenses;
7. differential-privacy traffic shaping;
8. in-network and programmable-switch traffic obfuscation;
9. P4 scheduling, shaping, recirculation, and replication;
10. ICS reconnaissance and moving-target defense;
11. DNP3 security, intrusion detection, specification analysis, and programmable-switch processing;
12. standards and authoritative incident reports.

### Existing citation leads that must be verified, repaired, or rejected

The author-written draft already identified these keys. Locate their actual records and verify that each supports the intended claim:

```text
kohno2005remote
radhakrishnan2014gtid
shu2006fingerprint
wright2009morphing
cai2014csbuflo
juarez2016wtfpad
apthorpe2019stp
sabzi2024netshaper
mehta2022pacer
dyer2012peekaboo
sirinam2018df
jeon2016passive
formby2016control
east2009taxonomy
fovino2010modbus
cardenas2011attacks
hu2023dnp3p4
```

Do not assume that the existing key, year, venue, or claim is correct. Verify it.

### Related Work organization

Organize by research problem, not by author list. Each paragraph must follow:

```text
what the category protects against -> representative mechanisms
-> strongest relevant result -> assumption or remaining leak
-> exact distinction from Defense 4
```

Do not place Related Work after the Conclusion. Place it where it supports the paper's argument, and keep the Conclusion last.

## 10. Citation quality gates

Create and populate the Zotero collection `OBfus_defense` only with verified records.

For each citation, record:

```text
claim | citation key | title | authors | venue | year | DOI
| authoritative verification source | exact supporting page/section
```

Reject:

- unreviewed arXiv versions when a peer-reviewed version exists;
- generic surveys used in place of the primary result;
- low-quality or unrelated papers added only to increase the count;
- citations that support only a neighboring claim;
- malformed metadata;
- invented page numbers or quotations.

Use official standards and incident reports when they are the primary authority, even though they are not journal papers.

## 11. Style requirements derived from the Hui Lin target papers

Follow these high-level characteristics:

- establish the physical or operational consequence first;
- define the research gap by identifying concrete limitations in existing approaches;
- use “First,” “Second,” and “Last” for genuine distinct arguments;
- use concrete system nouns and active verbs;
- explain why each design choice follows from the preceding limitation;
- preview implementation and evaluation only after the mechanism is understandable;
- state limitations directly rather than hiding them in Discussion;
- use contribution bullets that correspond to implemented and evaluated artifacts;
- connect figures to the argument in the surrounding text.

Do not copy wording from DefRec, RAINCOAT, or the testbed paper.

Avoid:

```text
Importantly,
Notably,
It is worth noting,
This novel and robust framework,
In today's rapidly evolving landscape,
seamlessly,
comprehensive,
groundbreaking,
```

Do not create short, dense paragraphs merely to sound “technical.” Use enough explanation for a new reader to reproduce the reasoning.

## 12. Figures required for reader comprehension

Propose original, editable figures before drawing them. At minimum, the storyboard should include:

1. **Native DNP3 running example:** master request, exact ACK event, response, and the CLRT measurement.
2. **Native versus defended view:** variable native timing and `[49]` versus policy timing and `[28,21]`.
3. **Threat model:** observer location, trusted boundary, and missing relay-facing tap.
4. **RRC concept:** blocker reservoirs as data-plane timers, without code names in the first version.
5. **BOR concept:** SELECT preparation, OPERATE hold, modeled `T0+J`, measured `T0+A/T0+R`, and the evidence boundary.
6. **Shared scheduler failure versus two-domain fix.**
7. **Detailed implementation:** ports, queues, pktgen, PRE, pipeline, and commit logic.

Captions must teach the figure. Mark measured, modeled, and unobserved events differently.

## 13. Phase-two editing rules after approval

After I approve the five checkpoint artifacts:

1. Restore the author-written sections from `*_desmoothed.tex` as the prose base.
2. Rewrite paragraph by paragraph according to the approved storyboard.
3. Preserve technically correct author phrasing when it already carries the intended story.
4. Add explanations before implementation details.
5. Expand and verify the literature.
6. Correct every fact conflict before compiling.
7. Keep the Claude-generated paper only as an audit source, not as the prose base.
8. Build the LaTeX paper and visually inspect every revised page.
9. Produce a redline/diff against the author-written base.
10. Report which original paragraphs were retained, reorganized, rewritten, or removed.

Do not rerun hardware, contact testbed hosts, or change final evidence.

## 14. Completion criteria

The repair is complete only when:

- a reader unfamiliar with the project can explain the native DNP3 transaction before RRC or BOR is introduced;
- the Introduction follows the author's reconnaissance-to-defense storyline;
- the paper separates device fingerprinting, transaction-class inference, and single-device signature replacement;
- all project-specific terms are defined before use;
- the Related Work is broad, comparative, current, and verified;
- the Conclusion is the final argumentative section;
- every implementation statement is traceable to final code or evidence;
- no unsupported “identical,” “exactly once,” “secret,” or general anti-fingerprinting claim remains;
- the paper compiles cleanly and its figures are readable at NDSS two-column scale;
- the Zotero collection, BibTeX, citation audit, and manuscript citations agree.

For your next response, produce only the five checkpoint artifacts from Section 3 and stop for approval.

---

