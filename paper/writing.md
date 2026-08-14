# Master Prompt for Claude Code: Defense 4 Paper Rewrite

Copy everything below into Claude Code as one task.

---

You are revising an experimental systems-security paper for submission in the style and technical discipline expected at NDSS. This is a repository-grounded rewrite, not a speculative writing exercise.

## 1. Objective

Rewrite only these paper sections:

1. Introduction
2. Related Work
3. Threat Model, Assumptions, and Security Goals
4. Implementation

Make the sections read as one coherent argument. Preserve the paper's actual contribution, implementation, experiments, and limitations. Improve structure, precision, technical explanation, transitions, figures, and citation support.

Use the high-level writing characteristics found in the target papers, giving the greatest stylistic weight to the papers authored by Dr. Hui Lin. Do not copy sentences, distinctive phrasing, paragraph sequences, or figure designs. Reproduce the argument discipline and section logic, not the authors' text.

## 2. Required workflows and tools

Use the following available workflows when they exist:

- `/research-pipeline` for literature discovery, source verification, and claim-to-citation mapping;
- `/journal-adapt` for NDSS-oriented organization, density, section balance, figure placement, and reference format;
- MinerU for layout-aware extraction of the target PDFs, including section boundaries, captions, figures, tables, and references;
- the connected Semantic Scholar API for literature metadata and citation discovery;
- the connected Zotero integration for reference management;
- the available writing, tone, LaTeX, figure, and compilation tools.

If a named workflow is unavailable, reproduce its intended steps manually and record the fallback in the rewrite log. Do not silently skip a required step.

. If `/watermark-remove` is only a prose-quality linter, use it solely as a final style-cleanup pass to remove repetitive AI-like wording, inflated transitions, canned summaries, and awkward phrasing. Preserve attribution, citations, copyright marks, metadata, and research provenance.

## 3. Repository and input locations

Paper repository:

```text
/home/philip/Projects/DNP3-size-probe/paper/
```

Target-paper directory:

```text
/home/philip/Projects/DNP3-size-probe/paper/target/
```

The target corpus contains or corresponds to:

1. **DefRec: Establishing Physical Function Virtualization to Disrupt Reconnaissance of Power Grids' Cyber-Physical Infrastructures** (Hui Lin et al.). Treat this as a primary model for the Introduction, threat framing, contribution structure, and claim discipline.
2. **Cyber-Physical Testbed: Case Study to Evaluate Anti-Reconnaissance Approaches on Power Grids' Cyber-Physical Infrastructures** (Hui Lin et al.). Treat this as a primary model for implementation explanation, testbed description, design tradeoffs, and limitations.
3. **RAINCOAT: Randomization of Network Communication in Power Grid Cyber Infrastructure to Mislead Attackers** (Hui Lin et al.). Treat this as a primary model for threat progression, defense motivation, system assumptions, and mechanism-to-goal reasoning.
4. **Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems** (Formby et al.). Use this primarily as the technical foundation for the fingerprinting threat, cross-layer response timing, device signatures, and attacker capabilities. Do not use it as the dominant prose model when it conflicts with the Dr. Lin papers.

Locate the current manuscript entry point, included section files, bibliography, figures, macros, and build command before editing. Locate the committed Defense 4 implementation, final evidence package, explainer, claim matrix, raw-capture analysis, and reproduction scripts. Record their exact paths in the rewrite log.

## 4. Hard scope and safety boundary

This is a writing, citation, and figure-revision task only.

- Do not contact the Tofino switch, SEL-751, relay master, or testbed hosts.
- Do not load P4, configure ports, send DNP3 commands, run SELECT or OPERATE, or rerun hardware experiments.
- Do not modify the frozen kernel, final PCAPs, CSVs, verdict files, or committed evidence.
- Do not invent new experiments, measurements, devices, captures, or results.
- Do not change numerical results to make the narrative cleaner.
- Do not broaden a claim beyond what the committed evidence supports.

Use the final committed evidence as the source of truth. Treat earlier drafts, notes, and superseded CSV fields as non-authoritative when they conflict with the final evidence package.

## 5. Phase A: inspect before rewriting

Complete these steps before changing prose.

### A1. Inventory the manuscript

Identify:

- main LaTeX file and section include graph;
- current text of the four sections in scope;
- all labels, references, citations, acronyms, macros, tables, algorithms, and figures used by those sections;
- bibliography engine and style;
- current page count and section lengths;
- unresolved citations, broken references, LaTeX warnings, and TODO markers.

Build the current paper once and save the build log and baseline PDF. Do not treat existing successful compilation as proof that claims or citations are correct.

### A2. Extract the target corpus with MinerU

Use MinerU on every PDF in `paper/target/`. Preserve:

- title, authors, venue, year, and DOI;
- section hierarchy;
- paragraph boundaries;
- figures and captions;
- tables;
- in-text citation locations;
- reference list.

Write the extraction to a temporary analysis directory under the paper workspace, not into the target directory. Do not modify the PDFs.

### A3. Produce a target-style matrix

Before drafting, create a concise style matrix with one row per target paper and columns for:

- Introduction argument order;
- paragraph purpose and typical paragraph length;
- sentence length and clause structure;
- preferred transition patterns;
- how limitations are introduced;
- how contributions are stated;
- how figures are introduced and interpreted;
- how threat models and assumptions are ordered;
- how implementation details move from architecture to components to workflow;
- citation density and placement;
- words or constructions to avoid.

Use this matrix to derive a unified style profile. Give the three Hui Lin papers priority. Use Formby et al. to preserve technical terminology and threat accuracy.

### A4. Build a fact and claim ledger

Create a table with these columns:

```text
claim_id | proposed claim | section | evidence source | exact evidence location |
measurement/model/design status | citation needed | allowed wording | prohibited overclaim
```

Every quantitative statement and every security claim in the rewritten sections must appear in this ledger.

## 6. Target writing profile

Adapt the manuscript to these corpus-derived characteristics.

### 6.1 Argument structure

Use a visible causal progression:

```text
physical/security consequence
-> attacker capability
-> observable technical weakness
-> limitation of existing defenses
-> research gap
-> proposed mechanism
-> why the mechanism addresses the gap
-> implementation reality
-> measured evidence
-> bounded contributions and limitations
```

Use explicit enumerations such as “First,” “Second,” and “Last” when they clarify distinct limitations, requirements, or contributions. Each enumerated item must express a real logical distinction, not decorative parallelism.

Begin paragraphs with the technical subject or problem. Do not begin with vague evaluative framing.

Good pattern:

```text
Passive observers can infer ...
Existing timing defenses do not ...
Defense 4 separates ...
The Tofino traffic manager ...
```

Avoid:

```text
Importantly, ...
Notably, ...
Interestingly, ...
It is worth noting that ...
In today's rapidly evolving landscape, ...
From a broader perspective, ...
```

### 6.2 Sentence and paragraph construction

- Prefer concrete subjects, active verbs, and explicit causal links.
- Keep one primary claim per sentence.
- Use subordinate clauses only when they explain mechanism, condition, contrast, or consequence.
- Use medium-length technical sentences. The Dr. Lin target papers commonly use structured sentences with a median near the mid-20-word range, but clarity takes priority over matching a number.
- Avoid multiple abstract nouns in one clause.
- Avoid adjective-led or qualification-led openings.
- Avoid stacked claims connected only by “and.”
- Define an acronym once and use it consistently.
- Use the same name for each mechanism, time variable, port role, queue role, and observation point throughout the paper.
- Use present tense for the paper and mechanism, past tense for completed experiments, and modal language only for unmeasured implications.

### 6.3 Claim language

Use direct but bounded language:

- “The hardware captures show ...” for measured facts.
- “The offline model verifies ...” for model results.
- “The design schedules ...” or “The mechanism is designed to ...” for implementation intent not directly observed at the required link.
- “The evidence does not establish ...” for limitations.

Do not use “proves,” “guarantees,” “eliminates,” “prevents fingerprinting,” “exactly once,” “byte-identical,” “indistinguishable,” or “general” unless the exact claim is established by the authoritative evidence and the claim ledger approves that wording.

### 6.4 Tone

Use restrained systems-security prose. Remove promotional terms such as:

```text
novel, groundbreaking, revolutionary, seamless, robust, comprehensive,
state-of-the-art, highly effective, remarkable, significant
```

Use them only when technically necessary, comparatively defined, and supported by evidence or citations.

Do not mimic the target papers through repeated signature phrases. Do not copy their contribution bullets, opening sentences, captions, or paragraph skeletons. The final prose must be original.

## 7. Non-negotiable technical terminology and claim boundaries

Verify every item against the final repository evidence before using it. If the repository differs, follow the final committed evidence and report the discrepancy.

### 7.1 Timing notation

Use one notation everywhere:

```text
T_ACK = T0 + A
T_response = T0 + R
CLRT = R - A
```

For the final evaluated policy, `A = 20 ms` and `R = 24 ms`, so the intended CLRT is 4 ms. Do not mix this absolute-offset notation with an older notation in which a response-delay symbol represented a relative 4 ms gap.

The hardware medians are approximately 4.001 ms for defended READ and SELECT traffic. Explain the documented master-facing path/capture offset and retained outliers wherever absolute A/R placement is discussed.

### 7.2 Segment-shape normalization

Describe the mechanism as fixed TCP segmentation or segment-shape normalization for eligible 49-byte responses:

```text
[49] -> [28,21]
```

State explicitly:

- TCP may segment a byte stream at any position.
- Byte 28 is a selected existing DNP3 CRC-block boundary that simplifies deterministic Tofino carving and validation; it is not a TCP requirement.
- The reassembled total remains 49 bytes.
- The defense normalizes the observed TCP segment vector for the eligible class; it does not hide the total reassembled payload length.
- The hardware evidence establishes sequence-contiguous, DNP3-block-CRC-valid, IP/TCP-checksum-valid 49-byte reconstruction.
- Do not claim hardware byte identity to a source frame because no paired source-side oracle was captured.

Use the final count of 1,280 defended eligible responses only after verifying it from the final size reconstruction and verdict files. Do not rely on superseded arrival-order counts or obsolete segment-vector fields.

### 7.3 RRC

Expand RRC consistently as **Release-Replicate-Carve**.

Explain it in this order:

1. strict-priority blocker reservoirs hold the real ACK and response;
2. ACK and response release at absolute policy offsets from the request timestamp;
3. PRE creates two master-facing copies of an eligible released response;
4. egress carving emits the 28-byte prefix and 21-byte suffix.

Do not say that a clone or mirror creates the relay response or echo. The physical relay creates the response. The pktgen mirror triggers internal tokens, while PRE replication creates the two copies used for segmentation.

### 7.4 BOR

Expand BOR consistently as **Block OPERATE, then Release**.

Separate three evidence levels:

1. **Measured on hardware:** master-visible ACK and echo placement and an echo-minus-ACK interval near 4 ms across the evaluated J values.
2. **Verified by implementation/offline model:** the BOR state machine and intended release at `T0 + J`.
3. **Not directly observed:** relay-facing `T0 + J` timestamp and relay-facing delivery multiplicity.

Do not claim exactly-once BOR delivery on hardware. The evidence shows that the master issued one OPERATE per transaction; it does not show how many copies reached the relay.

### 7.5 Two scheduling domains

Explain the hardware reason, not only the final topology:

- a shared strict-priority ladder caused higher RRC queues to starve the BOR blocker/hold queues after OPERATE;
- this coupling shifted release behavior toward A or R;
- the final design uses internal dp8 for the RRC queue ladder and internal dp10 for the BOR queue pair;
- both are internal paths in the same physical Tofino and the same P4 program, not additional inline devices.

### 7.6 Fingerprinting claim

Tie the threat to Formby et al. accurately. Distinguish:

- device fingerprinting;
- transaction-class inference;
- cross-layer response timing;
- segment-shape observation;
- single-device signature replacement;
- multi-device indistinguishability.

The evaluated classifier separates READ from SELECT using CLRT. It is not a device-identity classifier. The final evidence supports suppression/replacement of the evaluated master-facing CLRT and segment-shape features for one SEL-751. It does not establish multi-device anonymity or resistance to every fingerprinting feature.

### 7.7 Testbed and safety

State that native and defended trials use the same physical master, SEL-751, links, Tofino, capture clock, and loaded binary, with a runtime mode change. Document internal loopbacks as switch implementation details.

Preserve the safety result: only isolated CROB points `{1,3}` were permitted by the guarded driver, breaker-close index 6 was refused, and all 32 relay outputs remained OPEN. Do not imply that a breaker operation was attempted.

## 8. Section-specific rewrite requirements

## 8.1 Introduction

Rewrite the Introduction using this sequence:

1. Establish the physical consequence of reconnaissance and fingerprinting in ICS networks.
2. Explain how a passive observer uses DNP3 response timing and packet/segment shape.
3. Introduce Formby et al.'s cross-layer timing concept precisely and explain the feature relevant to this paper.
4. Explain why conventional encryption, simulation, padding, host-based delay, or controller-mediated defenses do not directly solve this deployment problem. Cite each category accurately.
5. State the research gap as a concrete systems problem: normalize timing and eligible segment shape in a programmable switch while preserving protocol validity and the physical testbed.
6. Introduce Defense 4 and its components without implementation overload.
7. Explain why BOR and two independent scheduling domains are needed.
8. Preview only the strongest final results.
9. State limitations in the Introduction, including the single-device scope and missing relay-facing BOR tap.
10. End with concise contributions that map one-to-one to implemented and evaluated artifacts.

Contribution bullets should cover, if supported by the final evidence:

- the hardware scheduling primitive for absolute ACK/response policy timing;
- deterministic PRE/egress segment-shape normalization;
- BOR and the two-domain scheduler design;
- one-program 12-ingress-stage implementation;
- evaluation on one physical SEL-751 with reproducible PCAP-to-claim analysis;
- safety and explicit evidence boundaries.

Do not claim that the contribution “prevents fingerprinting.” State which features are suppressed or replaced and under which observation model.

## 8.2 Related Work

Organize Related Work by technical approach, not by paper chronology. Use categories such as:

1. ICS and cyber-physical device fingerprinting;
2. network timing and traffic-analysis defenses;
3. packet-size padding, traffic morphing, fragmentation, and segmentation defenses;
4. moving-target and anti-reconnaissance defenses for ICS/power systems;
5. programmable-switch timing, queueing, recirculation, replication, and traffic shaping.

For each category:

- state what the category achieves;
- identify the assumption or limitation relevant to Defense 4;
- cite primary sources;
- end with the exact distinction from this work.

Do not write an annotated bibliography. Do not use a citation cluster to support several unrelated claims. Do not cite a survey when the original work is available. Do not imply that prior work is ineffective in general; explain the specific mismatch in threat model, observation point, protocol requirement, deployment location, or hardware primitive.

Include the three Hui Lin anti-reconnaissance papers where technically relevant, not merely because they are style targets. Keep Formby et al. central to the fingerprinting motivation.

## 8.3 Threat Model, Assumptions, and Goals

Use explicit subsections in this order:

1. **System and observation model**
2. **Adversary capabilities**
3. **Trusted computing base and deployment assumptions**
4. **Security goals**
5. **Non-goals and limitations**

The threat model must identify:

- physical master, Tofino switch, physical SEL-751, and master-facing observer;
- exactly where packets are observed;
- whether the adversary is passive or active for each claim;
- what headers, timing, TCP segments, payload lengths, and transaction classes are visible;
- what the adversary knows about the protocol and defense policy;
- whether endpoints, switch program, controller, and relay are trusted;
- what happens if the adversary observes the relay-facing link;
- why TCP timestamps must be absent for the stated timing argument;
- what traffic classes are eligible for shaping;
- what retransmissions, loss, reordering, non-49-byte responses, unsupported DNP3 functions, and malformed traffic do;
- the single-device and single-session evaluation limits.

Define goals as testable properties. Separate:

- CLRT policy normalization;
- fixed eligible segment vector;
- protocol-valid reconstruction;
- master-visible J independence;
- testbed preservation;
- safety.

List relay-facing `T0+J` verification, exactly-once relay delivery, full payload-length hiding, encrypted payload semantics, multi-device anonymity, and resistance to all traffic-analysis features as non-goals or unverified properties, as appropriate.

## 8.4 Implementation

Structure the Implementation from the system boundary inward:

1. physical topology and port roles;
2. one-program P4 pipeline;
3. parser and transaction classification;
4. absolute timestamp/deadline computation;
5. pktgen trigger and blocker reservoirs;
6. RRC queue ladder and release behavior;
7. PRE replication and egress carving;
8. BOR epoch, readiness, hold, release, and retirement state;
9. independent dp8/dp10 scheduling domains;
10. control-plane configuration and readback;
11. retransmission, stale-state, budget, watchdog, and failure behavior;
12. safety guard and testbed restoration;
13. hardware resource fit and implementation limitations.

For every mechanism, use the same explanatory pattern:

```text
problem -> state/input -> decision -> packet/queue effect -> release condition
-> observable output -> failure behavior -> evidence source
```

Name the relevant code symbols, tables, registers, ports, queue IDs, and scripts when they help a reviewer map prose to implementation. Do not turn the section into a code listing. Use short pseudocode or a state table only when it clarifies behavior better than prose.

Explain the one-outcome/one-commit design: earlier logic computes a compact `meta.outcome`, and a terminal `tbl_commit` applies port, queue, drop, bypass, or multicast effects. Connect this structure to auditability and the 12-stage fit.

Include hardware-only defects only when they explain the final design or a necessary invariant. Do not narrate the entire debugging history. The shared-scheduler failure, T0 anchoring, commit-default behavior, BOR spent state, pktgen profile separation, full `configure-all`, port setup, BFRT write scope, TCP timestamp control, and missing relay tap are candidates. Place development history in an appendix or implementation-notes artifact if it interrupts the final mechanism.

## 9. Figures and diagrams

Inspect how the target papers use figures to establish the threat, architecture, and mechanism. Create original figures that serve the same explanatory roles without copying their layout or artwork.

At minimum, evaluate whether the rewritten sections need:

1. a system/threat-model figure showing the observation point and trusted boundary;
2. a native-versus-defended packet timeline with `T0`, `T0+A`, `T0+R`, and `R-A`;
3. an RRC queue-reservoir diagram with qid 7/6/5/4;
4. a 49-byte DNP3 response and `[28,21]` carve diagram;
5. a BOR SELECT-to-OPERATE state/timeline with the relay-facing measurement gap marked explicitly;
6. a shared-scheduler-failure versus two-domain-fix diagram;
7. a one-program P4 pipeline diagram.

Figure rules:

- Use vector PDF/SVG or repository-native drawing sources where possible.
- Use consistent fonts, colors, line weights, notation, and terminology.
- Keep text readable at two-column NDSS scale.
- Make captions self-contained and claim-bounded.
- Mark measured, modeled, and unobserved events differently.
- Do not present inferred relay-facing behavior as a captured measurement.
- Do not fabricate topology, queue behavior, or packet bytes.
- Preserve editable figure sources.
- Reference every figure in the text and explain why it matters.

## 10. Citation and Zotero requirements

Create a new Zotero collection named exactly:

```text
OBfus_defense
```

Do not create duplicates when a verified item already exists. Add the existing verified Zotero item to the new collection.

For every citation:

1. Use Semantic Scholar to discover candidates and retrieve stable metadata.
2. Verify title, full author list, venue, year, pages, DOI, and URL against the publisher, proceedings, DOI registry, or authoritative paper PDF.
3. Prefer the primary paper over a survey or secondary description.
4. Confirm that the cited source supports the exact sentence.
5. Store the verified item in `OBfus_defense`.
6. Export a clean BibTeX file for the paper.

Use NDSS-compatible numeric citations in order of first appearance. Preserve existing citation keys only when their metadata is correct and doing so avoids unnecessary repository churn. Merge duplicates. Normalize venue names and DOI formatting. Do not fabricate metadata, citations, page numbers, quotations, or access dates.

Produce a citation-audit table:

```text
paper claim | citation key | source title | supporting page/section |
metadata verified against | Zotero status
```

Direct quotations should be rare, short, exact, page-located, and necessary. Prefer accurate paraphrase.

## 11. Required quantitative evidence checks

Before writing result previews or implementation claims, reproduce or inspect the final analysis outputs. Confirm, at minimum:

- native and defended READ/SELECT sample counts and CLRT statistics;
- defended medians and standard deviations;
- eligible native and defended segment vectors and counts;
- TCP-sequence continuity, DNP3 block CRC, and IP/TCP checksum validation;
- zero unsplit eligible defended escapes;
- BOR J values, transaction counts, ACK/echo offsets, invariant gap, spread, and outliers;
- Jensen-Shannon distance versus divergence terminology;
- mutual information bins and permutation-null intervals;
- READ-versus-SELECT classifier task, split, balanced accuracy, and chance baseline;
- absence of TCP timestamps in final defended captures;
- compiler stage usage and binary/source identity;
- all-output-open and point-guard safety evidence;
- manifest and reproduction status.

Do not copy numbers from the old manuscript when the final verdict or reconstructed CSV differs.

## 12. Editing and version-control rules

- Inspect repository status before editing.
- Preserve unrelated user changes.
- Create a dedicated rewrite branch or an isolated worktree if the repository workflow permits.
- Do not overwrite the only copy of the current sections.
- Keep labels, macros, and citation keys stable unless a correction requires change.
- Make focused commits with messages that identify the rewritten section or citation/figure change.
- Do not push, open a pull request, or merge unless explicitly authorized.

## 13. Quality gates

The rewrite is not complete until all gates pass.

### Technical integrity

- Every quantitative claim maps to final committed evidence.
- Measured, modeled, inferred, and unobserved claims use different wording.
- No sentence claims relay-facing `T0+J` capture or exactly-once hardware delivery.
- No sentence claims multi-device anonymity from one SEL-751.
- No sentence describes `[28,21]` as hiding the total 49-byte length.
- No sentence claims byte identity to an unavailable source oracle.
- RRC, BOR, A, R, J, T0, CLRT, ports, queues, and observation points are consistent.

### Citation integrity

- Every nontrivial prior-work claim has a supporting citation.
- Every citation supports the local sentence.
- Metadata are verified and deduplicated.
- The Zotero `OBfus_defense` collection and exported BibTeX agree.
- The bibliography follows the NDSS template.

### Writing quality

- No leading qualifying sentence or adjective-only setup.
- No canned AI phrases or inflated claims.
- No paragraph merely restates its heading.
- Every paragraph has one clear function in the section argument.
- Related Work is comparative rather than enumerative.
- Threat assumptions and non-goals are explicit.
- Implementation explains mechanisms and failure behavior, not only components.
- Captions are self-contained and readable without the main text.
- Prose is original and does not reuse target-paper sentences.

### Build and visual quality

- Run the complete LaTeX build, including bibliography passes.
- Resolve undefined references, multiply defined labels, missing citations, and fatal warnings.
- Check for overfull/underfull boxes and fix material layout problems.
- Render the PDF and inspect every revised page at readable resolution.
- Verify figure labels, axes, legends, fonts, line thickness, placement, and two-column readability.
- Confirm that the final page count and section balance remain plausible for NDSS.

## 14. Deliverables

Produce all of the following:

1. revised LaTeX source for the four sections;
2. revised and verified bibliography/BibTeX;
3. Zotero collection `OBfus_defense` populated with verified references;
4. editable sources and final versions of new or revised figures;
5. a successfully compiled paper PDF;
6. `STYLE_PROFILE.md`, summarizing the target-corpus characteristics actually applied;
7. `CLAIM_EVIDENCE_LEDGER.md`;
8. `CITATION_AUDIT.md`;
9. `REWRITE_LOG.md`, listing files changed, major argument changes, removed overclaims, added limitations, citation changes, figure changes, commands run, and any unavailable workflow fallback;
10. a concise section-by-section diff summary;
11. a list of unresolved decisions that genuinely require author input.

The final report must state:

- which commit or working-tree state was edited;
- the exact build command and whether it passed;
- which target papers drove each section's structure;
- how many Zotero items were added, reused, corrected, or rejected;
- which claims were narrowed or removed;
- whether any result or implementation fact could not be verified;
- confirmation that no hardware action or experiment rerun occurred.

## 15. Execution behavior

Proceed autonomously through inspection, extraction, style analysis, citation research, drafting, figure revision, compilation, and audit. Ask a question only when a missing choice would materially change the scientific claim or repository target, such as multiple plausible manuscript entry points with conflicting content.

Do not ask for stylistic approval after every section. Complete a coherent first rewrite, compile it, run the audits, and then present the bounded unresolved decisions.

Do not declare completion based only on fluent prose. Completion requires a successful build, visual inspection, verified citations, a populated Zotero collection, and a claim-to-evidence audit.

---

