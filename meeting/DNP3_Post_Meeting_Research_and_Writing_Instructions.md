# DNP3 timing paper: post-meeting research and writing instructions

Prepared 8 September 2026. Version 5: incorporates Dr. Lin's Introduction, whole-paper blueprint, scope-driven argument, respectful treatment of prior work, and checks against self-defeating claims. His prose and meeting establish the writing authority; the GitHub draft is the work to align. The meeting date itself was not supplied.

## 1. Purpose and source authority

Complete a clear, evidence-grounded timing-obfuscation paper. Retain the existing framework and four-queue ACK/RESPONSE mechanism. Concentrate the next work on explanation, parameter selection, necessary measurements, and writing. Constant target CLRT remains the implemented policy. READ, SELECT, and OPERATE remain relevant, but their timing anchors and evidence must stay distinct.

Use this order of authority:

1. The user's current directions and the latest meeting determine scope and priorities.
2. Dr. Lin's actual edited prose determines the intended argument and writing register.
3. Source code, deployed-build provenance, captures, and reproducible analysis determine technical facts.
4. Current writing guidance supplies consistent terminology and structure where it agrees with the above.
5. Older contracts, slides, summaries, and assistant explanations are historical context. They do not override new directions or measured evidence.

An advisor's suggestion can establish a research question without establishing its answer. A document labelled PASS or authoritative can still contain stale or contradictory statements. Record such conflicts and resolve the specific claim.

### Context recovered

The inspected remote draft is `paper/campaign-v1-ndss-corrections-20260828`, at commit `d895d53b1db5d4e9dec56f418f6c893be8ffd76a`. It includes revisions dated September 7. Its manuscript entry point is `paper/rewrite/main.tex`. This is the draft to bring into alignment with Dr. Lin's text and meeting, not the writing authority. The user's previously identified local working directory is `/home/philip/Projects/DNP3-size-probe/paper/rewrite/`; its current local branch, uncommitted changes, and parity with the remote were not inspected in this session.

Files read include the current README, writing guide, Introduction, Design, Evaluation, September 7 patch record, event-semantics table, claims and limitations, instrumentation audit, and Formby review. Targeted source inspection confirmed the common native-ACK anchor and the `da_dr` RESPONSE-deadline parameter. Earlier `LIN_STYLE_CONTRACT.md` and `LIN_STYLE_PROFILE.md` were read in full, together with the opening of RAINCOAT and an earlier meeting summary. This is a targeted context review, not a reproduction of the experiments or an exhaustive audit of every repository file.

## 2. Writing philosophy: the governing rule

**Every paragraph should help the reader understand why this particular problem needs this particular design, and every claimed benefit should lead to evidence the paper actually provides.**

Simplicity is an argument discipline. It is more than replacing long words with short ones. Decide the paragraph's purpose before drafting sentences. Then explain the mechanism and its consequence in the order the reader needs them.

### Rules for every drafting and revision pass

1. **Write the argument first.** Put a one-sentence purpose above each draft paragraph in working notes. If the paragraph has two unrelated purposes, split or relocate it.
2. **Explain why before how.** Give the problem or constraint before introducing the design choice that addresses it.
3. **Move from general to concrete.** State that the timing features differ, then identify the ACK-to-RESPONSE interval and explain why it is informative. A general statement must be followed by enough detail to make it meaningful.
4. **Make adjacent sentences connect.** Use the same subject or established term to carry the reader forward. Use “Because,” “For example,” or “Consequently” only when it expresses the actual relation. Do not satisfy a connective quota.
5. **Use plain, complete sentences.** Prefer “use,” “hold,” “release,” “measure,” and “change.” Name the actor and action. Avoid long strings of qualifications and fragments without a main clause.
6. **Repeat technical terms consistently.** A new synonym or symbol makes the reader ask whether the meaning changed. Prefer original CLRT, target CLRT, and measured CLRT over unexplained replacement variables.
7. **Introduce only gaps this paper addresses.** Do not motivate payload confidentiality, universal reconnaissance prevention, or all physical fingerprints when the work evaluates selected timing features.
8. **Separate motivation from implementation.** The Introduction should explain the need and idea. Queue details belong after the timing model and parameter choices. Register names and pipeline details belong in Implementation only when they explain a constraint or contribution.
9. **Treat prior work fairly.** Describe its purpose and what it achieves before stating the assumption that limits transfer to this setting. Do not make prior work sound weaker than the source supports.
10. **Use examples to explain the claim.** Avoid incident lists and duplicated impact statements. Verify each incident-specific statement independently; a source about Ukraine does not automatically support a six-month claim about Stuxnet.
11. **State evidence boundaries beside the claim.** “Observed on the master-facing link” and “one physical relay” are part of a result's meaning. Preserve them without burying the reader in audit terminology.
12. **Do not force novelty language.** A firstness claim requires a literature-supported, narrowly defined comparison. Older style documents that made it mandatory have been superseded.
13. **Preserve Dr. Lin's logic during editing.** Log substantive changes to his passages with original text, revision, and reason. Correct false or unsupported claims rather than preserving them as a matter of style.
14. **Judge readability as a reader.** A successful lint check does not establish a coherent argument. Do not optimize word counts, reading-grade scores, or vocabulary frequencies at the expense of clarity.

### What the supplied Introduction demonstrates

Dr. Lin uses a short chain of explanation. Paragraph 1 establishes the importance of device fingerprinting, narrows to ICS, explains the shift in the attacker's interest, and gives incidents as context. Paragraph 2 names the existing response, identifies the features it changes, explains the two families of techniques, and then motivates switch offloading through overhead. His new paragraph 3 states two reasons existing approaches do not directly apply, explains each reason, and makes the first concrete through the ACK-to-RESPONSE example.

The repeated terms are deliberate: “device fingerprinting,” “traffic obfuscation,” “features,” and “ICS.” Do not replace them with a rotating set of synonyms. “Consequently” links a premise to its consequence; “For example” makes a general statement concrete; “Since” supplies the reason for the next statement. Their purpose is logic, not a recognizable writing tic.

Follow the supplied three-paragraph argument closely. Do not replace it with a new incident-led opening, an expanded encryption discussion, a protocol-parser explanation, or an implementation catalogue. Extend it with the framework paragraph and contributions described in the meeting.

### Paragraph review questions

- What does this paragraph establish?
- Why does the next sentence follow?
- Is every technical term already understandable or defined here?
- Does the example explain the stated problem?
- Is the final claim narrower than, or equal to, the supporting evidence?
- Does the paragraph prepare the next question the reader should ask?

### Scope determines the argument

Dr. Lin explains that even a long paper has limited space and must provide depth on a specific idea. Build the motivation around the specific problems this framework addresses. Every major gap introduced should lead to a design response, and every claimed response should lead to evidence. A plausible but unrelated problem does not belong in the central motivation merely because it makes the domain sound more challenging.

Use a working argument map before writing:

| Link | Question to answer |
|---|---|
| Problem | Which particular information can the observer infer, and why does it matter here? |
| Prior work | What do the relevant existing approaches achieve, and under which assumptions? |
| Scope-specific gap | Which assumption or feature mismatch matters in our selected deployment? |
| Design response | What exactly does our framework change to address that gap? |
| Evidence | Which measurement or analysis supports that response? |
| Boundary | What remains visible, unsupported, or outside the selected objective? |

If a proposed motivation has no design response, narrow or remove it from the central argument. If a claimed design response has no evidence, mark it as unresolved and either complete the necessary evaluation or narrow the claim. Do not expand the implementation simply to justify an overbroad introductory sentence.

This is not an instruction to conceal weaknesses. Unaddressed problems that materially limit a claim, residual leakage, and deployment assumptions must still be disclosed. Distinguish an unrelated research problem, which need not be introduced, from a limitation of our own result, which must be reported.

For this paper: fingerprinting motivates the application, but selected timing features define the demonstrated intervention. Plaintext operation motivates the deployment constraints, but does not make payload confidentiality a contribution. The queue framework leads; its evaluated READ/SELECT and OPERATE cases support bounded timing claims. Keep each step within those boundaries.

### Respectful and accurate treatment of prior work

Dr. Lin's instruction is to explain limitations without trashing earlier research. Treat this as a scientific writing rule, not merely a strategy for avoiding an offended reviewer.

For each relevant work, describe its objective and useful result first. Then identify the assumption, feature, deployment, or cost that differs from ours. Explain why that difference matters for our objective. Support that comparison with the source, and distinguish a design assumption from a demonstrated failure.

Prefer the structure: “This approach addresses [objective] in [setting]. It assumes [verified condition]. Our setting requires [specific difference], so direct use would require [supported adaptation or missing capability].” This is an argument template, not text to repeat mechanically.

Do not write that existing techniques are ineffective, impractical, or unable to work in ICS as a class unless the evidence establishes that claim. Do not imply an approach failed at an objective it never claimed to address. Do not turn an untested transfer into a measured failure, or convert our different objective into universal superiority. Do not generalize an encrypted-channel assumption from a subset of papers to all obfuscation research.

During development, record one or two accurate sentences about each relevant paper. Once our design and contribution are stable, organize Related Work by the comparisons that matter. Refine the contrast then, without changing the earlier paper's facts to make our contribution appear stronger. Keep the Introduction's selective gap argument consistent with the fuller Related Work discussion.

## 3. Introduction: the required argument

### Avoid arguments that undermine the paper

This is a central part of Dr. Lin's instruction. Before retaining a sentence, ask what it leads the reader to expect, whether that expectation matches our design, and whether the paper supplies the needed evidence. A technically true sentence can still be misplaced if it redirects the argument toward a different research problem.

| Self-defeating move | Required correction |
|---|---|
| Motivate the legacy plaintext setting, then conclude that our central task is hiding timing after encryption. | Keep the chosen deployment and contribution consistent. Encryption-visible timing is not inherently false; here it changes the question without explaining why. |
| Say the goal is to defeat reconnaissance or device fingerprinting generally. | Identify the selected timing features and the evaluated setting. Explain their relevance without promising universal protection. |
| Make arbitrary payload modification and CRC repair the central obstacle in a paper that only schedules real packets. | Explain the relevant assumptions and why scheduling real protocol events addresses our selected objective. Move necessary protocol details to their proper section. |
| Say all obfuscation requires encryption or cannot work in ICS. | State the assumptions of the cited techniques and the specific mismatch with our setting. Avoid an easily refuted universal claim. |
| Claim the selected target is independent of native timing in every transaction. | State the response-availability condition and disclose the observed tail. The ideal replacement equation has a domain of validity. |
| Claim the same switch must produce identical, negligible variance. | Treat that as a hypothesis to measure under the relevant conditions, not a consequence established merely by shared hardware. |
| Call the OPERATE packet interval physical actuation time, or transaction-class results device identification. | Name the measured quantity and classification task correctly; do not substitute the broader claim. |
| Call a tested delay optimal, universally safe, or standards-compliant. | State the tested operating point, selection basis, applicable requirement, and evidence. |
| Describe the framework as supporting every policy its conceptual model permits. | Distinguish the design space from modes actually implemented and validated. |
| Add an interesting new gap that requires another mechanism or experimental program. | Remove it from the central motivation unless it is necessary to the actual contribution. Do not create work simply to rescue an unnecessary claim. |

Review the whole paper for consistency, not only individual sentences. The Introduction, threat model, design objective, equations, captions, evaluation, and conclusion must describe the same intervention and evidence boundary. For every major claim, trace the supporting design explanation and result. For every strong adjective or universal statement, check whether a precise, narrower statement is more accurate.

Do not turn this rule into hiding adverse evidence or avoiding fair comparison. Residual leakage and material limitations belong in the paper. Present each as a concrete boundary: what was observed, which claim it limits, and which narrower conclusion still follows. Avoid speculative self-criticism that introduces unrelated requirements, but retain limitations necessary for the reader to assess the contribution honestly.

Preserve the latest meeting's paragraph roles. Do not revive older paragraph numbering that refers to discarded drafts.

| Part | Reader's question | Content and boundary |
|---|---|---|
| Paragraph 1 | Why does fingerprinting matter? | Define device fingerprinting, explain its role in reconnaissance, and narrow to ICS device models and control behavior. Do not claim to disrupt all reconnaissance. |
| Paragraph 2 | What do existing defenses do? | Explain traffic obfuscation through size and timing changes. Introduce programmable-switch approaches at a high level where supported. Size is background, not a contribution. |
| Paragraph 3 | Why is a different design needed here? | Explain the two meeting arguments: different relevant timing features, and encrypted-channel assumptions that do not hold in the selected legacy plaintext setting. Name the relevant prior approaches and support their assumptions. |
| Paragraph 4 | What is our idea? | Explain that the switch schedules the release of selected real protocol packets to change a timing feature, while preserving endpoint operation and DNP3 contents. Present the framework before the hardware detail. |
| Contributions | What does this paper establish? | State the framework, its concrete realization, and bounded evaluation. Match each contribution to a section and evidence. |

The current Introduction's third paragraph pivots from encryption-visible timing to DNP3 CRC reconstruction. That does not follow the meeting's intended argument. Replace that paragraph's logic: the issue to explain is why the cited obfuscation assumptions do not directly transfer to the selected setting. Do not turn it into a byte-reconstruction design discussion in a timing-only paper.

In the newly supplied text, the final block beginning “First, the leaked features are different” repeats the gap paragraph. Based on the meeting's direct criticism of those same arguments, treat this as superseded draft text. Remove it from the active Introduction and preserve it in the revision history. In particular, remove the claims that protocol exchanges leave no flexibility and that arbitrary padding necessarily breaks reassembly/CRC as the motivation for this timing-only contribution. Do not splice that block into Dr. Lin's replacement paragraph.

Apply restrained corrections to the new paragraph: “TCP acknowledgment packets,” “each vendor,” “device models or types of operations,” and the duplicated “the.” Clarify the antecedent of “this time” and the phrase “execution time there” without changing the argument. Verify and scope the statement about encrypted channels to the cited methods. Verify the claim connecting materials/algorithms to the particular timing feature. These are factual and grammatical refinements to Dr. Lin's structure, not permission to invent a different structure.

Preserve the incident sentence's role, but verify whether reference [1] supports the stated duration for both incidents before retaining that exact factual claim. Do not reconstruct citation keys from the visible reference numbers; map them to the actual bibliography and read the sources.

Use care with the second gap. Do not write “all ICS traffic is unencrypted” or “all traffic obfuscation requires encryption.” Establish which techniques depend on hiding the distinction between original and added/transformed traffic, and explain why visible protocol contents can expose that distinction in the chosen deployment. Then connect the gap to scheduling existing packets. This does not mean the framework hides visible function codes or all payload information.

The general-to-specific example must also preserve physical meaning. CLRT can reflect device processing behavior. Differences in electromagnetic materials belong to physical-actuation examples, not automatically to READ processing. The meeting's informal examples should not become a claim that every timing interval measures physical execution.

## 4. Scope decisions and what they supersede

| Decision | Instruction |
|---|---|
| Retain the mechanism | Keep the current four-queue ACK/RESPONSE design. Do not start another architecture or refactor simply because the meeting is over. |
| Retain constant replacement | Use the configured constant CLRT policy as the main case. Distribution morphing or masquerading is optional future scope, not a new deliverable. |
| Stop expanding shifting | The advisor did not request a shifting research track. A short analytical comparison may clarify variance; remove its prominence if it distracts. |
| Timing-only paper | Keep size obfuscation out of methods, contributions, and results. Preserve relevant prior-work context. |
| Framework leads | READ/SELECT timing and master-visible OPERATE timing demonstrate the framework. Do not describe them as unrelated systems. |
| Preserve fail-open behavior | Keep unmatched traffic forwarding and existing bounded recovery behavior. Do not replace them with dropping. |
| Evaluation has limits | Do not claim device anonymity, physical actuation protection, or exactly-once relay delivery from master-facing observations alone. |

Earlier requests for size work, extensive hardening, other hardware platforms, and broad new campaigns are not reactivated by this transcript.

## 5. Timing model and notation: fix before rewriting equations

Dr. Lin's correction is substantive: use ACK delay for the interval from native ACK arrival to ACK release, RESPONSE delay for the interval from native RESPONSE arrival to RESPONSE release, and CLRT for the ACK-to-RESPONSE interval.

For explaining that correction, retain the user's timeline endpoints `t_A`, `t_R`, `e_A`, and `e_R`. Use descriptive CLRT subscripts rather than introducing an unrelated alphabet. The following are definitions at a common observation boundary, not a claim that all four endpoints were captured:

\[
\mathrm{CLRT}_{\mathrm{original}}=t_R-t_A,\qquad
D_A=e_A-t_A,\qquad D_R=e_R-t_R.
\]

Therefore:

\[
\mathrm{CLRT}_{\mathrm{new}}
=e_R-e_A
=\mathrm{CLRT}_{\mathrm{original}}+D_R-D_A.
\]

For ideal constant replacement:

\[
e_A=t_A+D_A,\qquad
e_R=t_A+D_A+\mathrm{CLRT}_{\mathrm{target}},
\]

and the required RESPONSE hold is:

\[
D_R=D_A+\mathrm{CLRT}_{\mathrm{target}}
-\mathrm{CLRT}_{\mathrm{original}}.
\]

**These three design quantities are coupled.** Once original CLRT, ACK delay, and the target gap are specified, the required RESPONSE hold follows. Do not call them three independent constant knobs. A constant pair of native-relative packet holds would preserve the original CLRT variation; replacement requires the RESPONSE hold to vary with arrival time.

The original RESPONSE must exist before its scheduled release. Ideal replacement requires:

\[
t_R\le t_A+D_A+\mathrm{CLRT}_{\mathrm{target}}.
\]

The ACK can leave before the native RESPONSE arrives while still satisfying this condition. That event order alone does not imply packet loss. When the RESPONSE misses its deadline, describe the actual fail-open path separately. Do not assign it a negative holding time or claim a constant target was achieved.

### Mapping to the current implementation

The current code and manuscript use `D_R` for the configured target gap, with `da_dr = D_A + D_R`, and arm both deadlines from the native ACK arrival. In the meeting's new interpretation, the existing code's `D_R` maps to target CLRT; it does not map to the RESPONSE's actual native-relative holding time.

Write a notation migration table before editing formulas, diagrams, captions, and prose. Keep original configuration field names in evidence files and record their paper meanings. Do not silently rename archived CSV columns or control-plane parameters.

Also distinguish scheduled release from actual release. The inspected source calculates the RESPONSE deadline from `t_A + da_dr`; it does not start a new timer at measured ACK departure. Thus `e_R = e_A + target CLRT` is the ideal relation, not proof that the actual hardware uses the ACK departure as its anchor.

READ and SELECT use that native-ACK anchor. OPERATE uses request-relative `A`, `R`, and `J` in the existing implementation. Preserve those established control-path quantities; do not apply the READ model to the complete SBO exchange without deriving the mapping.

## 6. Research task A: a defensible ACK-delay range

Question: how much additional ACK holding can this deployment tolerate before it disrupts transport behavior?

Start with the standards algorithm and the actual master implementation. RFC 6298 defines adaptive RTO computation using smoothed RTT and RTT variation, and timer management for outstanding data. Its recommendations are not a measurement of this master's timeout. See [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298).

Perform a focused literature and implementation review. Prefer an interpretable conservative estimate or deployment calibration. Machine learning was suggested as a possibility; it is not a requirement and should not become a separate research program.

Required steps:

1. Identify the master OS/TCP stack, relevant versions/settings, connection reuse, and which transmitted bytes the selected ACK acknowledges.
2. Distinguish TCP retransmission, other recovery events, and application retries. The reported approximately 80 ms event is an observation to classify, not a universal RTO.
3. Define the remaining time budget at the ACK-hold point. ACK holding begins after some sender-to-device-and-back time has already elapsed. Include remaining path time, release variability, and a conservative margin.
4. Evaluate whether host-observable timer information or a simple calibration method is available. A switch-side RTT estimate must not be described as exact knowledge of the sender's timer.
5. Check that the method remains conservative as the connection adapts; do not infer safety from a single successful delay.
6. Propose only the measurements needed to validate the chosen range. Reuse captures and logs first. Record the environment and uncertainty explicitly.

Output: a short parameter-selection note, a supported operating range for the tested deployment or an explicit unresolved bound, and a focused validation specification. No claim that 20 ms is universally safe or optimal.

## 7. Research task B: an application response-latency budget

Question: how much response holding is compatible with the operation being performed?

Identify the specific standard, profile, or operator requirement applicable to READ, SELECT, and OPERATE. The transcript does not identify the standard or establish a universal 100 ms budget. Its 10 ms margin is a discussion example, not an approved requirement.

For each relevant requirement record the exact edition/clause, operation class, measured endpoints, numerical bound, and why it applies to the testbed. Distinguish a communications transfer requirement from an end-to-end application completion deadline. Account for baseline communication and device processing when calculating the remaining overhead budget.

Distinguish a per-receive timeout from an overall transaction deadline and from an operational service requirement. After request bytes are TCP-acknowledged, awaiting the application RESPONSE is not simply another countdown of the master's TCP retransmission timer for that request. The outstation's own outstanding response data can also have transport consequences; inspect the actual exchange rather than merging these timers.

Output: an operation-to-requirement table and a clear selection argument for allowable added response delay. If no applicable standard can be verified, state an explicit deployment requirement and label it accordingly. Do not claim standards compliance from zero observed timeouts alone.

## 8. Research task C: release variability and residual spread

Dr. Lin explicitly asked that the small release delay be measured, even if it is difficult to see in a plot. Treat this as necessary measurement work, with a method that can actually observe the interval.

Define each endpoint: deadline expiry, last relevant blocking event, scheduler service, loopback re-entry, external egress, and master-side capture are different events. “Time to drain the queue” is too broad unless the measured interval really has those endpoints. Prefer “post-deadline release delay” and explain the physical operations it includes.

Because the current ACK and RESPONSE deadlines share an anchor, actual measured CLRT can include RESPONSE release delay minus ACK release delay, plus differential path/capture effects. If retaining epsilon, define it as the net residual for that equation; do not call it a single nonnegative queue delay. A fixed target has no variance itself, so variance in target-plus-residual equals variance of the net residual. That identity does not identify the residual's physical cause.

Separate three cases: packets present before their deadlines, late native RESPONSE arrivals, and fail-open expiry. Do not attribute every tail observation to queue draining. A narrow histogram alone cannot demonstrate that release variation is device-independent.

The September 7 instrumentation audit found inactive timestamp write actions and no demonstrated external release timestamps in the preserved evidence. It also records incomplete provenance for the loaded binary. Do not promise a control-plane-only readback of release time. Check for usable existing observations first; otherwise specify external synchronized capture or minimal instrumentation that observes the needed boundary. Account for timestamp precision, clock alignment, transaction matching, and instrument effects.

This measurement requirement does not authorize an architectural redesign. If a new build is required, identify it separately and keep its evidence separate from `campaign_v1`. Prepare the method and concrete change before any deployment decision.

Output: timing endpoint table, feasible measurement method, minimal collection plan, and statistics whose precision matches the instrument. Never label nanosecond clock resolution as demonstrated nanosecond measurement accuracy.

## 9. Figures and statistics: fewer, clearer views

The primary figure should show measured CLRT histograms before and after obfuscation. Dr. Lin explicitly preferred bins over a mark at each precise measured value. Use the relevant Formby figures as an explanatory reference, not as a mandate to copy their layout.

- Main labels: “Timing OFF”, “Obfuscated”, “CLRT (ms)”, and “Transactions (%)”.
- Use common bin edges and full-range horizontal limits for each main before/after comparison. Choose a simple, justified bin width; 1–2 ms were illustrative suggestions, not a fixed requirement for the zoom.
- Add a clearly labelled narrow zoom around the target if needed. Report the percentage of all transactions in that condition within the window; do not renormalize the visible subset to 100%.
- Prefer a readily readable linear view; if a logarithmic axis is needed to expose tails, label it explicitly.
- Report n, mean, sample standard deviation in ms, and sample variance in ms². Use n−1 for sample variance. Keep devices, classes, settings, and corpora separate.
- Show all relevant observations or disclose exclusions and their reasons. Do not remove tails to make the result look constant.
- Use a run-level variance dot plot only if it answers an additional necessary question. It is not required merely because an earlier assistant proposed it. Connect dots only where pairing is supported.
- Keep shifting as a small analytical explanation, if retained. The loaded program has no measured shifting arm. The latest meeting does not call for another large shifting figure.

Useful teaching example, not experimental data: original (1,2,3) ms has mean 2, sample STD 1, and sample variance 1. Shifting by 2 gives (3,4,5), mean 4 with unchanged spread. Ideal replacement gives (4,4,4), mean 4 with zero spread. Actual replacement must include the measured residual and deadline misses.

The 22 grouped runs are within one campaign. They are not independent deployments. Preserve the existing distinction between descriptive fold-score spread and a confidence interval. Do not combine the retired 999/599 sample comparison with the current campaign or reuse old headline values by memory.

## 10. Design and implementation: the reader's three questions

Dr. Lin supplies a blueprint for the entire technical argument, not only an introduction style. His three-part explanation is: present the model; explain the design space and parameters; show the four-queue implementation. Evaluation then answers the questions that this explanation raises. The following subsection names operationalize his directions; they are not titles dictated verbatim in the transcript.

### Design A: timing model

Reader's question: what does the observer measure, and what are we changing?

Begin with a simple READ timeline showing native ACK and RESPONSE arrival, their scheduled and actual releases where needed, original CLRT, and target/new CLRT. Define each quantity by its endpoints. Derive the replacement relation only after the reader understands the picture. Explain when a response is available in time to meet the schedule and what happens otherwise. Keep shifting to a brief clarification if needed; it is not a second proposed mechanism.

Output of this subsection: a reader can explain the intended timing transformation without knowing P4.

### Design B: design space and parameter choices

Reader's question: how do we choose the timing, and what prevents an arbitrary choice?

Discuss the three quantities Dr. Lin identifies: ACK delay, RESPONSE delay, and the new CLRT. Explain what each affects and their mathematical coupling. Associate ACK delay with TCP feedback/retransmission constraints, RESPONSE delay with the operation's service requirement, and target CLRT with the obfuscation objective. Then explain the feasible combination of those constraints, response availability, and the actual hold mechanism's limits. Do not present a configured value as self-justifying.

Separate the framework from the selected policy. Constant CLRT is the current neutralization objective and the simplest demonstrated policy. Other output patterns are a possible later use of the framework, conditional on evidence and paper space. They are not required additions to the present implementation.

Output of this subsection: a reader understands why the selected settings are reasonable, what trade-offs they make, and which selection questions remain open.

### Implementation: realize the model using queues

Reader's question: how does the hardware enforce the timing decisions?

Begin with ordinary queue scheduling, which a networking reader can follow. Explain the ACK blocker/hold pair and the RESPONSE blocker/hold pair, what waits in each queue, how blocking sustains a hold, and how expiration permits release. Follow one READ transaction through the mechanism. Explain why the queue arrangement is needed to realize the model on the target hardware.

Then map the explanation to P4 and the Tofino traffic manager. Include only details that explain feasibility, an implementation constraint, correctness, or a claimed contribution. Describe transaction association, independent timing paths, cleanup, and fail-open behavior in their functional roles before naming internal tables or registers. Keep the actual OPERATE mechanism and anchor distinct where the second case study requires them.

Output of this section: a reader understands both that the queue mechanism can implement the policy and which hardware constraints the implementation must satisfy. The next natural questions are how accurately it does so, how efficiently it operates, and what resources it consumes.

### Required connection between sections

Each section inherits a question from the previous one and leaves a specific question for the next. Do not write Design as a list of implemented features, Implementation as a source-code walkthrough, or Evaluation as a chronological account of experiments. The evaluation plan below must close the questions raised here.

**First: what timing do we change?** Present a readable transaction timeline and define original CLRT, packet holds, target CLRT, and the observer's measurement. Explain availability and release timing in plain language.

**Second: what settings are feasible?** Present the coupled design quantities and the factors that constrain them: TCP feedback timing, application latency, response availability, and the actual implementation's hold limits. Identify a feasible operating region; do not claim that every input can be normalized.

**Third: how do queues realize the schedule?** Introduce the four ACK/RESPONSE queues using familiar priority scheduling: ACK blocker and hold queues, RESPONSE blocker and hold queues. Explain internal blockers, deadline expiry, held-packet service, matching, and recovery before register names or compiler details.

Verify the timer explanation against code. Existing Design prose describes K blockers as directly implementing a K-times-drain-time timer; earlier guidance instead distinguishes the deadline from the blocker population needed to sustain priority blocking. Resolve this locally before publishing. Separate maintaining the hold from residual draining after expiry. Do not copy either explanation without checking the actual expiry path.

The four-queue pair structure must not be confused with the total queue or internal-port count across the additional OPERATE mechanism. Map the implemented paths explicitly. Preserve RRC/BOR names internally where needed; do not lead the reader through acronyms before the behavior is clear.

The evaluated binary and the conceptual policy family are also distinct. The current evidence reports 16 installed dual-deadline release policies plus three controls in the 19-capture sweep. Do not claim hardware validation of response-only or ACK-only modes from their conceptual definitions.

## 11. Evaluation and claim discipline

Dr. Lin explicitly connects a clear queue explanation to the reader's next questions: can the design be more efficient, and can it satisfy P4 hardware constraints? He also asks for the residual release time to be measured and for the overhead parameters to be justified. Therefore, evaluation is the evidence for the model, choices, and implementation, not an unrelated collection of results.

Use this question-led sequence as the working blueprint, adapting existing objective labels rather than inventing another competing set:

1. **Experimental setting and measurement definitions.** Identify the hardware, workload, conditions, observation point, timing endpoints, and scope so the reader knows what every result means.
2. **Does the timing transformation achieve its objective?** Show original and obfuscated CLRT distributions, their mean and spread, and their relation to the configured target. Present the READ/SELECT and OPERATE cases under their respective models.
3. **How close is actual release to the intended schedule?** Measure the small residual where observable, state its physical interpretation, and separate it from availability misses and fail-open events. Avoid attributing unobserved internal events from a master-facing histogram alone.
4. **What overhead and operating range result?** Show ACK and response latency, coverage, transaction completion, transport behavior, and the supported parameter range against the applicable constraints. Use existing sweeps where they answer the question.
5. **Does the implementation satisfy hardware constraints efficiently?** Report supported resource usage and relevant performance evidence. Distinguish line-rate capability, offered test traffic, and measured throughput. Do not claim efficiency relative to another platform without a valid comparison.
6. **What security claim does the evidence support?** Relate the timing result to the evaluated attacker and feature set. Report residual leakage and scope limitations. Reduced variance alone is not a complete fingerprinting-defense result.

This ordering is a concrete application of his blueprint, not a claim that he dictated six evaluation subsections. Reuse the existing evidence and reorganize its explanation. Collect additional measurements only to answer a necessary unanswered question.

Each design question must have a matching evaluation answer:

| Question | Evidence to use or complete |
|---|---|
| Does measured CLRT concentrate at the target? | Histograms, mean/STD/variance, target-window coverage, and full tails. |
| Can the policy select different target gaps? | Existing policy sweep, with installed modes and offsets verified. |
| What limits coverage? | Native timing distribution and explicit schedulability assumptions; distinguish estimated coverage from directly observed switch misses. |
| What does the observer still learn? | Existing fixed/adaptive attacker results and feature definitions, including residual request-to-ACK leakage. |
| What operational overhead occurs? | ACK and response latency, observed completion/retransmission behavior, and the new selection arguments. |
| Does it fit the hardware? | Matching compiler/resource evidence and measured operation, with source-to-binary provenance limits. |

The current claim record reports 63,360 exchanges in 132 captures across 22 grouped runs, one SEL-751A and one Tofino-1, with size shaping off in both arms. These are repository-reported facts, not independently reproduced during this planning session. Use the gated `MANUSCRIPT_VALUES.json` when inserting numbers into the paper.

The adaptive two-feature classifier remains informative (reported balanced accuracy about 0.651), despite target-CLRT suppression. Keep this result: it explains the boundary of the selected-feature defense. Visible plaintext function codes are also outside a timing-only classifier's feature set. Do not claim that transaction types become unknowable.

Formby's reported physical-fingerprint experiment retained SER-based operation times after its unsolicited packet-arrival method gave no usable result. Our master-visible solicited OPERATE response-to-ACK interval is different. No physical actuation, SER timing, or per-transaction realized J is established by the current campaign. Do not claim suppression of that physical fingerprint. Equally, do not infer a universal impossibility theorem for all command-delay policies from the absence of this evidence. See [Formby et al., NDSS 2016, Section IV-B](https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf).

## 12. Ordered execution instructions

1. **Confirm the local working state.** In the user-identified repository, inspect applicable instructions, branch, commit, worktrees, dirty files, entry point, and evidence manifest. Preserve ongoing work. Do not treat `main` as the current paper merely because it is the default branch.
2. **Update the instruction hierarchy.** Incorporate this meeting and Dr. Lin's supplied Introduction into the active writing guide and retain historical sources. The user's current instruction to align the GitHub draft authorizes the corresponding writing corrections; old protected-text or approval statements must not prevent that alignment. Correct stale guide statements: the current campaign has size shaping off, the existing draft's evaluation has RO1–RO5, and the new notation changes the meaning of RESPONSE delay. Retain objective labels where useful; their number is not an advisor-mandated structure. Do not falsify a checker result or remove scientific validation to pass it.
3. **Produce the argument outline and notation mapping.** Resolve the intended paragraph roles and endpoint definitions before prose or figure edits. Distinguish schedule, observation, configuration fields, and paper terms.
4. **Draft Introduction and conceptual Design first.** Implement the meeting's third-paragraph correction and the model/design-space/queue-realization progression. Preserve the intended logic of the advisor-authored opening paragraphs. Record changes.
5. **Complete the two bounded parameter investigations.** Prepare the ACK and application-delay notes. Keep writing moving where the result does not depend on an unresolved number; use explicit working placeholders, never fabricated values.
6. **Prepare and execute feasible release measurement work.** Reuse valid evidence first. If instrumentation or capture changes are necessary, prepare the exact method and reviewable change; keep the original campaign intact.
7. **Revise the minimum necessary figures and evaluation text.** Use histograms as the primary spread explanation. Repair overclaims, stale values, unsupported causal attributions, and mode descriptions. Avoid another plot family without a clear question.
8. **Develop Related Work incrementally.** While reading, add one or two accurate sentences per relevant paper: problem, method, applicable assumption, and difference. Finalize its synthesis after the design and contribution are stable.
9. **Finish Abstract and Conclusion after the argument is stable.** Keep scope, terminology, and headline results consistent with the body. Verify every number and citation.
10. **Build and inspect.** Run the existing meaningful build/provenance gates, compile LaTeX, and inspect pages, equations, figures, captions, and references. Use nonbreaking citation spacing such as `claim~\cite{key}` and `Figure~\ref{label}`. Stop optional testing once the concrete remaining risks are resolved.

Completion means the paper has a coherent argument, one notation convention with a code mapping, an honest operating-region argument, a valid release-variability measurement or explicit measurement gap, clear figures, and evidence-bounded claims. A larger implementation or a larger collection of plots is not the completion criterion.

## 13. Instruction to the agent revising the GitHub draft

Revise the timing-paper draft to follow Dr. Lin's supplied Introduction and the latest meeting. Treat those as the authority for argument, organization, scope, and writing philosophy. Use repository source and captures to verify technical statements. Do not use the current GitHub wording or an older style contract to overrule the advisor's intended argument.

Start with a paragraph map: fingerprinting and its ICS importance; existing traffic-obfuscation techniques; the two reasons they do not directly transfer; our framework; contributions. Keep the meaning and sequence of Dr. Lin's first three paragraphs. Remove the duplicated superseded gap block beginning “First, the leaked features are different.” Make only necessary grammar, terminology, citation, and scientific-accuracy corrections to his text, recording the reason for each substantive change.

Then restructure Design around the timing model, the coupled design quantities and their constraints, and the queue realization. Explain each design choice before its P4 details. Preserve the existing mechanism and fixed target. Keep READ/SELECT and OPERATE anchors distinct. Use the detailed parameter, measurement, and evaluation instructions above to complete the evidence needed for the paper.

Update the repository writing guidance to reflect the same hierarchy and record any stale rule it supersedes. Reconcile notation across prose, equations, figures, captions, and the code-to-paper mapping. Retain data provenance, preserve unrelated changes, compile the manuscript, and inspect the output. Report the changes made, unresolved factual support, and any measurement still missing. A successful writing-style check alone is not completion.

## Source map

- Latest meeting transcript, Dr. Lin's Introduction, and the user's clarification that GitHub must follow them: primary scope and writing directions.
- Earlier project context retrieved in this session: timing-only scope, framework-first contribution, local rewrite path, and prior advisor guidance.
- `LIN_STYLE_CONTRACT.md` and `LIN_STYLE_PROFILE.md`: historical style documents read in full; not current authority where superseded.
- RAINCOAT, opening Introduction: direct example of motivation, prior-work positioning, mechanism, and consequence; not a template for this paper's scientific claims.
- [Current paper directory at inspected commit](https://github.com/akekulip/DNP3_obf/tree/d895d53b1db5d4e9dec56f418f6c893be8ffd76a/paper/rewrite).
- [Active writing guide](https://github.com/akekulip/DNP3_obf/blob/d895d53b1db5d4e9dec56f418f6c893be8ffd76a/paper/rewrite/pipeline/DR_LIN_WRITING_GUIDE.md): useful structure, with stale facts identified above.
- [Current claims and limitations](https://github.com/akekulip/DNP3_obf/blob/d895d53b1db5d4e9dec56f418f6c893be8ffd76a/defense4/timing/CLAIMS_AND_LIMITATIONS.md).
- [Instrumentation audit](https://github.com/akekulip/DNP3_obf/blob/d895d53b1db5d4e9dec56f418f6c893be8ffd76a/defense4/timing/audit_current/INSTRUMENTATION_AUDIT.md).
- [September 7 patch record](https://github.com/akekulip/DNP3_obf/blob/d895d53b1db5d4e9dec56f418f6c893be8ffd76a/paper/rewrite/PROPOSED_PATCH_20260907.md): consult its “As applied” section; proposed and applied text are not identical.
- RFC 6298 and Formby et al.: primary external sources linked at the relevant discussions above.
