# Claude Code: revise the timing paper and push a reviewable GitHub branch

Execute this task through completion. Produce the actual revised manuscript, supporting research notes, necessary figures, a verified PDF, and a pushed GitHub branch. Do not stop at a plan, proposed patch, or list of suggestions. Preserve unrelated work. Do not invent results, hide limitations, or expand the mechanism to justify unnecessary claims.

**Latest user clarification: preserve Dr. Lin's authored Introduction verbatim.** It is the reference for the rest of the paper, not a passage to rewrite, polish, or correct during this task. Install his supplied text where the GitHub draft differs, then preserve its wording and paragraph sequence. Record factual, grammar, or citation concerns separately as review notes without editing his prose or presenting unresolved concerns as verified. Apply his tone, philosophy, argument structure, explanatory style, and voice to the other sections. This rule supersedes earlier instructions permitting edits to his text.

## 1. Establish the working state

The user-identified working directory is `/home/philip/Projects/DNP3-size-probe/paper/rewrite/`. The repository is `https://github.com/akekulip/DNP3_obf`. A previously inspected remote draft was `paper/campaign-v1-ndss-corrections-20260828` at `d895d53b1db5d4e9dec56f418f6c893be8ffd76a`; this is historical context, not permission to discard newer local or remote work.

Read applicable repository instructions. Inspect the local branch, HEAD, remotes, worktrees, dirty files, current manuscript entry point, latest relevant remote branches, and evidence provenance. Resolve which checkout holds the latest author changes. The known entry point is `paper/rewrite/main.tex`; verify it. Do not reset, clean, delete, force-push, or overwrite unrelated changes. Do not merge conflicting author versions by guessing.

Create a review branch from the appropriate current paper state, using `paper/lin-post-meeting-revision-YYYYMMDD` with the actual date and a suffix if needed. Use an isolated worktree when useful to protect concurrent work. Make the intended paper changes on that branch and push it to the existing repository origin. This task authorizes that push. Do not merge into the default branch.

## 2. Authority and scope

Dr. Lin's supplied Introduction and the meeting establish the writing philosophy, argument, scope, and structure. The GitHub manuscript is the draft to revise; it is not the writing authority. Repository code, captures, and reproducible analysis determine technical facts. Prior assistant explanations, old slides, and obsolete style contracts must not override the meeting or the evidence.

Read `DNP3_Post_Meeting_Research_and_Writing_Instructions.md` if supplied alongside this prompt. It contains the detailed meeting synthesis. This handoff is sufficient to start if that file is absent; do not make its absence a blocker. Read the current writing guide, advisor sample, Introduction, Design, Implementation, Evaluation, claim records, notation definitions, figure provenance, and relevant audits before editing.

Keep the timing-only framework, the current four-queue ACK/RESPONSE mechanism, constant target CLRT, and fail-open behavior. READ and SELECT share the read-path treatment; OPERATE has its own established timing anchor. Do not add size obfuscation, new platforms, policy families, controller algorithms, or P4 hardening. Shifting is an optional brief analytical clarification, not another research track or measured arm.

## 3. Dr. Lin's writing philosophy

Each paragraph has one purpose. Establish the problem or reason before introducing the design choice. Move from a general statement to a concrete explanation or example, then its consequence. Each sentence must follow logically from the preceding one. Use plain English, complete sentences, stable terms, and minimal unexplained notation.

Use “Because,” “Consequently,” and “For example” where the relationship requires them; do not optimize connective counts or reading scores. Explain the mechanism before internal acronyms and registers. Do not replace the advisor's argument with sophisticated-sounding prose or a different storyline. Do not invent a project name.

Build the argument within the contribution's scope:

**Specific problem → relevant prior-work limitation → design response → supporting evidence → bounded conclusion.**

Do not introduce an extra central gap unless this paper addresses it. Do not broaden the implementation merely to rescue an overbroad introductory claim. Keep material limitations and adverse evidence: scope discipline does not authorize concealing them.

Treat previous research fairly. Explain its objective and achievement first, then identify the verified assumption or feature mismatch that matters in our setting. Do not call a technique ineffective because it was designed for another setting. Do not describe an untested transfer as demonstrated failure. Do not generalize one paper's assumptions to an entire field or claim universal superiority.

For every major sentence ask: what does this make the reader expect, and do our design and evidence satisfy that expectation? Remove contradictory motivation, unsupported guarantees, unnecessary scope expansion, and terms such as “optimal” when only a tested operating point is established.

## 4. Authoritative Introduction supplied by the user

The following is Dr. Lin's supplied text, with line wrapping normalized only. Preserve the authored prose verbatim, including its paragraph sequence. Typesetting and verified citation-key mapping may accommodate LaTeX without changing the prose. Do not guess citation keys or silently replace citations; report unresolved mappings separately.

> Device fingerprinting has been an essential step in cyber reconnaissance, allowing adversaries to reveal unique features of target networks and to design effective, stealthy attack strategies. These techniques are becoming increasingly critical in industrial control systems (ICSs) such as power grids, where adversaries often use IP-based control networks and computing devices within as entry points to inflict physical damage. Consequently, fingerprinting shifts the focus from visited websites and user biometric behavior to device models and types of control operations that are critical to ICS attacks. In the 2015 attack that disrupted Ukrainian power grids and the Stuxnet attack that disrupted Iranian nuclear power facilities, it is widely believed that adversaries stay in their systems for at least 6 months to perform cyber reconnaissance [1].
>
> To disrupt device fingerprinting, many studies present network traffic obfuscation [2], [3]. Device fingerprinting targeting general computing environments generally relies on network-level features such as packet size and/or inter-packet latency observed from communication patterns [4]. Consequently, existing traffic obfuscation often focuses on (i) padding and splitting network packets, which hide or change the distribution of network packet sizes [2], and (ii) delaying network packets and adding dummy ones, which disrupt the inter-packet timing pattern [3], [5]. Since manipulating communication networks can introduce runtime overhead, recent works have begun to offload traffic obfuscation onto programmable network switches, which change communication patterns at much higher line rates than CPUs [6]–[8].
>
> Unfortunately, these methods cannot be directly applied to ICS environments for two main reasons. First, device fingerprinting methods on ICS devices rely on different features from the ones in general computing environments. Instead of using network layer knowledge, they attempt to use behavior on physical devices to reveal device model or types of operations. For example, work in [9] uses the latency between the TCP acknowledge packets and the actual response from the same device to estimate execution time there. Since each vendors may choose different materials or algorithms to implement the same control functionality, this time can be accurate in fingerprinting those devices. Second, existing traffic obfuscation is performed over encrypted channels, which are necessary to mix the obfuscated and normal traffic. Unfortunately, ICS networks still rely on unencrypted traffic due to a wide range of legacy devices, despite ICS network protocols may provide security features. Directly padding or adding dummy packets can easily reveal obfuscated packets, exposing the the underlying traffic pattern to adversaries.

The additional block in the user's excerpt beginning “First, the leaked features are different. General web traffic obfuscation…” was interpreted from the meeting as superseded draft text. Verify its authorship/status against the annotated source before removing it. Remove only confirmed superseded non-Lin draft text, preserving the change in history. If its status is ambiguous, leave it and flag it separately. Do not splice it into Dr. Lin's three-paragraph reference or delete advisor-authored text on an inference.

Record potential grammar issues such as “TCP acknowledge packets,” “each vendors,” and “the the” in separate review notes. Verify source support for incident durations, encrypted-channel assumptions, and the connection between the timing feature and physical-device properties. Do not apply corrections to his authored prose. Avoid propagating unsupported claims into the newly written sections.

Derive the rest-of-paper writing method from this reference: identify each paragraph's purpose, follow the chain from reason to mechanism to consequence, repeat established terms, introduce concrete examples after general statements, and give only the technical detail the reader needs at that point. Preserve his plain academic register and measured presentation. Do not imitate him by copying phrases into every section or forcing connective frequencies. The target is continuity of voice and reasoning across the paper.

Continue with a high-level framework paragraph and bounded contributions. Framework first; READ/SELECT and master-visible OPERATE timing are case studies. Size techniques remain prior-work context only. Do not promise suppression of all reconnaissance, all payload information, or all device fingerprints.

## 5. Blueprint for Design, Implementation, and Evaluation

### Design: model first

Begin with a clean READ timeline. Explain native ACK and RESPONSE arrival, intended release times, actual release when observable, original CLRT, and target/new CLRT. Give endpoints and units before equations. Explain replacement and its response-availability condition. A reader unfamiliar with P4 should understand the intended transformation.

### Design: parameter choices and constraints

Explain ACK delay, RESPONSE delay, and new CLRT, what each controls, their coupling, and the factors constraining them. Connect ACK delay to transport feedback/retransmission timing, RESPONSE delay to the operation's latency requirement, and target CLRT to the chosen obfuscation objective. Present the feasible operating region and the selection argument before implementation detail.

Dr. Lin explicitly wants D_A to denote the native-ACK-to-release delay and D_R to denote the native-RESPONSE-to-release delay. Older code/slides use D_R for target CLRT. Create a notation mapping before revising equations. Preserve configuration and archived evidence field names, recording their paper meanings rather than silently changing historical data.

Using the established timeline endpoints, the identity is:

`CLRT_new = (t_R - t_A) + (e_R - t_R) - (e_A - t_A)`.

For ideal replacement, the required RESPONSE hold is ACK hold plus target CLRT minus original CLRT. These are coupled quantities, not three independently chosen constant holds. The RESPONSE must arrive by its scheduled release. The ACK leaving before native RESPONSE arrival does not by itself imply packet loss.

Verify the actual timer anchor. The inspected read-path source arms both deadlines from native ACK arrival; do not imply that it starts the RESPONSE timer at measured ACK departure. Separate intended deadlines from actual release. Preserve the request-relative A/R/J convention for OPERATE where the implementation requires it.

### Implementation: explain queues before P4 details

Explain the ACK blocker/hold pair and RESPONSE blocker/hold pair through familiar priority scheduling. Follow one transaction through classification, holding, expiry, release, and cleanup. Explain why the arrangement realizes the model under hardware constraints. Then give the P4 details needed to establish feasibility and correctness.

Check the timer mechanism against source: distinguish blocker population sufficient to maintain a hold, deadline-based expiry, and residual draining after expiry. Do not copy a K-times-drain-time description if the actual code uses timestamp deadlines. Keep the four ACK/RESPONSE queues distinct from any additional queues used by the OPERATE path. Preserve unmatched forwarding and existing recovery behavior.

### Evaluation: answer the questions raised by the design

Organize existing results around understandable questions, using existing objective labels where helpful:

- Does the measured timing concentrate at the configured target, including its spread and tails?
- How close is actual release to the intended schedule, and what residual is genuinely measured?
- What parameter range, coverage, and latency cost are supported?
- Do transport and application exchanges complete under the tested settings?
- Does the implementation satisfy hardware constraints, with what resource and measured performance cost?
- What does the evaluated attacker still learn, and which security conclusion follows?

State testbed, conditions, sample units, observation points, extraction, and exclusions before results. Do not substitute link speed for measured throughput or resource fit for demonstrated comparative efficiency. No new benchmark suite is required simply to make the section larger.

## 6. Complete the bounded research and measurement work

**ACK-delay selection.** Consult primary sources on TCP retransmission timing and the actual master stack/configuration. Distinguish an observed retransmission from a universal timeout. Account for elapsed time before ACK holding, remaining path delay, release variability, and margin. Prefer a simple justified calibration or conservative range. Machine learning is optional, not required. Twenty milliseconds is a tested setting, not automatically a universal safe bound.

**RESPONSE-delay selection.** Identify the standard, profile, or explicit deployment requirement applicable to the operation. Record the source, edition/clause, latency endpoints, and applicability. Distinguish per-receive timeout, transaction deadline, and operational requirement. Do not treat the meeting's approximate 100 ms or 10 ms examples as established limits. If the standard cannot be verified, report the gap and use only a clearly identified deployment assumption.

**Release variability.** Check existing instrumentation and captures before proposing measurements. The September 7 audit found inactive timestamp actions and no demonstrated external release timestamps in preserved evidence; verify the current state. Do not promise that reading an existing register measures egress. Define endpoints, clocks, transaction association, precision, and the net ACK/RESPONSE release residual. Separate late arrivals and fail-open behavior from queue-release variability. Clock resolution is not measurement accuracy.

Use valid existing evidence and accessible read-only measurements first. This handoff does not authorize actuating a physical device or loading a new P4 binary. If completion of the measurement requires instrumentation, prepare the smallest reviewable measurement change or capture plan, identify what it can observe, and record the remaining execution requirement. Complete all other authorized writing and analysis and push the review package; do not fabricate a measurement or block the entire handoff on unavailable hardware.

## 7. Figures, evidence, and literature

Make aligned before/after CLRT histograms the primary spread explanation. Use common bins within comparisons, full-range views, and a clearly labelled target zoom if needed. Labels should be plain: Timing OFF, Obfuscated, CLRT (ms), Transactions (%). Report n, mean, sample STD in ms, and sample variance in ms². Zoom percentages use all transactions in that condition as the denominator. Do not clip tails or pool different classes, settings, or corpora.

Keep run-level variance plots only if they answer a necessary additional question. Do not expand shifting figures; any shift reference is analytical unless a measured arm actually exists. Use vector figures for the paper and readable previews. Regenerate through the existing provenance workflow, not manual changes to hashed published sidecars.

Use current campaign data and the authoritative generated manuscript values after verifying them. Keep historical datasets separate. Twenty-two grouped runs within one campaign are not independent deployments. Preserve distinctions between uncertainty intervals and descriptive spread; do not recreate previously withdrawn intervals.

Retain adaptive-attacker residual leakage. Do not call transaction-class classification device identification. Do not call the solicited OPERATE response-to-ACK interval physical breaker-actuation time or claim suppression of Formby's SER-based physical fingerprint without relevant evidence. Keep configured J distinct from observed per-transaction holds. Distinguish inferred native-distribution coverage from directly observed switch deadline misses.

Establish the protected Introduction first, then write the conceptual Design and remaining sections in its voice. Write only the unfinished, non-protected framework/contribution continuation where needed. Develop Related Work incrementally while researching, then organize it around the established contribution. Finalize Abstract and Conclusion after the body is consistent. Maintain the actual bibliography and verify citations against primary sources. Use nonbreaking LaTeX spacing, such as `claim~\cite{key}`.

## 8. Required review package and checks

Update the active manuscript sections and necessary figure sources. Update the existing active writing guide so it follows the meeting and does not preserve stale restrictions or contradict evidence. Keep one active guide, one manuscript entry point, and clear figure provenance; do not create competing paper versions.

Create or update one review report at `paper/rewrite/pipeline/reports/POST_MEETING_REVIEW_HANDOFF.md`. It must contain:

1. Starting branch/commit and final branch/commit, with a concise list of changed files.
2. The paragraph/section argument map: gap, design response, supporting evidence, and claim boundary.
3. Verification that Dr. Lin's authored prose remains unchanged, plus a separate list of concerns for author review. Identify any removed non-Lin draft text and the evidence that it was superseded.
4. The notation mapping and any remaining source/model inconsistency.
5. Findings and citations for ACK-delay and application-latency selection.
6. Release-measurement status: measured, inferable, or unavailable; concrete remaining work if needed.
7. Figure/data provenance and exclusions; identify any regenerated numbers and why they changed.
8. Build, relevant analysis/provenance validation, and visual inspection results.
9. Remaining substantive issues, with exact file locations and their effect on claims. No generic claims that everything is complete when a necessary measurement remains missing.

Compile the actual manuscript and inspect its rendered pages, especially timelines, equations, figures, captions, and references. Run the existing relevant validation gates. Correct stale style rules transparently when they conflict with the current user direction; do not weaken scientific checks to conceal a failure. Re-run only the checks needed for changed analysis or concrete remaining risks.

Inspect the final diff. Commit only intended changes, the verified PDF and figures where repository policy permits, and the review report. Do not commit temporary builds, credentials, unrelated edits, redundant archives, or third-party repositories. Push the review branch and verify the remote commit equals the intended local commit. If authentication or access prevents the push, preserve the commit and report the exact blocker; do not claim success.

## 9. Finish with a GitHub handoff

Return:

- Clickable GitHub branch URL and full commit SHA.
- Links to the revised manuscript source, compiled PDF if tracked, active writing guide, and review report.
- A short explanation of the main argument/structure changes.
- Which evidence was reused, which analysis was regenerated, and which measurements remain outstanding.
- Validation results and any unresolved substantive issue the reviewer should inspect first.

The reviewer must be able to open the pushed branch, compare the changes, inspect the PDF, and trace claims to evidence. Finish with that concrete handoff, not an offer to perform the work later.
