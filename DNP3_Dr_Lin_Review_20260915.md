# Review against Dr. Lin's meeting and writing instructions

Reviewed 15 September 2026. Repository: **akekulip/DNP3_obf**. Branch: **paper/clrt-four-corrections-20260909**. Reviewed head: **8278346666b6071d7a882914b98b3f5d9747fc06**, including histogram commit 3791bdf, diagnostic commit b45a76f, and the final prune.

## Overall assessment

The central timing result is supported by the archived measurements, and the new histogram calculations and binning follow the meeting well. The figure presentation still needs the cleanup the user requested: remove descriptions, statistics strips, and needless captions or labels from inside the graphics. The paper is **not yet fully aligned with the implementation or ready for a clean handoff**. The most consequential problems are a stale compiled manuscript, confusion between the master's and relay's retransmission timers, a new blocker measurement that does not measure the requested epsilon, and claims in the design and implementation that overstate what the evidence establishes.

Dr. Lin's three introduction paragraphs pass the repository's word-for-word check. Keep them intact. Correct the later arguments and technical descriptions to the same standard of clarity: identify the particular problem, explain the design decision that addresses it, and present the evidence that answers the resulting question.

This is a review, not a new experiment. No hardware was contacted, no traffic or control commands were sent, no frozen implementation or capture was edited, and nothing was pushed. The local checkout remained clean.

## What was covered

The active branch contains 823 tracked files. The remote advertises 19 branches, consistent with the push report. Review concentrated on the active timing manuscript, frozen P4 source, control-plane policy and setup, campaign and sweep reproduction, current audit documents, new relay diagnostics, and the latest prune. Historical size branches were treated as provenance, not merged into the timing project. This is not a claim to have reviewed every historical branch or every JSONL line manually.

The campaign checks processed all 132 captures and 63,360 exchanges, verified the 22 dataset manifests, and rebuilt the canonical analysis. The sweep checks covered 19 points and 5,860 exchanges. New diagnostic captures were decoded separately with integer nanosecond timestamps; they were not mixed into the campaign. The committed manuscript was extracted and relevant model, implementation and figure pages were visually inspected. Formby's original paper and RFC 6298 were checked directly.

## Meeting requirements: current position

| Requirement | Assessment | Next action |
|---|---|---|
| Preserve Lin's introduction | Pass: three paragraphs match word for word | Keep the protection check |
| Use his scope and argument structure | Partial: the broad structure is present, but several claims exceed the demonstrated result | Correct the specific claims below, then simplify the prose |
| Model, design choices, queue implementation, evaluation | Mostly present | Make the queue account and timing boundaries agree with the code |
| CLRT_original and CLRT_new | Adopted in current manuscript and histograms | Update the stale writing guide; preserve historical code/CSV names through the mapping |
| D_R means response latency | Partly corrected | Fix its observation boundary and remove double counting |
| Measure post-deadline blocker draining | Still open | Do not label the new 24.4/31 ms estimates as epsilon |
| Formby-style bins and histograms | Pass for the new artifacts | Rebuild the manuscript so it actually contains them |
| Research ACK-hold selection under TCP RTO | Useful diagnostics, wrong comparison in the new README | Separate the master and relay constraints |
| Application latency/IEC justification | No verified deployment-specific deadline established | Record the exact document, edition, clause and applicability; do not invent a universal bound |
| Respect previous work and stay within scope | Generally respectful, but Formby is mischaracterized in key places | Remove the unsupported attribution and report both attacker cases plainly |
| Keep the fixed-target/four-queue work focused | Good direction | Preserve READ's four-queue explanation; describe the additional OPERATE pair separately |

**Latest figure instruction:** Figures must be clean. Keep only necessary axes, units, panel/condition identifiers, essential legends and reference marks. Move explanations, sample statistics, coverage percentages and interpretation to the surrounding text or a short external caption. Do not remove the minimum information needed to read a figure correctly. The separate manuscript-and-figure review gives the edits for each figure family.

## Findings requiring correction

### 1. High: the compiled paper does not contain the latest histogram revision

**Evidence:** The committed `paper/rewrite/main.pdf`, page 8, still contains four histogram panels with logarithmic ordinates and a caption explicitly saying that the ordinates are logarithmic. In contrast, the current source includes separate linear main, zoom and full-range figures. [06_evaluation.tex, line 35](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/06_evaluation.tex#L35)

The current histogram PDF and PNG files themselves contain the intended linear plots. Their generation and data checks pass. Therefore, a reader who opens the paper PDF sees an older result presentation than someone who opens its source or figure directory.

**Correction:** Rebuild `main.pdf` from the reviewed source and current figures, inspect it at printed size, and update the PDF hash/build record together. A hash of an old PDF proves its identity, not that it represents the current source. Tectonic was unavailable in this review environment, so no replacement manuscript was compiled here.

### 2. High: the relay's observed approximately 3 s timeout does not replace the master's 200 ms guard

The new diagnostic README compares the relay measurement with `--tcp-rto-ms 200.0`, calls the headroom 15 times larger, and uses that comparison to explain the campaign's lack of retransmissions. [README.md, line 57](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/relay_rto_20260915/README.md#L57)

The timing policy explicitly describes its 200 ms floor as the **master's** retransmission timeout. [parameter_policy.py, line 57](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/implementation/control/parameter_policy.py#L57)

| Delayed packet | Sender whose feedback is postponed | Relevant timeout |
|---|---|---|
| Outstation ACK acknowledging a master request | Master, which sent the request | Master's TCP retransmission timer |
| Outstation response awaiting the master's ACK | Outstation, which sent the response | Outstation's TCP retransmission timer |
| Response arrival needed by the application | Master application | Application timeout/operational latency requirement |

These are separate constraints. A long relay timeout cannot establish that the master can tolerate a long ACK hold. Zero retransmissions visible at the master also cannot, by itself, exclude relay-side copies suppressed inside the switch.

**Correction:** State that the new captures show the relay's observed response retransmission cadence under deliberate ACK loss in these two sessions. Retain a separate master-side bound based on the real DNP3 socket, with time-aligned `ss`/TCP_INFO evidence if available. Do not use the earlier SSH socket screenshot for this purpose, and do not substitute 3000 ms into a master guard.

The paper also says RFC 6298 floors the RTO at 1 s and suggests a constant hold is absorbed by adaptation. RFC 6298 uses SHOULD for the 1 s rounding recommendation; it is not a measurement of this stack. Adaptation does not prove safety for the first delayed request, reconnection, or a policy change. Replace the universal language with the measured operating point and an explicit margin. [04_design.tex, line 128](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/04_design.tex#L128) [RFC 6298, sections 2 and 5](https://www.rfc-editor.org/rfc/rfc6298.html).

### 3. High: the new blocker measurement does not close Dr. Lin's epsilon request

The new README starts its interval when a transaction **arms** the reservoirs. It reports about 24.4 ms for RRC and 31.0 ms for BOR, with the latter computed from all 1,152,064 transmitted blocker frames at assumed line rate. That is the circulation/burst duration, including the intended hold or pass-budget lifetime. [README.md, line 3](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/relay_rto_20260915/blocker_drain/README.md#L3)

Dr. Lin asked for what happens **after expiry**: how long the relevant blocker queue takes to stop blocking the held packet. That requires the expiry event and the end of blocking, separately for ACK and RESPONSE. The new experiment distinguishes RRC and BOR ports; it does not isolate the two ACK/RESPONSE drain intervals on RRC. Those two reservoirs share dp8 and its priority scheduler. [RELEASE_MEASUREMENT_STATUS.md, line 44](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/audit_current/RELEASE_MEASUREMENT_STATUS.md#L44)

Independent checks of the raw polling files found:

| Poll file | Samples | Total counter increase | Median poll spacing |
|---|---:|---:|---:|
| dp10_bor_poll.txt | 2,172 | 1,152,064 frames | 6.381 ms |
| dp8_rrc_poll.txt | 1,537 | 911,038 frames | 11.504 ms |

The BOR count agrees with the reported budget total. It does not identify epsilon. The reported 31.4 ms span runs between coarse changing samples; agreement with a 30.97 ms serialization estimate does not establish sub-millisecond timing accuracy or continuous saturation. The poller timestamps before the blocking gRPC read and records no completion timestamp. The claimed per-arm frame/octet snapshots and repeated-run results are not archived alongside the script that would print them.

There is also a smaller definition conflict inside the older release audit: its first endpoint list starts at the first blocker observing expiry, while its later event table defines drain from the deadline itself. Those intervals differ by deadline-detection latency. [RELEASE_MEASUREMENT_STATUS.md, line 139](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/audit_current/RELEASE_MEASUREMENT_STATUS.md#L139)

**Correction:** Keep the diagnostic, but label it as a counter-based estimate of blocker circulation/budget lifetime. Keep epsilon explicitly unmeasured on this build. Define and archive, for each relevant gate: scheduled deadline, first expiry observation, last blocking termination, and actual held-packet departure, so queue draining can be separated from subsequent service/egress. This is a bounded future instrumentation task, not authorization to alter the frozen campaign or run new hardware now.

### 4. High: the new RTO diagnostic has different packetization and incomplete configuration provenance

Both new captures contain two response byte ranges: 21 bytes at the later TCP sequence number, followed by 28 bytes at the earlier number. Each byte range appears once originally and three more times with identical payload bytes. The frozen timing campaign instead contains unsplit 49-byte responses.

The diagnostic README says setup used `configure-all`. In the committed setup script, successful `configure-all` explicitly enables shape at the end. [defense4_rrc_bor_unified12_setup.py, line 900](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/implementation/control/defense4_rrc_bor_unified12_setup.py#L900) This is consistent with the new split response, but a full contemporaneous readback and exact loaded binary hash are needed to establish what ran.

**Correction:** Document this diagnostic's actual shape state, session, capture point, build identity and rule-installation evidence. Preserve it as a separate diagnostic. Do not describe it as the unchanged timing-only campaign configuration, or transfer its timing differences directly into the campaign's safety argument.

The reconstructed intervals for the 21-byte range are:

| Arm | Original response time relative to capture start | Consecutive retransmission intervals |
|---|---:|---|
| Timing OFF | 0.521812874 s | 2.994340131, 6.000359682, 12.000119212 s |
| Obfuscated | 0.530340502 s | 2.959811142, 6.000393285, 12.000002388 s |

This supports an approximately 3/6/12 s backoff pattern in these sessions. It does not establish a universal relay minimum RTO. The README should say **three retransmission rounds**, not four: there are four appearances including the original. Its explanation that the short first interval is caused by the relay starting its timer before capture is not isolated by these master-facing timestamps; differing switch treatment of original and repeated packets is also relevant.

### 5. High: D_R's decomposition double-counts the post-deadline delay

The model defines `e_R` as actual response departure and the response hold as `e_R - t_R`. It then says D_R consists of baseline path latency, that response hold, and the deadline-to-release drain term. Actual departure already includes the post-deadline wait. Adding it again counts it twice. [04_design.tex, line 105](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/04_design.tex#L105) [NOTATION_MAPPING.md, line 87](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/NOTATION_MAPPING.md#L87)

For the current switch-arrival boundary, the exact identity is:

> D_R = (e_R - t_R) + (m_R - e_R).

Alternatively, decompose the actual hold into scheduled waiting, post-deadline blocking, and subsequent service once, with explicit event definitions. Do not combine actual hold with an additional term already inside it.

The current D_R starts at response arrival at the switch, and the paper admits that it omits outstation-to-switch travel. The user's intended general outstation-to-master response latency includes that hop. Preserve the intended meaning and distinguish its unmeasured component from the measured boundary; do not quietly equate the two. Also distinguish response delivery latency from total request-to-response time, which includes device processing.

Finally, label the release equations as ideal scheduled releases. The same `e_A` and `e_R` cannot silently alternate between actual departures and ideal deadlines once epsilon is discussed. This correction can use plain-English qualifiers without inventing a new family of symbols.

### 6. High: the implementation section describes the wrong queue allocation

The manuscript says each of the two lanes has two queues and that four queues cover both lanes. [05_implementation.tex, line 26](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/05_implementation.tex#L26) [05_implementation.tex, line 91](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/05_implementation.tex#L91)

The frozen P4 declares:

| Scheduling domain | Queue | Role |
|---|---:|---|
| dp8 | 7 | ACK blockers |
| dp8 | 6 | Held ACK |
| dp8 | 5 | RESPONSE blockers |
| dp8 | 4 | Held RESPONSE |
| dp10 | 3 | OPERATE blockers |
| dp10 | 2 | Held OPERATE |

That is the READ/response four-queue ladder plus a separate OPERATE pair, six queues in the combined implementation. [defense4_rrc_bor_unified12.p4, line 372](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4#L372)

**Correction:** Start with Dr. Lin's requested four-queue READ explanation. Then show exactly what the control extension adds and which resources it reuses. Update the prose and schematic together. Also correct the claim that a response simply queues behind the ACK: it has its own held-response queue and blocker gate. No change to the frozen P4 is required to fix this description.

### 7. High: the paper turns a computed budget horizon into a universal wall-clock guarantee

The design says the mechanism cannot hold past H = 30.8 ms; implementation says every hold is released and state cleared by that horizon. The limitations section correctly says H is computed in the control plane rather than enforced as a data-plane wall-clock deadline. These statements conflict. [04_design.tex, line 141](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/04_design.tex#L141) [05_implementation.tex, line 76](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/05_implementation.tex#L76) [06_evaluation.tex, line 344](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/06_evaluation.tex#L344)

A token pass budget bounds serviced passes. A lower-priority reservoir can be starved while a higher-priority one runs, so that budget is not automatically the same elapsed-time bound for every queue. The reproduced sweep at configured ACK hold 36 ms and gap 4 ms has a READ request-to-ACK median of 31.0731 ms, request-to-response median of 40.5796 ms, and CLRT median of 9.5069 ms. This demonstrates why the ACK saturation point must not be advertised as a universal response-release deadline.

**Correction:** Describe the actual pass-budget mechanism, its assumed service rate, priority coupling, and observed saturation. Retain the narrower limitation in the main argument. Do not claim that a computed threshold alone proves timer safety. The policy's nanosecond detection/drain constants are explicitly sourced from older Defense 3 measurements; label their provenance rather than calling them current-build drain measurements. [parameter_policy.py, line 41](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/implementation/control/parameter_policy.py#L41)

### 8. High: the argument dismisses the adaptive result through an unsupported attribution to Formby

The threat model says an evaluation against a retrained classifier answers the wrong question. The evaluation says the 0.082 balanced-accuracy improvement is not the figure on which the contribution rests, and attributes a necessarily unchanged pre-defense profile to Formby's setting. [03_threat_model.tex, line 59](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/03_threat_model.tex#L59) [06_evaluation.tex, line 301](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/06_evaluation.tex#L301)

The original Formby paper studies fingerprints for identifying device types and detecting forged responses; its threat model does not establish that an observer of this defense is restricted to an unchanged pre-deployment classifier. Its histogram fingerprint and physical-operation feature are also distinct. The introduction's later, unprotected paragraph incorrectly equates this project's master-visible OPERATE interval with Formby's second feature, while the project's threat model and related work correctly distinguish them. [01_introduction.tex, line 57](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/01_introduction.tex#L57) [Formby et al., sections III-IV](https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf).

**Correction:** Present fixed and retrained classifiers as two explicit evaluation conditions chosen by this work. Explain what each answers without devaluing either or assigning the choice to Formby. State the result directly: the targeted CLRT becomes much less informative in this experiment, but ACK timing retains or creates class information. Remove the inaccurate claim that both evaluated intervals reproduce Formby's two fingerprints.

This is precisely where Lin's scope philosophy matters: support the narrower contribution clearly instead of defending a broader one through a convenient threat-model restriction. Respect for earlier work includes describing its actual problem and measurement accurately.

### 9. Medium: abstract and repeated-observation claims exceed a one-device transaction-class evaluation

The abstract says the device's signature leaves the interval and that measuring the same exchange again gains the adversary almost nothing. The experiment uses one relay and predicts READ/SELECT/OPERATE classes. It does not measure device-model confusion across multiple outstations or every possible classifier using a sequence of observations. [00_abstract.tex, line 17](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/00_abstract.tex#L17)

**Correction:** Keep device fingerprinting as the motivation established by Lin's introduction, then state the demonstrated result as timing-feature suppression and a transaction-class evaluation on one SEL-751A. Do not treat a lower variance, a near-null mutual-information estimate, or single-exchange classification alone as proof against repeated distribution-based fingerprinting. A cross-device evaluation would be separate future work, not something to imply has already happened.

### 10. Medium: the diagnostic rule is not a general pure-ACK filter, and its success is not checked

The probe matches ACK with SYN/RST/PSH clear. PSH is not a TCP payload-length test: a data-bearing segment may have PSH clear. The rule also matches every outgoing connection to the relay's DNP3 port rather than the one probe source port. `subprocess.run` ignores the return code, yet cleanup prints that the rule was removed. [rto_probe.py, line 14](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/relay_rto_20260915/rto_probe.py#L14)

The captures demonstrate that the particular READ did leave and the response was retransmitted. They do not make the filter's broad description true for all traffic.

**Correction before any future use:** Scope the rule to the probe connection, test the intended packet property explicitly, check and archive installation/removal outcomes, and retain cleanup protection. Do not execute this probe as part of an offline review. The original captured probe remains immutable provenance; any improved version must be distinguished from what produced the existing files.

### 11. Medium: the active writing guide still directs Claude to undo the latest notation correction

Its opening rules call D_R the response hold and introduce CLRT_target. Its terminology table repeats that convention, despite the current manuscript and notation mapping withdrawing it. Later protection language also alternates between the first three paragraphs and the entire introduction. [DR_LIN_WRITING_GUIDE.md, line 22](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/pipeline/DR_LIN_WRITING_GUIDE.md#L22) [DR_LIN_WRITING_GUIDE.md, line 130](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/pipeline/DR_LIN_WRITING_GUIDE.md#L130)

**Correction:** Update the active guide and entry README before another rewrite. State one current notation convention and one clear protected-text boundary. Keep historical field names in code and frozen tables, with an explicit translation. Do not mechanically rename those artifacts. The latest prune removed unused figures and old instructions but left this active contradiction.

### 12. Medium: the reproduction gate remains red, although the numerical evidence reproduces

The final targeted suite at the reviewed head completed with **129 passed, 1 failed, 1 deselected**. The deselected test regenerates all figures twice; repeated full-suite attempts did not yield a complete rerun summary in this environment. The remaining failure is the existing `fig_feature_overlap.pdf` byte comparison. The publication gate reports three messages arising from that same PDF mismatch.

Independent decoded-PDF comparison found one coordinate difference: `-39.6004742881` versus `-39.6004742882`, a difference of 10^-10 PDF points. Page dimensions and every recursively compared resource category matched. This substantiates the repository's cross-machine rendering explanation for these two files. It does not make the strict hash test pass.

An earlier complete run on b45a76f had 129 passes and two failures, including a generated PNG/provenance hash mismatch. After regeneration, that PNG failure did not recur in the completed selected suite. Do not count it as a confirmed current content defect.

**Correction:** Report numerical reproducibility separately from byte-identical rendering. Preserve the current strict gate unless an explicitly documented rendering-equivalence check is adopted. Do not report an all-green rebuild. [REPRODUCIBILITY_SCOPE.md, line 1](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/audit_current/REPRODUCIBILITY_SCOPE.md#L1)

### 13. Medium: the claimed single-script reproduction does not cover the whole current paper

Open Science says one script rebuilds every figure and that the publication gate catches disagreement with the manuscript. The campaign reproducer builds five NDSS figures; it does not call the separate current histogram generator or rebuild the paper PDF. Furthermore, the repository's top-level timing reproducer still points at the superseded `final_read_sbo` corpus. [09_ethics_openscience.tex, line 22](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/09_ethics_openscience.tex#L22) [reproduce.sh, line 65](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/evidence/campaign_v1/repro/reproduce.sh#L65) [reproduce.sh, line 25](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/reproduce.sh#L25)

**Correction:** Either provide one explicit current entry point covering the campaign, current histogram/model artifacts and manuscript build, or document the separate commands accurately. Update CLAUDE/README directions so a fresh reviewer does not rebuild the older corpus by following the advertised entry point. The stale manuscript in finding 1 shows why the current guarantee is too strong.

### 14. Medium: the timeline caption presents illustrative coordinates as measured timestamps

The timeline generator uses drawing choices, including a 0.35 ms propagation offset and a 1.2 ms late-response separation. Its sidecar discloses that these are not measurements, but the manuscript caption says filled circles were measured. These are *types of events observed in the campaign*, not necessarily measurements from the drawn transaction. The caption also calls the square markers open, although the plotted squares are filled. [make_model_figures.py, line 110](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/defense4/timing/audit_current/tools/make_model_figures.py#L110) [04_design.tex, line 19](https://github.com/akekulip/DNP3_obf/blob/8278346666b6071d7a882914b98b3f5d9747fc06/paper/rewrite/sections/04_design.tex#L19)

**Correction:** Use a clean schematic with established endpoint labels, minimal event marks and no arbitrary numerical time scale, or label the time values as illustrative in a short external caption. Say that markers identify the observation locations. Make marker fill match the caption. Remove the in-figure explanatory sentence about late forwarding and explain the behavior in the model paragraph.

## Results independently reproduced

| READ result | Timing OFF | Obfuscated |
|---|---:|---:|
| Transactions | 26,400 | 26,400 |
| Mean CLRT | 2.7999 ms | 4.0124 ms |
| Sample standard deviation | 2.6092 ms | 0.6279 ms |
| Sample variance | 6.807774 ms^2 | 0.394257 ms^2 |
| Within 3.90-4.10 ms | 3,571 / 26,400 = 13.5265% | 26,363 / 26,400 = 99.8598% |

The pooled READ variance reduction is approximately 94.2%. The narrow central peak and the remaining outliers both matter. All main and full-range bins sum to the full arm count. The zoom retains the full-arm denominator rather than renormalizing the visible subset.

All ten entries in the latest histogram manifest reproduced byte for byte, including all three PDFs, bin counts, run statistics, and source manifests. No failed or ambiguous READ exchange was identified by the histogram cross-check. The 1 ms bins, explicit overflow category, separately available full-range companion and narrow zoom are a sound response to Lin's request. Because 4 ms is a bin edge, the central mass occupies adjacent bins; the caption correctly explains this and the zoom resolves it.

The classifier analysis also reproduced:

| Timing features | Fixed model on Timing OFF | Fixed model on Obfuscated | Retrained model on Obfuscated |
|---|---:|---:|---:|
| CLRT alone | 0.6515 | 0.3332 | 0.3333 |
| Request-to-ACK plus CLRT | 0.7328 | 0.3337 | 0.6510 |

These are balanced accuracies on transaction classes, with chance 1/3. They support reporting a strong change in the targeted timing feature and a substantial residual in the combined features. They do not establish indistinguishability between device models.

The latest prune deleted 32 paths, including superseded figures, unused variance/shift figure artifacts and historical instruction documents. It retained the campaign captures and active histogram reproduction inputs; the rebuilt histogram hashes confirm that the retained path still works. Per-run statistics remain available after removal of the separate variance plot. A targeted check found no newly dangling deleted-file reference in active manuscript sections or the current guide; README references to the deleted removal manifest explicitly explain its recovery from history.

## How to carry Lin's voice into the rest of the paper

The strongest parts already follow his method: introduce an observable, explain what causes it, show how the schedule changes it, and state where that schedule cannot work. Keep that causal order.

For **design**, use one READ transaction to explain the model, distinguish configured deadlines from actual departures, and then explain the three relevant constraints: transport feedback, the intended CLRT interval, and operational response latency. Present fixed replacement as the current policy. Keep shifting as a short mathematical contrast, not another research track.

For **implementation**, first explain the four queues without P4 details. Then show how timestamps, blockers and priority implement the schedule, how late or unmatched packets are handled, and how the OPERATE extension changes the picture. Readers should understand the mechanism before encountering architecture-specific restrictions.

For **evaluation**, ask the natural questions in sequence: does the measured interval concentrate near the target, what fraction lies outside it, what costs and operating limits appear, and what timing information remains? Give the result before the RO tag. Avoid repeated assessment language such as “we achieve ROx if” and “ROx therefore holds” when an ordinary result sentence is clearer.

For **related work**, retain the generally respectful tone. Describe a prior method's setting, feature and assumption before stating the specific mismatch with this setting. Do not convert a local mismatch into a claim that the whole method fails. Never attribute a convenient attacker restriction or an unmeasured feature to a cited paper.

For **limitations**, place material qualifications where the claim is made. An accurate limitations paragraph does not repair an earlier universal assertion about timing safety, queue count, physical operation timing or fingerprint removal.

The fact that an unfavorable result is reported is a strength. The response should be a proportionate claim, not an argument that the unfavorable test was the wrong question. This keeps the paper from undermining its own contribution.

## Ordered handoff for Claude

1. Start from reviewed commit 8278346 on the active timing branch. Preserve the first three introduction paragraphs, frozen implementation, original captures, and historical field names. Do not merge unrelated historical branches or run hardware.
2. Correct the active writing guide and notation mapping first. Resolve D_R's boundary/decomposition and scheduled-versus-actual departure language before editing dependent paragraphs.
3. Correct the RTO and blocker README interpretations. Keep the diagnostics separate; distinguish observed backoff, burst duration, and unmeasured post-deadline draining. Record the split response/configuration discrepancy and absent provenance without inventing missing logs.
4. Correct queue allocation and the pass-budget/horizon description in design, implementation and schematic. State duplicate handling by its actual state and packet class; do not promise that every repeated TCP sequence number is globally dropped. Retransmissions after the original response retires are visible in the new diagnostic.
5. Remove the unsupported Formby attribution, distinguish its physical-operation feature, and narrow the abstract and later claims to the demonstrated timing result. Report both classifier conditions without dismissing the retrained result.
6. Keep the new histogram data and binning, but clean the figures according to the user's latest instruction. Remove in-figure descriptions, statistics strips, redundant titles and needless labels; retain essential axes, units and identifiers. Use short external captions and put interpretation in the results paragraphs. The full-range companion may be placed in an appendix if space requires, with its tails still reported and linked. Avoid rebuilding the discarded variance plot merely to add another figure.
7. Rebuild the manuscript, update its checksum/build provenance and inspect the resulting pages. Confirm the compiled paper shows the linear bins and agrees with the corrected text.
8. Run the introduction protection check, campaign numerical checks, histogram hash checks and publication gate. Report exact results, including the known rendering-byte failure unless it has been properly resolved. Do not weaken a test just to obtain a green report.
9. Commit the bounded documentation/presentation corrections and provide the resulting commit, changed-file list, test results and remaining evidence gaps for review. Follow the user's authorization for any push; this review itself has made no remote changes.

The next research work remains bounded: obtain and archive the master DNP3 connection's real timer evidence, characterize relay retransmission timing with explicit configuration provenance, define/instrument post-deadline draining, and identify the exact operational-latency reference and its applicability. The existing diagnostic does not close all four questions, and no new machine-learning project is needed to state that honestly.
