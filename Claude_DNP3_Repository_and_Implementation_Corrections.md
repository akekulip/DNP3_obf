# Claude Code task: repository organization, implementation corrections, and bounded research follow-up

Work on `https://github.com/akekulip/DNP3_obf`.

Complete a bounded correction pass covering repository organization, the active implementation tools, measurement preparation, reproduction, and the documentation that explains them. First understand the current tree and what actually ran. Then implement the necessary offline corrections and push a reviewable branch. Do not stop after an audit or a proposed plan when the correction can be completed offline.

## 1. Establish the starting point

The last reviewed branch is `paper/clrt-four-corrections-20260909`, at commit `18a595aff59577f8e9f19de65afeaea11065bd38`. It includes:

- `91f8c61`: revised READ histograms, bin-count CSVs and source manifest.
- `55dc174`: SEL-751A retransmission and blocker-counter diagnostics.
- `18a595a`: repository prune.

Fetch the remote and inspect whether the branch has advanced. If it has, review the intervening diff before carrying these findings forward; verify every finding against the actual starting commit. Do not overwrite a subsequent fix just because this prompt describes the older problem.

Locate the real checkout with `git remote -v`, `git status`, and `git worktree list`. `/home/philip/Projects/DNP3-size-probe/` is a historical project location, not permission to assume that it is the current authoritative worktree. Preserve unrelated uncommitted work. Use an isolated worktree and a new descriptive branch based on the current timing branch if necessary. Do not reset an existing checkout or merge the historical size branches.

Read the applicable AGENTS.md/CLAUDE.md instructions, root README, timing README, paper README and current audits before editing. Record the starting commit and a short change plan. Continue through the offline work without requesting approval for routine implementation choices.

## 2. Scope and authority

This task adds an isolated **offline correction and measurement-preparation path** beside the frozen experiment. It does not turn a corrected implementation into the implementation that produced the existing captures.

Preserve these boundaries:

- Keep `defense4/timing/implementation/` byte-identical, including its P4, control code and drivers. Treat this entire directory as the record of what ran.
- Keep original captures, raw application logs, original configuration/readback logs, manifests and recorded build identities unchanged. This includes campaign, sweep, historical and new diagnostic evidence.
- Preserve Dr. Lin's first three introduction paragraphs and their verbatim check.
- Keep the paper timing-only: READ, SELECT and OPERATE within the established scope. Do not restart size research or introduce a new defense, system name, protocol function or multi-switch architecture.
- No hardware connections, switch writes, binary loads, driver live mode, packet transmission, capture sessions, firewall changes, relay commands or physical operations in this task. Do not set hardware-authorization flags. Existing live-operation guards remain in place.
- Offline source changes, mocked tests, dry-run planning and compilation using an already available local toolchain are within this task. If the compiler exists only on a switch or another host, do not access that host; record the compile dependency and finish the other work.
- Ordinary commits and a push of the new review branch to this repository are part of the requested handoff. Do not force-push, rewrite history, delete branches or merge into the current paper branch/default branch.

Read local instructions as constraints, and do not edit them merely to bypass an approval or safety restriction. Update their stale descriptions only to accurately distinguish the frozen record from the new offline working path authorized here. Keep the no-live-hardware rule explicit. If an actual access restriction prevents a step, identify it and complete the remaining independent work.

## 3. Inspect and simplify repository organization first

Create one concise map of the current sources of truth. Distinguish:

1. Frozen implementation and evidence that produced the paper's results.
2. Corrected code intended for future use, not yet measured on hardware.
3. Current extraction, analysis and figure-generation code.
4. Current manuscript sources and published artifacts.
5. Separate diagnostics that do not belong to the campaign.
6. Historical context and recoverable retired artifacts.

Important existing locations:

```
defense4/timing/implementation/                    frozen record
defense4/timing/active_harness/                    existing corrected drivers and offline tests
defense4/timing/evidence/campaign_v1/               active campaign
defense4/timing/evidence/campaign_v1/repro/         campaign reproduction
defense4/timing/evidence/final_read_sbo/            historical evidence
defense4/timing/audit_current/                     current audits
defense4/timing/audit_current/tools/               histogram/model tools
relay_rto_20260915/                                separate loss/backoff diagnostics
paper/rewrite/                                    active manuscript
```

Reuse the existing `active_harness/`. It already implements framing/reassembly, CRC checks, monotonic transaction budgets, response association, SELECT-before-OPERATE validation, and dry-run/live guards. Verify its existing tests; do not rebuild these features under another directory.

Choose the smallest additional structure needed for corrected control code and an instrumented P4 candidate. For example, an `active_control/` sibling and a clearly marked measurement-build directory may be appropriate. Avoid copying the entire frozen tree, creating competing canonical scripts, or spreading the same instructions across many new Markdown files. If a wrapper imports frozen helpers, document and verify exactly which helpers it imports. Ensure it cannot silently resolve a module from another worktree or user-specific path.

Inspect dependency references before moving anything: imports, shell paths, manuscript inputs, figure scripts, manifests, readmes and artifact links. Prefer fixing entry points and clear historical status over relocating immutable evidence. No broad deletion based on a filename, age or absence from a single search. Record any actual move/removal with its reason and recovery reference. Preserve required provenance even if the current paper does not cite it directly.

Known organizational contradictions to verify and fix in active documentation:

- Root/timing instructions point readers to different reproduction scripts. `defense4/timing/reproduce.sh` still targets the old `final_read_sbo` corpus.
- CLAUDE.md describes only the five NDSS figures, although the manuscript also uses CLRT histograms and model/schematic figures.
- Some introductory documentation still says shaping was active in every capture; distinguish the historical shaped corpus from the current timing-only campaign and the later diagnostics.
- The writing guide still defines D_R as a response hold and introduces CLRT_target, contrary to the later convention.
- Some instructions point to a superseded figure directory deleted by the latest prune.
- Do not edit a frozen README inside `implementation/` to repair its historical wording. Clarify the current interpretation in the active index, with a link back to the preserved record.

## 4. Correct the timing-only configuration path

Inspect `implementation/control/defense4_rrc_bor_unified12_setup.py` and its dependencies. At the reviewed commit, successful `configure-all` ends with `set_shape_enable(..., on=True)`.

Implement a corrected **active** timing-only configuration path that:

- Preserves the required timing, queue, port, packet-generator and session setup.
- Keeps shape disabled throughout the timing-only activation path. Do not run the old configure-all sequence and merely switch shaping off afterward.
- Makes any shaping capability explicitly separate from the timing-paper profile. Do not expose it as the default or use it in this task.
- Validates the selected profile and staged values before applying them.
- Includes explicit readback expectations for timing mode, shape state, timing parameters, queue priorities/port mapping and relevant generator settings.
- Refuses to report successful configuration after a failed prerequisite, failed write or mismatched readback. Define partial-failure behavior without disabling legitimate network forwarding by accident.
- Emits a machine-readable configuration plan and verification record naming requested values, quantized values, readback values, software identity and status. An offline mocked readback is labeled as a mock, never as evidence of switch state.

Add focused mocked tests for the real failure modes: shape never enabled under this profile, readback mismatch detected, prerequisite failure prevents activation, and imports resolve to the intended files. Do not add tests that merely repeat the implementation's constants.

## 5. Correct delay admission and RTO handling

Inspect the active use of `parameter_policy.py`, `validate_bor_deadlines`, defaults, configuration snapshots and existing timeout audits before designing the correction.

Separate the quantities by sender and event:

- Holding the outstation's ACK delays feedback for the master's request and consumes the master's TCP timer budget.
- Holding the outstation's response delays delivery and consequently the feedback for that response; the outstation has its own TCP timer.
- Application response deadlines and SELECT validity are additional constraints with different start/end events.
- The configured CLRT_new is the desired ACK-to-response gap, not a TCP RTO or an application deadline.

Do not replace a 200 ms master assumption with the relay's observed approximately 3 s backoff. Do not infer the actual timer from an SSH socket, a ping RTT, the first retransmission timestamp relative to capture start, or a universal RFC minimum.

Build the corrected policy around explicit inputs and provenance:

1. Identify which required bounds are measured on the relevant connection, operator-supplied, inherited from another build, estimated or unavailable.
2. Keep those statuses in the output. Unknown inputs cannot yield a claim of verified transport safety; do not silently fill them with convenient numbers.
3. Account for time already spent before the switch begins the relevant hold, the hold itself, release/service and path uncertainty, and a stated margin. Use consistent boundaries rather than adding an RTT twice.
4. A reported RTO duration is not the remaining countdown. Explain which timestamp/flight information is needed to calculate remaining headroom and what conservative alternative is possible when it is unavailable.
5. Do not let the defense's inflation of measured RTT automatically justify progressively larger holds. Keep an independently justified policy cap and describe the first delayed exchange, reconnect and policy-change cases.
6. Preserve separate master, outstation and application checks rather than a single ambiguous `tcp_rto` field. Bridge historical parameter names explicitly; do not rename frozen fields.

The existing nanosecond detection/drain/tail constants come from earlier measurements. Do not relabel them as measurements of the current binary. Verify whether the terms overlap before adding them. Use uncertainty/provenance explicitly until current-build measurements exist.

The pass-budget horizon also needs attention. A finite number of serviced passes is not automatically a wall-clock bound for a lower-priority reservoir. Account for queue priority and shared-port service. The observed ACK saturation near 31.07 ms is not a universal response-release deadline. Do not introduce a claimed hard timeout without proving how the hardware can enforce it.

Add focused offline tests for missing bounds, units, margin accounting, first-flight assumptions, master/relay confusion, and priority-dependent service assumptions. Document which cases remain unverified on hardware.

## 6. Prepare a minimal measurement build for epsilon

Read these before touching the candidate:

```
defense4/timing/audit_current/RELEASE_MEASUREMENT_STATUS.md
defense4/timing/audit_current/INSTRUMENTATION_AUDIT.md
defense4/timing/audit_current/QUEUE_AND_ANCHOR_AUDIT.md
defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4
```

The existing timestamp actions are declared but not executed. Declaring registers, polling port counters, or plotting CLRT residuals does not measure post-deadline queue draining.

Create a separate candidate source or a reproducible patch over the frozen source. Record its base hash. Define the events before selecting register names:

- Scheduled deadline.
- First blocker observation of expiry.
- Last relevant blocking action/termination.
- Held-packet service or departure, if observable with the proposed instrumentation.

Measure ACK and RESPONSE separately. Their reservoirs are qid7 and qid5 on dp8 and share a priority scheduler. The BOR reservoir on dp10 is a different domain, not the second READ gate.

Evaluate the existing B1 proposal critically rather than assuming it is sufficient. A last `_DL` ingress timestamp must be shown to represent the intended end of blocking, or labeled as an internal-event proxy. It is not automatically a traffic-manager empty timestamp or wire departure. Separate deadline-detection latency, remaining blocking and subsequent service. External packet captures alone do not isolate all of these components.

The instrumentation must address:

- Consistent clock source, units, quantization and timestamp wrap.
- Per-transaction and per-lane association.
- Reset/retirement ordering and stale-token isolation.
- How the last relevant event is identified despite multiple tokens and pipeline ordering.
- Separate deadline release, budget release, late arrival and bypass outcomes.
- Validity flags for missing measurements, not zeros presented as elapsed time.
- No new controller participation in per-packet release decisions.
- Actual Tofino stage, PHV, stateful-access and compiler constraints.

Keep this minimal. Do not simply enable all dormant telemetry, add a general tracing framework, or redesign packet scheduling. Produce a readback/extraction utility and focused offline checks. If the local SDE is available, compile and compare resources to the frozen build. Otherwise finish the source/patch and compile procedure, clearly marking them uncompiled and unverified. A successful compile is not a hardware measurement or proof that instrumentation has no timing effect.

Do not load the candidate. Supply a later measurement procedure with explicit required evidence, expected outputs and failure criteria. Do not claim epsilon measured until a separately authorized experiment actually records its endpoints. Instrumented results must have a new build/run identity and must not be inserted into campaign_v1 as if captured there.

## 7. Repair the diagnostic tools and interpretation

Preserve `relay_rto_20260915/` as the original diagnostic record. Implement corrected probes in the active working path; do not rewrite the script that produced the original evidence.

The current rule using `--tcp-flags SYN,RST,PSH,ACK ACK` is not a general payload-length test and affects all matching connections to the relay port. Its subprocess failures are ignored.

For a future probe, prepare code that:

- Defaults to a dry-run plan and respects the existing live-operation guard.
- Restricts any planned filtering to the exact established probe connection.
- Implements the intended packet selection explicitly; does not equate PSH-clear with zero payload.
- Checks installation and removal results, verifies the final state, preserves cleanup protection, and reports failures truthfully.
- Does not retry an OPERATE, change the point allowlist, or replace the guarded driver with an unguarded sender. Start RTO measurement design with READ only.
- Records capture location, connection endpoints, interface, timing mode, shape state, loaded-build identity, host timing samples, capture precision and cleanup evidence.

Prepare capture and offline-analysis instructions for the real master/outstation DNP3 connection. Match retransmissions by connection and byte range, with connection lifetime, ACK progression, segmentation and possible fast-retransmission evidence considered. Preserve original packets and integer timestamp precision. Do not classify every repeated sequence number as a retransmission or propose dropping all repeated sequence numbers in the P4 program.

Recheck the existing diagnostic evidence and record:

- One original response and three retransmission rounds, with approximately 3/6/12 s intervals in these sessions.
- Master-facing capture, not a direct relay timer readback.
- Split 21-byte and 28-byte response ranges, unlike the campaign's unsplit 49-byte responses.
- The discrepancy between documented configure-all and timing-only campaign configuration.
- No proven explanation for the slightly short first interval solely from these captures.
- The new blocker counters show circulation/budget lifetime, not epsilon. Millisecond polling and line-rate conversion do not establish nanosecond drain accuracy.

Where an existing README is checksum-covered, preserve it and add a clearly linked correction note outside the immutable record. Do not silently recalculate original checksums to hide a changed record.

## 8. Review retransmission handling without expanding the project

Trace the existing request, ACK, response and OPERATE duplicate paths through active, pending and retired states. Produce a compact behavior table covering a duplicate while the original is held, a duplicate after original release, late response, unmatched flow and state reuse.

State what the code does and what the captures can verify. Use focused offline cases where a model/test genuinely checks the behavior. Do not promise exactly-once delivery from a master-facing trace. Do not suppress every future copy of a sequence number: legitimate loss recovery must remain possible.

If a concrete correctness defect is established, implement a minimal candidate fix separately from the frozen P4 and report its resource/validation requirements. If the behavior is intentional and consistent with the current scope, document it without inventing a new hardening campaign.

## 9. Repair reproduction and publication entry points

Provide one clear default route for the current campaign. Keep historical reproduction available only under an explicitly historical command/profile. It must be difficult to mistake old-corpus output for current paper evidence.

Integrate or explicitly orchestrate:

- Immutable-input verification.
- Campaign and sweep extraction/statistics.
- The current READ histogram generator and its bin/source manifests.
- Other figures and schematics actually referenced by the manuscript.
- Relevant offline active-code tests, with a clear distinction from evidence-analysis tests.
- Introduction protection, paper build, and a check that the published PDF reflects the current manuscript and referenced graphics.

Avoid import-time hardware access. Default build outputs to a separate directory. Publishing regenerated figures or main.pdf should be a deliberate step; do not overwrite the committed artifacts before inspecting the output.

At the reviewed commit, the committed main.pdf still contains the older logarithmic histogram despite newer linear source figures. Correct this mismatch. Update the built PDF and its hash/provenance together after a successful build and visual inspection.

The review reproduced all ten histogram manifest entries and the campaign's main numerical results. A known fig_feature_overlap PDF mismatch is confined, in the compared files, to one coordinate differing by 10^-10 points; the strict publication gate still fails. Do not silently relax or remove the gate. Separate numerical reproducibility, rendering/content equivalence and exact byte identity. If introducing a rendering-equivalence check, document exactly what it compares and ensure a genuinely changed label, point or axis would not pass. Report unresolved failures accurately.

## 10. Synchronize explanation, writing and clean figures

The full editorial revision is described by the earlier reviews if supplied:

- `DNP3_Dr_Lin_Review_20260915.md`
- `DNP3_Manuscript_Writing_and_Figure_Review.md`

Do not block this task if those attachments are absent: the requirements here are self-contained. At minimum, correct every active instruction, model explanation and manuscript statement affected by the implementation findings.

Apply these current conventions:

- CLRT_original and CLRT_new; configured versus measured is stated in words.
- D_A is the ACK hold. D_R is the intended response latency, not the 4 ms target or another name for response hold.
- Response hold is expressed by its established endpoints when needed. An actual hold already includes its post-deadline wait; do not add draining twice.
- Distinguish outstation-to-master latency, switch-arrival-to-master latency and request-to-response time. State the unmeasured component rather than equating them.
- READ/SELECT are ACK-anchored; OPERATE uses its request anchor. Do not claim all cases share the ACK anchor.
- Explain the four-queue ACK/RESPONSE ladder, then the additional OPERATE pair. Do not describe six queues as four across the whole combined program.

Carry Lin's argument style into revisions: one clear purpose per paragraph; explain the physical idea before P4 details; introduce only gaps addressed by the work; report measured answers directly; describe prior work accurately and respectfully. Keep the one-device transaction-class scope, residual ACK-timing information and unmeasured events consistent across sections. Do not justify the fixed-attacker case by attributing an unsupported restriction to Formby. Keep shifting to a brief explanatory comparison.

Figures must be clean. Remove in-figure descriptions, statistics strips, takeaway sentences, redundant titles and needless labels. Keep essential axes, units, short condition/panel labels, necessary series keys and reference marks. Put explanations and statistics in the text or a short external caption. Preserve verified data, linear histogram bins, full-arm denominators, the overflow category's meaning and access to tails. Clean scientific figures through their code/vector sources, not generated raster illustrations. Inspect the resulting PDF at publication size.

## 11. Evaluate the next ideas, without turning them all into implementation work

Write one short prioritized assessment:

1. **A simple delay-selection guideline.** Can baseline/connection measurements, explicit uncertainty and a margin select an admissible hold? Start with the simplest estimator or bound. Identify failure cases and whether any new experiment is needed. Do not introduce machine learning without a demonstrated need.
2. **Direct epsilon measurement.** Explain which question the minimal candidate answers, which events it cannot observe and how instrumentation could perturb timing.
3. **Residual ACK-timing leakage.** Different anchors contribute information. Assess a common-anchor or alternative schedule as future work only, including its impact on device availability, TCP feedback, operational latency and resources. Do not implement it as part of this correction pass.
4. **A hard elapsed-time limit.** Determine whether it is needed for the claimed deployment and whether the current queue mechanism can support it. Do not present the pass counter as an established substitute.

For each, state the problem, evidence, smallest useful next step, tradeoff and disposition: do now, measurement prepared, or defer. Reconcile the meeting's IEC/application-latency research task with the exact source: document title, edition, clause, message/service class and applicability. A reading note is not a universal TCP bound, and another protocol's timing class is not automatically a DNP3 requirement. Use primary sources for new technical claims and distinguish recommendations from measured implementation behavior.

## 12. Validation, commits and handoff

Use meaningful checks targeted at the changes. Do not rerun the expensive full classifier analysis after every prose edit, or add a large unrelated test program. Once the affected behavior is verified, finish the handoff.

Before committing:

- Compare frozen source and raw-evidence hashes with the starting inventory.
- Confirm existing active-harness tests still pass and the new active paths preserve its guards.
- Verify timing-only setup, timer-bound handling, probe planning and instrumentation bookkeeping with appropriate offline tests.
- Record P4 candidate compile status and resource changes, or the exact reason compilation was unavailable.
- Reproduce affected numerical/figure artifacts and inspect the rebuilt manuscript if modified.
- Check for broken paths after organization changes, stale authority instructions, secrets and accidental generated/vendor files.

Use a few focused commits, for example: repository entry-point corrections; active control/probe corrections; isolated measurement candidate; reproduction and affected paper/figure updates. Keep the current branch, frozen record and unrelated branches intact. Push the new branch normally to `akekulip/DNP3_obf`; do not merge it. If remote access is unavailable, retain local commits and report that specific limitation rather than claiming a push.

Return a concise handoff containing:

1. Starting commit, new branch, final commit and GitHub comparison link.
2. What changed in organization and which paths are now authoritative.
3. Each implementation defect addressed, its file location, and the test/evidence supporting the correction.
4. The frozen files verified unchanged.
5. Clear statuses for offline-tested code, compiled candidate, and hardware-validated behavior. Do not conflate them.
6. Updated manuscript/figure paths where affected, with build status.
7. Remaining research questions and one concrete, separately reviewable future measurement plan.

Use one concise correction report and one measurement plan where possible. Prefer executable fixes and clear entry points to a proliferation of audit documents. The end state should be easy for Philip and Codex to inspect, reproduce and review.
