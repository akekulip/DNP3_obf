You are beginning a 6–8 hour autonomous engineering, hardware-validation, evidence-generation, and documentation run in:

```text
/home/philip/Projects/DNP3
Repository: https://github.com/akekulip/DNP3_obf
Branch: defense4-size-native-parity-crc-split
Primary path: defense4/
```

## Mission

Finish the unified Defense 4 transaction primitive on the existing Tofino-1:

```text
BOR + RRC
Bounded OPERATE Release + Release–Replicate–Carve
```

The result must be one deployable logical primitive on the existing single Tofino-1. Prefer one physical ingress pipe. If a faithful corrected implementation cannot fit one pipe, use the two physical pipes already confirmed on the BFN-T10-032D. Each physical ingress pipeline must compile within its own 12-stage limit.

Do not expand to another switch, a proxy, TF2/TF3, a new endpoint architecture, or switch-side padding. Keep the work inside Defense 4 and the existing hardware/testbed.

Do not stop at design or compile-only unless a real technical or safety blocker remains after exhausting the bounded implementation paths below. Continue through implementation, offline verification, compiler placement, control-plane setup, hardware testing, PCAP analysis, figures, repository organization, and final documentation.

The detailed beginner explainer is the final deliverable. Write it only after the implementation and results are frozen.

## Current verified baseline

Re-read the repository and verify every item rather than trusting this summary blindly:

* RRC is already silicon-proven for READ and SELECT responses.
* Native READ and two-CROB SELECT responses are 49 bytes.
* PRE same-port/two-RID replication produces `[28,21]`.
* RID1 emits the 28-byte prefix.
* RID2 emits the 21-byte suffix.
* Reassembly is byte-exact.
* D4 timing plus RRC carving has passed on the physical SEL-751.
* Proven RRC baseline uses 12 ingress stages and 3 egress stages.
* The chip reports:

  * `num_pipes = 2`
  * SKU `BFN-T10-032D`
  * 12 ingress stages per pipe.
* Current stage-recovery evidence at or after `f3753d3` reports:

  * RRC baseline: 12 stages, 125 logical tables.
  * Additive BOR: 14 stages.
  * SR1 TM dispatch: 13 stages.
  * Current SR1+SR2+SR3+SR4 candidate: reported as 13 stages.
* The current RRC kernel, hardware evidence, and rollback path must remain intact until a replacement passes every gate.

Fetch the branch and begin from its actual current HEAD. Part 5 or later work may have landed after `f3753d3`. Audit those commits rather than overwriting them.

## Critical correction that must be handled first

The current SR4 implementation is not yet a faithful BOR readiness solution.

In `defense4_rrc_bor_sr_probe.p4`, the first OPERATE performs `op_ready_read` before the same packet executes `arm_clone()`. Therefore qid3 cannot already be confirmed for that OPERATE generation:

```text
first OPERATE
  → op_ready_read returns 0
  → immediate fail-open forwarding
  → arm_clone begins asynchronous qid3 generation
  → qid3 later marks the generation ready
  → an exact retry is classified as V_ARM_DUP and suppressed
```

This prevents the race by bypassing BOR on the first real OPERATE. It does not implement a working BOR hold.

`reg_op_ready` is also not cleared. Because the DNP3 application sequence is 4 bits, a later generation can wrap and match a stale readiness value after the old qid3 reservoir has drained.

The emulator’s `structural_guarantee` currently assumes that the original OPERATE can begin its hold at `resident_at`. The P4 has no hardware storage path that keeps the original safely between `T0` and `resident_at`. Correct this model.

Also verify the exact compile flags used for the selector results. The current evidence appears to compile `PART4_RANDOM` and `PART4_SALTED` without SR4. A build that does not combine readiness and the selector is not evidence for the complete primitive.

Do not retain the claim “faithful one-pipe BOR is 13 stages” until a corrected design shapes the first eligible OPERATE after a clean start.

## Autonomous working rules

Use specialist subagents in parallel where productive:

1. Tofino/P4 compiler and placement engineer.
2. TM, pktgen, PRE, multi-pipe, and control-plane engineer.
3. DNP3/TCP lifecycle and mutation-testing engineer.
4. Evidence, PCAP, statistics, fingerprinting, and figure engineer.
5. Documentation and repository-organization reviewer near the end.

The main agent must review every load-bearing result independently. Do not accept an agent’s compile, hardware, statistical, or security claim without checking the raw artifact.

Do not pause for ordinary implementation choices. Make the best evidence-based decision and continue. Ask the user only if a truly irreversible safety decision is required.

Maintain:

```text
defense4/OVERNIGHT_STATE.md
```

Update it after every major gate with:

* UTC timestamp.
* Current branch and SHA.
* Clean/dirty worktree state.
* Completed, failed, and pending gates.
* Exact active source and binary hashes.
* Exact compiler command and result.
* Current switch program and mode.
* Current relay reachability.
* Current output states.
* Last verified rollback command.
* Next exact command.
* Known blockers.
* Agent findings that still require main-agent review.

Commit and push small coherent checkpoints. Never leave important work only in an agent transcript or `/tmp`.

If context is compacted or token capacity resets, immediately reread:

```text
defense4/OVERNIGHT_STATE.md
git log
git status
```

Then continue from the recorded next command without restarting the project or asking the user to repeat instructions.

If the process itself is externally terminated, the state file must make a manual relaunch sufficient to resume.

Preserve unrelated user modifications. Do not reset, overwrite, or delete existing evidence. Archive obsolete probes with clear labels rather than silently removing history.

## Phase 1: Establish the exact starting state

1. Fetch the remote branch and confirm local/remote SHAs.
2. Inspect `git status` and preserve unrelated changes.
3. Read the current:

   * RRC kernel.
   * BOR probes.
   * stage-recovery report.
   * BOR/RRC design.
   * emulator and mutants.
   * setup scripts.
   * hardware evidence.
   * repository-specific operating and safety instructions.
4. Reproduce:

   * frozen RRC 12-stage build;
   * current additive BOR build;
   * current stage-recovery verdict.
5. Verify raw compiler logs, not summaries alone.
6. Determine the live switch program and mode using read-only checks.
7. Record the initial hardware state and rollback procedure.
8. Do not change the switch during this phase.

## Phase 2: Correct the readiness model and evidence record

Update the emulator to model the actual event order:

* Original OPERATE ingress.
* Register reads and writes.
* Clone trigger.
* Asynchronous pktgen generation.
* Token ingress.
* qid3 residency.
* qid2 eligibility.
* Deadline drain.
* Original OPERATE release.

Add required mutants:

* `first_operate_always_fail_open`
* `early_qid2_release`
* `magic_buffer_until_ready`
* `stale_ready_after_seq_wrap`
* `ready_without_reservoir`
* `ready_not_cleared_on_retire`
* `duplicate_release`
* `retransmit_releases_second_copy`
* `deadline_reanchored_to_operate_release`
* `public_sequence_selects_j`
* `tcp_timestamp_subtraction`
* `source_copy_leaks_to_relay`

The current SR4 code must fail the faithful first-OPERATE test. This is expected and proves the emulator detects the real defect.

Correct the reports:

* Preserve the stage measurements.
* Relabel the existing SR4 result as a resource probe if it cannot shape the first OPERATE.
* Do not call fail-open-only behavior BOR protection.
* Separate “safe bypass” from “successful shaping.”
* Record whether the combined readiness-plus-random-selector build has actually been compiled.

## Phase 3: Build a faithful readiness mechanism

Use the SELECT phase as the preferred preparation event. SBO naturally provides SELECT before OPERATE.

Do not bind the prepared qid3 reservoir to RRC’s SELECT or OPERATE DNP3 generation. SELECT and OPERATE are independent DNP3 transactions. Introduce a separate internal BOR/SBO epoch or equivalent hardware-safe preparation identity.

Target lifecycle:

```text
SELECT admitted
  → create BOR epoch
  → seed qid3 for that BOR epoch
  → confirm qid3 residency
  → retain BOR_PENDING across SELECT completion

OPERATE arrives at original upstream T0
  → require matching BOR_PENDING and confirmed residency
  → select leak-safe J
  → arm T0+J
  → arm response deadlines T0+A and T0+R
  → enqueue the original OPERATE into qid2
  → qid3 blocks qid2 until T0+J
  → release the original OPERATE byte-identically exactly once

ACK and echo arrive later
  → release at absolute T0+A and T0+R
  → carve eligible 49-byte echo to [28,21]
  → retire BOR and RRC state
```

Required cleanup:

* Failed SELECT.
* Missing OPERATE watchdog.
* Preparation timeout.
* Unready reservoir.
* OPERATE release.
* ACK/response completion.
* FIN/RST.
* Connection replacement.
* Invalid profile.
* Fail-open.
* Every abort path.

A missing or unready preparation must immediately forward the original OPERATE and increment an explicit failure counter. It must never enqueue into qid2 based only on a stale flag.

Test repeated application-sequence wraps. Internal BOR readiness must not become valid merely because the public four-bit sequence repeats.

The internal BOR epoch must never be the source of J. Use `Random<T>` or a bounded selector that an upstream passive observer cannot predict from public packet fields.

## Phase 4: Recover the 12-stage fit

First attempt a corrected single-pipe implementation. Do not stop after the first placement failure.

Use compiler-guided refactoring, including where appropriate:

* Preserve the SR1 single TM-dispatch design.
* Merge compatible keyless parameter actions.
* Apply TM dispatch once per packet.
* Reuse existing metadata containers and action data.
* Remove duplicate comparisons already guaranteed by parser state.
* Combine mutually exclusive BOR and RRC branches.
* Move non-load-bearing diagnostics to egress or compile-time test variants.
* Use indexed counters rather than separate counter objects.
* Store absolute deadlines rather than a separate T0 register where equivalent.
* Precompute only values consumed by the active packet role.
* Split dependency chains across a real internal phase only when the compiler proves it helps.
* Avoid adding 8-bit PHV metadata to exhausted groups.
* Preserve the RRC PRE carve and checksum correctness.
* Never remove exactly-once release, readiness, T0 anchoring, fail-open delivery, or random J merely to report 12 stages.

Compile an explicit matrix with raw evidence. It must include the fully composed candidate:

```text
RRC
+ BOR epoch/readiness
+ SELECT preparation
+ T0 anchoring
+ Random J selector
+ TCP timestamp preflight
+ TM dispatch
+ exactly-once release
+ RRC PRE carve
```

Do not infer the combined result by adding numbers from separate variants.

A successful candidate requires:

* `bf-p4c` 9.13.1.
* 0 errors.
* A generated `tofino.bin`.
* No more than 12 ingress stages.
* Resource report and final placement round.
* Explained warnings.
* Source and binary hashes.
* Raw compiler output committed.
* Offline conformance and all mutants killed.

If a faithful one-pipe implementation still cannot fit after bounded consolidation, preserve the result and immediately continue to the two-pipe implementation. Do not broaden to different hardware.

## Phase 5: Two-pipe single-chip implementation if required

The repository already proves that this ASIC has two physical pipes. Do not spend the night merely checking whether pipe 1 exists.

Build one logical primitive across the two on-chip pipes:

### Pipe 0

* Existing RRC request admission and session ownership.
* Capture original upstream OPERATE `T0`.
* Maintain absolute ACK and echo deadlines.
* Process later relay ACK and echo packets.
* Invoke PRE carve `[28,21]`.
* Preserve proven READ and SELECT behavior.

### Pipe 1

* Observe or receive the SELECT preparation event.
* Build the independent BOR epoch.
* Populate and confirm qid3.
* Receive the original OPERATE with an internal handoff header carrying only required state.
* Hold and release the original exactly once.
* Strip every internal header before forwarding to the relay.
* Forward the released original to relay port dp64.

Relay ACK and echo are new packets entering pipe 0 later. They are not a “second pass” of the released OPERATE.

Do not assume registers or counters are shared between pipes.

Produce and verify:

* Exact pipe scopes.
* Exact P4 program/profile configuration.
* Separate binaries or pipeline profiles as required by SDE.
* Exact internal recirculation or cross-pipe port.
* Port and parser mappings.
* Internal handoff header format.
* T0/deadline transfer.
* State ownership.
* No-source-copy property.
* Exactly-once route.
* Rollback configuration.
* Each physical ingress pipeline at no more than 12 stages.

A conceptual diagram is not a verdict. Compile the actual combined configuration that would be loaded by `bf_switchd`.

## Phase 6: Offline acceptance gates

Before touching hardware, require all of the following:

* First OPERATE after clean start is BOR-shaped.
* SELECT preparation completes before OPERATE admission.
* qid3 is confirmed resident before qid2 admission.
* Original OPERATE is byte-identical.
* Exactly one original reaches the relay.
* `T_OP_RELEASE = T0 + J`.
* ACK release is anchored to original `T0+A`.
* Echo release is anchored to original `T0+R`.
* Echo remains `[28,21]`.
* Reassembly is byte-exact.
* IP/TCP checksums are valid.
* No internal header leaves the switch.
* Missing preparation fails open.
* Invalid deadline configuration is rejected.
* Timestamp-negotiated connections cannot claim anti-subtraction.
* Public DNP3 sequence does not predict J.
* Random buckets match the configured bounded support.
* Retransmission never causes another physical operation.
* FIN/RST clears state.
* At least 1,000 modeled transactions pass.
* Multiple DNP3 sequence wraps pass.
* Every required mutant is killed.
* Frozen RRC regression suite remains green.
* READ, SELECT, and OPERATE use the intended shared response engine.

Have an independent review agent compare:

* Design.
* Emulator.
* P4.
* Compiler output.
* Control-plane assumptions.

Resolve every load-bearing disagreement before hardware.

## Phase 7: Production-quality control plane

Create or repair one authoritative setup path.

It must support:

* Offline import with no BFRT dependency.
* Dry-run.
* Configure.
* Verify.
* Evidence dump.
* Disable BOR only.
* Disable RRC only.
* Full rollback.
* Recovery after partial failure.
* Correct client lifecycle.
* Exact pipe targets.
* Correct TM queues and priorities.
* Pktgen programming.
* PRE multicast programming.
* Parameter readback.
* Counter/register readback.
* Timestamp preflight.
* Deadline constraints.
* Random J profile installation.
* Port bring-up using proven mappings.
* Refusal without `DEFENSE4_HW_AUTHORIZED=1`.

Validate:

```text
A > Jmax + native_ACK_bound
R > Jmax + native_response_bound
R >= A
```

Also bound `Jmax`, `A`, and `R` below:

* Master SBO timeout.
* Relay command timeout.
* TCP retransmission boundary with guard.
* Fail-open horizon.
* Operational command latency budget.

Use millisecond deadline configuration, not placeholder nanosecond-scale defaults.

The setup must not report PASS when a write silently reads back zero or when a required table is absent. Dead fields such as the retired `read_len` must be handled explicitly and documented.

## Phase 8: Hardware authorization and safety

This prompt authorizes:

* Compiling on the switch.
* Loading the corrected program after all offline gates pass.
* BFRT, TM, pktgen, PRE, and port configuration.
* Packet capture.
* READ traffic.
* Non-actuating SELECT traffic.
* OpenDNP3 software-endpoint SELECT and OPERATE traffic.
* Rollback and restoration.

This prompt does not authorize an unsafe physical SEL OPERATE.

A physical SEL OPERATE may run only if the repository or testbed evidence explicitly proves that every addressed output, including the odd decoy point, is safe and electrically isolated, and existing project authorization explicitly permits the actuation. If that proof is absent, mark only the physical-OPERATE gate BLOCKED and continue every other task.

Never infer electrical isolation merely because a previous SELECT left points open.

Before loading:

* Record current program.
* Record live mode.
* Confirm relay reachability.
* Capture all output states.
* Save current configuration.
* Verify rollback commands.
* Start packet captures.
* Make the smallest reversible change.

On any unexpected loss, duplicate, relay-state change, port failure, or timeout:

1. Disable BOR/RRC.
2. Roll back to the proven program.
3. Verify relay reachability.
4. Verify outputs.
5. Preserve failure evidence.
6. Diagnose offline before another load.

## Phase 9: Hardware campaign

Run gates in increasing risk.

### H1: Load and transparency

* Load the final candidate.
* BOR OFF, RRC OFF.
* Verify transparent READ/SELECT forwarding.
* Confirm no internal headers or duplicate packets.
* Confirm relay reachability.

### H2: RRC regression

* Enable RRC without BOR.
* Repeat physical READ and non-actuating SELECT.
* Confirm native 49-byte response.
* Confirm `[28,21]`.
* Confirm byte-exact reassembly.
* Run at least the existing 200-packet RRC stress level.
* Confirm no 49-byte source copy.

### H3: BOR on software endpoints through the physical Tofino

Place OpenDNP3 master and outstation across the switch.

Run full SELECT and OPERATE safely against software outputs:

* First OPERATE after clean state.
* Multiple J buckets.
* Repeated transactions.
* Retransmissions.
* Missing SELECT.
* Failed SELECT.
* Missing OPERATE.
* FIN/RST.
* Connection restart.
* Sequence wraps.
* At least 1,000 software operations if stable.

Prove on the wire:

* SELECT prepares BOR.
* Original OPERATE is observed upstream at T0.
* Relay-side/software-outstation OPERATE appears at T0+J.
* Exactly one OPERATE reaches the outstation.
* ACK and echo are released at T0+A and T0+R.
* Echo is `[28,21]`.
* Application completes successfully.
* No timeout boundary is violated.

### H4: Physical SEL non-actuating campaign

* Physical READ.
* Physical two-CROB SELECT.
* D4 timing.
* RRC `[28,21]`.
* Confirm BOR preparation state is established without physical actuation.
* Confirm outputs remain OPEN.

### H5: Physical SEL OPERATE, only when safety-authorized

If and only if isolation and authorization are documented:

* Capture pre-state.
* Use the minimum safe number of operations needed for the initial gate.
* Verify exactly-once operation.
* Verify expected output/SER behavior.
* Capture the response echo.
* Verify `[28,21]`.
* Increase samples only after the first operation is reviewed.
* Restore outputs to the approved safe state.
* Record final states.

If H5 is blocked, do not invent physical-operation evidence. Continue using the hardware-path OpenDNP3 campaign and existing physical datasets.

At the end of testing, leave the switch in a clearly documented safe state. Prefer the final program loaded with BOR and RRC disabled unless an already-proven running mode is explicitly required. Record the exact state.

## Phase 10: PCAPs, evidence, and fingerprinting evaluation

Create a timestamped evidence directory with:

* Native captures.
* Defended captures.
* Master-facing captures.
* Relay/outstation-facing captures where available.
* READ.
* SELECT.
* Software OPERATE.
* Authorized physical OPERATE if permitted.
* Switch configuration.
* Program/source/binary hashes.
* BFRT readbacks.
* TM queue state.
* Pktgen state.
* PRE state.
* Counters.
* Registers.
* Port state.
* Output state.
* Compiler logs.
* Test commands.
* Analysis JSON/CSV.
* SHA-256 manifest.

Every figure and reported number must trace to committed data and a reproducible analysis script.

### CLRT evaluation

Measure native and defended:

* Request-to-ACK.
* ACK-to-response CLRT.
* Request-to-response.
* READ versus SELECT.
* Median, mean, standard deviation.
* P5/P50/P95/P99.
* Confidence intervals.
* Outliers.
* Fail-open events.
* Deadline misses.

Demonstrate whether defended READ and SELECT timing distributions become difficult to distinguish.

### Physical-fingerprint evaluation

The upstream observable is:

```text
M = T_SER_event − T_OPERATE_observed
M = J + T_physical
```

Evaluate:

* Native `T_physical`.
* Defended `J + T_physical`.
* Whether J can be recovered from response timing.
* Whether TCP timestamps leak J.
* Whether the bounded random distribution reduces class separability.
* Added OPERATE latency.
* Complete SBO latency.
* Deadline and timeout margin.

Use only genuinely correlated physical/SER timestamps for physical claims.

If only one physical relay or one physical class is available, report:

```text
single-device physical mechanism proof
```

Do not call it multi-device fingerprint defeat. Use software or bootstrapped distributions only as clearly labeled supplementary analysis.

If two or more real device/operation classes exist, train and evaluate before/after classifiers using session-separated or run-separated splits:

* Simple threshold or nearest-centroid baseline.
* Logistic regression.
* Random forest.
* SVM if justified.

Report:

* Accuracy.
* Balanced accuracy.
* Macro F1.
* ROC-AUC where meaningful.
* Confusion matrix.
* Bootstrap confidence interval.
* Chance level.
* JS divergence or another distribution distance.
* Training/test separation.
* Number of samples.

Do not claim “defeated” unless classifier performance is statistically near chance under the stated observer. Otherwise report the exact measured reduction.

### Latency evaluation

Report separately:

* Switch processing/recirculation overhead.
* Configured J.
* ACK hold.
* Echo hold.
* Complete SBO overhead.
* P50/P95/P99 latency.
* Worst observed latency.
* Fail-open horizon.
* Master timeout margin.
* Operational safety bound.

Find the smallest bounded J profile that materially reduces classifier accuracy while remaining within the OPERATE timing budget.

## Phase 11: Publication-quality figures

Generate figures from scripts, not manual editing.

Save PNG plus vector PDF or SVG.

Required figures where supported by evidence:

1. Defense 4 testbed topology.
2. Unified BOR+RRC primitive.
3. SELECT preparation and OPERATE lifecycle.
4. Queue ladder qid7 through qid2.
5. One-pipe or two-pipe hardware pipeline.
6. Original T0, J, A, and R timeline.
7. RRC PRE replication and `[28,21]` carve.
8. Native versus defended CLRT distribution.
9. READ versus SELECT timing comparison.
10. Native versus defended physical-operation timing.
11. J convolution illustration.
12. Before/after classifier confusion matrices.
13. Accuracy and divergence before/after defense.
14. Added-latency distribution.
15. Compiler resource comparison.
16. Hardware gate summary.

Use consistent, colorblind-safe styling, readable labels, correct units, and honest axes. Do not hide tails or outliers.

Every caption must state whether evidence is:

* Physical silicon.
* Physical relay.
* Software endpoint through silicon.
* Offline emulator.
* Compiler-only.
* Synthetic or bootstrapped.

## Phase 12: Repository organization

Do this after the implementation and evidence are frozen.

Create a clear authoritative project map without destroying history.

At minimum provide:

```text
defense4/README.md
defense4/PROJECT_MAP.md
defense4/REPRODUCE.md
defense4/OVERNIGHT_STATE.md
defense4/docs/
defense4/figures/
defense4/evidence/
```

You may keep the existing implementation paths when moving them would break scripts or provenance. Prefer indexes and clear authoritative pointers over unnecessary mass renaming.

Clearly distinguish:

* Production kernel.
* Compile probes.
* Offline emulators.
* Control-plane setup.
* Analysis scripts.
* Hardware evidence.
* Archived negative results.
* Current authoritative result.

Correct contradictory and superseded claims. Preserve negative results as labeled history.

Do not commit multi-gigabyte compiler output directories. Commit the required raw logs, summaries, manifests, hashes, scripts, and small machine-readable evidence.

Ensure:

* No broken relative links.
* No broken commands.
* No stale SHA claims.
* No incorrect “one pipe” wording if two pipes are used.
* No claim that response normalization hides request sizes.
* No DPI-equivalence claim.
* No multi-device claim without multi-device evidence.
* Clean worktree.
* Local and remote SHA match.

## Phase 13: Write the final explainer last

Only after the implementation, hardware result, evidence, analysis, figures, and repository organization are final, write:

```text
defense4/EXPLAINER.md
```

This must be a detailed, beginner-accessible explanation in simple, natural language.

Use a human graduate-researcher tone. Avoid bloated language, unexplained acronyms, generic AI phrasing, and unnecessary jargon.

Explain with diagrams, timelines, concrete examples, and measured figures:

1. What device fingerprinting means in this project.
2. What the Formby paper’s CLRT and physical-operation fingerprints observe.
3. Basic DNP3 READ, SELECT, and OPERATE behavior.
4. Why an SBO contains two exchanges.
5. Why request sizes still differ.
6. How endpoint-native parity makes READ and SELECT echoes both 49 bytes.
7. What RRC is.
8. Why RRC uses PRE replication instead of insertion.
9. Why `[28,21]` is byte-preserving.
10. How TCP reassembly restores the original 49 bytes.
11. What BOR is.
12. Why BOR delays the OPERATE request.
13. What `T0`, `J`, `A`, and `R` mean.
14. Why all deadlines remain anchored to original T0.
15. Why a fixed J is insufficient.
16. How random J convolves the physical timing distribution.
17. Why TCP timestamps can reveal J.
18. How timestamp negotiation is handled.
19. How SELECT prepares the BOR reservoir.
20. The qid7–qid2 queue ladder.
21. The final one-pipe or two-pipe implementation.
22. Exactly-once physical delivery.
23. Fail-open behavior.
24. Compiler limitations and how they shaped the design.
25. The original padding/ledger failure.
26. The RRC innovation.
27. The readiness-race failure and correction.
28. Hardware setup.
29. Test procedure.
30. PCAP evidence.
31. CLRT results.
32. Physical-timing results.
33. Fingerprinting classifier results.
34. Added latency and timeout margin.
35. What is proven.
36. What remains limited.
37. How to reproduce the work.
38. Glossary.

Include simple examples such as:

```text
READ request: 20 B
SELECT request: 45 B
OPERATE request: 45 B
Native eligible response: 49 B
RRC output: [28,21]
```

Include equations, but explain each one in ordinary language.

Use final measured results only. Do not copy preliminary numbers that were later superseded.

## Final acceptance report

Finish with a concise operation review containing:

* Final architecture.
* One-pipe or two-pipe truth.
* Per-pipe compiler resources.
* Source and binary hashes.
* Offline conformance result.
* Mutants killed.
* Hardware gates.
* RRC READ result.
* RRC SELECT result.
* Software OPERATE BOR result.
* Physical OPERATE result or precise safety blocker.
* CLRT result.
* Physical-fingerprint result.
* Classifier result.
* Added latency.
* Fail-open count.
* Retransmission/duplicate count.
* Final switch state.
* Relay reachability.
* Final output states.
* Evidence path.
* Figure path.
* Explainer path.
* Final commit.
* Remote SHA match.
* Clean worktree.

## Non-negotiable honesty rules

* Compile is not silicon.
* Software endpoint traffic is not a physical relay operation.
* SELECT is not OPERATE.
* Fail-open is not successful BOR shaping.
* A fixed J is not physical-fingerprint mitigation.
* One physical device is not a multi-device classifier campaign.
* Response parity is not full transaction parity.
* Size/timing parity is not DPI parity.
* Two physical pipes are not one physical pipeline.
* A prompt or model must not invent authorization for a physical operation.
* No claim may be stronger than its raw evidence.

Begin now. Work continuously and autonomously. Do not stop after the first compiler failure, design note, or partial test. Preserve the proven RRC path, make progress through the ordered gates, and write the explainer only after the final engineering result is frozen.
