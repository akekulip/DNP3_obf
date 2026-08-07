# Defense 4 completion, experiments, classification, and explainer prompts

Use these prompts in order. Paste only one prompt at a time. Do not move to the next prompt until the current prompt has produced raw evidence, passed its stated gate, committed the work, and pushed the checkpoint.

The current audited repository boundary is branch `defense4-caseA-hw-integration` at commit `ae2a802` on 2026-08-07. The executing agent must verify the current local and remote tip before acting and inspect every later commit if the branch has advanced.

Important scientific boundary: one physical SEL-751 is enough to prove that Defense 4 controls its timing, but one device cannot establish before-versus-after device-classification mitigation. A device-classification result requires at least two comparable device implementations or a clearly labeled controlled software-profile study. Do not turn policy classification, OFF-versus-D4 classification, or synthetic timing-profile classification into a cross-device claim.

## Prompt 0: Standing execution charter

```text
You are continuing the DNP3_obf Defense 4 timing project. This project is not ADTA or ADTD. Do not rename it. Work only on timing Defense 4. Do not begin size obfuscation and do not merge into main.

Start on branch defense4-caseA-hw-integration. At the time this instruction was written, the last independently audited boundary was ae2a802, but do not assume that is still the tip. Fetch read-only metadata, verify local HEAD, remote HEAD, branch divergence, working-tree status, and all commits after ae2a802. Preserve all existing pre-fix and disputed evidence. Never overwrite old raw campaigns.

The current normal READ-path lifecycle repair is promising, but the repository's TIMING EXPERIMENTS PASS verdict is not accepted as proof. Treat it as reopened until the code, raw data, PCAPs, compiler artifacts, test harness, manifests, canonical evidence, and final live state independently satisfy the gates below. Do not rely on Claude summaries, commit messages, Markdown verdicts, medians, or code comments.

Known audited problems at ae2a802 that must be verified and closed, not merely restated:

1. score_campaign.py prints ATTENTION but returns exit code 0.
2. run_campaign.sh suppresses critical driver and scorer failures with || true.
3. malformed, missing, or empty evidence can be interpreted as clean.
4. byte_identity.py checks framing and length at one observation point, not exact ingress-versus-egress bytes.
5. controlled missing-ACK, missing-RESPONSE, overlap, duplicate, identity-mismatch, FIN/RST, combined-response, multi-segment, SELECT, and OPERATE tests were not executed.
6. campaign SHA256SUMS files hash run.log before later writes, so verification fails.
7. the global manifest and canonical evidence files disagree about source hashes, D2/D4 behavior, parameters, and verdict.
8. R11 reservoir readiness remains measured rather than structural.
9. the current Introduction overstates fixed-value normalization and byte preservation and must remain quarantined until the final gate closes.
10. the current normal-path data supports zero planned D2/D4 RESPONSE bypass on the tested READ path, but it contains late-arrival tails. Never describe the full distribution using only its median or as an exact fixed value unless all raw observations support that wording.

Evidence rules:

- Every conclusion must trace to committed raw evidence.
- Every experiment must record attempted, sent, responded, valid, invalid, and excluded counts, with exact reasons.
- A parser error, missing file, empty input, incomplete capture, counter-read failure, scorer anomaly, or hash mismatch is a hard nonzero failure.
- Do not use || true or an equivalent construct on any command whose output is required for validity.
- Preserve exact source, binary, compiler, setup, policy, and data hashes.
- Final manifests must be generated only after every file in the evidence directory is closed, and sha256sum -c must pass.
- Do not silently delete failed trials, rerun over them, or retain only successful runs.
- Keep pre-fix evidence clearly separated from post-fix evidence.

Safety rules:

- The physical SEL-751 is READ-only. Never send SELECT, OPERATE, DIRECT OPERATE, or another control command to it.
- Run hazardous, malformed, combined-response, multi-segment, SELECT, and OPERATE cases only against an isolated software outstation.
- Keep the current D4 build running during offline work. Immediately before a switch write, take a complete read-only state snapshot and arm an independent watchdog with the validated Defense 3 rollback as the emergency target.
- Restore Defense 3 only if the candidate D4 load fails a management, forwarding, safety, state, queue, or correctness check. If the validated D4 run passes, leave the exact tested D4 binary and policy running.
- Change policy only while the transaction engine is verified inactive and the queues are drained.

Do not stop after writing a plan. Execute the current phase, run its tests, preserve raw outputs, commit a meaningful checkpoint, push it, and report commands, exit codes, hashes, sample counts, failures, and paths. Stop only for a genuine safety or access blocker.
```

## Prompt 1: Reopen the gate and repair the evidence system

```text
Execute Phase 1 now: make the measurement and evidence pipeline fail closed before running more experiments.

First read the complete current versions of:

- defense4/TIMING_SPEC.md and the architecture documents;
- defense4/timing/p4/defense4_caseA.p4;
- defense4/timing/control/defense4_caseA_setup.py;
- every script under defense4/timing/control/deploy/;
- EXPERIMENTAL_EVIDENCE_FREEZE.md, EXPERIMENT_MATRIX.md, PARAMETER_CALIBRATION.md, SPEC_IMPLEMENTATION_EVIDENCE_MATRIX.md, DEFENSE4_BOTTLENECKS.md, SHA256SUMS, the final-state files, and the raw corrected campaigns;
- defense4/paper/INTRODUCTION_DRAFT.tex, its claim-source matrix, and QUARANTINE.md.

Independently reproduce the known scorer, manifest, and documentation failures. Record the commands and exit codes in a new NEXT_RUN_BASELINE_AUDIT.md. Reapply the Introduction quarantine and mark the current PASS verdict invalid until the final acceptance prompt closes it.

Repair the harness with the smallest clear implementation:

1. score_campaign.py must raise a hard error for a missing argument, unreadable file, malformed JSON, empty JSON, missing rows, capture_ok != true, unexpected row count, attempted/sent/responded disagreement, absent required counters, missing PCAP, missing ACK/RESPONSE outside the declared negative case, ordering inversion, protected D2/D4 RESP_BYPASS, token escape, queue/port drop, stale state, insufficient re-arm, counter mismatch, or any unrecognized mode. It must exit nonzero for every hard anomaly and zero only for a fully valid block.
2. Add an explicit scenario/expectation schema. The scorer must distinguish normal, deliberately missing-ACK, deliberately missing-RESPONSE, late-response, combined-response, multi-segment, teardown, and fail-open tests instead of treating all missing fields alike.
3. run_campaign.sh must propagate driver, capture, evidence-dump, scorer, analyzer, copy, and manifest failures. Remove || true from required operations. On failure, preserve partial evidence, perform the safety path, and exit nonzero.
4. Validate that the number and names of local PCAPs exactly match the experiment specification. A missing, empty, truncated, or unreadable PCAP fails the run.
5. Finalize the switch state and append the last run.log message before creating SHA256SUMS. Do not modify a hashed artifact afterward. Run sha256sum -c and store its successful output.
6. Replace the current byte-preservation claim with a paired-capture comparator. Match the same frame across relay-facing ingress and master-facing egress using direction, TCP 4-tuple, TCP sequence and acknowledgment numbers, flags, DNP3 application sequence, payload length, and occurrence index. Compare the full TCP payload exactly. Separately compare all Ethernet/IP/TCP fields that the transparent design promises to preserve, explicitly accounting for FCS absence, capture offload, VLAN, and any documented L2 differences. Emit a per-frame mapping and byte offset diff. Any unmatched, duplicated, reordered, or changed protected application payload fails.
7. Disable or account for GRO, GSO, TSO, LRO, and checksum offload at both capture points. Record the before/after offload configuration.
8. Add automated unit and integration fixtures that prove the tools fail on malformed JSON, empty data, a missing PCAP, an injected RESP_BYPASS, an ordering inversion, a stale tag, a counter mismatch, a dropped packet, an injected payload-byte mutation, and a bad manifest. Include one clean fixture that exits zero.
9. Make analyze_campaign.py fail on malformed or silently skipped blocks. Use session/block-aware statistics, not pooled pseudoreplicates alone. Report exclusion reasons and complete distributions.

Create a new immutable evidence root for the final run. Do not edit old raw files. At the end, run every offline test and a synthetic end-to-end dry run. Prove with captured exit codes that bad fixtures fail and the clean fixture passes.

Acceptance for this phase:

- all fail-closed tests pass;
- no required command is suppressed;
- paired byte comparison exists and catches a one-byte mutation;
- a newly generated test manifest verifies completely;
- canonical documents are marked REOPENED consistently;
- the Introduction is quarantined;
- working tree changes are committed and pushed.

Do not touch the live switch in this phase.
```

## Prompt 2: Build the controlled software outstation and negative-test laboratory

```text
Execute Phase 2 now: build an isolated, reproducible software outstation/injector path through the Tofino switch. Do not use the physical SEL-751 for this phase.

Reuse an existing standards-compliant DNP3 stack in the repository or environment if one exists. If none exists, implement the smallest deterministic software outstation and packet injector that can generate valid DNP3/TCP exchanges and deliberately controlled edge cases. Document the chosen stack, version, build steps, topology, addressing, clock source, and limitations. Do not fabricate DNP3 semantics or CRC behavior.

Capture full Ethernet simultaneously at both sides of the switch. Use the paired comparator from Phase 1. Record the software outstation's intended frame bytes before transmission so exact byte identity can be checked even when live physical values would normally change.

Create a machine-readable test matrix. For every case, declare the expected P4 classification, expected release cause, expected queue, expected final reg_tag state, expected counter deltas, expected wire behavior, and whether the next transaction must re-arm before executing it.

Run at least these cases:

1. Normal separate ACK and RESPONSE, with RESPONSE arriving before T_A.
2. RESPONSE after ACK release but before T_RESP. This is mandatory proof that the repaired response obligation survives ACK release.
3. RESPONSE after T_RESP but before the fail-open horizon. Record it as an explicit late-arrival path. It cannot be called deadline-normalized.
4. RESPONSE after the fail-open horizon.
5. Missing ACK with a later RESPONSE.
6. ACK with no RESPONSE.
7. Missing both ACK and RESPONSE.
8. Duplicate READ, duplicate ACK, duplicate RESPONSE, and retransmitted TCP segment.
9. Wrong DNP3 application sequence, wrong TCP sequence, wrong TCP acknowledgment, wrong source port, wrong 4-tuple, wrong direction, and stale generation.
10. A second overlapping READ while the first transaction is active. Verify that it does not overwrite the first transaction's expected sequence, port, acknowledgment, deadline, or generation state.
11. FIN and RST before ACK, after ACK but before RESPONSE, and after RESPONSE.
12. At least 33 READs on one TCP connection, configured once, covering C0 through CF twice and returning to C0, with no per-poll state clear.
13. A host-originated 0x88C1 frame and a malformed internal-token lookalike. Neither may reach a protected queue or escape to the master-facing wire.
14. Independent or asymmetric ACK- and RESPONSE-reservoir expiry.
15. True cold start, first protected transaction, repeated cold starts, reservoir establishment, earliest ACK, qid7/qid5 continuity, top-up, drain, and readiness across transaction boundaries.
16. Combined ACK-bearing DNP3 RESPONSE.
17. A valid multi-segment or fragmented RESPONSE.
18. READ, SELECT, OPERATE, and any other explicitly supported or bypassed function. SELECT and OPERATE are software-outstation-only. Verify that unsupported functions do not arm or corrupt protected READ state.

For missing-event tests, induce the actual event absence. A small budget is useful for calibration, but it is not a substitute for a silent outstation. For FIN/RST, overlap, duplicate, and identity tests, prove both the immediate behavior and the next transaction's ability to arm and finish.

If a test exposes a P4 defect, stop the campaign, preserve the failing PCAPs and state, and move to the P4 repair phase. Do not relabel a failed requirement as a scope boundary merely to obtain PASS. If combined response or multi-segment traffic remains unsupported by design, demonstrate its exact bounded behavior and close the paper claim accordingly.

Required artifacts:

- reproducible software-outstation and injector source;
- topology and launch scripts;
- scenario specification files;
- paired raw PCAPs for every case;
- intended-byte records and exact comparison reports;
- pre/post counters and registers;
- per-case scorer result and exit code;
- a lifecycle regression report;
- valid SHA256SUMS and sha256sum -c output.

Acceptance for this phase:

- every mandatory case has PASS, FAIL, or a technically justified unsupported result based on an executed test;
- actual missing-ACK and missing-RESPONSE cleanup is observed;
- late RESPONSE after ACK release is handled by the same generation and the next transaction re-arms;
- exact payload bytes match across the switch for all frames that should be transparent;
- no token escapes, unexplained drops, or stale state remain;
- results are committed and pushed.
```

## Prompt 3: Close P4 lifecycle risks, compile exactly, and deploy safely

```text
Execute Phase 3 only after the controlled tests identify the actual remaining P4 behavior.

Audit defense4_caseA.p4 from parser through ingress, traffic-manager queue selection, recirculation, and deparser. Do not trust stale comments. Trace each packet class and every RegisterAction with concrete control dependencies.

Challenge these known risks with the controlled evidence:

- mode-aware retirement after ACK release;
- qid5 blocker behavior when no RESPONSE is pending at T_RESP;
- a RESPONSE after T_A and after T_RESP;
- the active transaction's trackers being written before the fresh/busy arm decision;
- duplicate and overlapping READ behavior;
- absence or adequacy of FIN/RST cleanup;
- reuse of the 16 DNP3 application-sequence values and the ABA window;
- mode/parameter mismatch enforcement;
- low-byte-zero and half-range arithmetic invariants;
- reservoir readiness at cold start;
- combined-response and multi-segment behavior;
- exact transaction identity checks.

Implement the smallest resource-safe repair for every reproduced defect. Preserve D1 and D3 behavior. Do not hide a lifecycle defect by increasing D_A until every RESPONSE precedes ACK release. At least one mandatory test must retain ACK release before RESPONSE arrival.

If the implementation continues to use the DNP3 application sequence as its generation, say so explicitly and reconcile the specification. Do not call it an independent internal generation. Prove its bounded reuse assumptions. If the concurrency path can overwrite active trackers, either repair it or make the data plane reject the second READ before those writes. If FIN/RST cleanup is a required invariant, implement generation-qualified cleanup or demonstrate and document the exact bounded alternative.

For R11, evaluate a structural readiness guard, verified prefill with readback, periodic top-up, a compact residency ledger, or another fit-safe design. Compile each serious candidate before rejecting it. If only a measured readiness margin is possible, R11 remains OPEN and the final verdict and claims must reflect that.

Run offline reference-model and lifecycle regressions before compilation. Then compile the exact source with BF-SDE 9.13.2. Preserve the complete compiler transcript and raw artifacts, including table summary, stage allocation, MAU resources, PHV allocation, dependency/critical path, parser/deparser resources, SRAM, TCAM, Map RAM, stateful ALUs, statistics ALUs, logical tables, power, warnings, and errors. Record source and binary SHA-256 values and binary size. Compare them against both the pre-fix build and the ae2a802 repair build.

Do not infer resource use from prior logs. The exact source hash in the repository must match the exact compiled binary deployed.

Before a live write:

1. preserve a complete read-only current switch snapshot;
2. verify management and forwarding;
3. arm the detached watchdog with Defense 3 as the emergency rollback;
4. load the candidate D4 binary;
5. verify loaded program and binary hash, ports, queues, mirrors, pktgen, policy, relay reachability, and one READ;
6. run the controlled targeted cases and a short physical READ-only smoke test;
7. roll back only if a safety or correctness check fails.

Acceptance for this phase:

- exact BF-SDE 9.13.2 compile with zero errors;
- compiler artifacts and source/binary hashes are committed or otherwise repository-verifiable without pretending an absent binary is preserved;
- targeted controlled tests pass on the exact deployed binary;
- D1/D3 regression passes;
- D2/D4 preserve the response obligation after ACK release;
- missing events clean up and next transactions re-arm;
- resource and R11 conclusions are evidence-backed;
- checkpoint committed and pushed.
```

## Prompt 4: Recalibrate and run the final physical and controlled campaigns

```text
Execute Phase 4 on the exact candidate binary that passed Phase 3. Do not reuse old calibration merely because 4/8 ms or 4/10 ms was previously selected.

Run a fresh OFF pilot on the physical SEL-751 using READ only. Use multiple sustained TCP sessions and enough observations to estimate per-session and pooled p5, p25, median, p75, p95, p99, maximum, IQR, drift, connection-to-connection variation, loss, retransmission, reset, and response-size behavior. Define CLRT only as the master-facing interval from the pure TCP ACK to the first byte of the matching DNP3 RESPONSE. Keep request-to-ACK and request-to-RESPONSE as separate metrics.

Calibrate candidates:

- D2 requires D_A = 0. Select and test D_R from the native ACK-to-RESPONSE distribution plus an explicit margin.
- D4 selects D_A for the desired ACK release and selects D_A + D_R to cover a stated region of the native response-arrival distribution. D_R is the intended external ACK-to-RESPONSE interval when the RESPONSE arrives before T_RESP.
- Do not raise D_A to conceal the lifecycle case. Preserve a focused test where the RESPONSE arrives after T_A.
- Call final parameters selected and tested, never optimal.

For every candidate preserve requested milliseconds, encoded word, realized ticks, realized nanoseconds and milliseconds, quantization error, D_A + D_R, distance from the modular half-range, polling interval, fail-open horizon, measured release error, on-time proportion, late proportion, and reliability.

Run targeted campaigns first:

- D1 event causality, proving ACK release follows the matching RESPONSE event rather than an ordinary deadline;
- D2 normal, late, missing-response, and re-arm behavior;
- D3 ACK-deadline regression;
- D4 RESPONSE before T_A, between T_A and T_RESP, after T_RESP, and after fail-open;
- actual missing ACK and actual missing RESPONSE;
- fail-open followed by normal protected recovery;
- cold-start/R11 trials;
- 33 or more READ generation rollover;
- concurrency, duplicate, FIN/RST, combined-response, multi-segment, SELECT/OPERATE bypass, and identity negatives on the software outstation.

Then run the full statistical campaigns:

Campaign A:

- OFF, D1, D2, D3, and D4;
- fixed-condition blocks;
- at least 100 valid transactions per mode;
- at least two sustained TCP sessions per mode.

Campaign B:

- at least 100 additional valid transactions per mode;
- randomized block order with a recorded seed;
- policy changes only while inactive and drained;
- retain session and block identifiers;
- no state clear per poll.

Minimum accepted total is 200 valid transactions per mode and 1,000 across OFF and D1 through D4, plus targeted and negative tests. Failed and invalid transactions remain in the denominator and are reported with reasons.

For every block collect:

- full unfiltered master-facing PCAP;
- paired relay-facing PCAP where byte identity is part of the claim;
- intended bytes for controlled traffic;
- transaction JSON/CSV with session, block, poll, app sequence, 4-tuple, TCP seq/ack, t_READ, t_ACK, t_RESPONSE, T_A, T_RESP, release timestamp, CLRT, request-to-ACK, request-to-RESPONSE, arrival bucket, release cause, response disposition, lengths, duplicate/retransmit/reset/FIN fields, validity, and exclusion reason;
- pre/post registers, counters, queue watermarks, queue drops, port drops, pktgen state, policy readback, loaded binary hash, and clock information;
- scorer output and exit code.

Report complete empirical distributions, ECDFs, p5/p25/p50/p75/p95/p99/max, IQR, session-aware bootstrap confidence intervals, release-cause proportions, early/late/bypass proportions, release error, late-arrival tail, request latency, retransmissions, duplicates, resets, ordering violations, token escapes, queue/port drops, byte mismatches, stale state, and failed re-arms.

For protected D2/D4, any unplanned RESP_BYPASS is a hard failure. A matched response arriving after T_RESP must be reported as a late safe-release path, not hidden inside the deadline cluster. Never say the entire population equals the target when a late tail exists.

Finalize each raw directory only after the switch state and log are complete. Generate and verify SHA256SUMS. Preserve the exact final state. Commit and push the campaign checkpoint.
```

## Prompt 5: Before-and-after timing fingerprint clustering and classification

```text
Execute Phase 5 as a separate scientific experiment. Its question is not whether D4 delays packets. Its question is whether the timing information available to an observer becomes less useful for identifying the source device or implementation.

Begin with a dataset and device inventory. Do not run a device classifier unless there are at least two labeled, comparable, separate-ACK DNP3 device implementations performing the same READ operation with comparable response content and topology.

Use two evidence tiers:

Tier 1, physical devices:

- If two or more comparable physical Case-A devices are available, collect balanced OFF and D4 data from each under the same polling schedule, request, network path, capture point, and selected D4 policy.
- If only the SEL-751 is available, state that physical cross-device classification is unavailable. Do not classify OFF versus D4 and call that device-fingerprint mitigation.

Tier 2, controlled software profiles:

- Build at least three deterministic software outstation implementations or timing profiles with identical DNP3 payloads, packet sizes, ACK mode, TCP settings, and request stream but different native processing-time distributions. Include a short unimodal profile, a longer profile, and a heavy-tail or bimodal profile.
- Label this a controlled timing-profile experiment, not a multi-vendor physical-device experiment.
- Apply one common D4 policy to every profile. Do not tune a separate policy per class because that leaks the label and weakens the claim.

For either tier, use at least 10 independent TCP sessions per class and condition and at least 50 valid transactions per session, unless a documented power or precision calculation justifies a larger requirement. Preserve invalid trials. Randomize session and condition order and record the seed.

Create one canonical transaction table with:

- device/profile label;
- physical or controlled evidence tier;
- OFF or D4 condition;
- session, block, and transaction identifiers;
- ACK-to-RESPONSE interval in milliseconds;
- request-to-ACK and request-to-RESPONSE intervals;
- response size, segment count, packet count, TCP flags, retransmission, reset, release cause, late flag, and validity;
- capture, source, binary, policy, and raw-row provenance.

Pre-register three feature sets:

1. Primary CLRT-only feature: ACK-to-RESPONSE interval only. This directly tests the channel Defense 4 targets.
2. Timing-only residual features: CLRT, request-to-ACK, request-to-RESPONSE, inter-poll timing, and late-arrival indicator.
3. Full observable residual features: timing features plus size, segment count, ACK mode, and packet-count/TCP metadata. This does not test timing concealment alone. It shows what fingerprints remain because Defense 4 is timing-only.

Prevent leakage:

- split and cross-validate by TCP session, never by randomly shuffling individual packets from the same session;
- keep all samples from one session in one fold;
- perform scaling, feature selection, dimensionality reduction, and hyperparameter tuning only inside the training folds;
- use nested GroupKFold or leave-one-session-out validation;
- fix and record all random seeds;
- include majority-class and label-permutation baselines.

Analyses:

- For one-dimensional CLRT, use ECDF, histogram/density, violin or box plus jittered points, and per-session small multiples. Do not use PCA or UMAP on one feature.
- Quantify pairwise overlap coefficient, Wasserstein distance, Jensen-Shannon distance, and a session-bootstrap confidence interval before and after D4.
- Fit a simple interpretable classifier and at least one nonlinear classifier, such as multinomial logistic regression plus an RBF SVM or random forest. Report balanced accuracy, macro-F1, per-class precision/recall, confusion matrix, and 95 percent session-bootstrap confidence intervals.
- For unsupervised analysis, use a Gaussian mixture or k-means with the number of true classes withheld from fitting where appropriate, then report adjusted Rand index and normalized mutual information. Explain why cluster recovery is or is not meaningful.
- For multivariate features, use PCA as the main 2D projection. UMAP may be a supplemental visualization only, with a fixed seed and no claim based solely on its picture.
- Run four adversary tests: train OFF/test OFF, train D4/test D4, train OFF/test D4, and train on earlier sessions/test on later held-out sessions.
- Analyze the D4 late tail separately. Report late fraction by class, classifier performance with all observations, with the late indicator removed, and on the on-time subset. If class-dependent late rates remain discriminative, report that residual leak.
- Use a paired or session-bootstrap estimate of the drop in balanced accuracy and macro-F1 from OFF to D4, plus a permutation test. Do not infer mitigation from overlapping plots alone.

Required figures, generated from committed data by reproducible code:

1. Native versus D4 ECDFs, faceted by device/profile on a shared linear millisecond axis.
2. Native versus D4 distribution plots with all observations or a transparent sampling rule.
3. Per-session medians and tails to show drift and avoid pooled-data deception.
4. Pairwise overlap or Wasserstein heatmaps before and after.
5. Before and after confusion matrices.
6. Balanced accuracy and macro-F1 with confidence intervals and chance baselines.
7. PCA projection for the multivariate feature sets.
8. Late-arrival fraction and classification contribution.
9. Deadline choice versus on-time coverage, added latency, and residual classification accuracy.

Use plain, precise labels such as ACK-to-RESPONSE interval (ms). Do not use decorative AI-generated charts. Use reproducible statistical plotting code. Every plot must include the source data hash, script hash, sample counts, unit, and caption-ready interpretation.

Acceptance and wording:

- If D4 reduces CLRT-only classification toward chance with confidence intervals supporting the reduction, say it mitigates the tested CLRT channel.
- If timing-only or full-observable classifiers remain above chance, report the remaining fingerprint.
- If only controlled profiles are available, say D4 collapses controlled timing-profile separability. Do not claim cross-vendor or cross-device indistinguishability.
- If only one physical device exists, the physical result is timing normalization for that device, not classification mitigation.
- Never claim anonymity, full fingerprint removal, universal generalization, or size concealment.

Preserve the canonical dataset, split manifests, model parameters, seeds, predictions, metrics, plots, and environment file. Commit and push the analysis checkpoint.
```

## Prompt 6: Independent acceptance gate and evidence freeze

```text
Execute Phase 6 as a skeptical independent reviewer. Do not begin by reading the prose verdict. Start from the exact source, compiler artifacts, raw JSON/CSV, PCAPs, paired byte reports, counter snapshots, scorer exit codes, and manifests.

Recompute campaign totals and statistical distributions from raw files. Reparse every final PCAP independently. Re-run exact byte matching. Re-run all score and manifest checks. Spot-check transaction-to-counter reconciliation. Verify that the source hash, compiled binary hash, loaded binary hash, final binary hash, policy readback, and final switch snapshot all agree.

Reconcile these canonical files so they state one current interpretation and contain no stale banners or pre-fix conclusions:

- NEXT_RUN_BASELINE_AUDIT.md;
- SPEC_IMPLEMENTATION_EVIDENCE_MATRIX.md;
- EXPERIMENT_MATRIX.md;
- PARAMETER_CALIBRATION.md;
- DEFENSE4_BOTTLENECKS.md;
- EXPERIMENTAL_EVIDENCE_FREEZE.md;
- SHA256SUMS and every per-run manifest;
- final engineering report;
- final live-state snapshot;
- Introduction quarantine and claim-source matrix.

Every required row must end as PASS, FAIL, NOT APPLICABLE with a technical reason, or BLOCKED WITH EVIDENCE after bounded attempts. No row may remain unknown, planned, assumed, not attempted, or contradicted elsewhere.

PASS requires, at minimum:

- exact BF-SDE 9.13.2 compile and resource evidence for the deployed source;
- fail-closed scorer and harness, proven by negative fixtures;
- complete, valid, immutable evidence manifests;
- D1 event causality;
- D2 response-deadline behavior;
- D3 ACK-deadline regression;
- D4 ACK-before-RESPONSE lifecycle, including RESPONSE after T_A;
- explicit late-after-T_RESP behavior;
- actual missing-ACK and missing-RESPONSE cleanup;
- fail-open and next-transaction recovery;
- at least 33 READ generation rollover on one connection;
- duplicate, overlap, identity, FIN/RST, and token-isolation results;
- combined-response and multi-segment behavior tested and bounded, even if unsupported;
- SELECT/OPERATE bypass tested only on software;
- exact paired payload identity with zero unexplained mismatches;
- zero unexplained token escapes, ordering inversions, queue/port drops, stale state, and failed re-arms;
- Campaign A and B minimum sample counts and full distributions;
- R11 either structurally closed or explicitly carried into a closed partial verdict;
- classification conclusions that match the available number and type of device classes;
- a repository-verifiable final switch state.

Use exactly one verdict:

- TIMING EXPERIMENTS PASS
- TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY
- TIMING EXPERIMENTS FAIL
- TIMING EXPERIMENTS BLOCKED

Do not use PASS while a mandatory negative is unexecuted, exact byte identity is absent, a manifest fails, the scorer accepts bad data, canonical files disagree, or the final state is not verifiable. Do not use PARTIAL WITH CLOSED CLAIM BOUNDARY while an integrated D2/D4 lifecycle defect or an unbounded safety defect remains open.

If the verdict is PASS or a genuinely closed PARTIAL, leave the exact tested D4 binary and policy running, verify forwarding and idle state, ensure the watchdog is intentionally stood down, and commit the complete final snapshot. If the candidate fails, restore and verify Defense 3 and commit that state.

Commit and push the freeze before touching the paper. Report the starting and ending commits, all discrepancies, exact failures, sample counts, hashes, compiler resources, selected/encoded/realized parameters, classifier scope, R11 status, final verdict, final switch state, and push status.
```

## Prompt 7: Post-acceptance Defense 4 deep dive and visual explanation

```text
Run this phase only after Phase 6 has committed either TIMING EXPERIMENTS PASS or a genuinely closed TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY. At the start, independently verify that verdict, manifests, hashes, and final state. If the gate is not closed, stop and report the missing evidence. Do not create a success explainer from an unaccepted build.

Create a complete Defense 4 explanation package for Philip. It must first explain the design in simple English, then provide an engineering deep dive tied to the exact accepted source and compiler output.

If the skills are available, use answers-charts for numeric plots and visualize for an interactive timing/lifecycle explainer. Use Mermaid for exact causal, state, and topology diagrams. Use reproducible Python plotting for measured data. Do not use image generation for data charts, pipeline maps, state machines, or resource diagrams. If producing Word or PDF, use the document/PDF workflows and render every page for visual verification.

Create:

- defense4/explainer/DEFENSE4_SIMPLE_EXPLAINER.md;
- defense4/explainer/DEFENSE4_ENGINEERING_DEEP_DIVE.md;
- defense4/explainer/DEFENSE4_CODE_WALKTHROUGH.md;
- defense4/explainer/DEFENSE4_RESOURCE_AND_BOTTLENECK_MAP.md;
- defense4/explainer/FIGURE_INDEX.md;
- defense4/explainer/figures/ with publication-quality SVG/PDF/PNG figures generated from source or measured data;
- an optional interactive timing explainer showing t_A, T_A, RESPONSE arrival, T_RESP, fail-open horizon, and the resulting queues/release cause;
- a compiled, visually verified PDF technical report if the required tooling is available.

Explain in this order:

1. The problem: a passive observer measures the interval from the pure TCP ACK to the matching DNP3 RESPONSE and uses repeated observations as a device-behavior fingerprint.
2. Why random jitter alone can be averaged over repeated polls, while normalization tries to make the released timing follow a shared policy.
3. The threat model, trusted switch position, Case-A separate-ACK boundary, READ-only physical experiment, and what the defense does not hide.
4. The one-sentence mechanism: original ACK and RESPONSE packets wait in low-priority queues while higher-priority generation-bound blocker tokens recirculate until the release condition is met.
5. The four queues: Q_ACK_BLOCK qid7, Q_ACK_HOLD qid6, Q_RESP_BLOCK qid5, and Q_RESP_HOLD qid4. Explain strict priority and why the blockers, not the original packets, recirculate.
6. Timing semantics: t_A, D_A, T_A = t_A + D_A, D_R, and T_RESP = t_A + D_A + D_R. Explain the on-time and late-response cases without implying time travel.
7. The mode table: OFF, D1 event, D2 response deadline, D3 ACK deadline, D4 dual deadline, configured FAIL_OPEN, and induced runtime fail-open.
8. A complete packet journey: master READ, parser/classification, transaction arm, expected TCP/DNP3 state, pktgen blocker creation, queue assignment, ACK admission, ACK release, RESPONSE admission, RESPONSE release, retirement, stale-token termination, and next re-arm.
9. The transaction lifecycle and generation mechanism. State accurately whether the accepted build uses DNP3 app sequence or a separate internal generation, its rollover behavior, and the ABA bound.
10. Exact matching: direction, protected session, ingress port, TCP 4-tuple, TCP sequence/acknowledgment, DNP3 function, and generation.
11. Fail-open and cleanup: budget, missing events, late events, duplicate/overlap behavior, FIN/RST behavior, and why the next transaction is not stranded.
12. Control plane versus data plane: the control plane loads and configures policy between drained transactions; the P4 data plane, pktgen, recirculation, queues, and Traffic Manager perform per-packet enforcement without controller-timed releases.
13. Code implementation: parser states, metadata, tables, actions, RegisterActions, counters, queue selection, deparser, setup script, policy validation, watchdog, campaign driver, scorer, and analyzer. Cite exact file paths and current line ranges.
14. Tofino pipeline: show what happens in parser, each ingress stage or stage group, Traffic Manager, recirculation port, and deparser. Do not invent stage placement. Derive the map from the accepted compiler artifacts.
15. Resource use: ingress stages, egress stages, critical path, logical tables, SRAM, TCAM, Map RAM, parser TCAM, PHV containers/groups, stateful ALUs, statistics ALUs, registers, counters, and queues. Explain in simple terms what consumes each resource.
16. Why reg_deadline and reg_tresp are separate, the earlier co-location failure, the four-RegisterAction limit, PHV operand pressure, and why the accepted version fits or where it does not.
17. Runtime bottlenecks: K=64, reservoir establishment/readiness, one active scheduler domain, polling gap, maximum safe deadline, generation reuse, concurrency, late tails, combined responses, segmentation, and R11.
18. Experimental design and results: controlled negatives, physical Campaign A/B, selected parameters, reliability, exact byte evidence, release causes, full CLRT distributions, and before/after classification.
19. Claim boundary and remaining work, in plain language.
20. A glossary for DNP3, TCP ACK, RESPONSE, CLRT, T_A, T_RESP, blocker, queue residence, pktgen, recirculation, SALU, PHV, SRAM, TCAM, and fail-open.

Required visuals:

- testbed and adversary placement;
- native versus D4 timing sequence;
- D1/D2/D3/D4 timing small multiples;
- four-queue priority mechanism;
- transaction state machine with normal, late, missing, duplicate, fail-open, and cleanup paths;
- packet journey through parser, ingress, Traffic Manager, recirculation, and output;
- compiler-derived ingress-stage map;
- register/table dependency map;
- resource utilization chart with exact counts and limits;
- cold-start/reservoir readiness timeline;
- calibration tradeoff plot;
- Campaign A/B ECDFs and tail views;
- before/after device/profile clusters and classifier confusion matrices;
- acceptance and limitation matrix.

Every measured figure must be generated from committed data, show units and sample counts, and record source-data and script hashes. Every schematic must be checked against the P4 and setup code. Clearly label measured, modeled, inferred, and proposed quantities.

Correct these common errors:

- CLRT is ACK-to-RESPONSE for the Case-A study, not request-to-reply.
- Timing is observed from packet timestamps; DNP3 does not carry CLRT as a field.
- DNP3 CRCs protect link-layer blocks, not each application block.
- Held originals stay queue-resident. Blocker tokens recirculate.
- The controller configures policy; it does not schedule every release.
- A RESPONSE after T_RESP is a late safe release, not fixed-deadline normalization.
- Timing-only mitigation is not full device indistinguishability.

Use active, direct prose, simple English first, no em dashes, no generic AI phrasing, and no unsupported novelty claim. Commit and push the explainer package only after line-by-line technical verification.
```

## Prompt 8: Paper integration after acceptance

```text
Run this phase only after the experimental gate and explainer package are accepted.

Update the paper from the final raw evidence, not from the old Introduction. Preserve the old draft in history. Rebuild INTRODUCTION_CLAIM_SOURCE_MATRIX.md so every sentence maps to a primary source or a specific experimental artifact, and marks direct evidence versus inference.

Use Dr. Lin's scientific story:

1. Fingerprinting is reconnaissance used to learn device type, role, vendor, implementation, or behavior.
2. Narrow to the separate-ACK DNP3 observable: the pure TCP ACK-to-DNP3 RESPONSE interval.
3. Explain why repeated polling can average away independent random jitter and why policy-based normalization targets the distribution more directly.
4. Review size, timing, rate, and communication-pattern defenses, with careful plaintext and payload-opacity assumptions.
5. State the legacy ICS gap precisely: visible protocol semantics, unmodifiable field devices, transparent deployment, TCP ordering/retransmission safety, DNP3 transaction matching, and Tofino's inability to sleep and recall a packet.
6. Tell the design story: one switch keeps original ACKs and RESPONSEs queue-resident while generation-bound blocker tokens and Traffic Manager priority control visibility.
7. Make novelty come from the DNP3, TCP, and Tofino obstacles actually identified, solved, compiled, and tested.
8. State only contributions and limitations supported by the accepted freeze and classification study.

The Methods and Results must include the testbed, exact binary/source hashes, mode semantics, parameter encoding, controlled negatives, paired byte method, physical campaigns, sample accounting, full distributions, late tails, classification split design, confidence intervals, residual-feature attack, resources, R11, and final state.

Do not claim size obfuscation, full anonymity, every-fingerprint removal, cross-device indistinguishability from one SEL-751, general multi-flow scalability, SBO support, combined-response support, multi-segment support, production readiness, optimal timing, universal ICS applicability, or a first result without systematic literature evidence.

If only controlled software profiles support the classifier study, write that plainly. If full-observable classification remains above chance, present it as a limitation and motivation for later size work, not as a result to hide.

Use primary literature and official Tofino/P4/DNP3 sources where available. Compile the LaTeX, resolve every citation and syntax issue, generate all plots reproducibly, and have a skeptical reviewer check every novelty, threat-model, DNP3, TCP, Tofino, experimental, statistical, and limitation claim. Apply Philip's active, direct style only after technical review. Do not use em dashes.

Commit and push the paper checkpoint without merging into main.
```

## Recommended execution order

1. Prompt 0 once at the beginning of the working session.
2. Prompt 1 to repair the evidence system.
3. Prompt 2 to build and run the controlled testbed.
4. Prompt 3 only if the controlled results require P4 changes, then re-run Prompt 2's affected cases.
5. Prompt 4 for final calibration and campaigns.
6. Prompt 5 for clustering and classification.
7. Prompt 6 for independent acceptance.
8. Prompt 7 only after acceptance.
9. Prompt 8 only after the technical explanation and figures agree with the accepted evidence.

Do not combine Prompts 4 through 8 into one unattended closeout. Each transition is an evidence gate.
