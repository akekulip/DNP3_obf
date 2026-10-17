# DNP3 review and bounded completion directive

Reviewed revision: `af7bd434595d51b9644d6e67d5302ad74c6ab642` (17 October 2026).
Repository: https://github.com/akekulip/DNP3_obf

## Decision

Retain the 61-octet mechanism and finish its correctness gates. Do not promote m9 or describe it as fully qualified. The new measurements substantiate precise timing at the switch egress-parser observation point, but host-measured qualification still fails. There is also a reproducible reset race, independent of the timing tails.

This review inspected source, retained compiler/model records, acceptance code and raw diagnostic PCAPs. It independently ran source-interpreter counterexamples and acceptance tests. No compiler, compiled model or hardware was run by this reviewer. Changes supplied here exist only in an isolated audit copy, not in Philip's checkout or GitHub.

Abbreviations, relative to the repository:

- `C4 = defense4/timing/case4_architecture`
- `X = C4/integration/core/response_only_rearm/stage_experiments`
- `CT = X/ctl_timing_01`
- `S = X/seg61_02`
- `H = C4/integration/evidence/rearm_01/hw`

## 1. Reset race: fix this first

The retained diagnostic contention attempt reports 378/379, failing `reconnect_during_wait_READ_first_RST_relayed`. A validated master reset waits while N is busy; a legitimate response advances the owner before the reset resumes. The reset then disappears. A later cleanup reset is not successful delivery of the first one.

The supplied `reset_race_probe.py` reproduces this without register mutation, using the existing source interpreter and ordinary packets. Across 18 READ/SELECT interleavings, the reset at offset −3 laps is not relayed for either kind. The READ owner remains 5 and SELECT owner remains 10; neighboring interleavings relay the reset and close the owner. This is stronger evidence than treating a single passing baseline model run as exoneration.

Relevant evidence: `CT/evidence/model_contention_m9d_01_02/FAILURE_20261017.md`; m9 source SHA256 `6590141fc68b43788de7e969badf3d6bdf24ba0615a56631497ca39854c0ce0f`.

Required correction: preserve a valid pending close across legitimate same-incarnation response processing. Choose the smallest change supported by the trace. Do not simply ignore owner mismatches: an old reset must never close a new incarnation. Preserve exact sequence validation, mapper accounting, generation isolation, and held-response cleanup. Turn the supplied sweep into failing-then-passing regressions; prove first-reset delivery, no later response leak, and successful reconnect. Include invalid and old-incarnation resets as negatives.

The unused-timestamp optimization encounters the same failure class. Do not conclude that optimization caused the race without a deterministic baseline comparison.

## 2. Two remaining acceptance holes, with a tested patch

The new joint old-blocker accounting, overlapping observation intervals and model provenance checks are useful corrections. Two required-coverage holes remain:

| Counterexample | Current result | Required result |
|---|---|---|
| Supply only one of four required READ/SELECT × +48/+50 abort negatives | Model qualification passes | Blocked |
| Delete c2 and c3 from the isolation connection verdict | Traffic component passes | Failed |

`reproduce_remaining_acceptance.py` reproduces both using temporary evidence copies. The accompanying four-file `acceptance_coverage.patch` requires each abort-negative tag exactly once and requires c1, c2 and c3 connection evidence. It updates the misleading existing test and adds missing-connection tests. After the patch both counterexamples fail closed; 56 relevant tests pass.

Apply only after reviewing against the current checkout. This is a narrow coverage fix, not a claim that all acceptance logic is now complete. Full imported-driver dependency closure remains distinct from validating a wrapper and one inner driver. Diagnostic wrappers must also have explicit dependency and required-section rules.

## 3. Timing result: real progress, narrower attribution

The independent standard-library PCAP decoder matched all 2,316 exchanges across twelve diagnostic arms to their register entries. Of these, **1,158 are timed exchanges**, not 2,316. There were no missing or ambiguous packet pairs, observed index collisions, or extra observed packets sharing their diagnostic index in these retained captures.

Six timed host tails have ACK-to-response gaps of 28–41 microseconds. Their corresponding switch diagnostic gaps are approximately 956.856–956.863 microseconds. Across timed arms, maximum diagnostic error from the 950-microsecond target is below 7 microseconds.

The recorded timestamp is sampled at the **egress parser**, after traffic-manager queuing but before the remainder of egress processing, deparser, MAC, link and receiving host. Therefore the discrepancy is downstream of that observation point. It is not established to be solely a host/NIC defect, and it is not a wire-transmit timestamp. Keep the host p99 failures and all tails in the primary results.

The captures independently confirm 579 combined and 579 size-only responses of 61 bytes each. Timing-only and off each contain 195 native 49-byte READs and 384 native 37-byte controls. This check is payload-length and correlation evidence; it does not substitute for the existing full standards/CRC checker.

Correct the report's timed denominator. Retain instrumentation-effect observations: the small number of blocks does not establish a tail-frequency cause. Do not replace the host qualification contract with a switch-only contract silently.

## 4. A frozen build is not a model-qualified build

`CT/evidence/m9d_01/model_summary_v2.json` is blocked: ordinary driver coverage is incomplete and the latest contention attempt fails. Nevertheless, diagnostic silicon blocks were run. Document this as diagnostic work with an unmet model gate; do not claim that all model prerequisites passed.

`H/run_block_frozen.sh` verifies frozen files but does not itself enforce functional model qualification. It also needs to bind the actual configuration argument to the frozen candidate and manifest rather than merely checking an unrelated set of frozen files.

Before the next load, make the runner reject a missing/failed candidate gate and an unfrozen or mismatched actual configuration. If a diagnostic exception is authorized, record it explicitly as such; its measurements do not qualify the candidate. Keep all existing hardware and restoration restrictions.

## 5. Isolation: conservation passes; deadline remains indeterminate

For `ctl_m9_iso20_poll_950_01`, acceptance v3 accounts for 7 old READ and 4 old OPERATE tokens, and the post-permit blocker count is within the source-derived allowance. Traffic checks pass. Cleanup timing remains **INDETERMINATE**:

- Completion interval: approximately 14.817631–15.129588 seconds.
- Deadline: 15.001 seconds.
- Observation uncertainty: approximately 312 milliseconds.

Count conservation does not prove deadline compliance. Remove any statement that no old token outlives the bound while this interval straddles it.

Do not spend another block on the same coarse polling scheme. To resolve the deadline, identify the actual contract start event and final old-token rejection on a common sufficiently precise clock. Timestamping only the last rejection leaves uncertainty in the start reference. Keep the count, role/generation attribution and observation interval explicit. If that measurement cannot fit, leave the deadline unproven and seek a scoped claim decision rather than increasing the bound retrospectively.

## 6. Efficiency: useful resource savings, no stage reduction yet

Retained compiler results agree across both SDKs. All probes remain N12/E12/T11.

| Probe | Measured compiler resource change | Direction |
|---|---|---|
| Remove unused N timestamp | Pipe-0 TCAM −1; PHV containers 220→216 | Retain as a separate candidate after reset correction |
| T single-child state | Pipe-1 SRAM 55→49; TCAM 66→60; stateful ALUs 15→13; further table/gateway savings | Best next resource optimization |
| N bank-difference rewrite | SRAM +1; TCAM +1; additional crossbar, instruction and PHV use | Reject |

Source: `CT/efficiency_probes_m9/RESULTS_20261017.md` and `resource_comparison.json`.

Stage count alone misses real resource savings. Conversely, these results establish neither reduced recirculation nor lower total packet/byte traffic. The single-child probe needs a deliberate control-plane schema change: initialization, readback and snapshots currently expect multiple child registers. Do not hide missing registers with permissive lookup defaults. Pin child count in the build profile and verify parity before promotion.

Avoid a broad repository rewrite. Consolidate configuration into an explicit supported-profile manifest: native 49/37-byte inputs, 61-byte output, READ ranges, SBO 15/6/1 application partition, clock units, ports, child count and artifact identities. A fixed supported P4 profile is legitimate; undocumented scattered assumptions are the reproducibility problem. Arbitrary input-size support remains deferred.

## Bounded execution order for Claude

1. Reconcile current local work; retain dirty files and immutable evidence. Record this review and the actual HEAD in the existing authoritative checkpoint.
2. Apply/review the two acceptance coverage fixes. Correct the timed denominator and observation-point wording. Repair actual-config and model-gate enforcement before hardware.
3. Diagnose and fix the deterministic first-reset race in one separately named candidate. Require source regression, both SDK compiles, and the complete applicable compiled-model suite on that exact source. Preserve E/T unless the diagnosis requires otherwise.
4. Run targeted, authorized reset/interleaving and recovery silicon checks first. Ensure the new path is actually exercised; zero retry counts cannot prove it. Continue normal restoration and stop rules. Do not begin a broad repeated campaign while this gate fails.
5. Resolve the isolation deadline with a measurement that can decide it, or explicitly retain it as unproven. Preserve historical FAIL/INDETERMINATE evidence.
6. Only after correctness, evaluate the single-child optimization and unused timestamp independently against the corrected baseline. Compare compiler resources, complete semantics and internal packet/byte work. Drop the bank-difference experiment.
7. Freeze one candidate and produce a concise claim table: demonstrated encoding, delivery/recovery, internal timing, host timing, isolation and overhead. Keep host timing failures visible. Re-run only gates affected by changes or required for the exact final candidate; no reruns merely to obtain a pass.

No new architecture, TCP splitting, broad TCP-option extension, general input-size work, physical-relay OPERATE or default promotion is requested here. Writing can proceed now using supported results, but full mechanism qualification must not be asserted until its remaining gates pass. Encoding and timing correctness alone do not establish fingerprinting resistance; classifier results from an earlier architecture do not transfer automatically.

## Reproduction and limits

The companion ZIP contains the source race probe, acceptance counterexamples and before/after outputs, four-file patch, independent PCAP decoder/results, test log and checksums. Run in an isolated checkout pinned to the reviewed commit. Original affected tests yielded 54 passes and four environment failures because tcpdump is unavailable here; the decoder independently checks the retained diagnostic captures. After the narrow patch, the five relevant non-tcpdump test files yield 56 passes. This is not a full repository suite or a fresh standards-compliance certification.

No changes were pushed. Place this document and the extracted package in the project checkout for Claude; downloading the review does not put it into `/home/philip/Projects/DNP3` automatically.
