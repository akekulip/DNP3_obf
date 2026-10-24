# Verified assessment of dd7741152 and the next overnight hardware command

Reviewed commit: `dd7741152890efe7f02e153070f0db61c8411e34`, confirmed as GitHub main during this review. The comparison with `659bba2c6` contains 13 commits and 31 changed files. This document replaces the earlier generic continuation prompts for the next run.

## Assessment: useful READ progress, but no integrated relay-qualified candidate yet

I read the current notes, authorization, changed source, c30 generated P4/profile/manifest, relay-response records and tests through the connected repository. I regenerated c30 and ran offline checks locally. I did not run an SDK, the Tofino model, the physical switch or the relay in this review environment. Compiler/model/hardware claims below retain those limits.

### What is established and should be preserved

1. **The real READ response bytes support the selected construction.** The six recorded responses in `read_complete_01/evidence/relay_native_20261024/native_20261024.json` independently CRC-check and decode as:

   | Workload | Native | Original objects | Selected padded image |
   | --- | ---: | --- | --- |
   | Mixed READ | 91 B | G1V2 0–15, G30V1 0–7 | 141 B, link frames [50,91], 26 added G1V2 points |
   | Integrity READ | 134 B | G1V2 0–15, G10V2 0–31, G30V4 0–20 | 158 B, link frames [24,134], 4 added G1V2 points |

   These are recorded socket-response bytes, not timestamped TCP pcaps. The file reports the relay/master addresses; it is sufficient to recheck the encoded bytes, not independently isolate switch latency or prove packetization at the relay's physical interface.

2. **The relay constants reproduce.** I reran `derive_two_read_relay.py`: its constants remained byte-identical, with 512 varied samples for each shape and three retained response samples per workload. Request/response CRCs, object layouts, reassembly, target lengths and preservation of original object bytes check out. Do not redo this as a new sizing project.

3. **The c30 source reproduces exactly.** This command regenerates SHA256 `b006752236a7d1cccab461a010b2b68a3ea7b5629b1097c926ebacd348126de2`:

   ```bash
   python3 make_m12.py <new-output-directory> --policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay
   ```

   The generated file and retained compiler source agree. I also injected 1,024 varied relay-shape samples into the P4 source interpreter and checked exact encoded output and IP lengths, including 198 for the padded integrity response. All passed. This does not execute checksum externs or prove N/E/T timing on silicon.

4. **Reported placement is retained and source-bound.** The 9.13.2 manifest records exit 0, p0 ingress/egress 11/11 and p1 ingress/egress 11/4, bound to the above source. The profile contains 10 artifact pins. The compiled artifacts and physical stage-index reports are not available for fresh verification here; validate them on Gambit before loading.

5. **Some earlier checker defects were corrected.** I reran the 13 wire-check unit tests successfully, including faithful noncanonical order and a genuine ACK/FIN swap. Current repair deployment hashes match `capture_observation.py` and `wire_check.py`. The handshake-ACK exception now checks READ classification and flow/incarnation/seq/ACK/payload, improving the former length/payload-only match. Keep those fixes; do not repeat the old patches blindly. Do not assume this software-reflection helper is a suitable checker for the separate physical relay.

### Verified defects and unfinished work

**A. Critical: the master can accept an incomplete response.** `active_harness/session.py:_match()` still parses and validates each link frame separately. The new `TransportAssembler` exists and has unit tests, but is not wired into that session path. I supplied only the first, CRC-valid padding frame of the actual mixed READ image: `Session.transaction()` returned `OK` after one receive, with FIN clear and none of the original measurement frame delivered. All 69 existing active-harness tests pass despite this counterexample. The master must not be used to claim padded-response acceptance until this is fixed and regressed at the session level.

**B. Native-baseline success reporting is weak.** All three retained integrity records say `outcome: OK` while `validation_problems` says their G1V2 first object fails a legacy G10V2 expectation. `relay_native_baseline.py` records the problems but counts success solely from `outcome`. Its completion path parses the current link frame rather than the completed application fragment; mixed validation checks only whether the FIRST group is in the requested set. Requested source binding also falls back silently after failure. These are checker/driver defects; they do not invalidate the separately decoded retained bytes. Repair validation and verdict propagation, then re-evaluate or repeat only the affected evidence.

**C. c30 is READ-shaped, not relay-integrated.** `supported_profile.json` still declares `master_dev:9`, `relay_dev:9`, explicitly says no physical relay is in that profile, and declares SELECT/OPERATE 37→61 with a 22-byte application partition. `response_only.inputs.json` likewise sets `relay_port:9`. The physical relay path is reported as ports 9→64, and historical guarded two-CROB requests/responses are 45/49 B. Sealing a bundle does not correct this endpoint/profile mismatch. The relay campaign path and actual SBO admission/framing/mapper still need implementation.

**D. The FIN-loss issue was closed without relevant proof.** WORKING_NOTES dismisses the later graceful-persistence FIN loss using the October 11 close-path fixes and nine old tests. Those fixes were already present in the failing c29 build. I compared c29 and c30: `seq_fin`, `close_forward`, `emit_reset`, `busy_retry_rst` and `retry_stale` remain unchanged. The cited old tests cover different close behaviors; they do not reproduce the busy-work-cell FIN incident. Reopen this specific defect until a matching regression and recovery sequence establish its disposition.

**E. The wrong reproduction script was assessed.** The notes say `reproduce.sh` is only a historical capture-analysis script. That describes another path. The ACTIVE script `read_complete_01/reproduce.sh` explicitly regenerates candidates and recomputes their model gates; at this commit it defaults to c25 and rejects c30. Fix this exact entry point and correct the record. Do not create another parallel reproduction framework.

**F. Reported c30 model results are not independently replayable from this push.** Notes report six READ/size drivers totaling 1,332 checks and later rearm 799/799. The committed c30 directory has source, inputs, profile and compile directory; the active evidence listing has no `model_*c30*` run directories or c30 model summary. Recover the local results/provenance/logs and retain enough to recompute them. A notes entry or equal pass counts cannot qualify the full integrated relay workload, especially while SBO vectors still use the software shape.

**G. Correct the minimum-size claim.** 158 B is the minimum for the current preserved-tail PREFIX construction at the selected padding range. It is not the minimum across the software encoder's fallback. On the ACTUAL retained 134-byte integrity response, I reproduced valid reserialized targets 144–154 and 157. Preserve 141/158 for this milestone because they already have the shallow-parse construction and fit evidence; do not restart target selection. State the bandwidth/implementation tradeoff accurately and do not claim global optimality.

### Source pointers

- [Session response handling](https://github.com/akekulip/DNP3_obf/blob/dd7741152/defense4/timing/active_harness/session.py#L182)
- [Native-baseline completion and validation](https://github.com/akekulip/DNP3_obf/blob/dd7741152/defense4/timing/active_harness/relay_native_baseline.py#L72)
- [Current READ validator](https://github.com/akekulip/DNP3_obf/blob/dd7741152/defense4/timing/active_harness/dnp3_codec.py#L274)
- [c30 supported profile](https://github.com/akekulip/DNP3_obf/blob/dd7741152/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m12p_c30_sdk9132/supported_profile.json)
- [Active reproduction script](https://github.com/akekulip/DNP3_obf/blob/dd7741152/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/reproduce.sh)
- [Current working notes](https://github.com/akekulip/DNP3_obf/blob/dd7741152/WORKING_NOTES.md)

---

## Overnight command to Claude: execute the remaining relay work

Work from the current Gambit repository. Verify HEAD against `dd7741152` and inspect any newer changes before editing. Read this assessment, current `CLAUDE.md`, WORKING_NOTES, ACTIVE_CODE_MAP and the active CURRENT/STATUS/COMPLETION_RECORD. Then EXECUTE the remaining work over the available 10–12-hour window. A plan, launched background job, new compile or READ-only checkpoint is not the final deliverable.

### Fixed authority, scope and outcome

- The physical SEL-751 is the ONLY outstation. READ, SELECT and OPERATE against it, the necessary source/config/master/checker changes, model/compile work, candidate loading and guarded testbed runs are authorized. Do not launch any software outstation, proxy outstation or software-endpoint hardware fallback. A software master, offline encoder tests and Tofino-model packet vectors remain appropriate.
- Use the established research command points and guarded builders; preserve matching SELECT validation before OPERATE and the existing command semantics. Do not invent relay points or modify unrelated relay settings. Do not ask again which outstation to use or whether the already-authorized SBO is allowed.
- Retain one N/E/T implementation, blocker-based timing, queues, ACK normalization and OPERATE hold J. Finish two READ mappings 91→141 and 134→158, plus an attainable application-preserving size transformation for the ACTUAL relay SBO. Keep exactly two READ targets; do not force all responses to a universal size.
- Retain N/E highest occupied physical index ≤10, T ≤11 occupied stages and pipe-1 egress ≤4. Report PHV, TCAM/SRAM, stateful/hash/crossbar use and passes; do not trade away checks or hide an added traversal.
- Use SDK 9.13.2 and its matching model. Compile each immutable candidate once, pin before model execution, and load the same raw-hash-verified artifact bundle on the switch. A modified source/config requires the affected gates again.
- No Vision reboot, kernel/firmware change, keep-alive masking, relaxed 100 µs threshold, main D/J/attacker campaign, manual ownership edits, weakened restoration, IEEE audit or paper writing.
- Main only; preserve unrelated dirty work and historical freezes/evidence. Philip-only author/committer, no co-author trailer. Update and commit this run's notes with its work; no push without explicit instruction.

Use specialists with disjoint ownership: master/validation, relay campaign/SBO integration, P4/state/placement, and independent timing/evidence review. One integrator owns shared files. Serialize shared compiler/model/testbed resources. After three failures of one approach, diagnose and choose a justified alternative; do not stop the whole task there.

An obsolete project test is a contract to update; a missing harness is implementation work. If a genuine higher-priority platform restriction rejects an action, record that exact action/reason, do not evade it, and continue permitted independent work. It does not authorize switching to a software outstation or treating every remaining READ task as blocked.

### First 1–2 hours: make the real master and its verdicts trustworthy

1. Add the prefix-only counterexample as a failing SESSION-level test using the retained actual READ bytes. Then connect link-frame parsing to transport reassembly and validate ONLY a completed application fragment. Keep partial state across TCP receives, handle coalesced frames, sequence wrap/gaps, missing FIN, CRC failures, stale responses and deadlines. Never return OK on the first padding frame.
2. Decode every original object and all padding objects, indices, values and flags; validate the requested ranges/groups and expected complete response, not just its first group. Distinguish permitted IIN indications from response errors. Reject missing analog objects, truncated points and mismatched sequences. Preserve the existing SELECT-success gate and actual CROB status checks.
3. Fix baseline outcome propagation, complete-fragment parsing and source-bind failure. Record actual local/peer socket identities. Keep native baseline and padded acceptance checks consistent without making the baseline require nonexistent fixture groups.
4. Preserve the six valid recorded native samples and the already-reproduced constants. Correct the faulty historical verdict in a new readout, not by rewriting original evidence. Add a small representative native/padded master test with the real relay after the relevant hardware gates are ready; do not begin a new measurement campaign.
5. In parallel, inspect running c30 model jobs and retain their actual results. Do not restart completed jobs unnecessarily. Label legacy software-SBO vectors accurately; they do not test the real 45/49-byte relay exchange.

### Hours 1–5: finish the relay campaign path and actual SBO shape

1. Reuse the existing real-relay master and guarded builders. Extend the ACTIVE campaign tooling to support one explicit relay profile. Replace the obsolete software-only rejection with acceptance of the verified relay and rejection of unexpected destinations. Do not start a software-outstation process or fabricate an `outstation.json` as if the relay produced a fixture log.
2. Bind the actual master/relay IP/MAC/interface, TCP ports, DNP3 addresses and dev_ports to the config, profile, installer, model and checkers. Reported identity is master 192.168.10.1/address 1/dev 9 and relay 192.168.10.7:20000/address 0/dev 64; verify locally. Check SYN/SYN-ACK and data TCP options, header lengths, packetization and the supported parser profile. Do not silently waive validation or change global host settings to fit a fixture assumption.
3. Obtain a short captured native SELECT/OPERATE baseline through the guarded production/pass-through path using the established research command. Decode actual status, IIN, both CROBs and complete response bytes. Preserve application and transport identities. Historical requests are 45 B and responses 49 B with a 32-byte application fragment; TCP pieces 28+21 form one link frame, not two DNP3 transport segments.
4. Derive the real SBO size image. For that 32-byte fragment, two application-preserving transport segments can encode to 60 or 62 B; 61 is not reachable with this construction. Investigate 60 first, validate against actual responses and varied live fields, and continue without asking Philip to select a number. Preserve every command/result byte; do not add measurements to control responses or manufacture a status.
5. Update all coupled N/E/T admission, CRC/checksum, sequence/ACK mapping, accounting, reverse boundaries, J association, runtime rows and recovery selectors for the real SBO. A native 49-byte SBO and legacy 49-byte range READ collide by length: discriminate by validated protocol shape/request association. Do not classify both as READ or pad both merely because their lengths agree.
6. Create a new selected relay candidate, preserving c30 as the READ-shaped reference. Correct the profile's port 9/9 and software 37→61 assumptions, including transitive consumers. Extend the ACTIVE relay model inputs to actual request/response shapes. Keep old software-vector tests offline as historical regressions, with no software-outstation server.

### In parallel: reopen and resolve the actual FIN/ACK incident

Recover the c29 graceful-persistence trace, state/counters and captures. Reproduce its busy work-cell/generation/owner/epoch sequence on the current compiled model. The old October 11 fixes already existed when it failed; passing their tests does not close the later incident.

Trace delayed final ACK, READ-before-final-ACK, outstation ACK overtaken by its response, duplicate/retransmitted FIN, both close directions, reset during retry, retry exhaustion and same-port reconnect. Apply the smallest justified correction and add a regression that fails on the actually failing version. Do not blindly add FIN to an ACK retry row or rely on a 232-ms TCP retransmission while the planned third connection never runs. Prove complete persistence/reconnect state and all planned connections.

### Hours 4–7: qualify one exact relay image

Compile with 9.13.2 after coherent changes, retain actual physical-stage/resource extracts and pin the complete artifact bundle before model execution. Run focused new regressions, independent code review, then the complete relevant model gate once on the stable selected source. Retarget active driver vectors and expectations to the real relay profile without dropping semantic assertions; a green 37-byte fixture-control test is not relay SBO coverage.

Verify complete padding bytes, all original objects/statuses, TCP/IP/DNP3 checksums, native and padded sequence coordinates, start/end/stale ACK boundaries for every committed image, transitions between both READs and SBO, timing enabled, and OPERATE-J hold/release. Keep the documented shallow-parse validation limit honest; deferred standards auditing does not waive runtime corruption/recovery checks.

Fix the ACTIVE `read_complete_01/reproduce.sh` and add the selected candidate, exact flags/profile/hash, retained model provenance and relay hardware readout. Do not edit the unrelated historical script instead. Retain c30's reported run results/logs/dependencies from Gambit; their absence from this push is not proof they never ran, but must be repaired before claiming independent reproduction. Test derivations and gates fail closed if required evidence is absent or the live-sample list is empty.

### Hours 6–11: execute on the actual relay and diagnose timing in place

Dry-run every final config before testbed acquisition. Verify all required binaries/helpers in the real run directory, selected profile/route, no software-outstation launch, pipe-1 rows and frozen source/artifact/config/checker hashes. Preserve historical freezes; create a new freeze. Record this standing authorization on each valid planned run; do not request another approval for each block.

Use the ownership/frozen-wrapper/restoration mechanism. Run on ONE exact selected image:

1. A short complete padded mixed/full READ acceptance smoke with the fixed master.
2. Off, timing-only, size-only and combined arms, with repeated mixed READ→SELECT→OPERATE→integrity READ cycles on one connection.
3. Actual mixed/full response loss; graceful/reset persistence; reconnect; held OPERATE, with every planned connection and exchange present. Verify that the selected loss/hold hit the intended real-relay packet.

Use a relay-aware transaction/stream checker. Vision outgoing requests and incoming responses are different packets; the software VEPA reflected-copy matching assumption does not apply. A master TX/RX capture is one observation point, not both sides of the switch. Use available relay-side TAP/mirror or existing switch timestamps/state for a genuine pre/post comparison; label limitations if unavailable. Do not compare changing measurements in separate baseline runs as byte-identical originals of the same packet.

Preserve the existing blocker timing and 100 µs criterion. Establish the actual CLRT/D and J anchors, first-frame and COMPLETE-response times, packet/capture losses and nearest-rank p99/max. Distinguish native response readiness from late switch release and host-visible completion. Use same-clock measurements or measured alignment/error bounds; do not revive the circular idle metric or assume a kernel cause.

If timing fails on the physical relay, trace N work-cell delay, T readiness/deadline/release, recirculation and queues with available observability. Use minimal reversible diagnostics only when needed, separately source-bound. No reboot or keep-alive masking. Complete safely runnable recovery checks even if timing precision remains failed; keep per-dimension and overall verdicts separate.

Verify restoration after every block. A failed or ambiguous restore stops hardware activity; preserve the refusal and continue independent offline work. Do not manually clear ownership or broaden a comparator to force a pass. After a source or shared helper change, re-freeze and rerun affected gates on the changed candidate rather than borrowing an earlier result.

### Final hour: retain evidence and report the actual outcome

Update WORKING_NOTES and CURRENT/STATUS/COMPLETION_RECORD. Correct “READ complete end-to-end” to its demonstrated tier until relay padding is physically observed; correct the FIN/reproduction/minimum-size statements identified above. Keep historical failures and later re-evaluations separate.

Retain complete planned denominators, raw captures, master records, loaded artifact/row hashes, configs, model driver inputs/results/provenance, readout versions and restoration records. Deduplicate/compress large reproducible logs with hash-verified restoration; do not create another package or parallel framework. Missing captures, skipped checks and unexecuted connections are not passing evidence.

Deliver a concise matrix for both READs and SBO: native/target bytes and frame counts, actual master acceptance and preservation, measured overhead and denominator, SDK physical-stage indices/resources/passes, model and relay hardware verdicts, timing/J, recovery/close and restoration. Include the exact commit/source/artifact/master/profile identities and clean-worktree reproduction command.

Continue until the selected candidate has completed the required physical-relay work or the overnight window ends with a specific demonstrated external dependency. Report any remaining failure honestly with the reproduced cause or bounded uncertainty and a concrete next command. Do not substitute another authorization prompt, software-outstation campaign, unsupported completion claim or generic kernel recommendation.

**Execute now. Preserve the verified READ construction; fix the master and current profile; finish real-relay SBO, timing and recovery.**
