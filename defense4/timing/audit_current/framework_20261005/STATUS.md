# Framework / Case 4 status — 2026-10-06

The approved continuation implements and tests the independent offline work. **Full Case 4 target integration is unfinished and unqualified.** Current recovery, instrumentation and composite sources fail local Tofino PHV placement. No current hardware deployment, measurement, physical OPERATE, restoration or push occurred.

Use [STATUS_MATRIX.md](STATUS_MATRIX.md) for cumulative evidence, [CLAIMS_RECONCILIATION.md](CLAIMS_RECONCILIATION.md) for claim limits and [HANDOVER.md](HANDOVER.md) for the remaining dependency order. Continuation base is `5a816ab26d60da5fa041b19db6d0fbe9d2f21417`; protected execution base remains `235e7f01f1c87115455480ebf7c8d94f569c483b`. Work remains on `main`. Commits use `akekulip <akekulip@gmail.com>` as author and committer without contributor trailers; final revision is `git rev-parse HEAD`. Pre-existing user changes are preserved.

## Continuation results

- Recovery source `cac84a26aea5233ae01cb0f7ac220bded92a7a74c5005133dd8eeca2e53ca87a` conserves original ACK/response/unsent-OPERATE ownership, prevents rearm until cookie-qualified termination, checks OP commitment against its deadline, qualifies reset and requires a private validated handoff. Mask storage uses a zero-extended 16-bit cookie in a 32-bit bank plus a 16-bit mask bank. Source-fragment tests do not establish complete parser, bank interleaving, physical queues or drain. OPERATE deadline/reset checks exercise scalar/table decisions; actual queued OPERATE-envelope service is unproved.
- Core22 and instrument05 fail PHV placement: respectively 31 and 35 unallocated slices. Instrument source is `8dcf04c3076734cd675852c9277b9e775ef10447b12341c6ce6dd4ec143e74b1`. All failed attempts and exact source/log/manifests remain separate. No historical compile PASS qualifies these sources.
- Ingress arithmetic build33, source `31bb3303…`, compiles with local SDE 9.13.1 `e558d01`: six ingress stages, zero egress, 27 retained warnings. Its completion drops. It has no actual validation/image producer, lifecycle or final forwarding. Composite34, source `413e8c5b…`, fails PHV and remains an incomplete integration/resource probe.
- The full inactive size prototype now has correct tail ACK clamps and 32-bit window arithmetic. Exact build27 still fails its PHV action; missing cache/lifecycle and unsupported sentinel behavior remain gates. Software expectation tests do not qualify that prototype.
- The strict bounded software preprocessor implements MSS-only handshake admission, one SELECT/OPERATE pair, 35-byte/35-bit OPERATE assembly, an absolute non-extending 30 ms deadline, sticky quarantine, immutable replay, complete response checks and byte-preserving carving. It is an oracle, not the missing TNA producer.
- Pinned production OpenDNP3 context gate passes four cases / 46 assertions. The separate real Linux TCP socket pair and independent raw captures pass: each phase repairs one truncated initial image through a one-byte native kernel retransmission and 21-byte cached replay; both 57-byte echoes retain SUCCESS and real/decoy callbacks occur once. Observed replay intervals are 206.717 and 439.109 ms; SELECT-to-OPERATE acceptance is 440.139 ms under the configured 500 ms software retention budget. One software pair establishes no future bound or physical inertness.
- Fresh Case 4 BMv2 run passes **14/14**, zero skips, in 152.566 s. Its P4 source is unchanged `0fba5225…`; the launcher now reserves evidence exclusively before side effects. These Python codec endpoints remain distinct from production OpenDNP3 and Tofino queues.
- Acquisition directories refuse reuse before building or namespaces. Every failed/aborted acquisition remains intact; nine sealed inventories pass hash verification. Controller inventories bind exact policy, operation/profile and source/schema/build, validate all mutations before device calls, back up exclusively, read back and restore on failure/cancellation. The production full-target qualification registry remains empty.
- SBO admission uses successful outstation SELECT acceptance to matching OPERATE acceptance, charges native cycle and added costs once, and rejects absent/context-mismatched inputs. Observation import binds source/instrument/schema/build/connection/profile and refuses erasing clock masks. Internal termination records supply no physical departure/drain or outstation acceptance.
- Cases 1–3 remain explanation-only. The updated editable figure separates the proposed target and executed software size path; the working paper builds to four pages and includes the kernel loss-repair boundary. All 2,210 protected hashes pass. XML passes; 13 figure policy warnings are retained explicitly. Frozen text/captures/manuscript and author-promotion gates remain untouched.

## Verification and retained history

Current verification is bound in `CONTINUATION_VERIFICATION.json`. The 620-test
`CONTINUATION_OFFLINE.json/.log` aggregate passed with zero skips, but preceded
the final source-interpreter repair. Recovery `case4_recovery_verification_03`
binds the final interpreter and mutation tests and covers all affected simulator
modules: **69 model/packet + 26 source-parity = 95 fresh passes**, zero skips.
The separate frozen-P4 recovery suite has 100 passes; verification_03 explicitly
labels its reused verification_02 log, while the root aggregate independently
ran those 100 tests against the same P4. These overlapping counts are not added
to the 620-test aggregate as new distinct coverage. Overlapping `CONTINUATION_FRAMEWORK_FINAL` and
`CONTINUATION_SOURCE_FINAL` reruns were stopped as redundant; their partial logs
and explicit `aborted_redundant` JSON are retained and establish no suite PASS.
`CONTINUATION_CONTROL.log` and `CONTINUATION_BMV2.log` preserve the independent
controller/software-network checks. The interpreter now executes actual enclosing
cookie/mask/duplicate predicates and drain scan; it remains a subset, without
whole-target placement or interleaving proof. Deliberately excluded legacy network
modules are listed; they are not counted as passes or skips.

The original aggregate remains 503 tests: 501 passed, one failed, one errored, zero skips; its targeted corrections and raw log are unchanged. The earlier combined BMv2 result remains 22/23 with all 14 Case 4 passing and a retained legacy native-ACK forwarding failure of 1,242,183 ns against 1,000,000 ns. The older 21/22 result and its separate 200 us gap failure remain retained. No tolerance widening or successful rerun erases them.

Historical source `df599101…` was previously loaded/configured for Timing OFF: 30 main READs plus one separate precheck in the capture; master RTO 201 ms and first repeat 204.4 ms. Those are baseline observations. Current hardware state was not re-read and no historical restoration report is promoted to a current-state assertion.

## Remaining work

Complete the target validation/image/replay-cache producer, handshake/assembly/retirement lifecycle and size/timing association; preserve observed wire ACK before inverse translation. Resolve complete recovery/instrument/joint PHV fit and produce exact-source SDE9.13.2 artifacts. Prove processing-port 69 return/queue availability and service. Only then qualify the actual schema/mutation inventory, acquire applicable timer/release/heartbeat/drain/SBO inputs and enforce the guarded hardware runbook.

The full target stays required; no reduced or software substitute completes it. Prepared declarations remain **16,168 attempts <= 18,360**, with 600 warmups and 88 state READs. Setup/failure budgets, no implicit retry, requested D_A grid, 1 ms gap, requested 100 us heartbeat, 30 ms readiness and fixed 40 ms cap remain unchanged. Hardware collection and exact newer Dr. Lin text/acceptance plus Philip's manuscript-promotion instruction remain gates.
