# DNP3: finish the equal-size implementation, with trustworthy gates

Prepared 2026-10-14. Audited GitHub main: **49201301439b260ba08455e192e1302a7663e92b**. GitHub still pointed to this revision when checked. Repository: https://github.com/akekulip/DNP3_obf

## Execution checkpoint and remaining plan — 2026-10-14

**Update 2026-10-14 (resumed): the immediate next work items 1 to 4 below are done.** Offline verification is green (699 tests) and the bounded four-arm silicon smoke passed as `candidate61_fourarm_smoke_03`: off/timing-only READ 49 and SBO 37; size-only/combined READ, SELECT and OPERATE 61, each response one received TCP segment; SELECT authorized, OPERATE succeeded, checker conformant, calibration and offload restore verified, production restored with ping. `_01` and `_02` failed closed on harness defects, both fixed and retained. Commits are on `implement/seg61-qualified-20261014`, not pushed. Step 3 (persistence, all single-loss classes, reconnect, stale-token and external isolation, held-OPERATE duplicates) then passed on silicon too; see `rearm_01/STATUS.md`. The timing evaluation and strict comparison in the table below have **not** run.

Original checkpoint text: **Stopped at Philip's request before silicon execution.** This checkpoint supersedes the historical audit-status table below; the encoding specification and retained audit evidence remain unchanged. No candidate was installed on the switch in this session. The latest read-only observation showed production/restore image `case4_response_path`, PID 537002. No full timing-and-size qualification is claimed. Changes remain uncommitted; nothing was pushed or promoted.

### Completed and evidenced

Candidate: `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/` (paths below are relative to it).

- Generated whole candidate: `evidence/full_04/response_only.p4`, SHA256 `1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa`. E changed; pinned strict source, unchanged N/T hashes and replace-back equality checked.
- Complete SDK 9.13.1 and installed SDK 9.13.2 builds pass, both **N11/E12/T11**. Actual stage/PHV/table/hash placement and mirror checks are retained in `evidence/full_04/resource_review.json` and the compile directories. Failed earlier compile attempts remain retained.
- Compiled-model padding-on smoke **30/30**, padding-off/native smoke **30/30**, transport/packet suite **622/622**, mapper/rearm suite **399/399**, corrected duplicate suite **102/102**. Evidence: `evidence/model_smoke_02/smoke_results.json`, `model_native_01/smoke_results.json`, `model_packets_04/packet_results.json`, `model_rearm_02/rearm_results.json`, and `model_dup_02/dup_results.json`.
- READ becomes exactly 61 bytes; SELECT and OPERATE each become one 61-byte TCP payload containing 28/19/14-byte DNP3 frames. Model checks cover all 64 transport sequences, application preservation, independent framing/CRC/checksums, mapping/window boundaries, retransmissions, wrap and stale/rearm cases. Padding-off remains READ49/SBO37.
- Duplicate READ case C now waits for observed request delivery before injecting actual server ACK/response. Their hold/release and no repeated generation/allocation are checked. The late request retransmission is correctly normalized and forwarded; `acct.hi` records pending reverse distance, while the wire frontier and image mapping stay fixed. The failed `model_dup_01` fixture is retained.
- Shared acceptance, capture-boundary/offload calibration, per-trial generation-headroom checks, candidate build registration, and 17 candidate/strict configurations are implemented. Entry points and final integration still need the final verification below.

### Immediate next work when resumed

1. Finish the final test/review checkpoint before any hardware run. Earlier integrated suite passed **671 tests**. The latest broad run ended **687 passed / 3 failed** during strict-profile config alignment; a subsequent focused config run ended **8 passed / 1 failed**. The remaining focused failure is an obsolete test assertion expecting `candidate61-only` in the strict qualification status, after support for explicit `packet_boundary_required` was added. Correct that assertion, check generated strict configs use `profile=strict_comparison`, regenerate after final model evidence, rerun the full integrated suites, and complete the interrupted independent smoke-path review. Do not describe the final tree as test-clean yet.
2. Re-read the candidate smoke plan from `hw/RUNBOOK.md`, validate source/build/profile/capture bindings, and confirm the switch still runs the configured restore image. Recheck candidate sealed-profile registration and physical capture prerequisites. Require sufficient READ/OPERATE generation headroom before each trial.
3. Run only the bounded four-arm silicon smoke first: **off, timing-only, size-only, combined; 20 READs plus one SELECT/OPERATE pair per arm** through the software endpoints. Candidate config: `hw/config/candidate61_fourarm_smoke.json`. Retain loaded-artifact identity, endpoint callbacks, counters, mapper state and both capture directions. Physical incoming capture must pass separate coalescible-packet calibration with GRO disabled and LRO/hardware GRO verified off; restore original offloads after the block. Every transformed response attempt must be exactly one received TCP segment carrying the full 61-byte image. Missing or mismatched evidence rejects the run.
4. Require verified production program/port/relay-slot/Vision restoration and restored-path ping after every hardware block, including failures. Record success or the exact failure in this plan, `integration/evidence/rearm_01/STATUS.md`, `WORKING_NOTES.md` and the candidate progress ledger. The prior requested stop point was after this smoke; the latest request stopped execution before it.

### Planned full timing and size obfuscation qualification — not run

| Phase | Planned work | Evidence required to advance |
|---|---|---|
| Size and semantics on silicon | Smoke above, then mixed persistent READ/SBO; size-only and combined produce READ61/SELECT61/OPERATE61, off/timing-only produce 49/37/37 | Exact per-function sizes; one received segment per transformed attempt; preserved applications/points/Rule 8 authorization; successful OPERATE callback; CRC/checksum and TCP mapping pass |
| Recovery and state isolation | Graceful/RST same-tuple persistence, every configured single-loss class including padded SELECT/OPERATE and data ACK, reconnect, stale tokens, old external traffic, early/held/late OPERATE duplicates | Bound per-connection acceptance; expected recovery; no premature held-OPERATE departure, duplicate callback, double growth, stale authority or unexplained fallback; headroom and restoration |
| Four-arm timing evaluation | Three order-rotated blocks × four arms × 500 READs at **59,570 PPS / 950 µs**; retain SBO in each connection and add repeated successful SBO cycles when quantifying control timing distributions | Separate READ ACK/response commit and release evidence, OPERATE hold/release timing, per-exchange timestamps and callbacks; actual quantized rates and identical endpoint/fixture settings |
| Strict comparison | Matched strict baseline blocks at the same **59,570 PPS / 950 µs**, with the same qualified physical capture procedure | Strict lengths READ58/SBO37 when padding is on, native49/37 when off; matched per-block timing and overhead attribution |
| Piggyback ACK | Separately labelled runs with no synthetic separate request ACK; characterize READ and SBO completion timing | Request-to-response/completion latency and fallback behavior; do not report CLRT where a separate request ACK does not exist |
| Rate trade-off | After correctness, matched **14,892 versus 59,570 PPS** runs with the same candidate, target and workload | Precision versus total internal packet/byte overhead, external growth, recovery and callback outcomes; retain all timing tails and exclusions |

For every timing block retain signed/absolute target error, p50/p95/p99/max, all tails and their exchange identities, request-to-response and complete SBO latency, intentional hold versus processing/polling overhead, exclusions and their reasons, retransmissions/recovery, per-operation callbacks, total internal packets **and bytes**, and external growth (`12 × READ + 24 × (SELECT + OPERATE)` for eligible newly delivered responses, with retransmission traffic reported separately). Preserve per-block results and state the SD convention. Provisional p99 absolute error ≤100 µs is not a maximum-error guarantee. Investigate the retained strict ~1.1 ms tails with matched captures/counters/host logs before attributing them to the new encoding.

Full completion requires all correctness/recovery gates and the matched timing/overhead evidence, followed by a reviewed coherent commit. Real-relay compatibility and default promotion remain separate. Equal payload length does not hide plaintext object contents or the one-versus-three DNP3 link-frame structure.

## Decision

**Continue the 61-octet candidate from the qualified strict build. Correct the acceptance-checker defects below, implement the E encoder and mapper changes, and qualify that candidate through model and the authorized software-endpoint hardware gates. Keep the real-relay native-passthrough experiment separate.**

The project has made substantial hardware progress. The circularity comes from changing the meaning of “done”: software encoding, endpoint acceptance, compilation, model execution, silicon execution, standards conformance, and timing precision have repeatedly been reported together. They require different evidence.

Do not restart architecture selection, return to Group 41 filler, resume TCP packet splitting, or undertake a repository-wide refactor. The next missing implementation is identifiable. Whether the new E layout fits remains an engineering question to answer by compiling the whole candidate—not a reason to declare it impossible in advance.

## What is actually established

| Item | Evidence at this revision | Limit |
|---|---|---|
| Strict `rearm_57s` | Retained silicon runs demonstrate READ 49→58 by legal G10V2 range re-encoding, native SELECT/OPERATE responses at 37, timing, rearm and bounded loss gates | Not equal-size READ/SBO; controlled software endpoints and supported TCP profile |
| Strict resource use | Local and switch-compiler manifests report **N12 / E12 / T11** | The earlier N11/E12/T11 result describes another build; a smaller compile-only variant dropped SYN-ACKs on the model |
| Equal-size 61 encoder | Offline oracle and a pinned OpenDNP3 master/outstation through a software proxy | No 61-octet P4 source, compile, model, or silicon result |
| Endpoint acceptance | 20 READs plus SELECT/OPERATE; application callbacks and point checks pass | Two loopback TCP connections through a proxy; no in-place TCP mapper is exercised |
| Real-relay `full_02` | `network-only` compiles and retained model results match the stated 99/99, 519/519, 37/37 and 88/89 | Native passthrough only; tuple wedge remains; other proposed variants fail PHV allocation; not hardware-qualified |
| Timing evaluation | Strict candidate: 3 blocks × 4 arms × 500 READs; 3,000 timed READs | Six large host-measured tails remain; successful commit/release counters do not establish per-packet precision |

The active restore image, `case4_response_path`, is a restoration target. It is not evidence that the equal-size standards-conforming candidate is deployed.

### Audit scope and independent checks

This was a targeted audit of the generators, generated N/E/T sources, encoder, standards checker, capture reassembler, experiment drivers, manifests and retained results relevant to completion. It was not a claim to inspect every file. The GitHub recursive-tree response was truncated; the relevant paths were downloaded explicitly.

Independently executed here:

- `read_reencode_01/tests`: **21/21 pass**, no skips.
- `seg61_01/tests`: **11/11 pass**, no skips, using the retained native capture.
- Re-encoded all 22 native responses from that capture: 61 octets each; separately implemented wire CRC checker accepts them.
- Mutated captures exposed the checker defects below.
- Recomputed timing error from the retained per-exchange JSON, rather than copying summary prose.
- Verified six candidate CRC XOR deltas against 1,024 random fixed-length inputs apiece.

No SDE compilation, model execution, endpoint binary execution, or lab hardware run was performed in this audit. Those results below are retained repository evidence, explicitly distinguished from the checks rerun here.

## Findings that affect implementation

### 1. The capture checker can approve corrupted SBO responses

`read_reencode_01/check_capture.py` compares READ application-header/IIN bytes with the native response. Its control branch instead calls `dnp3_std.check_control_echo`, which compares only object bytes against the request.

In three separate mutations, I changed the SELECT response's application sequence, IIN1, or IIN2, recomputed valid CRCs, and encoded it into the 61-octet form. **All three still returned `conformant: true`, with zero failures.**

This is a concrete acceptance gap. In particular, setting IIN2 bit 0 is one of the conditions under which IEEE 1815 §4.4.4.3 Rule 8 says the matching OPERATE must not be issued. The helper checks the byte-echo portion of Rule 8, not all of Rule 8.

Required correction:

- For SBO, compare the **entire reassembled application fragment** to the native response, including application control, function and both IIN bytes.
- Separately judge whether a SELECT authorizes OPERATE: exact echoed object bytes, required status values and relevant IIN error bits. A faithfully transported error response is valid transport behavior, but it is not a successful SELECT.
- Match transactions by connection incarnation and application sequence; verify requests as seen at the master are preserved at the outstation. Count all expected responses, including missing controls.
- Add mutations for each omitted field. Keep the current positive endpoint evidence; do not imply these probes show the existing encoder actually changed those fields.

`seg61_01/run_endpoint61.py` already checks complete control application-byte preservation. Transfer that invariant into the actual capture acceptance gate. Its comparison with `encode61.encode()` is useful consistency checking, but is not an independent implementation of the encoder.

### 2. TCP stream reconstruction can silently discard or accept wrong bytes

Confirmed in `read_reencode_01/capture.py`:

| Synthetic input | Current result | Required result |
|---|---|---|
| seq 100: `ABCDE`; seq 103: `xyFG` | Accepts `ABCDEFG`, silently ignoring conflicting overlap `xy` | Reject conflicting byte overlap |
| seq `0xfffffffc`: `ABCD`; seq 0: `EFGH` | Returns only `EFGH` | Return `ABCDEFGH` across sequence wrap |
| seq 100: `ABC`; seq 100: `ABCDE` | Raises “different payload at the same sequence number” | Accept consistent retransmission with a different segment length |

The stream key also lacks a connection incarnation. A capture containing reconnects on the same tuple cannot safely be treated as one stream.

Fix this bounded reassembler before treating loss/reconnect captures as proof. Establish an incarnation and a serial-number origin from the handshake where available; unwrap offsets relative to it; compare every overlapping byte; preserve consistent retransmissions; reject gaps, conflicting bytes and ambiguous captures. Do not silently guess ordering across an ambiguous half-sequence-space span.

Also fix `wire_check.dnp3_ok`: a CRC-valid 10-byte frame with link LEN 4 currently returns `(True, 'ok')`. Link LEN must be validated before subtracting 5. This probe was `0564044401000a006bd4`.

### 3. Some reporting proves growth, not the selected target

`hw_vepa/report.py` calculates READ `padding_coverage` using `resp_len > 49`. A 50-byte or 60-byte response therefore counts as padded even when the configured target is 61.

Keep generic growth as a separate descriptive metric. Acceptance must require the exact expected length and encoding for each eligible function, and report eligible, transformed, correctly transformed, native/ineligible and failed counts separately. A correct total growth alone can conceal offsetting per-response errors.

The 61 endpoint manifest also carries an inherited `wire_transform_sha256`, while the source snapshot list omits imported checker/runner dependencies. Pin the actual encoder and its dependency closure, endpoint commit, binary and command. A pinned repository revision makes recovery possible, but the manifest should not name the wrong transform.

There is a shape-contract mismatch to settle before coding: `encode61` accepts a READ with application CON set and a control response with nonzero status, returning 61 bytes. The input E profile requires application upper bits `0xc0` under mask `0xf0` and its control row requires status zero. These are shape-level differences, not a claim about end-to-end N admission. Explicitly align the new candidate's oracle, admission/eligibility contract and negative tests; do not broaden live control handling merely to make the oracle pass.

### 4. The permanent 88/89 duplicate result is testing the wrong READ contract

`dup_hold_01/model_drive_dup.py` case C sends READ requests and their duplicates, then checks for early delivery of the **request**. This architecture forwards the READ request and holds the request ACK and response. The test sends neither of those response-side packets in this case.

Replace the inapplicable premise with a test of the actual contract: retransmitted READ requests, followed by separate ACK and response; duplicates before/after the real hold deadline; no double accounting, no incorrect generation change, and correct release of the held originals. Preserve the historical failing result and explain why the fixture changes. Do not merely delete the assertion to obtain 89/89.

### 5. The real-relay work is a compatibility track, not the missing 61 encoder

The latest `realrelay_native_01/full_02` deliberately forwards supported option-bearing traffic **without padding or timing protection**. Solving its wedge will not demonstrate obfuscation against the SEL-751.

The README opening claim that the tuple cannot wedge is contradicted by its later review. A clean SYN followed by an option-bearing SYN-ACK leaves phase 2. Other listed wedges include an unanswered SYN and quarantine phase 6. A phase-2 abort action alone would not establish general recovery.

There are also explicit unsupported cases: MSS+WS+SACK without timestamps, and offset-5 segments such as an option-less RST. Retained positive timestamp-profile tests do not establish universal native passthrough. The `generate_02.py` metadata includes `pending_open_abort` even for `network-only`; make the variant's enabled features unambiguous.

Keep this candidate off hardware until its declared state-transition contract passes. Do not merge it into the 61 experiment to solve two distinct problems at once.

### 6. Sustained lifetime and timing are bounded

The strict source's `gen_admit`, `gen_bump` and `op_gen_bump` saturate at `0xffff`; `tin_verdict` rejects exhausted work. OPEN/CLOSE consume generations too. These are 32-bit registers with an intentional **16-bit usable allocation budget**. A reconnect does not replenish it.

At 50 READ allocations/second, 65,534 allocations last under 22 minutes, even before additional generation consumers. This is arithmetic from the source, not a measured maximum rate. Do not describe the candidate as indefinitely operating because short reconnect tests pass. Preserve the fail-closed guard; do not remove it or wrap counters without proving stale-token isolation. Before any overnight run, calculate and log its generation budget and bounded trial length.

Recomputed strict-candidate timing, configured gap **950 µs**, shaping **59,570 PPS**:

| Arm | Timed READs | Median signed error | p99 absolute error, nearest rank | Signed min / max | Absolute error >100 µs |
|---|---:|---:|---:|---:|---:|
| Timing-only | 1,500 | +35 µs | 88 µs | −923 / +93 µs | 2 |
| Combined | 1,500 | +14 µs | 60 µs | −923 / +1,145 µs | 4 |

The reported provisional p99 threshold can pass while individual tails fail. Preserve both facts. Short CLRT here can arise from a late ACK, not necessarily an early response. Host capture does not by itself localize the delay inside the ASIC.

The retained T-on totals are approximately 0.43–0.88 million loop packets and 32–64 MB per 500 READs. Total internal overhead remains meaningful; original-rewait reduction alone is insufficient. The earlier one-run 0.60 ms versus 0.79 ms endpoint result also cannot establish that segmentation has no latency cost.

## Ready-to-use continuation prompt for Claude

> Begin the execution brief below. The preceding findings and appendices are supporting evidence. Do not spend the session rewriting the brief.

### Objective and fixed scope

Finish a **bounded, standards-grounded 61-octet equal-response candidate** for the supported software-endpoint TCP profile, including correctness, timing and overhead evidence on the authorized testbed. Preserve requests and application semantics. One eligible response must leave as one TCP segment; SBO may contain three DNP3 transport segments/link frames within that TCP payload. Do not reintroduce the discarded TCP packet split or request-side decoy scheme.

Use the latest tree, first checking for changes beyond audited revision `492013014`. Preserve other work. The strict baseline remains available and its restoration behavior stays unchanged. A platform policy rejection is not overridden by this brief: do not retry a blocked operation through rewording, another agent or another model. Record the rejected gate and continue only permitted work.

### Start from one explicit baseline

Define:

```text
C4 = defense4/timing/case4_architecture
X  = C4/integration/core/response_only_rearm/stage_experiments
H  = C4/integration/evidence/rearm_01

Input = X/dup_hold_01/evidence/full_02_strict/response_only.p4
SHA256 = 2ad71761399e023b0d3b6b72f9fb71257da012499ffe30ac4758b395fc1bd97c
Oracle = X/seg61_01/encode61.py
```

This input is `rearm_57s`, N12/E12/T11. It includes the held-OPERATE duplicate fix. A direct source comparison confirms it differs from the all-58 `dup_hold_01/full_01` source in just the `ctl_profile` entry. Thus **retain N and T byte-identically for the first 61 build**, and change E deliberately. Do not base this work on an unqualified smaller-stage variant or `realrelay_native_01`.

Read only the current plan/status, the input, the encoder, the relevant generator, and the named checkers first. Consult old experiment directories only for a particular failed constraint or regression. Avoid rereading the entire working-notes chronology each turn.

### Gate A — repair the few acceptance checks that can approve wrong results

Make the bounded fixes in findings 1–3 and their failing-then-passing regression cases. Add full SBO application-byte comparison, SELECT success semantics, TCP overlap/wrap/incarnation checks, legal link LEN checks and exact profile-length acceptance. Preserve all original evidence.

Use one explicit test/runner profile with separate native and output lengths: READ 49→61, control 37→61. Replace boolean strict/all58 expectations in **new candidate drivers**, including `model_drive_dup.py`'s hardcoded `CTL_IMAGE`, READ frontiers and oracle wrapper. Existing historical drivers retain their recorded meaning. A single shared profile can configure expectations; it must not make the independent checker simply call the encoder being tested.

Resolve the CON/status eligibility mismatch described above. For the first build, retain the qualified profile's restrictions and test that excluded responses follow the documented behavior. Do not label the encoder's broader shape predicate as matching P4.

Resolve duplicate-READ case C against the actual timing contract. Do not advertise an unexplained 88/89 as complete qualification.

Acceptance: existing positive fixtures still pass; each supplied mutation now fails for the intended reason; consistent TCP resegmentation and sequence wrap pass; missing/ambiguous input evidence fails closed.

### Gate B — implement the 61 encoder and mapper in E

Create a candidate generator beside `seg61_01`, using the strict source hash above. Require exact edit anchors, record changed sections, and assert unchanged N/T hashes. Keep a single authoritative generated candidate and manifest.

**READ output:** the same 23 G10V2 points, flags, application header and IIN. Three object ranges: 0–5 with qualifier 0x00; 6–9 with 0x00; 10–22 with 0x01. The 45 user octets occupy data blocks 16, 16 and 13. Link frame length is 10 + 45 + 6 = **61**.

**SBO output:** preserve all 22 application octets. Transport portions contain 15, 6 and 1 application octets, each preceded by its transport header. Frames are 28, 19 and 14 octets, total **61**. Use FIR on the first, FIN on the last, and successive modulo-64 sequences. Retain the native first sequence; a new FIR is permitted to start at any sequence. Requests and control object bytes stay unchanged.

**Mapper changes are more than `58 → 61`:**

| Site in strict generated E | Required change |
|---|---|
| `r_IMAGE_LEN`, around line 530 | 61 |
| `start_arm`, around 943 | Virtual image start ISN+1−61: `0xFFFFFFC4`, replacing `0xFFFFFFC7` |
| `fwd_prep`, around 966 | `m.pm = m.p − 61`: `0xFFFFFFC3`, replacing `0xFFFFFFC6` |
| `classify_rev`, around 1041 | Cover image offsets −59, −60, −61 as well as existing offsets; generate both window cases and recompute capacity (existing allocation 118 becomes 124 if preserving its spare slot) |
| `read_eligible`, around 1010 | New ranges/CRC layout, link LEN 0x32, IP/TCP growth **12** |
| `ctl_eligible`, around 1012 | Replace filler layout entirely with three legal frames, growth **24**; enable `ctl_shape` only with this new encoding |
| Native parser/accounting | Keep input lengths **49 and 37**; do not blindly replace literals |
| TCP checksum and deparser | Sum the actual concatenated 61 bytes, with odd-length zero padding only at the end of the TCP checksum calculation |

Frame starts for SBO are offsets **0, 28, 47**. The last frame starts on an odd byte boundary. This is a concrete checksum risk: do not independently pad each DNP3 frame when calculating one TCP checksum. Validate the complete emitted packet with an independent checksum implementation.

For resource fit, preserve input headers where possible, partition data once rather than copying it into overlapping headers, emit constant header bytes without unnecessary long-lived metadata, and compute independent CRC tails early. Keep necessary checksum/PHV pragmas. The CRC delta table below supplies measured optimization candidates; verify their field byte order against emitted bytes.

Acceptance: compile the **whole composed candidate**, using the installed SDK unchanged, then inspect actual stage/PHV/table/hash placement. No claim of fit from separate slices. Target no additional ingress stages or pipeline traversals, E ≤12 stages and T unchanged. If it fails, identify the exact resource/dependency and make one bounded change at a time; do not remove validation, stale-state guards or checksum protections to fit.

### Gate C — compiled-model packet and state proof

Exercise actual compiled output, not source interpretation alone:

1. Distinct READ point bytes, varied valid flags and IIN; legal ranges with no missing/duplicate points.
2. SBO exact native application bytes; nonzero on/off durations and distinct fields to expose byte swaps; correct handling of error/status responses within the declared eligibility profile.
3. All 64 transport starting sequences, including 62 and 63; valid link CRCs and IPv4/TCP checksums, especially odd-length output.
4. Mixed READ/SBO on a persistent connection. Verify cumulative growth `12 × READ + 24 × (SELECT + OPERATE)` for eligible responses, not merely the response count.
5. New image boundaries: partial/cumulative ACKs, zero and nonzero windows, retransmission of the same response without double growth, TCP sequence wrap, FIN/RST after growth. Explicitly exercise the newly added −59..−61 reverse-map cases.
6. Previously qualified rearm, old-token, old-external and held-OPERATE duplicate behavior. A retransmitted OPERATE must not leave before the original hold deadline. Treat unsupported resegmentation or overlapping application responses according to an explicit contract; never silently call them supported.

Run the retained relevant regressions with profile-correct expectations. Review surprising failures against bytes, direction, connection incarnation and timing before changing either implementation or assertions. A fake peer that never emits an ACK/response cannot prove their timing behavior.

Acceptance: reproducible compile/model commands, output hashes, exact wire comparisons and state invariants; no unexplained failures hidden behind a pass total.

### Gate D — bounded silicon qualification

After the preceding gates and the existing hardware review pass, use the already authorized software-handler endpoint path and restoration procedure. One operator owns hardware. Physical relay OPERATE remains attended-only. Do not make unrelated host, relay, SDK or production-default changes.

Start with T-off and T-on blocks on the new candidate, then persistence, loss, reconnect and stale-traffic gates. Capture both endpoints, switch counters, mapper state and actual loaded-artifact identity. Prove ASIC traversal using the established path controls. Verify **one emitted TCP segment per eligible response**: one proxy `sendall()` is not proof of this property.

For the first timing comparison, retain the strict evaluation's 59,570-PPS shaping and 950-µs gap. Changing target, shaping and encoding together would confound attribution. Record realized rates and all timing settings. Validate generation headroom before each trial; exhaustion is an explicit limit, not a reason to silently recycle tags.

Acceptance: successful READ/SBO semantics, exact 61-byte eligible responses, valid CRC/checksums, correct translation and recovery, genuine timing commit/release, no unexplained fallback, and verified restoration. Report each gate separately. This demonstrates the controlled software-endpoint profile; it does not establish real-relay interoperability.

### Gate E — measurements and efficiency after correctness

Run the same four arms with repeated, paired or order-rotated blocks. Change one experimental factor at a time when attributing effects. Include the native/piggyback-ACK fixture as well as the separately labelled response-delay fixture: CLRT is not defined when no separate request ACK exists.

Report host CLRT, signed and absolute target error, p99, maximum and every exclusion/tail; also request-to-response latency, total internal packets **and bytes**, external growth, loss recovery, callbacks, stage/PHV/table/hash use and pipeline traversal counts. Separate intentional obfuscation delay from processing and polling overhead. State the SD convention and preserve per-block results. The provisional p99 absolute error ≤100 µs is not a maximum-error guarantee.

Investigate the retained ~1.1-ms ACK/response tails by correlating packet times, queue/pktgen counters, host scheduling/fixture logs and sequence values. A similar event at indices 127/255 is a lead, not proof of an 8-bit counter defect. Compare against the same strict baseline before blaming the 61 encoder.

Only then compare 14,892 and 59,570 PPS on this candidate. Choose a measured precision/total-overhead trade-off. Any stage-recovery experiment is a separate change with an actual compiler dependency hypothesis and byte/state regressions. Fewer occupied stages alone is not a measured forwarding-latency improvement.

### Keep the real-relay compatibility track bounded

Do not require `realrelay_native_01` to unblock software-endpoint 61 qualification. If continuing that track, specify the pending-open state transition and stale-incarnation behavior before adding an owner RegisterAction. Add mixed-handshake, wrong-ACK, retransmission, unanswered-SYN, quarantine and offset-5 close/RST tests. A phase-2 repair is not full timeout/rearm recovery. Prove the whole program still fits and preserve active mapped-flow isolation.

Actual SEL-751 padding remains a later positive gate on a documented TCP profile. A native-passthrough success must be labelled native. Do not resurrect the handshake-only parser change that accepted SYN-ACK but dropped subsequent timestamped packets.

### Stop changing the definition of completion

At each milestone update one short current checkpoint with: source/build identity, completed gate, failing gate, evidence path, precise next action and current hardware/restoration state. Fold durable findings into the subsystem's existing authoritative status. Do not generate another long historical handoff or delete evidence to reduce context use.

The deliverable is one reproducible 61 candidate with qualification results and explicit limits. Do not call universal IEEE conformance, transparent real-relay support, indefinite lifetime, zero latency cost or comprehensive fingerprint resistance established by this bounded campaign. Equal TCP payload length hides that feature; plaintext object content and one-versus-three link-frame structure remain visible to a protocol-aware observer.

Commit coherent reviewed changes under the repository's established rules. Push only when Philip explicitly instructs it. Continue authorized work without presenting a new menu for each routine implementation choice. If a gate is blocked, report the concrete cause and completed artifacts; do not redefine a proxy result as hardware completion.

## Technical appendix: standard, byte layout and CRC opportunities

### Standards basis rechecked in the supplied IEEE 1815-2012 PDF

This audit checked the relevant clauses; it does not claim to have reread all 821 PDF pages or certify the full standard.

- **Table 4-8, printed p.35 / PDF p.77:** qualifiers 0x00/0x01 are used for static-object responses; 0x06 is not permitted in a response. This is why the earlier zero-object Group 41 filler was not an acceptable READ solution.
- **§4.4.4.3 Rule 8, printed p.51 / PDF p.93:** SELECT object bytes must exactly echo the request, and specified status/IIN failures prevent issuing OPERATE. Merely choosing another filler group does not solve that echo requirement.
- **§8.2.1.3–4, printed pp.268–269 / PDF pp.310–311:** transport sequence is six bits; it advances modulo 64 within a fragment; a first/FIR segment may start at any sequence independently of prior history.
- **§8.2.2, printed p.269 / PDF p.311:** segments may contain 1–249 application octets and have different sizes; application-byte order must be preserved. The standard recommends large segments for efficiency, so small segments are permitted but are not free of overhead.

These clauses support the bounded proposed encoding. They do not show that every master implementation interoperates with it or that 61 is the only possible compliant design.

### Layout

`H` below is the native transport header plus four response application-header/IIN octets. `P0..P22` are the original G10V2 point bytes, not new measurements.

| READ data block | Contents before its two CRC octets | Length |
|---|---|---:|
| 1 | `H`, `0a 02 00 00 05`, P0..P5 | 16 |
| 2 | `0a 02 00 06 09`, P6..P9, `0a 02 01 0a 00 16 00` | 16 |
| 3 | P10..P22 | 13 |

The 10-byte link header includes its own CRC. Total READ size is 10 + 18 + 18 + 15 = 61.

For SBO, application bytes A0..A21 are unchanged:

| Frame | Transport header | Application bytes | Link LEN | Full frame size |
|---|---|---|---:|---:|
| 1 | FIR, sequence s | A0..A14 | 0x15 | 28 |
| 2 | sequence (s+1) mod 64 | A15..A20 | 0x0c | 19 |
| 3 | FIN, sequence (s+2) mod 64 | A21 | 0x07 | 14 |

The receiver reassembles one unchanged application response. There are three DNP3 link frames, not three TCP packets. The switch must enforce and capture that output-packet property.

### CRC delta table

CRC is affine for fixed message length. For a fixed bit change in an otherwise unchanged block, old CRC XOR new CRC is a constant. Reuse is valid only after checking the incoming CRC and ensuring exactly the assumed bytes change. The following deltas were independently computed with the reflected 0xA6BC implementation and checked over 1,024 random inputs each. They are optimization inputs, **not compiled-P4 proof**.

| Change | Numeric reflected CRC XOR | Two wire-order octets |
|---|---:|---|
| Native READ link LEN 0x26 → 0x32, same other seven header octets | 0x35af | `af 35` |
| Native control link LEN 0x1c → first-frame 0x15 | 0x2f3b | `3b 2f` |
| Native control link LEN 0x1c → second-frame 0x0c | 0x78c1 | `c1 78` |
| Native control link LEN 0x1c → third-frame 0x07 | 0x714d | `4d 71` |
| READ first 16-byte block: stop index at offset 9, 0x16 → 0x05 | 0x2262 | `62 22` |
| SBO first 16-byte block: clear transport FIN at offset 0 | 0x370c | `0c 37` |

P4 fields often hold the two CRC wire bytes as a big-endian bit string; choose the literal for that representation explicitly. Do not interchange the numeric and wire columns. The remaining READ blocks and SBO tail blocks need their actual new CRCs, calculated early from native fields where dependencies allow.

### Reproduction commands

From a checkout of the pinned revision:

```bash
AUDIT_C4=defense4/timing/case4_architecture
AUDIT_EXP="$AUDIT_C4/integration/core/response_only_rearm/stage_experiments"
python3 -B -m unittest discover -s "$AUDIT_EXP/read_reencode_01/tests" -v
python3 -B -m unittest discover -s "$AUDIT_EXP/seg61_01/tests" -v
```

The audit probe appended below is standalone. Save it as `audit_probes.py` outside the repository and run `python3 -B audit_probes.py /path/to/DNP3`. It writes no repository files and makes no hardware or network calls. At the audited revision it should demonstrate the false positives above; after repairs those outputs should change as specified.

## Source map

All links are pinned to the audited commit, rather than moving `main`.

- [Strict baseline and duplicate-hold findings](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/dup_hold_01/README.md)
- [Strict generated N/E/T source](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/dup_hold_01/evidence/full_02_strict/response_only.p4)
- [61 encoder](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_01/encode61.py)
- [61 endpoint result](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_01/evidence/endpoint_01/completion.json)
- [Capture acceptance checker](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_reencode_01/check_capture.py)
- [TCP capture reconstruction](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_reencode_01/capture.py)
- [Standards checker](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_reencode_01/dnp3_std.py)
- [Hardware wire checker](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/protocol/hw_vepa/wire_check.py)
- [Campaign report calculation](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/protocol/hw_vepa/report.py)
- [Real-relay native experiment, findings and limits](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/realrelay_native_01/README.md)
- [Current rearm/hardware status and timing results](https://github.com/akekulip/DNP3_obf/blob/492013014/defense4/timing/case4_architecture/integration/evidence/rearm_01/STATUS.md)

## Reproducible audit probe

```python
#!/usr/bin/env python3
"""Read-only offline probes against the source at 492013014. No hardware access.
Run: python3 audit_probes.py /absolute/path/to/repository
"""
import argparse
import hashlib
import json
import random
import struct
import sys
import tempfile
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('repo', type=Path)
a = ap.parse_args()
sys.dont_write_bytecode = True
c4 = a.repo.resolve() / 'defense4/timing/case4_architecture'
exp = c4 / 'integration/core/response_only_rearm/stage_experiments'
sys.path[:0] = [str(exp / 'seg61_01'), str(exp / 'read_reencode_01'),
               str(exp / 'read_reencode_01/tests'), str(c4 / 'protocol/hw_vepa'),
               str(c4 / 'protocol/hw_vepa/tests')]
import capture
import check_capture
import dnp3_std as std
import encode61
import pcaptk as tk
import test_check_capture as fixture
import test_standards
import wire_check

results = {'revision': '492013014', 'scope': 'offline Python checks only'}
results['fixture_sha256'] = hashlib.sha256((test_standards.RUN / 'out.pcap').read_bytes()).hexdigest()
native = test_standards.directed(test_standards.RUN / 'out.pcap', 20000, 59440)

with tempfile.TemporaryDirectory() as tmp:
    baseline = check_capture.check(fixture.synthetic(tmp, lambda i, f: encode61.encode(f) or f))
    results['unmodified_61'] = {'conformant': baseline['conformant'],
                               'responses': baseline['responses'],
                               'lengths': [v['wire_len'] for v in baseline['verdicts']]}
    for label, index, value in [('app_sequence', 1, 1), ('iin1', 3, 1), ('iin2', 4, 1)]:
        def change(i, frame):
            if i == 20:
                h, u = std.deframe(frame)
                u = bytearray(u)
                u[index] ^= value
                frame = std.frame(h, bytes(u))
            return encode61.encode(frame) or frame
        verdict = check_capture.check(fixture.synthetic(tmp, change))
        results['corrupted_select_' + label] = {
            'checker_conformant': verdict['conformant'], 'failures': verdict['failures'],
            'select': verdict['verdicts'][20]}

    def stream_probe(segments):
        path = Path(tmp) / 'stream.pcap'
        tk.write_pcap(str(path), [(i * 100, tk.frame('192.168.10.61', '192.168.10.62',
            54321, 20000, seq, 0, tk.PSH | tk.ACK, data)) for i, (seq, data) in enumerate(segments)])
        try:
            return {'accepted_bytes': [v.hex() for v in capture.streams(path).values()]}
        except Exception as e:
            return {'error': type(e).__name__ + ': ' + str(e)}
    results['conflicting_overlap'] = stream_probe([(100, b'ABCDE'), (103, b'xyFG')])
    results['sequence_wrap'] = stream_probe([(0xfffffffc, b'ABCD'), (0, b'EFGH')])
    results['consistent_resegmentation'] = stream_probe([(100, b'ABC'), (100, b'ABCDE')])

h = bytes.fromhex('0564044401000a00')
malformed = h + struct.pack('<H', tk.dnp3_crc(h))
results['invalid_link_len_4'] = {'frame': malformed.hex(), 'wire_check': wire_check.dnp3_ok(malformed)}
results['independent_crc_all_22'] = all(wire_check.dnp3_ok(encode61.encode(f))[0] for f in native)

# Shape-level divergence from the P4 profile that the 61 docstring says it mirrors.
# This does not assert end-to-end N admission for these inputs.
results['eligibility_mismatches'] = {}
for label, frame, offset, xor_value in [('READ_CON', native[0], 1, 0x20),
                                        ('SBO_nonzero_status', native[20], 22, 1)]:
    h, u = std.deframe(frame)
    u = bytearray(u)
    u[offset] ^= xor_value
    output = encode61.encode(std.frame(h, bytes(u)))
    results['eligibility_mismatches'][label] = {
        'oracle_output_length': len(output) if output else None,
        'baseline_E_profile_match': False}

# XOR deltas are numeric reflected CRC values, not P4 field byte order.
rng = random.Random(1815)
def delta(length, offset, xor_value):
    constants = set()
    for _ in range(1024):
        b = bytearray(rng.randrange(256) for _ in range(length))
        changed = bytearray(b)
        changed[offset] ^= xor_value
        constants.add(tk.dnp3_crc(b) ^ tk.dnp3_crc(changed))
    assert len(constants) == 1
    v = constants.pop()
    return {'reflected_numeric': '0x%04x' % v,
            'wire_octets_hex': struct.pack('<H', v).hex(), 'random_checks': 1024}
results['crc_deltas'] = {
    'READ_link_LEN_26_to_32': delta(8, 2, 0x26 ^ 0x32),
    'SBO_link_LEN_1c_to_15': delta(8, 2, 0x1c ^ 0x15),
    'SBO_link_LEN_1c_to_0c': delta(8, 2, 0x1c ^ 0x0c),
    'SBO_link_LEN_1c_to_07': delta(8, 2, 0x1c ^ 0x07),
    'READ_first16_stop_16_to_05': delta(16, 9, 0x16 ^ 0x05),
    'SBO_first16_clear_FIN': delta(16, 0, 0x80),
}
print(json.dumps(results, indent=2))
```
