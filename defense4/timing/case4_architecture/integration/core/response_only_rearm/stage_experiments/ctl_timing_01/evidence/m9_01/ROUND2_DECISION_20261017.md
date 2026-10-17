# m9_01: round-2 qualification decision (2026-10-17)

**Candidate.** ctl_timing_01 **m9_01**, source `6590141f…`.
- Freeze v2 (`freeze_v2.json`, 85 files) was checked before every round-2 block (`freeze_check.json` in each run).
- The 950 µs target, the p99 ≤ 100 µs criterion (nearest rank), every tail, and the restoration requirement are
  unchanged.
- No default is promoted. The directive and the 7637390c1 review are retained in
  `../../efficiency_probes_m9/REVIEW_7637390c1.md`.

## Decision table

| # | gate | verdict | evidence | supported claim |
|---|---|---|---|---|
| 1 | Model gate, verified provenance (summary v2) | **PASS** | `model_summary_v2.json`: 9 drivers, latest attempt each; driver hashes equal the retained copies; abort's executed contention driver verified; sections complete | m9_01 passes every compiled-model driver on its frozen source |
| 2 | Abort handling, model | **PASS** for the reachable branches | `../model_abort_m9_01_02` 79/79: READ/SELECT held and released, OPERATE released, translated SEQ/ACK and checksums, no leak, reconnect, +48/+50 negatives with surviving response | An outstation RST one held response ahead resets the master at RCV.NXT. OPERATE's response is never held (J > D). Bare RST is forwarded untranslated (limitation) |
| 3 | Master RST while a response is in flight | **FAIL** (open limitation) | `../model_contention_m9d_01_02/FAILURE_20261017.md` (trace); the same case failed on the N-only probe; m9_01's single run passed | If the outstation's response claims N's owner during the m9 reset wait, the master's RST is lost and the outstation keeps the connection. Not a noncompliant-sender case. Not fixed this round |
| 4 | Silicon recovery: persistence graceful/RST, loss core, reconnect, held OPERATE | **PASS** | round 1, `COMPLETION_REPORT_20261017.md`; restore verified each | Recovery behaviour holds on silicon for the supported workloads |
| 5 | Piggyback qualification b1–b3 | **PASS** | round 1, strict aggregate | Piggyback-bound timing meets its objectives on silicon |
| 6 | Repeated-SBO precision, host-observed: 950 µs, p99 ≤ 100 µs | **FAIL** | round 1: b1, b3 fail on one exchange; round 2 controls: tail in 4 of 6 timed arms, none in b3; all at exchange 126–127 | The end-to-end, host-observed criterion is not met. One exchange per affected arm misses by about 910 µs |
| 6a | Where that tail arises | **Localized: downstream of the switch's egress parser** | round 2, m9d diagnostic build, 6 of 6 timed arms: host CLRT 28–41 µs while switch egress CLRT is 956.9 µs; 193 of 193 exchanges matched per arm (`seg61_02/evidence/hw_campaigns/m9_round2_sequence/ack_diag.md`) | At the latest point the pipeline can observe, after every hold and the final queue, the switch released the ACK and response 956.9 µs apart. The ~1 ms delay is added after that point: E egress, the MAC, the cable, or Vision's receive path |
| 6b | Switch-side release precision (diagnostic observation, not the qualification criterion) | **observed, 7 µs** | m9d, 2,316 timed exchanges (18 kind-and-arm groups): max \|switch CLRT − 950\| = 7.0 µs, a constant +6.9 µs offset | The switch's request-anchored release is precise to 7 µs at the egress parser. The host-observed p99 adds up to ~93 µs of variation, plus the exchange-127 tail |
| 6c | Instrumentation effect (plan rule) | **flagged, not excluded** | medians within 8.5 µs (< 10). The precision objective differs in 4 kind-and-arm pairs, all through where the single per-arm tail falls; tail present in 6 of 6 m9d arms against 4 of 6 controls | The instrument does not create the tail, which occurs on the uninstrumented build. Whether it raises the tail's frequency is not decidable from 6 arms |
| 7 | Isolation: old tokens rejected (v3) | **PASS** | `ctl_m9_iso20_poll_950_01/isolation_v3.json`: raw 7 + 4 equal the cohort, 0 stale blockers before the permit, 2 after it (allowance 25); bound to the run's own config | Old generator tokens are rejected and none outlives its bound |
| 8 | Isolation: later traffic correct (v3) | **PASS** | the same file: restore, quiet polls, bank isolation, post-traffic authority, c1–c3, Vision series | Traffic on the new connection is unaffected |
| 9 | Isolation: cleanup deadline (v3) | **INDETERMINATE** | the same file: switch-clock drain bracket 14.82–15.13 s against the 15.001 s deadline; resolution 0.31 s | Not established |
| 10 | Restoration | **PASS** | restore_verify ok after all 12 round-1 and 7 round-2 blocks | Every block left the switch on the production program, verified |
| 11 | Efficiency probes (outside the qualification build) | none carried forward | `../../efficiency_probes_m9/RESULTS_20261017.md` | t_single_child saves T resources and needs a control-plane schema change; the others either do not save resources or failed one model case |

**Overall: m9_01 is not qualified.**
- Gate 6 (host-observed precision) and gate 3 (reset race) fail.
- Gate 9 (cleanup deadline) is indeterminate.

## Remaining gates: the one missing fact, and one bounded next measurement each

- **Gate 6, host-observed precision.**
  - *Missing fact:* what, between E's egress parser and Vision's capture timestamp, delays one frame pair near the
    128th exchange of every timed arm.
  - *Next measurement:* one diagnostic block with an independent capture point between the switch and Vision, a
    passive tap or a second host. Alternatively, switch MAC TX timestamps (Tofino 1588 TX timestamping) on the
    m9d image, compared with Vision's receive time. Until then, the claim is limited to 6a/6b.
- **Gate 3, reset race.**
  - *Missing fact:* whether a reset that waits across an owner change can be made safe without weakening N's owner
    guard.
  - *Next measurement:* a source-pipeline design study of the owner-changing interleaving, outcome-only, and no
    silicon until it passes the model suite. This round fixes nothing here.
- **Gate 9, cleanup deadline.**
  - *Missing fact:* the instant of the last raw READ rejection, to better than 1 ms. By design the last old token
    is emitted at 15.000 s, against a 15.001 s deadline, and a gRPC poller resolves about 0.3 s.
  - *Next measurement:* a separately named diagnostic build that records T's raw-rejection time on the switch, the
    same pattern as m9d, in one isolation block.

## Supported profile, stated precisely

- **Contract.** Native requests; eligible READ, SELECT and OPERATE responses transformed to 61 bytes; the existing
  request-anchored blocker timing with D = 950 µs and the OPERATE hold J; software endpoints under the documented
  TCP profile.
- **Measured:**
  - **Recovery:** correct on silicon.
  - **Release timing:** precise to 7 µs at the switch's egress parser.
  - **Host-observed timing:** meets the p99 criterion except for a single downstream-delayed exchange per affected
    arm.
- **Not claimed:**
  - safety of a master reset that races an outstation response;
  - bare-RST translation;
  - two-response-ahead resets;
  - an established isolation cleanup deadline;
  - exactly-once delivery;
  - size, splitting or real-relay behaviour.

## Corrections (2026-10-17, review af7bd434)

The table above is kept as written. Where it conflicts with this section, this section holds.

1. **Row 6b, denominator.** m9d ran 12 arms of 193 exchanges: 2,316 exchanges in all, every one matched to its
   register entry. Six arms are timed: **1,158 timed exchanges** in 18 kind-and-arm groups. The 7 µs maximum
   switch-side error is over those 1,158, not over 2,316. Recomputed from `ack_diag.json`. The review's
   independent decoder (`../../review_af7bd434/package/verify_diag_pcaps.py`) reproduces the same counts from the raw
   captures, byte for byte (`../../review_af7bd434/reproduced/independent_diag.json`).
2. **Row 6a, observation point.**
   - The diagnostic timestamp is sampled at E's egress parser: after the traffic manager's final queue, but before
     the rest of egress processing, the deparser, the MAC, the link and the receiving host.
   - What is established is that the ~1 ms delay arises **downstream of the egress-parser observation point**.
   - It is not established that the host or its NIC alone adds the delay, and the timestamp is not a wire transmit
     time.
   - The host p99 failures and every tail stay in the primary results (row 6).
3. **Row 7, wording.** Delete "and none outlives its bound". Count conservation shows every old token was
   rejected. It does not show when the last one was rejected, and row 9's interval (14.82–15.13 s) straddles the
   15.001 s deadline. The supported claim is "old generator tokens are rejected".
4. **m9d silicon had an unmet model gate.**
   - The six m9d blocks were diagnostic work.
   - m9d_01's `model_summary_v2.json` is `blocked`: the ordinary drivers were not run on that source, and the
     latest contention attempt fails 378/379 on the reset race (row 3).
   - The freeze recorded file hashes. It did not record a functional model gate, so nothing here claims that every
     model prerequisite for m9d passed.
   - Its measurements localize the tail. They do not qualify any candidate.
5. **Payload-length check.** The review decoder confirms 579 combined and 579 size-only responses of 61 octets, and
   in each of timing-only and off, 195 native 49-octet READ and 384 native 37-octet control responses. This is
   payload-length and correlation evidence only. The standards and CRC checker remains the encoding evidence.
6. **Model summary re-evaluation.** After this round's efficiency probes, a re-run of `model_summary.py --v2` on
   m9_01 reported `blocked`. The cause was the attempt pattern: it read the probe build's runs
   (`model_*_probe_n_zero_unused_timestamp_m9_01_01`) as m9_01's own. The pattern now accepts only run_model's
   driver names, and the re-evaluation equals the retained `model_summary_v2.json` again (`model_gate_passed`,
   same latest attempts).
7. **Dependency evidence.** m9_01's model runs predate mandatory dependency evidence (summary v3). They keep their
   recorded v2 status. The provenance limitation is that no executed-closure hashes were recorded; only the driver,
   one wrapped driver and two listed modules were hashed.
