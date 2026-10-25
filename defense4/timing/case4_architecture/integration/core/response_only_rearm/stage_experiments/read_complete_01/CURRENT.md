# Current status — c67 response-ready timing v2 (2026-10-25 closeout: hardware qualification FAILED)

Continue from repository-root [CLAUDE_HANDOVER_20261025.md](../../../../../../../../CLAUDE_HANDOVER_20261025.md) (see its Closeout section), then `plan.md` and `WORKING_NOTES.md`.

**c67 outcome (2026-10-25 closeout; Philip's disposition).** The planned c67 hardware testing is complete, and c67 has
**not** passed hardware qualification.

| dimension | result | evidence |
|---|---|---|
| model gate | PASS | 17/17 drivers; `model_summary.py --v3 --enforce` = model_gate_passed (`model_summary_v3.json` 4dbd5710...) |
| smoke (D5) | PASS | campaign `rc01_hw_c67_20261025_02` |
| FIN recovery | PASS for the planned scope (plan.md FIN criterion) | campaign `_07`: graceful, RST and reconnect, each with all three connections, restoration verified |
| timing | FAIL, cause unresolved | campaigns `_03` (D5, four arms), `_04`/`_05`/`_06` reference_rest (D10/D15/D20) |
| mixed-loss SBO recovery | FAIL | campaign `_06` loss_mixed_950, trial t3 |
| physical OPERATE J | unproven | no relay-side observation |

- **Freeze:** every block ran under `freeze_v3_02.json` (b82acb00...). `freeze_v3.json` (bd8852a2...) predates the
  v2-only installer fix and is retained. Campaign 01 was refused by the installer dry-run before any pipeline write,
  because the installer expected a T register (t0_reg) that the v2 build does not compile. Every block's
  restoration was verified, and ownership ended inactive with unsafe_restoration=false.
- **Timing:**
  - All 1,930 planned reference exchanges were observed and eligible.
  - Every timed class at every D fails the unchanged 100 us criterion (0 of 32 timed cells pass).
  - The nearest-rank p99 absolute errors range from 1.722 to 44.104 ms.
  - The worst case is D10 timing_only mixed READ (n=33). Its observed complete CLRT is 54.104 ms, an absolute error of
    44.104 ms at D=10; with 33 samples, that error is also the p99.
  - The other timed classes lie roughly within D +/- 2-3 ms. The spread does not change with D, which does not locate
    its source. No cause is attributed (Vision included).
  - `evidence/c67_reference_replay_20261025.json` (5010adec...) is an offline replay with the campaign checker
    (relay_check.py), not an independent checker validation. It reproduces the recorded per-class precision exactly.
- **Mixed loss:**
  - In trial t3, the padded SELECT response was dropped by identity-targeted loss. SELECT recovered after 1024.2 ms,
    and the relay then answered OPERATE with CROB status TIMEOUT on points 1 and 3.
  - This is recorded as an application failure, separate from transport correctness.
  - The other SELECT recovery times (c67 loss_full t3 1007.5 ms with OPERATE OK; c52 loss_mixed t3 1001.7 ms with
    OPERATE OK) neither measure the relay's select window nor show that D caused the expiry.
- **Debugging scope:** further work is limited to bounded, hypothesis-specific debugging and retesting of these two
  failures, on the existing testbed, profiles, guarded operations and restoration (Philip, 2026-10-25). Failed
  evidence and the original thresholds are preserved. It must not become a new feature, production default, relay
  profile or instrumentation project.

## Superseded checkpoint — c67 takeover start (2026-10-25, before the model gate and hardware ran)

Continue from repository-root [CLAUDE_HANDOVER_20261025.md](../../../../../../../../CLAUDE_HANDOVER_20261025.md), then `plan.md` and `WORKING_NOTES.md`.
The root handover owns the final model-attempt inventory, remaining gates and next commands; older entries below
are historical checkpoints. Philip requested handover: no new implementation, model or hardware launches in this session.

The selected candidate is `m12p_c67_sdk9132`, source
`e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1`, with `timing_contract=response_ready_ack_d_v2`.
SDK9.13.2 compilation passes: N/E indices0..10, T0..9, pipe1 egress0..3; all 11 T state objects have one physical bank.
ACK waits for the matching whole response, releases once, then response follows after D=5/10/15/20ms. There is no
exchange deadline or timing fallback. Suppress a validated retry only while its original request or response is
retained; otherwise allow ordinary TCP recovery without new admission, growth or J. FIN/RST/epoch clean up ownership.
Preserve native91/134/49/49 to encoded141/158/60/60, successful SELECT before OPERATE, and J=2.4ms.

The repeat/lifecycle harness repairs require exact output endpoints and ACK/response order, full D from the compiled
T clock, and immediate stop on a failed exchange with planned/completed counts retained. The [independent harness review](evidence/timing_response_ready_20261025/claude_handover/harness-final-review.md)
is PASS (64 focused tests and 24 production-function probes). Lifecycle02 passes 138/138 with planned=completed
9READ/18SELECT/6OPERATE. Final repeat03/control_timing02 outcomes and all other driver results belong in the root
handover rather than a second mutable table here.

**The 17-driver model gate remains blocked; no c67 freeze or physical run exists.** Control_timing02 passed. Remaining blockers include missing abandon, stale repeat dependency closures in
abort01/contention02, and abort01 negative-survivor coverage missing for four required tags. The root handover
records the confirmed v2 held-negative stimulus defect: all four probes omit the genuine ACK, so responses=0
and no commit/release occurs. The strict validator is correct. Future repair is limited to injecting the genuine ACK
after the no-reset proof and observing the exact surviving response after full D; preserve positive abort scenarios.
Follow the root handover scope limits: no new campaigns, instrumentation or architecture. Recompute v3 before any freeze. No historical c52/c62 result qualifies c67. Ten prepared physical configs cover
combined D5 smoke, 1,930 reference exchanges, and combined D20 identity-loss/graceful/RST/three-connection recovery.
Every future block uses the existing frozen supervisor, generation headroom and independent restoration gates.
The 100 us timing criterion is unchanged; physical OPERATE J remains explicitly unproven. No new tap, software
outstation, OS changes or attacker campaign. c52 source 8f37f702 and its measured evidence remain immutable.

## Historical status — c52 physical SEL-751 set (2026-10-24 night)

## c52 measured baseline (immutable from 2026-10-25)

c52 is the baseline for the timing diagnosis. Nothing under `ctl_timing_01/evidence/m12p_c52_sdk9132/`, the c52
hw_blocks/hw_campaigns (23-31), the c52 configs, or the ledger may be edited again. Diagnostic work uses separate
candidates (`m12p_c52d_sdk9132`), configs and freezes, and is labeled as a separate evidence tier.

| artifact | sha256 |
|---|---|
| source `response_only.p4` | `8f37f70240ffa03daf887349e5e52a6abf7e32eb4b43ec559e35077902e3dce4` |
| `freeze_v3.json` (blocks 23-30) | `aa0e06dd393c37becd1d64269242a602d9037b2270cb94efc30ea6ed738e2865` |
| `freeze_v3_ref2.json` (block 31) | `c81b2b4baaf309bb6cf85fb37d7d2e11a26c8bdea46f8aa854882fb454dabbd4` |
| `model_summary_v3.json` (model_gate_passed) | `81a9f8b422d1d70f28133defef660446bade21be7f2412b1b774363299bf9a00` |
| `evidence/c52_reference_ledger_20261024.json` | `682cc26a38fabe90497ca4760e233682844b30da7696e1b0809db8f3ce7fc6e5` |

Evidence commit: ee7b7f47f (pushed). Blocks: rc01_hw_c52_20261024_23 ... _31.

FIN: overall FIN/reconnect qualification stays OPEN. FIN delivery and the application reconnect checks now pass
on all three connections (blocks 27, 28 and 29); blocks 28 and 29 fail only their switch gate (fallbacks).

c52 (`m12p_c52_sdk9132`, source 8f37f702; c51 plus acceptance of the relay's FIN+PSH+ACK as its FIN) passed the
enforced 16-driver model gate and ran the full guarded physical SEL-751 set (campaigns 23-31, Vision at
10.10.54.19). Every block restored with verification and ownership never became unsafe.

- **Reference:** 772/772 planned and eligible exchanges, recorded in
  `evidence/c52_reference_ledger_20261024.json`. Block 24 ran off and timing_only, then stopped on its switch gate;
  block 31 ran size_only and combined under a fresh freeze, `freeze_v3_ref2.json`. The application passes in all
  four arms.
- **Timing and J:** timing fails the unchanged 100 us criterion in both timing arms. READ p99 is 64,389 us for
  timing_only and 3,626 us for combined. OPERATE J is unproven.
- **Recovery blocks:**
  - Passed: smoke (23), loss_mixed (25), graceful persistence (27; the relay FIN+PSH+ACK close works where c51
    failed), held OPERATE (30).
  - loss_full (26) fails on one trial, t0, whose dropped packet was not the intended frontier.
  - RST persistence (28) and reconnect (29) pass the application on every connection but fail the switch gate
    on 2 and 1 ACK/RESP fallbacks.
- **Open fallback class:** every switch-gate failure is the designed fallback when the relay's first response on a
  fresh connection arrives after the readiness bound (30 ms, configured from T's t0; the master sees it later by forwarding and recirculation time that master-side captures cannot separate). Those responses took 38-98 ms, against
  about 30 ms on c51, and c51 block 04 shows the same counters. Rows c52 changed cannot match READ data (flags
  0x18). The cause is unobserved, because nothing captures the relay side. No threshold was relaxed.
- **FIN recovery: OPEN.** The reconnect block did not pass as a block.

Details: repository-root WORKING_NOTES.md (top).

Reproduction: clean worktree at 5a4eef229, `CANDIDATE=c52 bash reproduce.sh` rc 0: source regenerated byte for byte
  (8f37f702), retained logs restored hash-verified, model_gate_passed recomputed, all 9 c52 configs bound to their freeze.

Next: locate or address the late first-response fallback (relay-side observation, or a reviewed first-READ readiness change as a new candidate) without relaxing 100 us; FIN stays open until a reconnect block passes.

## Previous status — c51 physical SEL-751 continuation (2026-10-24 evening)

c51 (source 3fe70879; c50 + 8 qualified half-closed RST first_event rows) passed the enforced 16-driver model gate
(model_gate_passed) and ran on the physical SEL-751 through the frozen wrapper: smoke rc0 (91->141, 134->158);
four-arm reference rc0 772/772 exchanges with exact native/padded sizes; timing arms FAIL the 100 us criterion
(p99 complete CLRT ~2.6-4.5 ms) and OPERATE J is unproven; loss_full rc0 7/7; loss_mixed rc1 with 4/7 presets
(dropped SELECT response -> relay SBO TIMEOUT, safe); persistence_graceful rc2 because Vision 10.10.54.166 became
unreachable mid-block -> unsafe_restoration=true, all hardware stopped; persistence_rst, reconnect and held OPERATE
not run. FIN/RST physical recovery remains OPEN. Two hardware-path defects were fixed on the way (installer E
provenance check; logical vs wire-order READ link addresses, located with a new opt-in MAU snapshot). Details:
repository-root WORKING_NOTES.md (top) and the commits from 76888456a to the latest.

Blocker: Vision must be restored by Philip (no reboot by Claude); then reconcile through evaluation_campaign.py
reconcile, rerun persistence_graceful under a new ID, then 06-08 and the three missing loss presets.

## Previous status — Claude handover (2026-10-24)

Authority: repository-root Claude_dd7741152_Verified_Assessment_and_Overnight_Command.md and Philip's subsequent
packetization corrections. Execution plan/ledger: OVERNIGHT_PLAN_20261024.md. History: STATUS.md;
full record: COMPLETION_RECORD.md. Continuation: repository-root plan.md and CLAUDE_HANDOVER_20261024.md.
Philip requested handover and commit/push; implementation and runtime execution are stopped at verified c50.

## Demonstrated current tier

The repaired software master accepted a fresh native physical-relay block through production Tofino passthrough:
`evidence/relay_native_capture_20261024/relay_native_20261024_02/`.
Campaign `evidence/hw_campaigns/sel751_native_20261024_02` completed rc0; independent restoration passed;
recorded ownership is inactive, unsafe_restoration=false. This is NATIVE acceptance, not padded silicon qualification.

| Exchange | Request bytes | Native response bytes | Master outcome | Selected encoded response (offline) |
|---|---:|---:|---|---|
| mixed READ |25|91|OK|141, link frames[50,91]|
| integrity READ |27|134|OK|158, link frames[24,134]|
| SELECT |45|49|OK, both guarded points SUCCESS|60, link frames[28,32]|
| OPERATE |45|49|OK, both guarded points SUCCESS|60, link frames[28,32]|

All responses were observed as one TCP payload each. Historical sbo_j2's28+21 was the old switch PRE carve, not
proof of native relay packetization. No split-input reassembly/holding is needed for this observed profile.
The capture is one master-NIC observation under hash-bound verified forwarding-only production state;
pre-switch ingress packetization is inferred from that path, not independently TAP-observed.

Current connection has IPv4 IHL5, TCP SYN40 bytes / SYNACK44 bytes, and timestamp-bearing DATA/ACK32-byte
TCP headers. The old clean TCP20 candidate/model assumptions do not qualify this connection. Host global TCP
settings remain unchanged. Actual IP/MAC/address/dev identity is .1/1/dev9 to .7:20000/0/dev64;
master MAC3c:fd:fe:cc:5d:c0, relay MAC00:30:a7:02:4c:a2.

## Completion matrix

| Deliverable | State |
|---|---|
| Master complete-response validation | Independently reviewed and committed f60a3ae21;104tests+135subtests pass; prefix-only acceptance repaired |
| Native baseline READ/SBO | Physical02 block PASS; all4 planned exchanges; full capture and independent restoration retained |
| READ construction | Preserve c30 source b006752 and its original READ model evidence;91→141 and134→158 targets fixed |
| Actual SBO encoding | c49 relay_sbo1085/1085 across3 connections, including complete application, one+11 commit, partial/full ACKs, replay and timing; final-image/physical qualification pending |
| Integrated candidate | c50 compiled/reviewed within every limit; exact fin_busy193/193 across3 connections. No successor loaded on hardware |
| Exact model gate | BLOCKED: c50 has fin_busy only; all16 required on final repaired source. c49 SBO pass cannot substitute |
| FIN race | OPEN for physical recovery: c50 repairs exact busy FIN race in model193/193. Separate half-closed qualified RST defect remains unimplemented |
| Relay padded/four-arm/recovery/timing/J | NOT RUN; requires current timestamp-capable image, placement, review and complete model gate |
| Reproduction | Active reproduce.sh recognizes c30/c48/c49/c50 exact metadata; default remains historical c30. Final candidate/full gate/readout pending |

## Handover state and retained milestones

- P4/resource lane: c47 source `2191c15b94f4f83fcd78650b0bdc8f66f3029eda66253d8df85abfb48e1711fe`
  compiles successfully on pinned SDK9.13.2. Raw contexts confirm N/E/T stages0–10 and pipe1 egress0–3;
  independent review verifies parser deposit bounds, mirror guards and all ten artifact/source pins.
  The first smoke observes one SYN with an extra16-byte internal header before the exact Ethernet frame.
  E's missing provenance parsing on dev64 caused the leak; c48 repairs this path. Failed attempts remain retained.
  No stage-limit, checksum, traversal or packet assertion waiver.
- c48 adds only relay port64 to E provenance parsing, preserving OPEN processing before stripping the internal header.
  Source `902a84bf1714d15788b707b7c23b86c4abe8f66a4ba8395d1d52f0377a2eae66` compiles in96.862s;
  physical indices, PHV summaries and table placement match c47. All ten pins and mirror guards verify independently.
  Smoke01 passes15checks through SYN/SYNACK, READ91→141 and mapped ACK, then SELECT_request produces no departure.
  Installed-row diagnostics localized this SELECT drop to constant-key offsets; c49 repairs it.
- c49 repairs the installed constant-key encoding by merging repeated w0 slices into equivalent whole-word
  predicates. Source `995386583fc373e9a770b22e50194b49c246afc0e1c5789ccd099d9ae0b31bc2` compiles in96.674s;
  physical stage limits and resource use remain unchanged. All86 static tables pass the offset-layout audit.
  Diagnostic01 passes30/30, including READ141 and SELECT/OPERATE60, independent application/framing checks and ACKs.
  Dedicated relay_sbo passes1085/1085 across3 connections; fin_busy01/02 fail62/70 and remain retained.
- c50 source `1c4138ede50aaea8a662f0fba4db6b6dac2916cad46679b5d16599d34f67f43b` adds3 guarded FIN retry rows.
  Compile95.989s, all ten pins, stages/resources/mirror/static-offset review pass. Exact fin_busy193/193 completes all3
  connections.143 offline tests and10 legacy identities pass. Normal traversal unchanged; the proven collision adds
  one bounded recovery retry lap.
- Model lane: actual-SBO assertions are exercised on c49; c50 final gate remains blocked with15 drivers unexecuted.
  c51 half-closed RST admission and its model_packets regression are proposals only: no edits/tests/source/build exist.
  Keep old fixtures only as offline historical regressions. Gate fails closed for missing relay/FIN evidence.
- Campaign lane: explicit sel751 profile, permitted privileged Python application with explicit --apply,
  persistent+independent NIC/firewall restoration and frozen helper closure committed d3d2fe634;1543tests+5export checks pass. Physical four-arm/recovery await the image gate.
- Integrator: all agents stopped; source/artifacts/logs and handover notes retained for commit/push. Continue from
  root plan.md: reproduce qualified half-closed RST, implement/review c51, run all16 gates, then physical smoke/reference/recovery.

## Boundaries and corrected claims

158 is the floor of the preserved-tail prefix construction, not a global minimum: software reserialization can
reach144–154 and157 on the retained integrity response. Keep141/158; no new target selection.
Native samples and software/model encoding do not establish physical padding or same-packet original preservation.
The c30 213/415 timing failure used a stale247-byte software vector; corrected134-byte vector passes415/415 on the
same sealed bundle. This does not qualify actual two-CROB SBO. The specific c29 FIN race remains open despite old
close tests and eventual retransmission. Every planned connection must be present in the recovery verdict.
No software outstations/proxies, Vision reboot, kernel/firmware change, keep-alive masking, relaxed100us threshold,
D/J or attacker campaign, manual ownership edits, weakened restoration, IEEE audit or paper work.
