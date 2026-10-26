# c69 — offline milestone complete; fixed OPERATE hold removed (2026-10-26)

Current handover: root `CLAUDE_HANDOVER_20261026_C69.md`. The direct user instruction removes fixed J from the
active candidate, preserves Git/evidence history, and ends this task at compile/model verification. No hardware
operation or physical-event/SER implementation belongs to this task.

- Source `5efad5c85b1adeb5aaac2f24d0eadd7660abab14d52a8a8ec0325d94e4998d59`; c68 plus `--strip-operate-hold`.
- New contract `response_ready_ack_d_no_j_v3`: `gap`, `budget`, `enabled`; no J field. Common request admission
  forwards OPERATE, preserving its identity and existing response-ready ACK/D behavior. N/E source unchanged.
- SDK 9.13.2 compile PASS: p1 ingress stages9→8, SRAM47→36, TCAM51→36; p0 unchanged. Three stateful banks and
  five J-specific tables removed. Original failed parser-capacity attempt retained.
- All17 fresh required model drivers pass (6339 checks); shared v3 gate recomputes model_gate_passed,
  23 attempts including6 retained failures. All46 logs archived and independently verified. Clean checkout at
  `6b0b5efa2` reproduces exit0: all374 retained logs restored, all38 compiler files verified, model gate PASS. The
  approved offline scope is complete; no follow-on hardware work is included.
  Records/resources/log retention: `evidence/c69_no_operate_hold_20261026/`. No c69 hardware qualification.
- c68 remains the last physical candidate; its application recovery failure is preserved. Removing J does not
  establish that failure's cause or resolution. Physical-fingerprint suppression remains unproven.

## Historical checkpoints below

# Reviewed c68 repair — completed execution, 2026-10-26

Root handover: `CLAUDE_HANDOVER_20261026.md`. Direct current user decisions restore software OPERATE hold >= J
and piggyback fixture identity, keep additional latency criteria ungated, and include the two existing D20 recovery
blocks. Directive provenance and all verification are in `evidence/c68_repair_20261026/`.

- P4 and core model helpers unchanged; source 825b7e6d…b289, existing SDK 9.13.2 compile, fresh model 17/17 PASS.
- Software checks, bounded event-clear fix, retention and reproduction repairs committed as f12458308;
  missing-freeze refusal as a4aa1f330. No event-clear operation performed during these repairs.
- Fresh c68 reproduction: seven current freeze04 checks, four historical freeze03 checks, 1544 reference exchanges,
  exit 0. Historical c67: ten a4ebbecbe-pinned freeze checks, 1930 reference exchanges, exit 0. No freeze skipped.
- Existing 30 compiler artifacts/reports and 83 c68 archives retained byte-exactly. Clean published restoration has
  328 candidates; historical c67 checkout 245; local 348 includes additional local retention. Audits preserve counts.
- New D20 mixed loss: rc01_hw_c68_20261026_05 PASS (7/7),154 application responses and exact one-shot loss targets
  independently verified, restoration PASS. t3 SELECT recovered after 1021.67 ms; OPERATE SUCCESS on both points.
- New D20 full loss: rc01_hw_c68_20261026_06 FAIL overall; six of seven trials passed, all seven attempted. In t3 the exact SELECT-response
  drop was followed by SELECT OK after 1015.238 ms and OPERATE TIMEOUT on both guarded points. Block rc 1;
  independent restoration PASS. Packet replay and raw application/CRC checks preserve this failure.
- Both campaigns are finished; ownership inactive, unsafe_restoration=false; production baseline verified live.
- The older c67 TIMEOUT evidence is preserved. A new pass does not establish its cause or prove it fixed. Physical
  J and general relay compatibility remain unproven. Visible CLRT is reported data, without a precision gate.

## Historical checkpoints below

# read_complete_01 — completion record (current execution 2026-10-25)

## 2026-10-25 — c67 closeout: model PASS, smoke PASS, FIN PASS; timing FAIL, mixed-loss FAIL; J unproven

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

Closeout work in this entry: the four `test_sealed_profile.py` snapshot fixtures were repaired (test-only, both timing modes); every completed c67 model attempt (failed and passing) is archived and pinned in `evidence/c67_dependency_retention_20261025/manifest.json` (56 logs, restore verified); the reference replay above was added. The entry below is the superseded takeover-start checkpoint.

## 2026-10-25 — c67 v2 Claude takeover; model gate blocked, no physical run (superseded by the closeout above)

The active continuation is repository-root [CLAUDE_HANDOVER_20261025.md](../../../../../../../../CLAUDE_HANDOVER_20261025.md), with `plan.md` and `WORKING_NOTES.md`.
That handover owns the final model inventory and next commands. No new implementation, model or hardware launches are allowed during this handover; already active attempts
are accounted for in the root handover. Do not infer current authority or pending work from older entries below.

Selected `m12p_c67_sdk9132` source `e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1` implements
`response_ready_ack_d_v2`: matching whole-response readiness, ACK once then D=5/10/15/20ms, no exchange deadline,
retained-original retry suppression, ordinary recovery after release, and FIN/RST/epoch cleanup. J remains 2.4 ms.
The exact SDK9.13.2 bundle compiles within N/E0..10,T0..9,pipe1egress0..3; all 11 T objects are single-bank.
c52 source 8f37f702 and its measured physical evidence remain immutable; c62's deadline-based v1 is superseded.

Repeat/lifecycle exact-port, full-D and fail-stop repairs are complete; independent review PASS is retained in
[harness-final-review.md](evidence/timing_response_ready_20261025/claude_handover/harness-final-review.md) (64 focused tests and 24 production-function probes). Lifecycle02 passes 138/138 with planned=completed
9READ/18SELECT/6OPERATE. The final repeat03/control_timing02 outcomes and other passing runs are recorded only in
the root handover. Control_timing02 passed. Remaining gate blockers include missing abandon, stale repeat
dependency closures in abort01/contention02, and abort01 negative-survivor coverage missing for four required tags.
The root handover records the confirmed v2 held-negative stimulus defect: all four probes omit the genuine ACK,
record responses=0 and no commit/release, then clean up. The strict validator is correct. Future repair is limited to
ACK injection after the no-reset proof and exact surviving-response observation after full D, preserving positive abort
scenarios. Follow the root handover scope limits: no new campaigns, instrumentation or architecture. Fresh v3
recomputation remains required.

No c67 freeze or physical run exists. Ten physical configs are prepared for combined D5 smoke, 1,930 reference
exchanges and combined D20 identity-loss/graceful/RST/reconnect qualification through the existing frozen supervisor
and independent restoration. Keep 100 us; physical OPERATE J remains unproven. No new tap, software outstation,
OS changes or attacker campaign. All prior claims and failed attempts remain historical evidence.

## 2026-10-24 (night) — c52 physical SEL-751 set

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

## 2026-10-24 — Claude handover at verified c50

The current authority is `CURRENT.md` and `OVERNIGHT_PLAN_20261024.md`. Older completion claims below are historical.
c30 establishes relay READ construction and compiled-model behavior; it does not establish padded physical relay
READ/SBO delivery. Corrected c30 control_timing04 passes415/415 on the original bundle; earlier213/415 used the
unsupported software integrity247 fixture. The six READ runs remain1332/1332.

Physical native02 accepted mixed91, integrity134 and SELECT/OPERATE49 with both guarded CROBs SUCCESS. Each response
was one TCP payload on the verified production forwarding path. Historical28+21 was switch PRE carving; no split-input
machinery is being added. Current TCP is SYN40/SYNACK44/DATA32 with timestamps and master scale7. Evidence and independent
restoration are under `evidence/relay_native_capture_20261024/relay_native_20261024_02/`; supervisor COMPLETE rc0.
All89 frozen source entries are retained byte-exact beside that run. Native01 failure and restoration remain separate.

The old c29 exact busy-FIN probe fails5checks and remains retained. c49 fixes installed constant-key corruption:
strict diagnostic30/30 and relay_sbo1085/1085 across3 connections pass. Its fin_busy01/02 still fail62/70.
c50 source1c4138ede50aaea8a662f0fba4db6b6dac2916cad46679b5d16599d34f67f43b repairs the FIN/ACK owner-CAS collision:
compile95.989s, all ten pins and independent artifact/resource review pass; exact fin_busy193/193 completes all3.
143 offline tests and10 legacy identities pass. The collision adds a bounded recovery retry lap; normal traversal is unchanged.
FIN remains OPEN for physical recovery. A separate valid half-closed RST is still ignored by first_event; c51's approved
8-row proposal and runtime counterexample are NOT implemented. See repository-root plan.md and CLAUDE_HANDOVER_20261024.md.
Philip requested handover, all working notes updated and commit/push; all agents stopped with no partial implementation.
No final16-driver gate has passed and no padded candidate has been loaded. Physical smoke,772 exchanges, loss/recovery,
reconnect, held OPERATE, timing/J and independent restoration remain. Keep100us; timing failure must not suppress safe recovery.
No software outstation is used. Current push is explicitly authorized by Philip's latest instruction.

## 0a. Resource-reduced successor m12p_c26 (overnight 2026-10-22/23; resource reduction only)

m12p_c26 (P4 `21b98f5182ed…`) = m12p_c25 plus `transform_two_read_reduce` (`make_m12.py ... --two-read --reduce`),
a behavior-preserving rewrite: in the pipe-1 egress padder the block-0 CRC is checked by its residue (hash of the
block with its received CRC field == 0x993a, equivalent to c25's byte-swapped compare for every field value), the
outcome index and the IP length (181/311) are set where they are decided, and the deparser checksum conditions use
one-bit flags set by pad_mx/pad_full; in E three CRC compares on headers that no parser state extracts were removed.
Evidence: interpreter tests (the c25 padder/N/E tests rerun on c26, 74 pass incl. the CRC-guard mutation);
compiled model gate on the exact source `model_gate_passed` with every driver's count equal to c25's
(control_timing 415, policy 281, policy_boundary 206, smoke 30, packets 622, smoke_sizeoff 30, rearm 799, dup 102,
repeat 523, select_lifecycle 120, abandon 12, abort 79, contention 413, two_read_robust 163); independent code review:
no behavioral divergence on any hunk. `CANDIDATE=c26 bash reproduce.sh` passes. Not frozen; no hardware run.

Model attempts that failed and are kept: the first gate pass ran before the artifact hashes were pinned (rearm/dup
_01 refused by sealed_profile; the other eleven _01 runs bind the unpinned profile and were superseded by _02 after
pinning). control_timing _01 failed once (OPERATE_request_held_J_then_relayed at lane generation 30, then cascading
failures; 261 s vs 141 s for later runs); _02 and _03 passed 415/415 and an untouched copy of c25 passed 415/415 under
the same conditions. The _01 failure is not explained; it did not reproduce in three further runs.

Resources from the compiler reports (both SDKs identical; occupied stages are a resource count, not latency):

| control | m11_09 | c25 | c26 |
|---|---|---|---|
| N (p0 ingress): stages / PHV containers / TCAM / crossbar B | 11 / 123 / 60 / 438 | 12 / 116 / 63 / 510 | 12 / 116 / 62 / 515 |
| E (p0 egress): stages / PHV containers (bits) / TCAM / crossbar B | 12 / 140 (2472) / 30 / 304 | 12 / 129 (2384) / 33 / 257 | 12 / 121 (2272) / 31 / 264 |
| T (p1 ingress): stages | 11 | 11 | 11 |
| pipe-1 egress padder: stages / PHV containers | 0 / 21 | 7 / 79 | 4 / 78 |
| summed occupied stages | 34 | 42 | 39 |

The reduction is NOT strict on every resource: attributed crossbar bytes rose (N +5, E +7) and the padder's SRAM and
action data rose slightly (specialist scratch metrics: SRAM 12 -> 13, action data 41 -> 49 bytes). Stage counts of N, E
and T did not fall. Tested and not kept: merging the two prefix CRC tables (net neutral), a PHV pragma on E (ignored by
the compiler), folding image lengths into the profile tables (critical path back to 11). Removing the 49-byte range-READ
path from N saves PHV/crossbar/hash/TCAM but no stage and changes behavior (a model test uses it as a retransmission
control); it was not adopted. Why N sits at 12: its deepest table can go no earlier than stage 8, and the extra stage is
a placement effect of sharing pipe 0 with E; pipe 0 falls only if both N and E reach 11.

## 0b. c26 headroom and hardware (2026-10-23)

**Headroom objective (N and E highest index <= 10): NOT met.** Philip's three experiments plus combinations and one
N follow-up (`ctl_timing_01/evidence/headroom_probes_20261023/README.md`): best E is 11 occupied with highest index
still 11 (h1c2); N stays 12/11 in every build. Pipe 0 is held by N's stateful-ALU saturation in stages 7-8 (4/4) and
logical-table saturation in stage 10, not by dependency depth; pins that remove PHV-forced edges take effect but free no
stage. No probe was adopted: c26 stays the selected candidate. c26's egress PHV pins have never applied (attached to an
uninstantiated parser).

**c26 on the physical Tofino (new hardware runs, exact image 21b98f51...):**
- rc01_hw_c26_20261023_01 reference: FAILED, loss of forwarding in its first trial (off arm): every master packet after
  the handshake dropped in N (uncounted path); same signature as the m11_09 control's 10-22 failure; cause open.
- rc01_hw_c26_20261023_03 reference (rerun, N-state snapshot instrumentation): restoration verified; independent readout
  OK; every arm 65 READs (33 mixed + 32 full) + 64 SELECT + 64 OPERATE exact; padded arms 141 / 271 / 61, unpadded
  91 / 247 / 37. Timing precision FAILED (p99 |CLRT error| timing_only READ 2009, SELECT 9650, OPERATE 3216 us;
  combined 2047 / 2082 / 1972 us; limit 100 us).
- rc01_hw_c26_20261023_04 recovery: STOPPED at its first block (persistence_graceful) in the runner preflight -- the
  read-schedule endpoint was never deployed to the series tool's Vision run dir; switch not contacted; unsafe_restoration
  set; reviewed reconcile refused on both paths; flag left set. Recovery blocks NOT RUN on c26. Hardware stopped pending
  Philip.

## 0. Two-READ-target candidate m12p_c25 (Claude_Two_READ_Targets_Hardware_Directive.md)

m12p_c25 (P4 `61f9af0fa141…`, = m12p_c24's P4 with the corrected declared disposition) pads the mixed READ
(g1v2 0-15 + g30v1 0-7 in one request) 91 → 141 as link frames [50, 91] (26 G1V2 points 1024-1049, value 0, flags 0)
and the base-database full/integrity READ 247 → 271 as [24, 247] (4 points 1024-1027); SELECT/OPERATE 37 → 61
unchanged; timing and J unchanged. Range READ admitted and timed at native 49 (not padded). analog/class0 READ
requests are WITHHELD on an admitted connection (measured; a master issuing one stalls).

| workload | software (live endpoints) | compiler (9.13.1 + 9.13.2) | model (v3 gate, exact source) | physical switch |
|---|---|---|---|---|
| mixed READ 91->141 | live master via pad_read proxy, strict padding check (M1) | exit 0, N12/E12/T11 + pipe-1 egress 7 | gate passed (14 drivers incl. two_read_robust 163/163) | **size: 33/33 byte-exact at 141** (size_only + combined, campaign 02; endpoint strict check passed); **timing: FAILED, unresolved** |
| full READ 247->271 | same | same | same | **size: 32/32 byte-exact at 271**; **timing: FAILED, unresolved** |
| SELECT/OPERATE 37->61 | unchanged | same | same | 64/64 byte-exact at 61 per arm; **timing: FAILED, unresolved** |
| recovery (loss per class, persistence graceful/rst, reconnect, held OPERATE) | harness + configs, dry-runs rc 0 | -- | robust driver green | **NOT EXECUTED** (run only after timing passes) |

Timing (all evidence in STATUS.md, 2026-10-22 entries): READ/SELECT/OPERATE CLRT nearest-rank p99 2.0-3.6 ms vs the
100 us threshold in timing_only and combined. The matched m11_09 control fails the same way at the same magnitude on
today's host (shared symptom; no additional c25 effect was detected in these comparisons, which does not show none
exists). Localization (corrected 2026-10-22, `evidence/timing_reanalysis_20261022/`): the earlier
"receive-idle-dependent delay" label is **withdrawn**. Its metric measured receive idleness up to each packet's arrival,
which includes the transit being explained (circular): every c25 off-arm OPERATE request was sent within 221 us of the
previous receive, yet the old metric split them into 36 "busy" (median 58 us) and 27 "idle" (median 1,995 us). With
silence measured before transmit, off-arm request transit through the switch (Vision NIC out -> Vision NIC in, one host
software clock, microsecond pcap resolution, DNP3-flow capture filter) has medians of 1.0-1.9 ms at every prior silence
from 0.25 ms to > 25 ms, and p90 ~2.1 ms even in the < 0.5 ms bucket; the three m11_09 controls show the same pattern.
What remains is an intermittent ~1-2 ms transit delay on the Vision -> switch -> Vision path, independent of prior
receive silence, cause not located. The ICMP idle-gap probe does not isolate it either (echo after >= 200 ms idle: median
RTT 2.67 ms; echo ~100 us behind it: 3.41 ms; both include the relay's own reply time). The tested RX-coalescing and
CPU-latency interventions did not remove the delay. Tofino port configuration and
counters for the Vision and relay ports are unchanged from the good 2026-10-18 run. The only identified change on that
path since the good run is Vision's kernel (6.8.0-146 -> 6.8.0-147 at the 2026-10-19 reboot; no i40e entry in its
changelog); relevance not shown. **Distinguishing next measurements, each awaiting Philip's authorization:** (a) NIC
hardware timestamps on Vision (a reversible NIC setting change) for ~200 UDP probes through the switch, half isolated and
half sent ~30 us after a receive, to place the delay in host TX, NIC-to-NIC, or host RX (stop at 200 probes, or at once
if `ethtool -T` shows no hardware stamping); (b) boot Vision once into the installed 6.8.0-146, re-run the m11_09
control and the c25 combined arm, return to 6.8.0-147 and re-run the control there (to separate a kernel effect from a
reboot-induced reset). Thresholds, mechanism and
evaluation conditions are unchanged; no background traffic was used.

Hardware incidents, all recorded with evidence: campaign 01 fixture gap (separate-ACK delay missed the new READ
lengths; fixed 4233d533a); control freeze not rewritten after that fix (refused pre-hardware; reconcile extended,
reviewed); RX-coalescing restore rejected by i40e (host repaired; reviewed repair path; runner result stays failed); one
m11_09 control size_only trial lost forwarding (campaign 04; not reproduced in campaign 06; unexplained).

Limitations specific to this candidate: the READ-response TCP checksum on the shallow path is a WAIVER (0xffeb written,
not computed); responses are validated first block only; bare-RST behaviour is open (two model runs disagree); no
general READ-length support, no whole-response switch validation, no indistinguishability or conformance claim;
padding is visible to the master (declared, strictly checked).

Reproduce offline: `bash reproduce.sh` (CANDIDATE=c25 default); readout:
`bash reproduce.sh --readout evidence/hw_blocks/rc01_hw_c25_20261022_02_reference hw/config/rc01_m12p_c25_reference.json`.


**Delivery candidate: m12p_c20** (source sha `1e94c31d80e6…`), the faithful segmented READ 377→401 build.
**m12p_c12** (source sha `742089cbe762…`) is preserved unchanged as the reproducible checkpoint.

**Status by tier: software, encoding, both-SDK placement, and the compiled-model gate are COMPLETE and
reproducible for c20. The physical-switch tier for c20 is PENDING (not yet run) — it is NOT blocked: the
testbed is idle and restored (`unsafe_restoration=false`, no active unit).** Sizing and timing together on
silicon for the segmented class have NOT been shown. The earlier b08 block-1 silicon result is recorded as
history in §3.

## 1. Tiers reached (c20)

| tier | result |
|---|---|
| Source reasoning | Policy rule v3 (Ditto-inspired, aggregate-response layer): targets **141 / 247 / 401**, 10.93 % added vs 19.04 % for the 163/269/399 comparator (`policy/TARGET_POLICY.md`). Ditto's guarantee does not transfer; low overhead is not evidence of effective obfuscation. |
| Encoding tests | Handoff tests 51/51; policy coverage 25/25 over 10,243 profile cases; range constants byte-exact vs `pad_read` on 512 samples (`vectors/constants.json`, byte-stable at `6f819e7e…`); **segmented shape byte-exact vs `pad_read` on 512 samples** (`vectors/constants_segmented.json`; `prefix_link_crc_delta` 0x79bf invariant across samples); new interpreter tests `test_segmented_pad` (7) + `test_segmented_classifier` (2) + `test_segmented_mapper` (2). |
| Live software endpoints | Pinned OpenDNP3 4648fcb (binary `ea734720…`): range 49→141, analog/class0/integrity at target, large 377→401, 16+16 each, IIN 0x9000, no errors (`evidence/m3_live_policy_01`). Endpoint acceptance, not an IEEE 1815 conformance claim. |
| Compiler placement | m12p_c20 source `1e94c31d80e6…`: SDK **9.13.1 and 9.13.2 both exit 0**; **N 12 / E 12 / T 11** stages + the **pipe-1 egress padder, 7 stages** (same profile as c12; m11_09 is N 11 / E 12 / T 11). The segmented padder lives in pipe-1 egress, off the pipe-0 MAU budget, so the p0 wall feared in the c13/c15 probes did not materialize. The c16/c17 deparser nested-conditional wall was diagnosed and fixed with separate top-level validity-guarded checksums. |
| Compiled model (baseline shapes) | **v3 gate: `model_gate_passed`, blocked_reasons [], all 13 drivers, 0 failures** (smoke, packets, rearm 799/799, dup 102/102, repeat, select_lifecycle, control_timing, contention, abort, abandon, policy, policy_boundary, smoke_sizeoff). Committed `33e21fd07`; **recomputes `model_gate_passed` on a fresh detached worktree** after `restore_retained_logs.py`. This gate exercises the range/analog/class0/integrity shapes and the R→S→O→R timing and confirms c20 does not regress; `rearm`/`dup` exercise the two-child child-bank mechanism. None of the 13 drivers sends the 292+85 segmented wire shape. |
| Compiled model (segmented) | **PARTIAL — measured, seg0 only.** A dedicated driver (`seg61_02/model_segmented.py`, run `model_segmented_m12p_c20_01`, 10/10) injects a real 377-B two-segment integrity response through the compiled c20 model. **seg0 (native 292 B, ip.len 332) is admitted and padded to the exact 316-B first image at the wire-start TCP seq** (via E `out_translate` + the pipe-1 padder, `p1_outcome.p1_padded`) — the segmented padder fires correctly. **seg1 (85 B, ip.len 125, FIN continuation) is NOT forwarded:** it is admitted by N's parser (`read_response_fb`, kind 11) but dropped in N's pipe-0 ingress control before egress (0 egress frames, no E outcome code, no `p1_outcome`/`count_busy`/T-outcome bump). **The end-to-end 401 image is therefore NOT delivered by c20 — it emits only the padded first segment.** See §3a. |
| Physical switch (c20) | **PENDING — not yet run** and must not run for the segmented class until seg1 forwarding is fixed (a seg0-only build cannot deliver the 401 image on silicon). Testbed idle and restored. No c20 silicon result exists; none is claimed. |

## 2. Tier boundaries (honest)

- **Proven (source + encoding + placement):** the segmented construction's bytes (prefix frame, per-frame
  block-0 rewrite + recomputed CRCs, continuation renumbering) are byte-exact against the reference padder, and
  the integrated source places on both SDKs at the stage budget above.
- **Model-measured, seg0 only:** the segmented padder forwards and pads the **first** segment correctly on the
  compiled model (seg0 → 316 B at the wire start), but the **second-segment continuation is dropped in N ingress**
  (§3a), so the forward two-frame single-commit is **non-functional**, not merely unexercised, in c20. The deparser
  **IP/TCP checksum externs** on the seg0 path are compile-placed and seg0's 316-B bytes match the reference exactly,
  but the externs' wire-checksum correctness is not offline-checkable (same caveat as the range padder).
- **Content-blind gating:** seg1 admission keys on `dl.len==0x46 && FIN`, not on segment content.
- **Hardware:** segmented READ on silicon — size, first-frame vs complete-response timing, OPERATE hold J, ACK
  mapping, and recovery — is **pending**, not shown.

## 3a. Open finding: the segmented second segment is not forwarded by c20 (model-measured)

The driver `seg61_02/model_segmented.py` and the counter localization (`SEG_DIAG` run) establish, on the exact
c20 image:

- **seg0 works.** The FIR response segment (native 292 B, ip.len 332) is admitted, the pipe-1 egress padder
  prepends the 24-B frame and rewrites block 0, and the switch emits the exact 316-B first image at the wire-start
  TCP seq. Counters: E `TRANSLATE` +1, `p1_outcome.p1_padded` +1.
- **seg1 does not.** The FIN continuation (85 B, ip.len 125) is admitted by N's parser (`read_response_fb`,
  `packet_kind` 11 — the parser already carries the 332/125 entries from `segmented_classifier`) but is **dropped
  in N's pipe-0 ingress control before egress**: 0 egress frames, and across seg1 **no** counter moves — not E's
  `outcome` (no drop code either), not `p1_outcome`, not N's `count_busy`, not the T outcomes register. It is a
  silent read-lane drop, consistent with seg1 arriving after seg0 has consumed the outstanding read, with no
  continuation state to forward it.
- **Consequence.** c20 delivers only the padded first segment; the end-to-end two-segment 401 image is not
  delivered. The `--segmented-full` build applies `segmented_pad_pipe1` + `segmented_classifier` + `segmented_t`;
  the missing piece is **N read-lane continuation handling** — recognizing seg1 as the second segment of one
  in-progress response and forwarding it (the plan's "one commit at segment 1 with the continuation mapped by
  `out_translate`/`wend_fwd`"). `transform_segmented_n` only adds parser admission (already effectively present);
  it does not supply the N-control continuation, and its probe anchors no longer match the full+passthrough base.
- **Diagnosed, not fixed.** The fix is a non-trivial N-control change and is the next scoped step. The hardware
  campaign for the segmented class must wait for it — a seg0-only build cannot deliver the 401 image on silicon.
  The range/analog/class0/integrity classes are unaffected (single-frame; seg0-style path).

## 3. Physical-switch history (b08, 2026-10-21)

Recorded for provenance; superseded as the delivery tier by the pending c20 hardware run.

- Campaign `rc01_hw_b08_20261021_01` block 1 (four-arm reference) on m12p_b08: `off` and `timing_only` READ/SBO
  exactly native (65/65 READs); `size_only` SELECT/OPERATE 37→61 on all 128 responses, +16.75 % wire octets
  (SBO only), **READ 49 (padder not enabled)**. Root cause: the baseline installer `plan()` discarded the
  `p1.x_Egress.p1_conn` enable row; fixed as `plan_with_p1`, test red→green, review-confirmed (`232e26c57`).
- A later control config error set `unsafe_restoration` on a step that **never reached hardware**; the reviewed
  reconcile was later extended for that case and the flag cleared on fresh `restore_verify` evidence. The flag is
  now clear (§ status).

## 4. Open timing finding (not attributed to any build)

`timing_only` READ CLRT precision on today's Vision host fails the gate for **m11_09 as well as b08** (control
block `rc01_hw_b08_20261021_03`): m11_09 today p99 abs CLRT error 3,551 µs / median 1,344 (18 Oct: 63 / 5). The
`off` arm already differs (request transit median ≈ 1.1 ms vs ≈ 98 µs on 18 Oct). This **rules out a build-only
cause**; it does **not** identify a single cause and does **not** exclude an additional candidate-specific
component on top of the shared degradation. Vision was rebooted 2026-10-19, now runs docker bridges with adaptive
RX/TX coalescing; no latency tuning is recorded in the repo and Vision sudo needs a password, so nothing was
changed. Hardware timing **precision** is gated by this host state for every build equally until the pre-reboot
latency is restored (Philip's decision). Size / delivery / recovery hardware checks are not affected.

## 5. Coverage: software vs hardware

Software + compiled model cover the full declared profile for the **single-frame** classes: range 49→141, analog
141 and class0/integrity 247 at target (pass-through). The **377→401 segmented class** is implemented in P4 and
its construction is byte-exact at the interpreter tier, but on the compiled model it is **seg0-only**: the first
segment pads and forwards correctly, the second-segment continuation is dropped in N ingress (§3a), so the
end-to-end 401 is not delivered. Per-class recovery covers the single-frame classes (analog 141; one 247-B loss
selector `read_resp_247`, since class0 and integrity are byte-indistinguishable at 247 B — length-level claim
only); **segmented recovery is NOT_EXERCISED** (its forwarding is not yet functional). **Hardware coverage for c20
is pending** for all classes; the segmented class is additionally blocked at the model tier by §3a.

## 6. Residual limitations

C3: the SBO-61 image's pre-start region is withheld, not stale-dropped (a per-image key costs a 13th stage).
`ina_img_t` is not keyed on direction. E's CRC defence-in-depth is reduced (N validates all CRCs; pipe 1 checks
block 0; the segmented path's block-0 CRCs are recomputed on chip). T timing was calibrated on shorter frames;
segmented frames are longer, so first-frame vs complete-response timing must be measured separately on hardware.
The packet-boundary checker binds lengths as a set, not per kind. The model gate cannot see control-plane
installer behaviour (the b08 defect in §3).

Two findings from the adversarial review of commit `33e21fd07` (both honest-tier, neither a defect; the code is
faithful, byte-exact, both-SDK, model-gate-green):

- **Stateless seg1 renumber (cross-frame scope assumption).** `fix_s1` applies `tcp.seq += 24` and the transport
  renumber to any `(dl.len==0x46 && FIN)` frame on a `p1_conn` connection, with no per-flow state confirming this
  flow's seg0 (FIR) was actually prefixed. This is correct **only** because the obfuscated connection carries
  exactly the 292+85 integrity/class0 segmented shape; a different multi-frame response ending in a 70-byte FIN
  frame would be mis-renumbered and desynchronize the master's TCP stream. No guard is added (a per-flow register
  costs stages; the connection is single-shape by scope). Documented at the code site (`make_m12.py`, the seg0/seg1
  gate comment). **Hardware bring-up of the segmented class must exercise a mixed-response flow before this
  assumption is relied on.**
- **Segmented deparser checksum has no offline correctness coverage.** Its correctness rests on analogy to the
  range padder (every per-segment IP/TCP checksum varies across samples and is derived on chip). The seg0 `+24`
  pseudo-header growth and the seg1 `tcp.seq += 24` are the two places a wrong incremental checksum would first
  surface. **The hardware gate for the segmented class must verify master-side TCP/IP checksum acceptance;** it is
  not provable offline.

## 7. Corrections recorded

The 2026-10-19 reverify ran with counter-statistics stripping added after the original failure (`291e8cb30`);
I had told Philip it passed with unchanged rules. The hardware readout first paired captures in the wrong
direction (out.pcap is what Vision sent); fixed before any number here was taken.

## 8. Reproduce

`CANDIDATE=c20 bash reproduce.sh` (offline: software tests, policy, constants + segmented constants, P4
regeneration to `1e94c31d80e6…`, model gate, freeze) and `bash reproduce.sh --readout` for the hardware readout.
`bash reproduce.sh` with no override still regenerates and gates **c12** (the preserved checkpoint, source
`742089cbe762…`). The c20 model gate is recomputed on a fresh worktree via `restore_retained_logs.py` then
`model_summary.py evidence/m12p_c20 --v3 --enforce`.

## 9. SEL-751 relay READ-side deliverable (m12p_c30), 2026-10-24

The relay is the outstation (SEL-751, 192.168.10.7:20000, DNP3 addr 0; master addr 1). READ construction and compiled-model checks are demonstrated; padded physical relay READ/SBO delivery remains pending.

- **Baseline (tier 3):** `relay_native_baseline.py` drove READ-only mixed+integrity polls .1->.7 through the
  switch; `evidence/relay_native_20261024/` holds the decoded natives. Mixed answers 91 B (G1V2 0..15 + G30V1
  0..7), integrity 134 B (G1V2 0..15 + G10V2 0..31 + G30V4 0..20). The software 247 B integrity database does
  not apply to the relay.
- **Shapes:** `vectors/derive_two_read_relay.py` -> `constants_two_read_relay.json`. mixed 91->141 (+50, 26
  points), integrity 134->158 (+24, 4 points; 158 is the prefix floor 134+24). construct == pad_read proven on
  512 varied samples/shape AND the 3 real captures; every constant invariant. 141/158 no longer provisional.
- **Candidate m12p_c30:** `make_m12.py --policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry
  --read-handshake --headroom --relay` (source sha b006752236a7). bf-p4c 9.13.2 exit 0; placement p0 11/11,
  p1 11/4 (identical to c29). Sealed via `efficiency_candidates.py <bundle> --record-artifacts`
  (sealed_profile.describe -> sealed True).
- **Two defects found by the executing model (not visible at compile/seal time):**
  1. Model vectors were the software tier: `two_read_templates.json` integrity native is 247 B (mixed 91 B is
     identical across tiers, so it masked the gap). Added `make_two_read_templates_relay.py` +
     `two_read_templates_relay.json` from the real captures; `seg61_02/model_policy.py::_two_templates()` selects
     the set matching the build's `read_policy_expect.SHAPES` and fails loudly on a tier mismatch.
  2. Generator `two_read.py::transform_two_read_reduce` folded the padded-image IP total length to a hardcoded
     `16w311` (= software native 287+24); relay needs 174+24 = 198. The model emitted a correct 158-B payload
     under a software 271-B IP length (4 bytes off: ip.len + checksum). Fixed to `native_ip_len + added` per
     shape (mixed 181 unchanged, full 311 software / 198 relay).
- **Model gate (READ/size, the pinned sealed bundle):** two_read_robust 163/163, packets 622/622, policy
  281/281, policy_boundary 206/206, smoke 30/30, smoke_sizeoff 30/30 = 1332/1332. Software regression: c29
  two_read_robust 163/163; generator identity 10/10 byte-identical; m12_fullsize 74 + 56 subtests.
- **Reproducible:** relay vectors regenerate byte-identically; c30 source regenerates to b006752236a7.
- **Open at the c30 milestone; now in progress under the approved SEL-751 task:** control-coupled model drivers
  (dup, rearm, select_lifecycle, abort, abandon, contention, repeat, control_timing), the SBO image derivation
  (correction #3, try 60 first), and the hardware four-arm + recovery + timing blocks on the SEL-751. c30 remains the READ-shaped reference. The active reproduce.sh now recognizes c30_sdk9132 with its exact flags/hash; current dependency changes must not be represented as historical v3 qualification. Integrated relay qualification remains pending.
