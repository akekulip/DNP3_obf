# Claude handover — SEL-751, 2026-10-24

## Update (night): c52 physical set executed

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
  fresh connection arrives after the readiness bound (about 33 ms). Those responses took 38-98 ms, against
  about 30 ms on c51, and c51 block 04 shows the same counters. Rows c52 changed cannot match READ data (flags
  0x18). The cause is unobserved, because nothing captures the relay side. No threshold was relaxed.
- **FIN recovery: OPEN.** The reconnect block did not pass as a block.

Details: repository-root WORKING_NOTES.md (top).

## Update (evening): c51 executed

c51 (source 3fe70879; c50 + 8 qualified half-closed RST first_event rows) passed the enforced 16-driver model gate
(model_gate_passed) and ran on the physical SEL-751 through the frozen wrapper: smoke rc0 (91->141, 134->158);
four-arm reference rc0 772/772 exchanges with exact native/padded sizes; timing arms FAIL the 100 us criterion
(p99 complete CLRT ~2.6-4.5 ms) and OPERATE J is unproven; loss_full rc0 7/7; loss_mixed rc1 with 4/7 presets
(dropped SELECT response -> relay SBO TIMEOUT, safe); persistence_graceful rc2 because Vision 10.10.54.166 became
unreachable mid-block -> unsafe_restoration=true, all hardware stopped; persistence_rst, reconnect and held OPERATE
not run. FIN/RST physical recovery remains OPEN. Two hardware-path defects were fixed on the way (installer E
provenance check; logical vs wire-order READ link addresses, located with a new opt-in MAU snapshot). Details:
repository-root WORKING_NOTES.md (top) and the commits from 76888456a to the latest.


Philip requested handover now, updated notes/plan, and commit/push. All implementation agents stopped cleanly.
Read [plan.md](plan.md), then the linked source/evidence below. Continue the original physical-relay objective;
do not restart completed master, native-baseline, sizing or compiler investigations.

## Exact handover state

- Last compiled/tested image: **c50**, source
  `1c4138ede50aaea8a662f0fba4db6b6dac2916cad46679b5d16599d34f67f43b`.
- Exact busy-FIN model: **193/193, all3 planned connections complete**. This is model proof; FIN remains open for physical recovery.
- c49 actual-SBO model: **1085/1085, all3 connections**; full application, framing, one+11 commit, partial/full ACKs,
  retransmission, timing and ordinary close. Earlier image evidence cannot qualify final source.
- c49 installed-row diagnostic: **30/30 packet checks**,86 operand values+8 masks exact SW/HW/context agreement.
- Current generator:143 offline tests and10 legacy identities pass. c50 compile95.989s, SDK9.13.2, all ten pins
  recorded before runtime; N/E/T stages0..10 and pipe1 egress0..3. Independent source/compiled reviews approve.
- **No final16-driver gate, no candidate physical padding, no four-arm/recovery/timing/J qualification yet.**
- **c51 does not exist.** Its approved eight-row half-closed-RST solution and required regression are in plan.md.
  No RST helper method, diagnostic wrapper, new tests, generated source or compile has begun.
- No model/compiler/hardware campaign remains running from this session. Last locally read ownership record:
  active=false, unsafe_restoration=false; recheck before hardware.

## Read first

1. [Assessment and overnight command](Claude_dd7741152_Verified_Assessment_and_Overnight_Command.md).
2. [Current continuation plan and possible solutions](plan.md).
3. [Working notes](WORKING_NOTES.md).
4. [Current status](defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/CURRENT.md).
5. [Original approved task plan/ledger](defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/OVERNIGHT_PLAN_20261024.md).
6. [Full completion record](defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/COMPLETION_RECORD.md)
   and [status history](defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/STATUS.md).
7. [Active code map](defense4/timing/case4_architecture/ACTIVE_CODE_MAP.md) and [architecture plan](defense4/timing/case4_architecture/PLAN.md).

## Files and checkpoints

Use path variables in plan.md. Active generator is `$STAGE/m12_fullsize/make_m12.py` plus `m12gen/relay_sbo.py`
and `relay_ts.py`; model drivers are `$CTL/model_*.py` and `$STAGE/seg61_02/model_*.py`.

| Evidence under `$CTL/evidence/` | Meaning |
|---|---|
| `m12p_c49_sdk9132` | Immutable source/profile/compiled bundle; canonical keys correct installed controls |
| `model_profile_diagnostic_m12p_c49_sdk9132_01` | Correct installed SW/HW rows and strict30/30 |
| `model_relay_sbo_m12p_c49_sdk9132_01` |1085/1085; all3 connections |
| `model_fin_busy_m12p_c49_sdk9132_01` and `_02` |62/70 failures preserved; primary FIN owner-CAS collision;02 also isolates qualified half-closed RST rejection |
| `m12p_c50_sdk9132` | Current verified source, exact9.13.2 artifacts, resources and generated preparatory configs |
| `model_fin_busy_m12p_c50_sdk9132_01` |193/193; all3 busy-FIN closes/reconnects complete |

Generator preimages are under each c49/c50 candidate's `generator_source/m12gen/relay_sbo.py` and match its inputs.
c49 preimage SHA`df116b0458cacd0ed1821fd71a96d6b925e133a97861b6d0ac69e911576e3355`;
c50/current SHA`6ea643a87ae6acec4d264939e57748de3aaf4f1b023dae18f3cd37ad35e99a99`.
Current model_fin_busy.py SHA`1c9be518e5f7569013548a12a1838a61493da05fd1ec73b5a18460bfd94f8459`
includes correct post-FIN cleanup SEQ and per-connection coordinates. Its assertions/three core attempts are unchanged.
model_packets.py remains pre-RST-extension SHA`5385c479fe33bb28800708bda9fbc036cea3ebb35c266592ab260c3c6de116dc`.

Model logs/source closures: `$RC/evidence/{c30,c49,c50}_dependency_retention_20261024/manifest.json`.
Run `python3 $RC/restore_retained_logs.py` before replay; it validates compressed and original hashes and never
overwrites an existing log. Large raw originals remain local and are excluded from commits in favor of restorable xz.

Physical native02: `$RC/evidence/relay_native_capture_20261024/relay_native_20261024_02/`; supervisor
`$RC/evidence/hw_campaigns/sel751_native_20261024_02`. Complete native91/134/49/49 pass, restoration pass,
89 exact frozen source entries retained. Native01 failure remains separate.
Packetization is one master-NIC observation under hash-bound forwarding-only state; ingress packetization is
inferred from that path, not an independent TAP. Whole49 is supported; no speculative split-input retainer exists.

## Do not rediscover these causes

1. c47 leaked16-byte TEV to relay64; E parser omitted64. c48 adds64, preserving OPEN before stripping.
2. c48 strict SELECT missed despite source-interpreter hit. Both installed tables had shifted second-CROB constants.
   Inspected local9.13.1 loader offset code predicts every observed9.13.2 readback value when repeated slices share
   a logical key position. c49 whole-word predicates avoid it without SDK changes. Do not claim inspection of9.13.2
   loader source. All86 current static tables passed offset safety review.
3. c29 half-close cleared retry_epoch; selected profile now preserves it until qualified terminal/reset.
4. c49 then revealed a second FIN failure: concurrent pure ACK advanced owner0101→0109 while FIN expected010b;
   reset_boundary default-aborted the same-generation FIN. c50 adds3 guarded bounded restart rows, recomputes
   from fresh owner, and passes193/193. Collision adds a recovery retry lap; normal traversal is unchanged.
5. Qualified post-FIN RST is still omitted from first_event for half-closed owner109. **This is the next repair.**
   See precise masks, alternatives, stale guards and runtime counterexample instructions in plan.md.

## Resources and physical boundaries

c50 raw totals: P0 SRAM182/TCAM102/crossbar866bytes/SALU24; P1 SRAM61/TCAM63/crossbar403bytes/SALU13.
PHV containers/capacity: N107/2360bits,E139/2568,T60/1344,P1E81/1544. Allocated hash-bit coordinates by
(stage,function,bit):1077/178; hash distribution slots23/5 for P0/P1. Pipe1 egress costs are included in
shared/unattributed totals; its zero attributed category does not mean zero physical cost. Raw reports are retained.

No padded hardware loaded; only native production baseline ran. After final model gate, use existing guarded
campaign and independent restores for smoke,772-exchange reference, both losses, graceful/reset persistence,
reconnect/all3 and held OPERATE. Timing failure must not suppress safely restorable recovery checks.
Native readiness/switch residence/J need genuine anchors or an explicit unproven label; do not infer kernel cause
or same-packet latency from independent baseline/master samples.

## Git and next action

Work is on main. Session commits before final handover include f60a3ae21,6aba47221,d3d2fe634,d1dd65c1a,
7215701b1,b44cd6ede,13a845b4d,37874c473; final handover commits follow them. Verify `git log -1` after pull.
Preserve pre-existing local deletions `BRANCH_PRUNE_20260915.txt` and `DNP3_Implementation_Directive_492013014.md`
and unrelated historical untracked material; they are outside this task. Never blanket-add or reset the workspace.

Start with the focused half-closed-RST regression on retained c50, implement/review c51 without overwriting c50,
then qualify one final image through all16 model gates and the authorized physical relay campaign. The handover commits retain all task changes
and recorded evidence; verify remote main against the final local HEAD. No further implementation was started.
