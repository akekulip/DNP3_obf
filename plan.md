# Status update (2026-10-24 night, Claude)

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

Step 3 (physical set) has now run in full on c52; the remaining open items are the fallback class, FIN recovery
(reconnect block) and the timing/J dimensions.

# Status update (2026-10-24 evening, Claude)

c51 (source 3fe70879; c50 + 8 qualified half-closed RST first_event rows) passed the enforced 16-driver model gate
(model_gate_passed) and ran on the physical SEL-751 through the frozen wrapper: smoke rc0 (91->141, 134->158);
four-arm reference rc0 772/772 exchanges with exact native/padded sizes; timing arms FAIL the 100 us criterion
(p99 complete CLRT ~2.6-4.5 ms) and OPERATE J is unproven; loss_full rc0 7/7; loss_mixed rc1 with 4/7 presets
(dropped SELECT response -> relay SBO TIMEOUT, safe); persistence_graceful rc2 because Vision 10.10.54.166 became
unreachable mid-block -> unsafe_restoration=true, all hardware stopped; persistence_rst, reconnect and held OPERATE
not run. FIN/RST physical recovery remains OPEN. Two hardware-path defects were fixed on the way (installer E
provenance check; logical vs wire-order READ link addresses, located with a new opt-in MAU snapshot). Details:
repository-root WORKING_NOTES.md (top) and the commits from 76888456a to the latest.

Steps 1-4 below are DONE (c51 = the final candidate). Step 3 is PARTIAL: smoke, reference, loss_full done;
loss_mixed 4/7; persistence_graceful aborted by the Vision outage; persistence_rst, reconnect, held OPERATE pending.

# SEL-751 continuation plan for Claude — 2026-10-24

This is the current continuation plan. Read `CLAUDE_HANDOVER_20261024.md` first.
Philip requested handover, updated notes and plans, and commit/push on 2026-10-24; execution stopped at c50.
Earlier “no push” directions were superseded for this handover. There is no running candidate model or hardware campaign.

## Paths and authority

```sh
ARCH=defense4/timing/case4_architecture
STAGE=$ARCH/integration/core/response_only_rearm/stage_experiments
CTL=$STAGE/ctl_timing_01
RC=$STAGE/read_complete_01
HW=$ARCH/integration/evidence/rearm_01/hw
```

Read the repository-root `Claude_dd7741152_Verified_Assessment_and_Overnight_Command.md`, `CLAUDE.md`,
`WORKING_NOTES.md`, `$ARCH/ACTIVE_CODE_MAP.md`, and `$RC/{CURRENT,STATUS,COMPLETION_RECORD,OVERNIGHT_PLAN_20261024}.md`.
The newer user packetization corrections and this handover supersede conflicting historical checkpoints.

Physical SEL-751 is the only outstation. Guarded READ/SELECT/OPERATE and necessary candidate loading are already
authorized by the assessment and “Implement the plan”; use the existing frozen wrapper and independent restoration.
No software outstation/proxy/fallback. Preserve N/E/T, timing blockers/queues, ACK normalization and J; preserve
READ91→141[50,91], READ134→158[24,134], SBO49→60[28,32], and all32 original control application bytes.
N/E highest stage index≤10; T≤11 occupied; pipe1 egress≤4. Keep100µs. Guarded command only: points{1,3},
code1/count1/on200ms/off0, completed successful SELECT before OPERATE. No reboot, kernel/firmware/global TCP change,
keepalive masking, raw-TCP-master workaround, main D/J/attacker campaign, manual ownership edit, weaker restore,
new target-size search, IEEE audit or paper work. Author/committer: `akekulip <akekulip@gmail.com>`.

## Completed and reusable

| Work | Evidence / limit |
|---|---|
| Complete-response master | f60a3ae21;104tests/135subtests, independently reviewed; prefix-only acceptance and silent bind fallback repaired |
| Physical native baseline | `$RC/evidence/relay_native_capture_20261024/relay_native_20261024_02`; all4 exchanges pass, both CROBs SUCCESS, restore verified |
| Packetization | Native responses are whole91/134/49/49 on verified production forwarding path; historical28+21 was switch PRE carving |
| Current TCP | IPv4 IHL5; SYN40/SYNACK44/DATA+ACK32 with timestamps; MSS1460, master WS7/relay WS0; global host TCP settings unchanged |
| c30 preservation | Original READ construction/models retained; six READ drivers1332/1332; corrected control_timing04=415/415; old213/415 used stale247-byte fixture |
| Real-relay campaign | Explicit sel751 profile; guarded master,8 config types, independent offload/firewall restore and passive same-port readiness guard;1552 checks passed |
| c47→c48 | Successful stage fit; repaired16-byte provenance leakage to dev64 by E parsing, preserving OPEN processing |
| c48→c49 | Repaired corrupt constant-table tail fields by canonical whole-word ternary keys; unchanged predicates, no SDK patch |
| c49 model | Installed SW/HW rows:86 values+8 masks match; strict diagnostic30/30; relay_sbo1085/1085 across all3 connections |
| c50 model | Exact busy-FIN regression193/193 across all3 connections;143 offline generator tests and legacy10 identities pass |
| Resource fit | c50 SDK9.13.2 compile95.989s; N/E/T0..10, pipe1 egress0..3; ten artifact pins recorded before model; independent review approved |

These are distinct image-specific proofs. c49 SBO results do not replace c50/final-image gates. No padded successor
has been loaded on physical hardware; no final16-driver gate has passed. FIN remains open until physical recovery qualifies.

## 1. Reproduce and repair the remaining half-closed RST defect

**Current c50**: `$CTL/evidence/m12p_c50_sdk9132`, source
`1c4138ede50aaea8a662f0fba4db6b6dac2916cad46679b5d16599d34f67f43b`.
Do not recompile or overwrite it. c51 is a proposal only: no edits, tests, generated source or compile exist.

Failure: `$CTL/evidence/model_fin_busy_m12p_c49_sdk9132_02`.
After master FIN and relay ACK, owner=`0x01090001`; valid master RSTACK has SEQ70234(c+1), wire ACK90540→native90422.
`sequence_guard` yields `seq_fin`5; `close_phase_t` qualifies desired`0x200`; **first_event misses** because its
half-close rows cover ACK16/FIN17 but omit RST4/RSTACK20. The reset is ignored and subsequent SYNs remain blocked.
This is separate from c50's repaired FIN/ACK CAS collision. Corrected cleanup SEQ alone does not solve it.

### Preferred bounded solution (approved proposal, not implemented)

In the selected relay transform, add **eight first_event const rows only**, size176→184; retain its key/actions/state.
Require kind4, both direction encodings1/2, sequence_valid`3w1 &&& 3w3` (prove the field is exactly3 bits, so{1,5}),
and flags`8w4 &&& 8w0xef` (exactlyRST4/RSTACK20). Four disjoint owner bands, low16 generation wildcard:

```text
0x01010000 &&& 0xfff10000
0x01020000 &&& 0xfff30000
0x01040000 &&& 0xfff70000
0x01080000 &&& 0xffff0000
```

They cover exactly phase101..10f and exclude100/200/normal phases. Reuse `first_close()`.
Prove source dominance: work-free stage0 calls `close_phase_t` before first_event, and these flags qualify desired200.
Retain sequence, tuple, epoch, generation, work/CAS and retry guards. Never allow arbitrary RST across all phases.

Tests before implementation: exact109 failure, both directions/all15 phases/flags4+20, exhaustive3-bit mask and
65536-phase band coverage, invalid coordinates/sequence values, stale epoch/generation, failed CAS, retirement200
and same-tuple reconnect. Assert emitted changes are only the eight rows/size; legacy10 identities stay exact.

Runtime counterexample plan: extend existing `seg61_02/model_packets.py` with one sel751-only
`PacketGate.half_closed_rst()` case, called at the end of the full required packets driver. Genuine handshake+READ,
master FIN, relay ACK→owner109; lock existing work cell phase1, inject valid RST(c+1,w), require busy[2] anchor,
unlock phase4; require exact forwarding, no stale/exhaust, retirement and fresh handshake+READ. Record both reset
and SYN failures on c50; never count dependent READ success after a failed SYN. Keep fin_busy's3 core attempts unchanged.
A retained c50 diagnostic wrapper may invoke only that method for the counterexample through existing launch_model/
record_closure. It is not a qualification-driver substitute. **Do not add an unchecked partial-case environment selector.**
Neither the method nor diagnostic wrapper has been written.

Alternatives if review rejects the masks: use30 explicit phase/direction rows, retaining the same guards and validating
resource cost; or add an explicit desired200 guard/key only if source dominance cannot be proved, then recompile and
review its PHV/stage cost. Avoid a new architecture, broad RST admission, buffer/ACK fabrication or SDK changes.

## 2. Freeze one final source and complete its model gate

Generate a new immutable candidate after coherent changes:

```sh
python3 $STAGE/m12_fullsize/make_m12.py $CTL/evidence/m12p_c51_sdk9132 \
 --policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry \
 --read-handshake --headroom --relay --relay-sbo --relay-ts
python3 $ARCH/build.py $CTL/evidence/m12p_c51_sdk9132/response_only.p4 \
 $CTL/evidence/m12p_c51_sdk9132/compile_local --timeout 1200 --event-logger --parser-debug
```

Use a new identity if c51 already exists at continuation. Review raw stages, PHV, SRAM/TCAM, SALU/hash/crossbar,
mirror guards and static-entry offsets; pin exact9.13.2 artifacts before model. `efficiency_candidates.record_artifacts`
works as a Python function; its CLI has an unrelated trailing `transforms` KeyError on these generator profiles.
Do not treat `build.verify_evidence()['full_target']==False` as failure: check the four actual verification booleans.

Run affected focused regression first, then all16 required drivers on the same stable source/profile/artifacts:
`smoke packets rearm dup repeat select_lifecycle control_timing contention abort policy policy_boundary
two_read_robust smoke_sizeoff abandon relay_sbo fin_busy`.

```sh
python3 $CTL/run_model.py evidence/m12p_c51_sdk9132 DRIVER 1 --milestone m12
python3 $CTL/model_summary.py evidence/m12p_c51_sdk9132 --v3 --write --enforce
```

The model needs private namespace/raw-socket permission. Serialize runs; never overwrite attempts. Source/helper
changes require affected reruns and a new hardware freeze. Complete real49→60 logical-response proof: one commit/+11,
partial ACK28/29/59, complete ACK→native49, retransmission/no extra growth, all32 application bytes, checksums and
complete-response timing. Execute actual TCP/tail-CRC corruption and recovery; inherited shallow READ checks are an
explicit limitation, not a waiver. Keep failures and planned connection denominators visible.

## 3. Physical SEL-751 qualification after the final gate

Generate8 new configs with `$RC/hw/make_sel751_configs.py --build FINAL_BUILD`, using the retained native02 observation.
Dry-run every config, verify helpers in the actual Vision run directory, create a new freeze bound to final source,
all16 results, exact artifacts/config/checkers and standing authorization. Use existing evaluation_campaign/
run_block_frozen/guarded_block/restoration only. Check fresh ownership; unsafe restoration stops hardware.

1. Padded READ smoke: mixed+integrity, size_only,2READs/no SBO.
2. Four-arm reference: each65READ+64SELECT+64OPERATE; total772 exchanges.
3. Mixed/full loss; graceful/reset persistence; reconnect; held OPERATE350ms. Execute every planned connection.

Prefer separate one-block campaigns so a safely restored timing failure does not suppress recovery blocks. Exit2/
unsafe restoration stops all hardware; ordinary failure with independently verified restore remains reportable.
Existing same-port readiness guard polls `ss` up to80s; do not change global TCP settings or use raw TCP to evade it.

Switch `decps@10.10.54.81`; Vision `decps@10.10.54.166`, interface`enp59s0f0np0`, run directory
`/home/decps/sel751_guarded_20261024`. Master `.1:59410`/dev9/link1, relay`.7:20000`/dev64/link0.
Use existing production restore pins/config; never hand-edit ownership.

Separate master RTT/CLRT/first/complete timing from native readiness, switch residence and actual J. Use genuine
observation anchors or label those dimensions unproven; unrelated native samples are not same-packet proof.
Keep the100µs criterion. Preserve captures, outcomes, loaded row/artifact hashes and independent restoration for every block.

## 4. Reproduction, notes and completion

Active `$RC/reproduce.sh` recognizes c30/c48/c49/c50 exact metadata; its default is still historical c30.
Add the final candidate/hash/profile, select it explicitly, retain all required model evidence and hardware readout,
then verify one clean-worktree reproduction command. Failed historical candidates are not full gates.
Use `$RC/restore_retained_logs.py`: c30/c49/c50 dependency-retention manifests preserve exact sources and hash-checked
xz logs; raw originals remain local. Do not create another package/framework.

Update WORKING_NOTES, CURRENT/STATUS/COMPLETION_RECORD, ACTIVE_CODE_MAP and this plan with source/model/hardware,
timing/J/recovery and restore verdicts separately. 158 is the preserved-tail prefix floor, not a global minimum.
Commit coherent milestones as Philip. Finish real-relay work or report a demonstrated external dependency with an
exact next command. A compile, model pass, READ-only checkpoint or detached job is not the final deliverable.
