# Defense 4 — overnight autonomous run state

**Purpose:** single source of truth for resuming this run after compaction / token reset / external
termination. On resume: re-read THIS file, then `git log --oneline -15` and `git status`, then continue
from "Next exact command". Do not restart the project.

## ►► RESUMED 2026-08-13 (after reset). PROGRESS: P8b pipe1 mirror session 7->8 DONE+verified (7b42579,
## nil cost). Codebook range-band install = documented TODO for the gated load (not blocking). P10/P11
## evidence+figures IN FLIGHT (ac7af0c, from proven data + honest provenance). NEXT after it lands: P12
## repo org (PROJECT_MAP/README/REPRODUCE), then P13 EXPLAINER (last). Load stays READY-GATED; H5 BLOCKED.
## ---- original resume block (still valid) ----
## ►► RESUME NOW (session limit hit ~2026-08-13, resets 1:30am ET). Continue here:
The SOFTWARE result is COMPLETE + strong (faithful two-pipe BOR+RRC: compile-proven local 9.13.1 AND
switch 9.13.2, pipe0=12/pipe1=10 both tofino.bin; real per-transaction Random<bit<8>> J that CONVOLVES;
24/24 offline acceptance gates + no cross-artifact disagreement; two-program control plane
offline-validated; exactly-once/T0-anchor/fail-open/carve/first-OPERATE-held all proven). HEAD at pause:
ce79c99 (+ untracked evidence SUMMARY files to `git add`). Do, in order:
1. Commit the untracked evidence SUMMARYs under evidence/bor_two_pipe_faithful/pipe0,pipe1/.
2. P8b de-risk (compile-only, no hardware): pipe1 distinct mirror session (7->8) + recompile <=12;
   update defense4_bor_twopipe_setup.py codebook install to {dst_port,rand8:range} bands (J-tick low byte 0).
3. P10 evidence/CLRT/fingerprint/latency from PROVEN data (this session's joint RRC pcaps are the CLRT
   silicon proof; physical-fingerprint = OFFLINE convolution model, labelled; NO physical OPERATE).
4. P11 figures (16, IEEE, provenance captions), P12 repo org (PROJECT_MAP/README/REPRODUCE), P13 EXPLAINER last.
5. Two-program HARDWARE LOAD (H1-H4) stays READY-GATED on a watched window (do NOT load blind vs the
   working RRC switch autonomously). H5 physical OPERATE BLOCKED (no isolation). Leave switch untouched.
Honesty rules in force: compile != silicon; two pipes != one pipe; fixed J != mitigation (now fixed to
random); software-endpoint != physical relay; no claim > raw evidence.

Directive: `autonomous_overnight.md`. Mission: finish the faithful unified **BOR + RRC** primitive on the
existing Tofino-1 (BFN-T10-032D, num_pipes=2, 12 ingress stages/pipe), one deployable logical primitive,
one pipe preferred else two on-chip pipes; through implementation → offline gates → control plane →
hardware → PCAP/fingerprint analysis → figures → repo org → EXPLAINER (last). No other switch / proxy /
TF2-3 / new endpoint / switch-side padding.

---

## Live status (UTC 2026-08-12)

- Branch `defense4-size-native-parity-crc-split`; local == remote == **f3753d3**; worktree clean
  (untracked: `autonomous_overnight.md` + 2 pre-existing build logs, unrelated).
- Running background agent: **part-5 two-pipe compile/topology proposal** (a p4 engineer) — building on the
  CURRENT (unfaithful) BOR; its TOPOLOGY/route/T0-in-header work is reusable, its BOR-hold will be
  replaced by the faithful design. Do not edit `defense4_rrc_bor_sr_probe.p4` or the two-pipe files while
  it runs.
- Switch: bf_switchd **up (1 proc)**, running `/home/decps/rrc_build/defense4_rrc.conf` (the RRC kernel);
  last configured RRC joint D4 earlier this session. Program baseline recorded; no switch change made.
- **H5 (physical SEL OPERATE) = BLOCKED**, confirmed: `RRC_HW_RESULTS.md` — odd-point electrical-isolation
  evidence is absent, "No physical OPERATE run or recommended." Per the safety rule, physical OPERATE will
  NOT run; the OPERATE lifecycle uses OpenDNP3 software endpoints through the physical Tofino (H3).
- Rollback: `configure-timing --mode OFF` (size-only) or `+ rollback-rrc` (transparent); safe restore =
  frozen `defense4_caseA` via `swap_generic.sh`. Frozen RRC kernel + caseA are byte-for-byte intact.

## Verified baseline (Phase 1, reproduced this session)
- Proven RRC kernel compiles clean, **ingress 12 / egress 3**, 125 logical tables (bf-p4c 9.13.1).
- Additive BOR probe: **14** stages. Stripped core: **13**.
- Consolidated SR1+SR2+SR3+SR4 "candidate": **13** stages — BUT see the critical correction: SR4 is NOT a
  faithful hold.

## CRITICAL CORRECTION (Phase 2, must precede fit claims)
SR4 readiness in `defense4_rrc_bor_sr_probe.p4` is NOT faithful BOR:
- first OPERATE does `op_ready` read → 0 (qid3 not yet resident) → **fail-open forward** → `arm_clone`
  starts async qid3 → later ready → an exact retry is `V_ARM_DUP`-suppressed. => BOR is BYPASSED on the
  first real OPERATE; no hold happens.
- `reg_op_ready` not cleared; 4-bit DNP3 seq wrap can match a stale ready value.
- Emulator's `structural_guarantee` assumes the original can begin its hold at `resident_at`; the P4 has
  NO storage keeping the original between T0 and resident_at. Model this.
- **Do NOT retain "faithful one-pipe BOR is 13 stages"** until a design shapes the FIRST eligible OPERATE
  after a clean start. Relabel the SR4 result as a RESOURCE PROBE (fail-open-only ≠ BOR protection).
- Verify selector flags: PART4_RANDOM/PART4_SALTED appear compiled WITHOUT SR4 → not evidence for the
  complete primitive.

## Plan (phases; the faithful design is the pivot)
- **P2** correct emulator (async event order) + required mutants (first_operate_always_fail_open,
  early_qid2_release, magic_buffer_until_ready, stale_ready_after_seq_wrap, ready_without_reservoir,
  ready_not_cleared_on_retire, duplicate_release, retransmit_releases_second_copy,
  deadline_reanchored_to_operate_release, public_sequence_selects_j, tcp_timestamp_subtraction,
  source_copy_leaks_to_relay) + correct reports (relabel SR4).
- **P3** faithful readiness: SELECT creates a **BOR epoch** (separate internal identity, NOT the DNP3
  generation), seeds+confirms qid3, retains BOR_PENDING across SELECT; OPERATE requires matching
  BOR_PENDING+residency, then holds in qid2 to T0+J, releases once; deadlines anchored to original T0.
- **P4** recover 12-stage fit for the FAITHFUL design (compiler-guided). **P5** two-pipe if one-pipe can't.
- **P6** offline gates (1000+ txns, wraps, all mutants, RRC regression). **P7** control plane.
- **P8-9** hardware (H1 load/transparency, H2 RRC regression, H3 OpenDNP3 software OPERATE, H4 physical
  non-actuating, H5 physical OPERATE only if isolation+authorization documented else BLOCKED).
- **P10** PCAP/CLRT/physical-fingerprint/latency. **P11** figures. **P12** repo org. **P13** EXPLAINER.

## Gates
| gate | state |
|---|---|
| P1 starting state | DONE (verified) |
| P2 emulator+report correction | DONE (faithful emulator, 12/12 required mutants, SR4 relabelled) |
| P3 faithful readiness design+emulator | DONE (design + emulator; P4 fold IN FLIGHT) |
| P4 one-pipe faithful fit | DONE-NEGATIVE (13; hold core is a real +1 -> two-pipe) |
| P5 two-pipe FAITHFUL | **DONE** — pipe0=12/3, pipe1 faithful=10/0, BOTH independently re-compiled (tofino.bin); first OPERATE genuinely HELD; exactly-once proven; frozen RRC 0-diff (323d93f) |
| P6 offline acceptance + cross-artifact review | **DONE** — 24/24 gates PASS, no cross-artifact disagreement (8770750) |
| P4b real leak-safe random J selector | **DONE** — Random<bit<8>> PRNG per-transaction, convolves (not shifts); pipe1 10/12, +1 table (0eaf3a4) |
| P7 two-program control plane | **DONE** (ce79c99, offline-validated: dry-run valid exit0 / invalid rejected pre-connect / auth-gated / TS preflight parses kind-8) |
| P8a switch-side 9.13.2 compile | **DONE** — pipe0 + pipe1 BOTH build clean on the SWITCH compiler (tofino.bin present in /home/decps/bor_build/out_p0,out_p1) |
| P8b mirror-session + codebook de-risk | **NOT DONE** — agent a8bb0be FAILED on the session limit. TODO on resume (compile-only): (1) give pipe1 a distinct clone/mirror session id (pipe0=7, pipe1->8) in defense4_twopipe_pipe1_faithful_probe.p4, recompile <=12; (2) update defense4_bor_twopipe_setup.py set_j/codebook install to the {dst_port,rand8:range} bucket-probability bands (per-bucket J-tick low byte 0). |
| P8/9 two-program LOAD H1-H4 | **READY, GATED on a watched deployment window** (PI call): novel two-program silicon deploy has unproven deps (pipe-1 port bring-up dp144/136/196, cross-pipe MAC-loopback, per-pipe pktgen + mirror-session scoping) NOT confirmable read-only; NOT attempted blind vs the working RRC switch autonomously. RRC half ALREADY silicon-proven (joint pcaps, this session). |
| P8/9 H5 physical OPERATE | **BLOCKED** — no odd-point isolation proof (RRC_HW_RESULTS.md) |
| P10-13 evidence/figures/repo/explainer | PENDING — from PROVEN data (RRC silicon pcaps + compile-both-toolchains + offline models) with honest provenance captions; physical-fingerprint = offline convolution model only (labelled) |

## ARCHITECTURE DECIDED (PI call, a9f0bb1): TWO-PIPE split
One-pipe faithful genuinely cannot fit (hold core is a real +1; verified). Two-pipe is FEASIBLE and
verified independently (my own compile of the pipe0 final recipe produced tofino.bin at 12/3):
- **pipe 0** = frozen RRC + T0-admission + in-chip MAC-loopback cross-pipe route = **12 ing / 3 egr**
  (recipe `-DTWO_PIPE_PIPE0 -DBOR_NO_TOPJ -DPIPE0_ARM_FOLD`; naive split was 13, the +1 was the
  T0-anchor write-after-write, folded into the decode action with the anchor ACTIVE).
- **pipe 1** = BOR OPERATE hold/release core = **6 ing / 0 egr** (6 stages headroom for faithful readiness).
- Cross-pipe route: pipe0 sets ucast_egress dp144 (pipe-1 MAC near-loopback) + bypass_egress; T0 in a
  reversible 6B xpipe header (byte-identical at release); released OPERATE egresses pipe1->dp64.
  Two-program device, pipe_scope [0]/[1]. Exactly-once at both pipes (pipe0 reg_tag + pipe1 V_OP_DUP).
Faithful readiness emulator DONE (a9f0bb1): first_operate_shaped faithful=True / SR4=False; 1000-txn +
4-bit-wrap drivers pass; 12/12 required mutants + 5 legacy killed; SR4 relabelled a RESOURCE PROBE.

## MILESTONE (323d93f): FAITHFUL two-pipe BOR+RRC compiles on both on-chip pipes (≤12 each)
pipe0=12/3 (RRC + T0-admission + cross-pipe route + SELECT-prepare), pipe1 faithful=10/0 (epoch
readiness, first OPERATE held). Both independently re-compiled to tofino.bin. Honest: faithful readiness
is not free (pipe1 6→10, irreducible epoch serialization). fail-open-first pipe1 kept as 6-stage control.

## Next exact command (superseded milestone note below is historical)
IN FLIGHT (a9bce22 P6 acceptance+review; ae7d0fe P7 control plane). On completion review vs raw
artifacts, commit, then: P8 hardware prep (compile the two programs on the SWITCH 9.13.2; H5 BLOCKED),
H1 load/transparency (smallest reversible change, rollback armed) → H2 RRC regression → H3 OpenDNP3
software OPERATE → H4 physical non-actuating. Then P10 evidence/CLRT/fingerprint/latency, P11 figures,
P12 repo org, P13 EXPLAINER. HISTORICAL next-command (done):
p4 engineer folding the FAITHFUL SELECT-prepares-epoch readiness into the two-pipe design
(pipe0 emits a cross-pipe SELECT-prepare trigger; pipe1 builds the epoch + holds the FIRST OPERATE),
recompiling both ≤12, proving the faithful cross-pipe lifecycle offline. On completion: review vs raw
compile logs + the emulator; commit; then P6 offline acceptance gates, P7 control plane, P8/9 hardware
(H5 BLOCKED), P10 evidence/CLRT/fingerprint, P11 figures, P12 repo org, P13 EXPLAINER (last).

## Known blockers
- H5 physical SEL OPERATE: no documented electrical-isolation proof for the odd decoy point → default
  BLOCKED; use OpenDNP3 software-endpoint OPERATE (H3) for the OPERATE lifecycle.
- Faithful one-pipe fit is the open question (unfaithful was 13; faithful adds the epoch/prepare path).

## Agent findings awaiting main-agent review
- part-5 two-pipe proposal (in flight).
