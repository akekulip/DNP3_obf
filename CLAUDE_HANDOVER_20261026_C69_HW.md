# c69 on the SEL-751 — hardware verification and two bounded N/E experiments (2026-10-26)

## Authority and scope

Spec: root `CLAUDE_NEXT_TASK_C69_HW_NE.md` (written by Codex). Authority: on 2026-10-26 Philip answered "Yes, as
written" to a direct question about its hardware scope, confirmed that answer from his native session, and required
five plan corrections. After the first smoke failed only on a stale switch gate, he chose "Repair gate, rerun smoke".
Ledger with the authority record, every step and the scope-drift record:
`defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/evidence/c69_hw_ne_20261026/`
(`authority_review.md`, `progress.md`). This task is complete. Nothing in it authorizes further hardware work.

## What passed

- **Receiver-visible acceptance (38b46ff6c).** The shared standards validator (`protocol/hw_vepa/standards.py`) now has
  an internal SEL-751 branch, reached through the same entry point (`Campaign.validate_standards_file`) from ordinary,
  loss, reconnect and persistence relay verdicts.
  - It rehashes the six bound files and recomputes transport, application and size from them with `relay_check`.
  - Sizes by arm: native 91/134/49, padded 141/158/60; reconnect c2 stays native.
  - CROB TIMEOUT is an application FAIL.
  - Switch-emitted boundaries, departure timing and physical-event protection are reported NOT EVALUATED.
  - Software-profile rules and output are unchanged (100/100 contexts identical).
  - Independent review (one HIGH fail-open, fixed) and qa-verifier: PASS.
- **Switch gate, c69 no-J rule (265d1ffd1).**
  - Only installed loop roles are checked (`hb_return` is retired).
  - Generator app0 must fire once per admitted READ, SELECT and OPERATE, with 2k packets each; the retired app1 must
    stay idle.
  - The three-connection series gate follows the build's `switch_telemetry` flag.
  - The premises are pinned to the c69 source by tests. Review: correct per the source.
- **Hardware matrix on unchanged c69** (source `5efad5c8…`, freeze `freeze_v3_02`, runs `rc01_hw_c69_20261026_11..20`).
  All ten blocks ran: smoke, four-arm reference at D5, timing_only+combined at D10/15/20, graceful/RST persistence,
  reconnect, and mixed/full loss with seven identity-targeted trials each.
  - Every block: rc 0, independent restoration verified, ownership inactive and safe.
  - 2,440 planned, 2,440 observed, 2,440 OK outcomes.
  - Every trial passed application, switch and receiver-visible standards, and loss target for the 14 loss trials.
  - Sizes were exact by arm.
  - Visible CLRT (reported, never gated): timing arms centred on D; off and size_only relay-native.
  - Readout: `matrix_readout.md` / `.json`.

## What failed, and what stays unproven

- **First smoke failed.** `rc01_hw_c69_20261026_01` (freeze_v3_01) is a recorded FAIL on the stale switch gate. The
  traffic itself was correct. Campaigns 02–10 never ran.
- **E experiment (c70): not retained.** `--strip-rbad` compiled, but final placement is unchanged in stages, SRAM,
  TCAM, Map RAM, Meter ALU, stateful tables and PHV used. Only ternary crossbar -2 and PHV bits allocated -3.
- **N experiment (c71): did not compile; not retained.** `--merge-n-terminal` failed PHV slicing of
  `hdr.event.event` three times, including a whole-field write and an 8/8 container-size pragma. Stopped by the
  three-attempt rule; all attempts are retained. `first_event` is held in N's last stage by `close_phase_t` and
  `snapshot_t`, and that is not addressed.
- **No successor candidate.** No successor model gate, freeze or hardware matrix ran.
- **c68's OPERATE TIMEOUT.** The full-loss t3 OPERATE TIMEOUT did not recur here (c69 full loss 7/7). One passing run
  neither locates nor resolves its cause.
- **Not evaluated:** switch-emitted boundaries, departure timing and physical-event (fingerprint) protection.
  Resource results are not hardware qualification. The hardware result is not a fingerprint-protection claim.

## Disclosed limits of the changes

- `protocol/hw_vepa/report.py` keeps its own `LOOP_ROLES`, so c69 loop metrics print '-' in that software-path report.
  It gates nothing.
- `campaign.json`'s `mirror_fix` note text still describes the J-era rule.
- The token-stale bound is J-era; it cannot be observed without telemetry.
- `relay_wire.json` is bound by hash only. TCP-header and FIN/RST checks stay in the trial application dimension.

## Reproduction and identities

- c69 reproduction now pins its generator at `e1c16ecbc` (`read_complete_01/reproduce.sh`), because the shared
  generator gained opt-in transforms. Result: `c69_reproduce_after_pin.txt` in the ledger.
- Candidates:
  - c70 `ctl_timing_01/evidence/m12p_c70_sdk9132` (compile retained);
  - c71 `ctl_timing_01/evidence/m12p_c71_sdk9132/compile_attempt_0{1,2,3}`.
- Commits (local `main`, not pushed):
  - 38b46ff6c, fd4e28f6f, 489f6a66c, 265d1ffd1, 3b67bbfaf, 49eb06684, f8f9857c5, 130484434;
  - plus the closeout commit.
