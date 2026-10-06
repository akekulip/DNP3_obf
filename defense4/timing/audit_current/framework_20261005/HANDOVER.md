# Next-session handover — framework track (written 2026-10-06, updated after the master-timer measurement and the push)

**Read `STATUS.md` first.**

Repository `/home/philip/Projects/DNP3`, **on `main`**: the framework track was merged by pull request #6 (merge commit `20eef2019`, 2026-10-06). It was built on `codex/framework-implementation-20261005`, which remains on the remote and is not needed. Work directly on `main`; no new branches. Base `origin/main` = `f8be278eb`.
All commits are by `akekulip <akekulip@gmail.com>`, author and committer, with no co-author trailers; keep it that way. Your uncommitted `CLAUDE.md` edit is untouched, as are untracked items from before this track.

## State of the lab

The switch host (decps@10.10.54.81) runs one `bf_switchd`, last started 2026-10-06 ~17:05 UTC by `launch.sh` with `~/Philip_repo/logs/bringup_20261005/frozen_abs.conf` (program
`defense4_rrc_bor_unified12`), ports replayed from the snapshot; configuration verified identical to the pre-test snapshot. The candidate is **not** loaded. Hardware sessions this day: see `STATUS.md`.
Host files created (nothing pre-existing was edited): `~/framework_build_20261006/` (scripts, snapshots, first build), `~/framework_build_20261006c/` (the 9.13.2 build of source `df599101…`). Vision: `~/dnp3_timing7_20260925/cand_off_30_20261006/` and `master_rto_probe.py`; `/tmp/master_rto_cand_20261006.*`.
Do not infer the loaded program from this note; read it again (`framework/control/live_snapshot.py`).

## Hardware procedure, scripted

```
bash ~/framework_build_20261006/swap_daemon.sh launch_candidate.sh LOG        # stop the ONE daemon and start the candidate; aborts on any surprise
DEFENSE4_HW_AUTHORIZED=1 python3 candidate_bringup.py --case off --backup B.json --record R.json    # strict readback; PASS required
# ... session ...
bash swap_daemon.sh /home/decps/Philip_repo/logs/bringup_20261005/launch.sh LOG   # restore
python3 restore_ports.py defense4_rrc_bor_unified12 live_snapshot_20261006.json.gz --apply --wait 35
python3 live_snapshot.py defense4_rrc_bor_unified12 after.json; python3 compare_snapshots.py before.json after.json
```

Live state was read again this session: `framework/results/live_state_20261006/` (see PHASE8_HARDWARE_RUNBOOK.md). The daemon is unchanged.

## What is verified

```
defense4/timing/framework/run_tests.sh                       # 5 suites, about 3 minutes, no hardware (BMv2 cases build private namespaces)
python3 defense4/timing/response_ready/verify_build.py defense4/timing/response_ready/src/defense4_response_ready.p4 \
        defense4/timing/response_ready/evidence/sde_9_13_2_build_02                       # source/build identity and the 7-stage limit
python3 -B defense4/timing/framework/bmv2/lab/run_lab.py step5 /tmp/run '{"mode":4,"da_us":10000,"gap_us":1000,"budget":1000,"loop_pps":20000,"shape":1}'
python3 defense4/timing/framework/runner/cli.py plan --case combined --d-a-ms 10          # offline plan, writes nothing
python3 -B defense4/timing/framework/analysis/clrt_figure.py <results> <out>              # statistics, bins, figure, provenance
```
Reproduced into `framework/build/repro_20261006/`: campaign_v2 (the pinned repro; campaign_v1 has no standalone one).

## Blockers, exactly

1. ~~Restoration not rehearsed~~ **Done** (three restores this session, each verified identical in configuration): `RESTORATION_REHEARSAL_20261006.md`, `restore_frozen.sh`, `swap_daemon.sh`.
2. ~~Candidate bring-up not written~~ **Done and run**: `framework/control/candidate_bringup.py`. The first load exposed a real defect (two const tables over capacity), now fixed and covered by a test; see `HARDWARE_SMOKE_20261006.md`.
3. **Holding arms need admission.** The master's timer is now measured on this build (201 ms; `MASTER_RTO_CANDIDATE_20261006.md`), and the master checks carry it, but the verdict is still `provisional`: `detect_ms` and `release_tail_ms` (need an instrumented measurement of the mechanism on this build) and `outstation_feedback_path_ms` (needs a relay-facing observation point) are unavailable. Options are listed in that file; the activation gate admits only `admitted_conditional`.
4. The relay-facing capture point is still unknown; conclusions are limited to the master-facing view.
5. SELECT and OPERATE are not admitted by the candidate; OPERATE stays attended-only.

Decisions that are yours: push of the branch; the scope-change line in `CLAUDE.md`; how to clear the three remaining admission inputs (see `MASTER_RTO_CANDIDATE_20261006.md`): a recorded operator acceptance of `provisional` for a bounded smoke, an instrumented measurement build, or a relay-facing tap. Each hardware session costs a cold restart; the way back is rehearsed and scripted (four restores this session).

## Findings that change what to build next

- Token loss leaves the owner armed and later READs bypassed; there is no FIN/RST handling; a timeout does not clear the tag.
- In D_A mode the ACK's worst-case hold is the watchdog horizon (about 30.8 ms), not D_A; admission is charged accordingly.
- `control.py` accepts only D_A in {5, 10, 15, 20}; ACK-focused needs D_A = 0.
- The generated ACK cannot be repaired after a loss without a retaining, retransmitting proxy.
- BMv2 priority queues do not gate; its artifact emulates gating with a token count.

## Where things are

`defense4/timing/framework/{contract,model,tests,control,runner,size,bmv2,analysis,declarations,figures,results}`; reports in
`defense4/timing/audit_current/framework_20261005/` (PHASE0_INVENTORY, STATUS_MATRIX, PHASE7_GENERATED_ACK, BMV2_ARTIFACT,
PHASE8_HARDWARE_RUNBOOK, PHASE9_MEASUREMENT_DESIGN, CLAIMS_RECONCILIATION). The framework-track commits are `git log 817355077..20eef2019 --oneline` (the 117 commits before them are earlier local work).
