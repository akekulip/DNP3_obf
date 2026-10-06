# Next-session handover — framework track (written 2026-10-06)

Branch `codex/framework-implementation-20261005` in `/home/philip/Projects/DNP3`; **not pushed**. Base `origin/main` = `f8be278eb`.
Your uncommitted `CLAUDE.md` edit is untouched. Untracked items from before this track are untouched.

## State of the lab (read-only recon this session)

`bf_switchd` pid 10674 on the switch host (decps@10.10.54.81) has run about 24 h, cold-started with
`~/Philip_repo/logs/bringup_20261005/frozen_abs.conf`. The candidate is **not** loaded. No traffic was sent to the relay. A new directory
`~/framework_build_20261006/` on that host holds the SDE 9.13.2 build of the current source; nothing else there was written. Do not infer the
loaded program from this note; read it again.

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

1. **Restoration has not been rehearsed.** Stop and cold-restart `bf_switchd` with `frozen_abs.conf`, replay `ports_up.py`/`up2`–`up4`, apply
   `dnp3_latency_20260926/off_config.json`, and read back ports, queue ladder, pktgen, mirror/PRE and the parameter tables. Only then is a candidate load defensible.
2. **No candidate bring-up exists for the 9.13.2 schema** (ports, TM queues, packet generator, mirror and PRE, session tables). The adapter covers three tables.
3. **The `connect()` and CLI live paths have never run**; `bfrt_grpc` exists only on the switch host.
4. The relay-facing capture point is unknown; without it conclusions are limited to the master-facing view.

Decisions that are yours: push of the branch; the scope-change line in `CLAUDE.md`; whether the Tofino can be cold-restarted unattended for step 1.

## Findings that change what to build next

- Token loss leaves the owner armed and later READs bypassed; there is no FIN/RST handling; a timeout does not clear the tag.
- In D_A mode the ACK's worst-case hold is the watchdog horizon (about 30.8 ms), not D_A; admission is charged accordingly.
- `control.py` accepts only D_A in {5, 10, 15, 20}; ACK-focused needs D_A = 0.
- The generated ACK cannot be repaired after a loss without a retaining, retransmitting proxy.
- BMv2 priority queues do not gate; its artifact emulates gating with a token count.

## Where things are

`defense4/timing/framework/{contract,model,tests,control,runner,size,bmv2,analysis,declarations,figures,results}`; reports in
`defense4/timing/audit_current/framework_20261005/` (PHASE0_INVENTORY, STATUS_MATRIX, PHASE7_GENERATED_ACK, BMV2_ARTIFACT,
PHASE8_HARDWARE_RUNBOOK, PHASE9_MEASUREMENT_DESIGN, CLAIMS_RECONCILIATION). Review commits are listed by `git log codex/framework-implementation-20261005 ^origin/main --oneline | head`.
