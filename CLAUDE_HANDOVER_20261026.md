# c68 handover — reviewed repair, 2026-10-26

Paths prefixed `SE/` are relative to
`defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/`.

## Current execution

The user requested review of Claude's reports, code, runs and evidence, warned that every directive attributed
to him must be reviewed, selected the three bounded decisions below, and then said “do it”. Agent summaries and
handover labels are records, not authority by themselves. The directive audit is in stage
`read_complete_01/evidence/c68_repair_20261026/authority_review.md`.

- Restore software OPERATE hold >= configured J and piggyback fixture identity.
- Keep visible CLRT and the additional piggyback latency criterion ungated.
- After offline repairs, run only the existing c68 D20 mixed/full recovery workloads with new IDs and normal
  guarded authorization, freeze, ownership and independent restoration.

Code commits: `f12458308` (repairs and retention), `a4aa1f330` (required-freeze refusal). The final evidence commit
records both recovery blocks and this handover. P4 and core model helpers are unchanged. No new model attempts or
P4 compile were necessary.

| Item | Current evidence |
|---|---|
| c68 model gate | Fresh `model_gate_passed`, all 17 required drivers |
| Source/compile | Unchanged source 825b7e6da3c24dd1705d43f1d921dbd2184a99fe47f75f4de1d2d372e160b289; existing SDK 9.13.2 compile retained |
| Normal before/after | Four historical blocks, eight trials, 1544 exchanges reproduce exactly |
| D20 mixed loss | New campaign05 PASS (7/7); 154 application responses independently validated; restoration PASS |
| D20 full loss | New campaign06 FAIL; six of seven trials passed, all seven attempted; t3 OPERATE TIMEOUT on both points; restoration PASS |
| Physical J | Unproven; no relay-side timing observation |
| c67 mixed-loss failure | Preserved; c68 passing observations do not prove a cause or that the old defect is fixed |

Campaign06 finished rc 1 after its application failure, with independent restoration PASS. Its record is under `read_complete_01/evidence/hw_campaigns/rc01_hw_c68_20261026_06`.
Both planned recovery blocks are finished. Ownership is inactive and unsafe_restoration=false; production baseline verified live. Unverified restoration stops hardware work.

## Repairs and reproduction

- Software J and piggyback fixture identity are restored with the original software loss/reconnect/runner
  exemptions. Standards recomputes applicable J from bound captures; an artifact cannot supply its own exemption.
- Event-clear now checks FIN rather than FIR, binds solicited response sequences, and requires completed class-0
  verification. Unit tests cover fragmentation and stale/missing replies. No event-clear operation was run in this
  repair; READ-only preflights returned expected 91/134-byte responses and wire IIN8000.
- One retention helper restores pinned completed or aborted logs without inventing execution closures. All 83 c68
  archives are integrated; all 30 existing compiler artifacts/logs/resource reports are retained byte-exactly.
- The current wire report is `sel751-wire-v2`. Historical analysis uses isolated pinned checkers; original results
  remain unchanged. Replay success means recorded verdicts reproduced, including failures.
- Full fresh-checkout c68 and c67 reproduction both exited 0. Current c68 freeze04 checks all seven configs. Original
  c68 freeze03 checks run at 789092c2d for its four successful references; c67 source/gate/freeze use a4ebbecbe.
- `freeze_v3_04.json` binds the repaired current harness. Do not substitute it for old runs' original freezes.
- Reproduce: `CANDIDATE=c68 bash read_complete_01/reproduce.sh` or `CANDIDATE=c67 ...` from the stage directory.
  Full logs, counts and postcommit guard verification are in `read_complete_01/evidence/c68_repair_20261026/`.

Local restoration validated 348 logs. The clean Git checkout contains 328 helper candidates, including all 83 c68;
the pinned historical c67 checkout contains 245. These distinct inventories are recorded in verification audits.
Do not describe the local inventory count as the number of Git-published logs.

## Dataplane and claim boundaries

c68 is c67 with write-only measurement state removed by `--strip-telemetry`. Mechanical source comparisons
support that transformation; they are not an exhaustive hardware-equivalence proof. Existing resource reports
show N/E 11 stages, T 9 and pipe1 egress 4, SRAM 170/47 on p0/p1.

Removed counter values in model tests are derived from action logs. Functional register state is read through
BFRT. The 16 disclosed live HELD_REWAIT sampling differences are not synchronized-register parity. Holding the ACK
until the response is ready is the required behavior; quoting it does not prove every physical departure.

The original normal reference data follows. It remains a receiver-observed CLRT report, without a pass/fail
precision criterion. The off arm disables obfuscation in the candidate pipeline; general relay compatibility,
loss recovery and physical J are separate claims.

## Results (visible CLRT at the master NIC, median ms, before → after; 193 exchanges per arm)

| D | mixed READ | integrity READ | SELECT | OPERATE |
|---|---|---|---|---|
| 5 | 2.325 → 4.851 | 2.961 → 5.085 | 2.219 → 4.920 | 3.098 → 5.000 |
| 10 | 2.758 → 10.197 | 2.526 → 10.046 | 2.277 → 9.977 | 2.808 → 9.883 |
| 15 | 2.453 → 14.774 | 3.923 → 15.216 | 2.296 → 14.957 | 2.841 → 14.778 |
| 20 | 2.502 → 20.049 | 2.942 → 19.944 | 2.188 → 20.105 | 2.740 → 20.086 |

- **Sizes.**
  - Before: 91, 134, 49 and 49 bytes.
  - After: 141, 158, 60 and 60 bytes.
- **Spread.** The full minimum, median and maximum per class are in `SE/read_complete_01/CURRENT.md`.
  The data is in `SE/read_complete_01/evidence/c68_visible_clrt_20261026.json`, produced by
  `SE/read_complete_01/analysis/visible_clrt.py`.
- **Pcaps.** The before and after captures are under
  `SE/read_complete_01/evidence/hw_blocks/rc01_hw_c68_20261026_0N_reference_rest/physical_relay/{off,combined}/`.
- **Campaign records** are in `SE/read_complete_01/evidence/hw_campaigns/rc01_hw_c68_20261026_0N/`, including the
  authorization `.md` files.

## Testbed and open verification

Vision is currently `decps@10.10.54.19`, verified as `vision` with data MAC 3c:fd:fe:cc:5d:c0. Switch is
`decps@10.10.54.81`, production baseline `case4_response_path`. Re-prove identities and current state before a run;
the shared historical topology map also contains stale addresses.

Pending class-2 events can change the fixed integrity response shape. The observed A/B establishes this for c67
and c68 under this profile, not “every build”. If pending events invalidate a precondition, report it; do not
silently clear events or change the workload. The earlier one-time clear and narrow vision_never_reached
reconciliation have recorded question answers and evidence; neither is general ownership-edit authority.

The bounded repair and both planned recovery blocks are finished. Full loss remains a genuine application failure after SELECT-response loss. Independent packet replay, raw application/CRC checks, loss targets, artifact hashes and restoration all validate the recorded outcomes. The cause remains unlocated; mixed versus integrity history alone is not an explanation.
The two old v1 test-fixture failures remain documented baseline debt. Do not broaden this repair into historical
cleanup, new relay profiles, instrumentation, production defaults or a queue redesign.

Preserve c52/c67 evidence, old freezes, `paper/`, and the two pre-existing deleted root files. Use explicit task
paths and the required author/committer identity; no history rewrite or force push.

New full-loss t3: SELECT OK after 1015.238 ms; OPERATE TIMEOUT status 1 on points 1 and 3. New mixed-loss t3 passed after 1021.670 ms. These master-side durations do not measure the relay selection window or establish a switch re-hold. No additional hardware or instrumentation was run.
