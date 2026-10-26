# c69 — hardware verification, then bounded N/E reduction — 2026-10-26

Authority: see `authority_review.md` (direct "Yes, as written", verified by the user). Spec: root
`CLAUDE_NEXT_TASK_C69_HW_NE.md`. Baseline commit `e1c16ecbc`; candidate `ctl_timing_01/evidence/m12p_c69_sdk9132`,
source SHA256 `5efad5c85b1adeb5aaac2f24d0eadd7660abab14d52a8a8ec0325d94e4998d59`, contract
`response_ready_ack_d_no_j_v3` (gap, budget, enabled).

## Execution ledger

- [x] Phase 1: SEL-751 receiver-visible branch of the shared standards validator + regressions
- [x] Phase 2: c69 configs, freeze, preflight, dry-runs, 10-block matrix (2,440 planned exchanges), readout
- [ ] Phase 3: E experiment (rbad0/rbad1/rbadt) — compile + final-resource comparison
- [ ] Phase 4: N experiment (first_event/abort_t terminal) — compile + final-resource comparison
- [ ] Phase 5: successor model gate / reproduction / matrix (only if a change is retained)
- [ ] Phase 6: closeout (notes, handover, commits)

## Phase 1 record — SEL-751 receiver-visible standards branch

- One shared entry point: `relay_verdict` -> `Campaign.validate_standards_file` -> `standards.build_standards_artifact`
  / `standards.validate_standards`, which dispatch on `config.endpoint_profile == 'sel751'` to internal SEL-751
  helpers (schema `dnp3-standards-sel751-v1`, scope `sel751_receiver_visible`). `relay_check.analyze/master_checks`
  are reused; observations are recomputed from the six bound files (out/in pcap, master.json, result.json,
  capture_offloads.json, relay_wire.json), which are rehashed. Sizes 91/134/49 native, 141/158/60 padded; reconnect
  c2 native. Build profile label kept (`candidate61`); emission proof NOT EVALUATED, explicit requirement rejected;
  software-profile boundary requirement unchanged.
- `expected_identity` split into shared identity + scope expectations; software output identical to e1c16ecbc on 100
  contexts (`software_identity_equivalence.txt`).
- Independent review found: HIGH standards dimension fail-open in `relay_verdict` (fixed: own guard per connection,
  any exception -> recorded FAIL); MEDIUM unmarked evidence tests (module evidence_tree + skip guard), framing/socket
  master findings mis-split (now transport), missing wiring tests (added ordinary raise, reconnect via
  verdict_scenario, candidate_series relay branch, fail-closed). LOW: size table shared, producer closure completed.
- Four existing tests edited as consequences of the intended routing (sel751 tier case, CLRT stub, loss stubs gain the
  standards dimension); none relaxed an assertion on the software path.
- Baseline (HEAD code restored temporarily in the working tree, stash verified by hash): hw_vepa 905 passed / 1 failed
  (test_markers tracked-source export), rearm 811 passed / 6 failed. Post-change: 944 / same 1, 813 / same 6. The
  first baseline attempt overlapped my edits and an archive-tree attempt hung/failed on untracked evidence; both
  discarded.

## Phase 2 record — c69 freeze, preflight and smoke

- Configs/freeze/manifests/dry-runs committed fd4e28f6f; freeze_v3_01 178 files, 0 untracked; all ten exact-argv
  dry-runs rc 0 (installer --t-gap/--t-budget/--t-enabled only).
- Read-only live preflight 2026-10-26T20:33Z: switch ufispace on production case4_response_path; Vision .19, route
  to .7 via enp59s0f0np0; ownership inactive/safe; native READ mixed 91 / integrity 134, IIN 0x80, no problems
  (`read_preflight_01.json`).
- Smoke rc01_hw_c69_20261026_01 (20:34:05Z-20:36:58Z): **block rc 1 (FAIL)**; independent restoration ok; ownership
  inactive, unsafe_restoration false. Trial t0: application True, standards True, switch False. Switch failures:
  "mirror_fix build: the snapshots carry no pktgen trigger/packet counters" and "loop-port counters for hb_return are
  missing or unreadable". Receiver-visible: 2 READ + SELECT + OPERATE all OK, CROB SUCCESS, sizes 141/158/60;
  visible CLRT READ mixed 5.964 ms, integrity 4.623 ms, SELECT 6.408 ms, OPERATE 5.319 ms (D = 5 ms; reported only).
  Snapshot: pktgen carries only the READ app (triggers 0->4, packets 0->16); loop ports n_ack_return/t_in/held_return
  present with zero octet gap; hb_return absent. Per the smoke stop rule the matrix and the optimization phase are
  halted pending Philip's decision.

## Phase 2 record — no-J switch-gate repair (Philip: "Repair gate, rerun smoke")

- checks.py: `NO_J_CONTRACT`, `loop_roles()` (= build_ports.loop_names minus the non-loop names); evaluate_switch
  gates only installed loop roles; `_mirror_checks` under no-J: app0 triggers == reads + 2*SBO (READ, SELECT and
  OPERATE each pass admit_request once; retries and T-off never clone), 2k packets per trigger, retired app1 idle if
  reported (one-sided report fails closed); earlier contracts unchanged.
- candidate_series.series_switch_gate: passes `telemetry=build.switch_telemetry is not False` (as relay_verdict has
  since c68) and tolerates the "no switch telemetry" outcomes string. Demonstrated offline: on c69-shaped snapshots it
  failed with "required outcome is unreadable: OUT_ACK_COMMIT" independent of traffic. This also applies to c68
  telemetry-free series (none were run).
- Review (approve with warnings): rule correct per the c69 source (admit_request is the only clone setter; only
  first-copy REQUEST/OPERATE reach it; installer configures app0 only) and consistent with retained c68/c67 counters
  (c68 loss 21+1 per trial, c68 reference combined 129+64, c67 reconnect 42+2). Acted on: source-pinned premise
  test, loop-role/build_ports consistency test, distinct one-sided-app1 message, style. Not changed (disclosed):
  report.py's own LOOP_ROLES copy (software-path report, gates nothing, would print '-' for c69 loop metrics);
  campaign.json mirror note text; J-era stale-token bound (unobservable without telemetry).
- Suites: hw_vepa 963 passed / baseline 1; rearm 815 passed / baseline 6 (`tests_post_gate_*.txt`).

## Phase 2 record — baseline matrix result (c69, freeze_v3_02)

- Smoke rerun rc01_hw_c69_20261026_11 21:01:46Z: PASS (application, switch, standards; app0 4 triggers/16 packets).
- Matrix 12-20 (21:05:10Z-~21:5xZ), one guarded campaign each, sequential driver; every block rc 0, independent
  restoration ok, ownership inactive/safe after each. Planned = observed = OK outcomes: 772 + 386x3 + 66x3 + 154x2 +
  smoke 4 = 2,440. Every trial: application, switch and receiver-visible standards True; all 14 loss trials also
  loss_target True. Sizes exact by arm (native 91/134/49; padded 141/158/60; reconnect c2 native). Visible CLRT
  (reported only): timing arms centred on D (medians within ~0.7 ms of 5/10/15/20 ms); off and size_only relay-native
  (medians 2.1-4.1 ms, long tails to ~25 ms). Full table: matrix_readout.md / matrix_readout.json.
- Not evaluated: switch-emitted boundaries, departure timing, physical-event protection. c68's full-loss t3 OPERATE
  TIMEOUT did not recur in this run (c69 full-loss 7/7); one passing run does not locate or resolve that cause.
- Block 01 (first smoke, freeze_v3_01) remains a recorded FAIL on the switch gate's missing no-J rule; campaigns 02-10
  never ran. The background driver/monitor session ended during block 20; the block ran to completion under its
  detached supervisor (rc 0, restoration ok), verified after resume.

## Phase 3 record — E experiment (rbad0/rbad1/rbadt), transform prepared

- Data dependencies (c69 source 5efad5c8, E = r_EgParser/r_Egress, P4 lines 567-1309): each predicate's only
  assignment is the parser-start zeroing (P4:741); the compares were deleted by two_read_reduce because c0/c1/c2 are
  extracted only by state read_b0, which no transition reaches (dl/dl_mid select read_pp, ctl_b0 or accept); E's
  producers in_rb0_t/in_rb1_t/in_rt_t are declared and never applied (the in_rb0_t apply at P4:2185 is p1 x_Egress's
  own table). Consumers: acct_t key positions 10-12 (stage 4, ternary) and classify_fwd key positions 10-12 (stage 7,
  ternary, 16 keys); every const entry holds 0 or _ there. The three bits share container B36 (with m.grant, m.in_cb0);
  their pa_solitary pragmas sit on r_EgParser. Kept: m.in_rt (status_crc_t -> cbadt) and badh/cbad0/cbadt.
- Transform m12gen/strip_rbad.py (`--strip-rbad`, requires --strip-operate-hold), candidate id c70 (m12p_c70_sdk9132).
  Fail-closed premises (single zeroing assignment, no applied producer, removed entry values only 0/_). Tests
  tests/test_strip_rbad.py: c69 byte identity without the flag, N/T byte-identical, only predicate/producer lines
  change in E, row-for-row entry equivalence with order and actions, fail-closed cases, CLI dependency. Generator
  suite 202 passed / 1 optional legacy skip.
- Historical reproduction: c69 now pins its generator at e1c16ecbc (reproduce.sh GEN_PIN), because generator_files in
  its recorded inputs.json would otherwise differ; the pinned generator reproduces c69's inputs.json exactly (checked
  from the e1c16ecbc export); c69 source bytes are identical either way.
- Compile deferred until the hardware matrix finishes (brief sequencing).

## Phase 4 record — N experiment (terminal construction), transform prepared

- Data dependencies (c69 final placement, p0/logs/table_summary.log and table_dependency_graph.log): N's last stage
  (10) holds only first_event and abort_t. abort_t follows next_stage_t by OUTPUT and ANTI_ACTION_READ edges
  (hdr.event.event slices). first_event follows snapshot_t (OUTPUT, ACTION_READ: envelope/event/origin headers) and
  close_phase_t (ACTION_READ: m.desired), and close_phase_t is in stage 9 because its key reads m.observed from owner_t
  (stage 8). So restructuring the snapshot alone cannot move first_event; doing so would also require folding the
  96-row close_phase_t into first_event (cross product of rows), which is the excluded invasive fallback and is not
  attempted. The earlier report next_stage_analysis_01 proposed a 32-bit m.snapshot_epoch precompute; with pipe-0
  normal 32-bit containers full and close_phase_t still binding, it is not part of this trial.
- Transform m12gen/merge_n_terminal.py (`--merge-n-terminal`, requires --strip-operate-hold), candidate id c71: next_stage()
  folded into abort_work()/carry_current() (disjoint fields), branch restructured so exactly one keyless table applies
  per path; table names and keyless shape kept; no field/key/table added. Tests tests/test_merge_n_terminal.py: c69
  identity, N-only change, executed-action equivalence over 1,944 branch inputs with all three outcomes reached, field
  disjointness, composition with --strip-rbad, CLI dependency. Expected compiler effect: abort_t may leave stage 10;
  first_event stays, so N's stage count is not expected to drop — the compile decides.

## Scope-drift records

(requirement / observable / mechanism / cheapest falsifying test — added before any new requirement or chase)

1. Smoke switch-gate failure (2026-10-26).
   - Requirement: the existing switch gate (checks.evaluate_switch via relay_verdict) is part of block acceptance.
   - Observable: c69 smoke snapshots (switch BFRT, before/after) lack pktgen app OPERATE and loop role hb_return.
   - Proposed mechanism: c69 removed packet-generator app1 and the HB runtime resources by design (c69 handover);
     `_mirror_checks` still requires READ+OPERATE generator counters (a J-era rule: OPERATE app triggers == SBOs)
     and LOOP_ROLES still lists hb_return. A checker-expectation defect, not a dataplane fault.
   - Cheapest falsifying test: offline, against the retained smoke snapshots and c69 bfrt.json — if c69's compiled
     program still declares pktgen app1 or an hb_return port, the premise fails. RESULT: premise holds —
     integration/core/response_only/hw/build_ports.py:28,72 omit hb_return for response_ready_ack_d_no_j_v3 and c69
     setup disables stale app1 (c69 progress.md:15), while protocol/hw_vepa/checks.py:17 (LOOP_ROLES) and
     _mirror_checks were not given a no-J rule. No repair made.

## Claim boundaries

Receiver-visible SEL-751 evidence only. Switch-emitted boundaries, departure timing and physical-event protection
are NOT EVALUATED. Resource improvement is distinct from hardware qualification and fingerprint protection.
