# c69 — hardware verification, then bounded N/E reduction — 2026-10-26

Authority: see `authority_review.md` (direct "Yes, as written", verified by the user). Spec: root
`CLAUDE_NEXT_TASK_C69_HW_NE.md`. Baseline commit `e1c16ecbc`; candidate `ctl_timing_01/evidence/m12p_c69_sdk9132`,
source SHA256 `5efad5c85b1adeb5aaac2f24d0eadd7660abab14d52a8a8ec0325d94e4998d59`, contract
`response_ready_ack_d_no_j_v3` (gap, budget, enabled).

## Execution ledger

- [ ] Phase 1: SEL-751 receiver-visible branch of the shared standards validator + regressions
- [ ] Phase 2: c69 configs, freeze, preflight, dry-runs, 10-block matrix (2,440 planned exchanges), readout
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
