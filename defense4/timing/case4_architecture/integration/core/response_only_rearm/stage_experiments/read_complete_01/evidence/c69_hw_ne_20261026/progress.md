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

## Scope-drift records

(requirement / observable / mechanism / cheapest falsifying test — added before any new requirement or chase)

## Claim boundaries

Receiver-visible SEL-751 evidence only. Switch-emitted boundaries, departure timing and physical-event protection
are NOT EVALUATED. Resource improvement is distinct from hardware qualification and fingerprint protection.
