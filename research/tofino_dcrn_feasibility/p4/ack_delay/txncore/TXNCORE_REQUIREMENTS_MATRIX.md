# Transaction Core — Requirements Traceability Matrix

Maps each required transaction-core behavior to its code location, test, status, and **validation level**.
Produced in the offline fallback (dp8 blocked). The validation-level column uses the seven-level scale and
is never inflated: nothing below is BMv2-, Tofino-, or SEL-validated.

**Validation levels:** `impl` (implemented) · `compiled` (bf-p4c PASS) · `offline` (reference model +
unit/replay tests) · `bmv2` · `tofino-partial` · `tofino-full` · `sel`.

Code refs: `RM` = `txncore_refmodel.py`; `P4` = frozen `dcrn_defense1.p4`; `GEN` = `dcrn_defense1_gen.p4`
(generation-carried variant, compiles 12/12). Tests: `T` = `tests/test_txncore.py`; `R` = `replay_txncore.py`.

| # | Requirement | Code location | Test | Status | Validation level |
|---|---|---|---|---|---|
| 1 | DNP3 request recognition | RM `process` ARM; P4:487-496 | T`test_read_arms_flow` | done | offline; P4 compiled |
| 2 | DNP3 response recognition | RM `_reverse_response`; P4:615-627 | T`test_response_admitted_behind_held_ack` | done | offline; P4 compiled |
| 3 | Physical direction | RM `is_tcp_dnp3_fwd/rev`; P4:385,438,441 | T`test_read_wrong_direction_not_armed` | done | offline (logic). NOTE: silicon gates on physical port — validated on Tofino for the *shadow* dir-1 only, NOT the txncore |
| 4 | Request/response correlation | RM `exp_ack`; P4:494-495,571 | T`test_qualified_ack_is_held_once` | done | offline |
| 5 | Transaction creation | RM ARM (gen bump, armed=1) | T`test_read_arms_flow` | done | offline |
| 6 | Transaction completion | RM RESP release | T`test_held_response_releases_after_ack_gone` | done | offline |
| 7 | Unrelated TCP ACK handling | RM `_reverse_pure_ack` qualify=0 | T`test_ack_wrong_ackno_not_held`, `test_ack_without_arm_is_forwarded` | done | offline |
| 8 | Retransmissions | RM re-arm (same exp_ack) | T`test_retransmitted_read_rearms_same_expack` | done | offline |
| 9 | Duplicate requests | RM re-arm (new gen) | T`test_second_distinct_request_rearms_and_stales_prior_hold` | done | offline |
| 10 | Duplicate responses | RM `_reverse_response` post-drain | T`test_second_response_after_completion_bypasses` | done | offline |
| 11 | Multiple sequential transactions | RM one-outstanding/flow | R (300 sequential) | done | offline |
| 12 | Concurrent/overlapping (cross-flow) | RM per-flow_id independence | T`test_no_collision_flows_independent`, `test_collision_stale_frame_discarded_not_misreleased` | done | offline. INVARIANT: single-outstanding **per flow** |
| 13 | Timeout / expiration | RM `release_pass` maxpass | T`test_held_ack_releases_at_maxpass` | done | offline |
| 14 | TCP sequence behavior | RM 32-bit modular `exp_ack` | T`test_expack_wraps_32bit` | done | offline |
| 15 | DNP3 transport sequence | — | — | **N/A — documented limitation** | correlation keys on TCP seq/ack, not the DNP3 transport sequence; the frozen P4 does the same |
| 16 | DNP3 application sequence | shadow classifier only | — | **N/A — documented limitation** | app_seq is used by the Phase-1 *classifier* (`shadow_refmodel`), not by txncore correlation |
| 17 | Malformed traffic | `shadow_refmodel.classify` MALFORMED | shadow `test_shadow_negative.py` (magic/truncated) | done | offline |
| 18 | Unsupported function codes | RM `fc_ok=False` → ARM_BYPASS; P4 `fc_allowlist` | T`test_arm_bypass_when_fc_not_allowed` | done | offline; P4 compiled |
| 19 | Non-DNP3 pass-through | RM PASSTHRU branch | T`test_non_dnp3_forwarded_no_state` | done | offline |
| 20 | Register initialization | RM `FlowState` defaults 0; P4:366-370 seeded 0 | covered by every fresh-flow test | done | offline; P4 compiled (structural) |
| 21 | Register wraparound / exhaustion | RM gen mod 256, seq mod 2³²; flow-table collision | T`test_generation_rolls_over_mod_256`, `test_collision_*` | done | offline |
| 22 | Disabled-mode behavior | RM `enabled=False` transparent | T`test_disabled_is_transparent_no_state` | done | offline |
| 23 | No controller in fast path | P4 arm/hold/release all in ingress datapath; control plane installs only `fc_allowlist` + seeds `reg_gen` | (structural review) | done | compiled (structural) |

## Offline gate — status

| Gate item | Result |
|---|---|
| P4 compile succeeds (`dcrn_defense1_gen.p4`, bf-p4c 9.13.1) | **PASS** (exit 0) |
| Compiler warnings recorded | 2 benign TNA parser warnings (`max_loop_depth` unroll); 0 errors |
| Pipeline stage usage recorded | **12/12 ingress** (stages 0–11); `reg_gen` at stage 5 |
| Resource use recorded | matches frozen Defense-1 profile (SRAM 55, TCAM 0, SALU 9 per plan §5); logs in `evidence/` |
| Phase-1 classifier regression passes | **PASS** (`shadow/replay_shadow.py` + 14 negatives) |
| Transaction-core positive tests pass | **PASS** (subset of 24 in `tests/test_txncore.py`) |
| Transaction-core negative tests pass | **PASS** (stale/dup/abort/malformed/wrong-dir/wrong-fc) |
| Disabled mode preserves Phase-1 baseline | **PASS** (`test_disabled_is_transparent_no_state` — transparent, no state) |
| Malformed / unsupported behavior matches spec | **PASS** (fc-bypass + malformed classification) |
| No controller introduced into the fast path | **PASS** (structural — all datapath in ingress) |

## Explicit boundary (not done — human-gated)

Generation **enforcement** (the recirc `reg_gen` read that actually discards stale stragglers) does **not
fit** the 12/12 Defense-1 variant (`COMPILE_FIT_RESULT.md`). Only generation *carried* is compiled here.
Enforcement requires a compact redesign = a human-authorized architecture decision. Requirements #9/#12/#21
are validated **as logic** (reference model); their silicon enforcement inherits that open decision.
**No item above is hardware- or relay-validated.**
