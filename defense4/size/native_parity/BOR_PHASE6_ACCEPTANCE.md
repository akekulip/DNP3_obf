# BOR Phase-6 offline acceptance + cross-artifact consistency review

Scope: the FAITHFUL two-pipe BOR+RRC (SELECT prepares a BOR epoch). This records (A) the
consolidated Phase-6 acceptance gate results and (B) an independent cross-artifact consistency
review of the design, the emulators, the P4, and the compile evidence. **Offline only — a
behavioral model is not a compile, and a compile is not silicon.** Nothing here was loaded on
hardware.

Runner: `offline/test_bor_acceptance_gate.py` (imports `bor_rrc_emulator.py`,
`bor_twopipe_faithful_emulator.py`, `rrc_emulator.py`). Reproduce:

```
$RESEARCH_PYTHON offline/test_bor_acceptance_gate.py        # 24/24 gates PASS, exit 0
```

## Part A — Phase-6 gate results (24/24 PASS)

Every gate in `autonomous_overnight.md` §"Phase 6: Offline acceptance gates" is asserted against
real emulator output. Overlapping gates are backed by BOTH the single-pipe (`bor`) and two-pipe
(`twopipe`) models; carve/reassembly/checksum gates also cross-check the frozen `rrc` model.

| # | Phase-6 gate | result | backing |
|---|---|:--:|---|
| 1 | First OPERATE after clean start is BOR-shaped | PASS | `bor.first_operate_shaped` & `twopipe.first_operate_shaped` & SR4-discrimination (fail-open-first correctly NOT shaped) |
| 2 | SELECT preparation completes before OPERATE admission | PASS | `twopipe.select_prepare_crosses_once` & `epoch_resident_before_operate` & `bor.reservoir_seeded_resident` |
| 3 | qid3 confirmed resident before qid2 admission | PASS | `bor.reservoir_resident_before_release` & `twopipe.epoch_resident_before_operate` |
| 4 | Original OPERATE byte-identical | PASS | `bor.operate_byte_identical` & `twopipe.released_byte_identical` |
| 5 | Exactly one original reaches the relay | PASS | `bor.exactly_once_operate_release` & `twopipe.relay_receives_operate_exactly_once` & `cross_pipe_operate_exactly_once` |
| 6 | `T_OP_RELEASE = T0 + J` | PASS | `bor.t0_anchored_deadlines` (release==T0+J) & `twopipe.release_at_T0_plus_J` |
| 7 | ACK release anchored to original `T0+A` | PASS | `bor.t0_anchored_deadlines` (ack==T0+A) & `twopipe.ack_echo_T0_anchored` |
| 8 | Echo release anchored to original `T0+R` | PASS | `bor.t0_anchored_deadlines` (echo==T0+R, R≥A) & `twopipe.ack_echo_T0_anchored` |
| 9 | Echo remains `[28,21]` | PASS | `bor` & `twopipe.echo_carved_28_21` & `rrc.both_option_fixtures_28_21` |
| 10 | Reassembly byte-exact | PASS | `bor` & `twopipe.echo_byte_identical` & `rrc.reassembly_byte_exact` |
| 11 | IP/TCP checksums valid | PASS | `bor`/`twopipe` echo checksum-verified & `rrc.checksums_valid` |
| 12 | No internal header leaves the switch | PASS | `twopipe` relay_rx payloads == byte-identical original (xpipe stripped) + native `[28,21]` echo |
| 13 | Missing preparation fails open (+counts) | PASS | `bor`/`twopipe.fail_open_when_reservoir_not_ready` & `bor.run_operate_only(no SELECT)`→fail_open |
| 14 | Invalid deadline config rejected | PASS | `BORConfig.deadlines_valid()`: good True; A≤Jmax+ackb / R≤Jmax+respb / R<A / >horizon all rejected |
| 15 | Timestamp-negotiated cannot claim anti-subtraction | PASS | `anti_subtraction_holds`: ts-off True, ts-on False via the `tcp_tsval` channel |
| 16 | Public DNP3 sequence does not predict J | PASS | `scale.public_not_oracle` & clean `observer_cannot_recover_J` & `public_sequence_selects_j` mutant leaks |
| 17 | Random buckets match configured bounded support | PASS | each `j_index`→`codebook[j_index]`; selected-J set == configured codebook `{0,2,4,6,8,10,12}` |
| 18 | Retransmission never causes a second operation | PASS | `bor.exactly_once_under_retransmit` & `twopipe` retransmit + double-cross exactly-once |
| 19 | FIN/RST clears state | PASS | shared retire/teardown clears epoch/ready; later stray OPERATE fails open (design §6)* |
| 20 | ≥1000 modeled transactions pass | PASS | `bor.run_scale_driver(1000).all_ok`, every per-txn invariant 1000/1000 |
| 21 | Multiple 4-bit sequence wraps pass | PASS | `bor.run_seq_wrap_driver(4).all_ok` (4×0..15) & `twopipe.seq_wrap_stray_fails_open` |
| 22 | Every required mutant killed | PASS | 12/12 required `bor` mutants + 8/8 `twopipe` mutants killed |
| 23 | Frozen RRC regression stays green | PASS | `rrc` clean all-pass + 8/8 `rrc` mutants killed + `bor` clean all-pass |
| 24 | READ/SELECT/OPERATE share the response engine | PASS | `rrc.all_functions_arm_same_engine` & `carve_type_agnostic` & `select_retires_before_operate` |

\* **FIN/RST caveat (honest):** the emulators carry no distinct FIN/RST packet event.
`BOR_RRC_DESIGN.md` §6 routes FIN/RST to the same retire/teardown path used at OPERATE release, so
gate 19 checks that teardown CLEARS state (no pending epoch/ready/gen; a later stray OPERATE fails
open). A dedicated FIN/RST-frame path is a hardware/control-plane obligation, not modeled here.

**Non-vacuity:** injecting a broken emulator result (e.g. forcing `released_byte_identical=False`)
flips the corresponding gate to FAIL and `all_pass()` to False; each mutant gate is backed by a
mutant that genuinely breaks its target invariant.

## Part B — cross-artifact consistency review

Compared: design (`BOR_RRC_DESIGN.md`), emulators (`offline/bor_rrc_emulator.py`,
`offline/bor_twopipe_faithful_emulator.py`, `offline/rrc_emulator.py`), P4
(`p4/defense4_twopipe_pipe0_probe.p4`, `p4/defense4_twopipe_pipe1_faithful_probe.p4` — read, not
edited), compile evidence (`evidence/bor_two_pipe_faithful/COMPILE_MATRIX.txt`,
`BOR_TWO_PIPE_FAITHFUL_RESULT.md`), and the control-plane assumptions.

### Verdict: NO LOAD-BEARING DISAGREEMENT FOUND.

On all five asked-for axes the design, the emulators, and the P4 agree; the compile evidence
matches the split the emulator assumes. The one substantive limitation (leak-safe J is still a
per-flow codebook placeholder, not the random selector) is **disclosed identically in the P4, the
design, and the result doc** — it is a not-yet-built item, not a contradiction between artifacts.

**1. Epoch / readiness ordering vs the emulator's SELECT-prepares-epoch model — MATCH.**
- P4 pipe1 `PC_PREPARE`: `epoch_prepare` (`reg_epoch := epoch_in`), `ready_clear` (`reg_ready := 0`),
  `gen_clear` (`reg_gen := 0`), `arm_clone()` (seed qid3 for the epoch), then forward the SELECT
  byte-identically to the relay (pipe1 lines 509, 520-521, 548-549, 582-587). A live qid3 token
  (`PC_TOKEN`, `blk_live`) runs `ready_confirm` (`reg_ready := epoch`) — residency confirmed BEFORE
  the OPERATE (pipe1 lines 536-545). `PC_OPERATE` requires `op_matched` (`reg_epoch==epoch_in`) AND
  `op_ready` (`reg_ready==epoch_in`), `V_OP_FRESH` → `hold_and_arm`→`to_op_hold`; else fail-open
  forward (pipe1 lines 556-609).
- Emulator mirrors this exactly: `receive_prepare` (bor_twopipe lines 184-199), `confirm_residency_if_due`
  (202-205), `receive_operate` (208-229).
- The serialization `epoch → blk_live → reg_ready → op_ready → hold_ok → topj` (P4) is the same
  data dependency the emulator's SELECT-prepare→OPERATE-consume order encodes, and is the +4-stage
  cost the compile evidence reports honestly (`COMPILE_MATRIX.txt` L26-31; `BOR_TWO_PIPE_FAITHFUL_RESULT.md`
  "honest negative"). Pipe0 allocates the epoch on SELECT and re-reads it on OPERATE (`epoch_alloc`/
  `epoch_read`, pipe0 lines 1767-1772, 3119-3133), stamping the SAME epoch into `xpipe.epoch` on both
  crossings (pipe0 lines 3436-3443, 3487-3492) — matching `Pipe0.select`/`Pipe0.operate`.

**2. ACK/echo anchored to T0 (not T0+J) — MATCH.**
- P4 pipe0 arms `reg_deadline := T0+A` (`bor_ack_cand`) and `reg_tresp := T0+R` (`bor_resp_cand`),
  computed from now-at-OPERATE = T0, with the explicit invariant "the ACK/echo release instants are
  T0-anchored and NEVER re-anchored to the delayed release or the relay ACK (anti-subtraction §2)"
  (pipe0 lines 3067-3088). ACK/echo T0-anchoring lives on pipe0; the OPERATE hold+`reg_topj=T0+J`
  lives on pipe1 — the same split the emulator uses (`Pipe0.operate` sets `reg_deadline=T0+A`,
  `reg_tresp=T0+R`, bor_twopipe lines 123-124; pipe1 owns `reg_topj`).
- The `reanchor_ack_to_release` mutant (bor_twopipe lines 144-146; single-pipe
  `deadline_reanchored_to_operate_release`) is KILLED, matching the P4's "never re-anchored"
  invariant. Design §1/§2 states the same.

**3. J from a leak-safe selector (not the epoch, not the DNP3 sequence) — MATCH, with a disclosed
placeholder (ranked #1 below).**
- P4 pipe1 selects J from `tbl_bor_codebook` keyed on `hdr.tcp.dst_port`, "NEVER on any public DNP3
  application value and NEVER on the BOR epoch" (pipe1 lines 435-444); `reg_topj := T0+J` (pipe1 lines
  378-384, 461, 527). Pipe0 is compiled `-DBOR_NO_TOPJ` (`evidence/.../pipe0/compile.cmd`), so
  J-application is removed from pipe0 — J is owned by exactly one pipe (pipe1), as the emulator assumes.
- Emulator `Pipe1._select_j` uses the secret `j_index`, never `app_seq`, never the epoch
  (bor_twopipe lines 178-181); `j_from_public_seq` / `public_sequence_selects_j` mutants are KILLED.
  Design §7 requires a leak-safe source and forbids deriving J from public DNP3 sequence values.

**4. Exactly-once enforced in the P4 (pipe0 dedup + pipe1 dedup) — MATCH.**
- Pipe0 dedup: `reg_tag` arm-once; a retransmitted OPERATE reads `V_ARM_DUP` → `D3_DROP()`
  (`CF_OP_RETRANS_SUPP`); a fresh OPERATE crosses exactly one ucast copy to `PORT_X1` (pipe0 lines
  3426-3467). Matches `Pipe0.operate` (DUP → no second cross, bor_twopipe lines 131-139).
- Pipe1 dedup: `reg_gen`; `V_OP_DUP` → `OP_DROP()` (`CF_OP_RETRANS`), defence-in-depth for a pipe0
  dup-drop miss / a cross-pipe double-cross (pipe1 lines 363-375, 590-592). Matches
  `Pipe1.receive_operate` (bor_twopipe lines 211-213) and the emulator's
  `double_cross_backstopped_by_pipe1_dedup` check. `pipe0_cross_twice`, `pipe1_duplicate_release`,
  `pipe1_no_dedup` mutants are all KILLED.

**5. Deadline constraints identical across design / emulator / P4-comment — MATCH.**
- Design §1: `A > J_max + native_ACK_bound`, `R > J_max + native_response_bound`, `R ≥ A`, and
  `A, R, J_max < min(op-latency, master-timeout−guard, TCP-retransmit−guard, fail-open horizon)`.
- Emulator `BORConfig.deadlines_valid()` (bor_rrc lines 101-105): the same three inequalities plus
  `max(A,R,J_max) < watchdog_horizon` (the fail-open horizon member of the design's `min()` set).
- P4 pipe0 comment: "Constraints A>J+ackbound, R>J+respbound, R>=A are CP-validated" (pipe0 line 438);
  the P4 correctly defers enforcement to the control plane, since a P4 constant cannot bound a
  runtime write (design §1). Gate 14 exercises all four rejection cases.

### Ranked findings (disclosed limitations — none is an inter-artifact contradiction)

1. **Leak-safe J is a per-flow codebook placeholder, not the random selector (most load-bearing).**
   The compiled pipe1 keys J on `hdr.tcp.dst_port`, which yields a DETERMINISTIC per-flow J. The
   design §7 and the emulator's anti-subtraction argument intend a per-transaction RANDOM/secret J
   (`Random<>`/salt). Both channels the observer can read (response-timing, TCP-TSval) are closed by
   T0-anchoring + no-TS regardless of J's randomness, so this does not break the modeled
   anti-subtraction gate; it matters for cross-device shaping toward a common target and for
   unpredictability. **This is disclosed identically** in the P4 ("The production build swaps this for
   a leak-safe Random<>/salt source", pipe1 line 437), design §7, and
   `BOR_TWO_PIPE_FAITHFUL_RESULT.md` — a not-yet-built item, not a disagreement.
2. **Anti-subtraction requires a no-TCP-timestamp protected flow (MVP boundary).** Design §2; enforced
   as a violation counter on pipe0 (`ctr_ts_viol`, pipe0 lines 3181-3188) and modeled by
   `tcp_ts_enabled` + the `tcp_timestamp_subtraction` mutant (gate 15). Consistent across artifacts;
   listed so it is not read past.
3. **Compile ≠ silicon.** `COMPILE_MATRIX.txt` and `BOR_TWO_PIPE_FAITHFUL_RESULT.md` state (and the
   emulator docstrings repeat) that placement + the behavioral lifecycle are proven, but NOT the
   cross-pipe MAC-loopback timing, the qid3 residency-continuity sizing (budget/rate vs J), or the
   physical operation-time divergence floor. All artifacts agree; nothing is loaded on hardware.

### Compile evidence cross-check (consistent)

`evidence/bor_two_pipe_faithful/`: pipe0 `-DTWO_PIPE_PIPE0 -DBOR_NO_TOPJ -DPIPE0_ARM_FOLD
-DPIPE0_SELECT_PREP`, exit 0, INGRESS=12 EGRESS=3, 143 tables, 0 errors; pipe1 (no flags), exit 0,
INGRESS=10 EGRESS=0, 52 tables, 0 errors. Real `tofino.bin` for both. The `-DBOR_NO_TOPJ` pipe0 flag
confirms J-application is on pipe1 only — exactly the split the emulator encodes.
