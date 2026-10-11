# T's queue-resident timing role: source-level complete; whole file compiles for Tofino-1 (11/0 stages)

Status of `read_queue_timing.p4`, the blocker-queue-based replacement for T's heartbeat/recirculation
design (`read_timing.p4`), per `INTEGRATION_CONTRACT.md` §5's hard constraint that real ACKs/responses
stay queue-resident and only blocker tokens circulate.

## Current state (2026-10-09, latest): the whole file compiles on both SDKs, 11 ingress / 0 egress stages

**Whole-file compile** of `read_queue_timing.p4`, sha256 `b3470a690e89…`: **exit 0** on local 9.13.1
(`final7_full_local`) and on the switch's installed 9.13.2, compile-only (`final7_full_switch_9132`). Both
report 11 ingress / 0 egress stages, critical path 9, and 54 match + 5 action + 21 condition + 15 stateful
tables. The OPERATE slice compiles at 8 / 0 and the capture slice at 3 / 0. Tests:
`python3 -m pytest -q read/tests core/harness/tests` gives 195 passed (`final8_pytest.txt`; 193 at `final7`). Nothing has been
loaded or run on the switch.

**Local Tofino-1 model run of the whole compiled program** (`route_ab_01/model_t_queue_03`, driver
`read/model_drive_t_queue.py`, build `final7_full_local`): **20 of 20 checks pass**. Seven phases of real
packets on T_IN, with the mirror session bound locally, were compared against the interpreter (`QueueSim`)
replaying the same events at a scaled time base (`--predict` prints its prediction):
- A: READ request, ACK, response and a duplicate response.
- B: an ACK released by readiness fallback, then a late response.
- C: an OPERATE held and released.
- D: an OPERATE followed immediately by RESET (the clone-window case).
- E: a quarantined-epoch request and ACK.
- F: RESET while an ACK is held.
- G: policy off.

What matched in every phase: the released frames, in order, on the forward (9) and relay (64) ports; every
decision counter delta (`OUT_ACK_COMMIT`, `OUT_RESP_RELEASE`, `OUT_RESP_DUP_DROP`, `OUT_OP_RELEASE`,
`OUT_HELD_STALE_FLUSH`, `OUT_ACK_FALLBACK`, `OUT_RESP_FALLBACK`, `OUT_HELD_OFF_FLUSH`, `OUT_REQ_BYPASS`,
`OUT_UNMATCHED`); and the final generation registers (READ 5, OPERATE 4, quarantined epoch 2). In phases
A, B, C and F the held originals waited 9 to 28 recirculation laps on the model before release
(`OUT_HELD_REWAIT`), so the holds are real.

Limits of this run:
- **Functional only.** The model clock moves in about 1 ms quanta and one pass costs several ms, so no
  timing claim is made.
- **No packet generator.** Without it there are no READ blocker tokens, and token and re-wait counters are
  not compared. Strict-priority residency was not exercised.
- **Not exercised:** two response children, and pipe-local ports outside 324–327.
- `model_t_queue_01` stopped before phase G on a driver bug (passing `enabled` twice); `model_t_queue_02` is
  the same run before the lap check was added (16 of 16).

**The model run shows the try register actions return the value from BEFORE their write.** Each `*_try`
action returns `value ^ generation` and then writes the generation. If the compiled register unit
returned the just-written value instead, the result would always be 0 ("already done or duplicate"). The
run rules that out for each action separately:
- **`child_try*`:** the first response would read as a duplicate and be dropped. In phase A the first
  response (`a2`) was released and only the real duplicate was dropped (`OUT_RESP_DUP_DROP` = 1).
- **`ack_done_try`:** the commit-path writes are gated on `done_diff != 0`, so a_commit would never be
  recorded and the response would fall back. Phase A has `OUT_ACK_COMMIT` = 1, `OUT_RESP_RELEASE` = 1 and
  `OUT_RESP_FALLBACK` = 0.
- **`resp_done_try`:** a readiness-fallback commit would hit the `done == 0` row and be counted as a
  release. Phase B has `OUT_RESP_FALLBACK` = 1 and `OUT_RESP_RELEASE` = 0.
- **`op_done_try`:** the releasing pass would hit the `done == 0` row and re-wait indefinitely. Phase C
  has exactly one relay emission (`c0`) and `OUT_OP_RELEASE` = 1, after 10 laps held.

**Control-plane reset rule.** These registers reset to 0xffffffff, not 0, and any control-plane clear or
re-initialization must restore 0xffffffff:
- `child_seen0_reg`, `child_seen1_reg`, `child_seen2_reg`
- `ack_commit_gen_reg`
- `quarantine_reg`

Each is compared for equality with a live READ generation or epoch, and 0 is both the live generation
before the first request and a possible epoch. A zeroed `quarantine_reg` would quarantine epoch 0. In
generation 0 a zeroed child register cannot drop a response: `resp_done_reg` also resets to 0, so a
generation-0 response passes through as already released, before any duplicate check. Tests:
`K_ResetValues` pins the reset values (it fails on a zero-initialized variant) and that generation-0
behavior. The rule is also stated next to the child registers and `ack_commit_gen_reg` in
`read_queue_timing.p4`. `quarantine_reg` has no such comment yet; adding one would change the source bytes
that the compile and model evidence above are tied to, so it is left for the next source change. No
controller or core code reads or clears these registers today (checked by grep of `controller/*.py` and
`core/*.py`).

**What closed it** (rounds `b35`..`b40`; scripts `b35_verdict_tables/consolidate.py`, `child_regs.py`).
Every step is behavior-preserving at the source level, and the full suite passed after each one.
- **Per-port verdict tables (`b35`).** Each port's terminal decision is one const-entries ternary table
  (`tin_verdict`, `token_verdict`, `held_verdict`, `hb_verdict`) instead of a chain of gateways and
  one-action tables. Rows keep the original if/else priority.
  - Two-field equalities become "== 0" keys through XOR diffs: `lgen_diff`, plus `done_diff` returned by the
    done registers as `value ^ generation`.
  - "!= 0" is expressed by an earlier row that matches 0.
  - The `*_sign` tables are gone; deltas are keyed on their sign bit directly.
  - The go tables (`ack_go_check`, `resp_go_check`, new `op_go_check`) now include liveness, so each try
    register action runs for its whole role and writes only on a live pass.
  - Result: 116 → 49 tables and 32 → 18 gateways, and "too many tables total" disappeared.
- **No write-after-write between two call sites of one register (`b36`).** The RESET-path OPERATE
  generation bump no longer writes `md.op_gen`, and it is chained `else if` with the OPERATE arm.
- **Gateway chains ordered by stage (`b37`, `b38`).** bf-p4c places a gateway together with the first table
  it guards, so a late branch first in an else-if chain held every later branch back. The held-return role
  chain now runs held ACK, ACK blocker, held response, response blocker. The response-only reads of
  `ack_commit_at_reg` and `ack_commit_gen_reg` moved into the response branches. The N-input read of
  `resp_done_reg` has its own gateway.
- **Seed actions read `batch_id` before invalidating the timer header (`b38`).** The consolidation had
  briefly read it after `setInvalid()` (a compiler warning; the read value is undefined).
- **Per-child response registers (`b40`).** With placement solved, the assembler rejected the
  `{gen, mask}` pair's masked condition `(value.mask & BIT) != 0` ("Syntax error, expecting register
  slice"; swapping field order does not help, `b39`). It was replaced by `child_seen{0,1,2}_reg`, each
  holding the READ generation in which that child was last admitted. Same semantics. Initial value
  0xffffffff, which must be restored on any clear.

**Fit headroom.** 11 of 12 ingress stages, with egress unused. Any addition on the ingress critical path
must be checked against that one spare stage.

**Composition with the B' response path: a proof of concept for the T-to-response-path join only
(`route_ab_01/compose_t_response_01`).** It is NOT evidence that the full system fits or works. See
"What it does not show", which incorporates an adversarial review (2026-10-09) and this session's
read-only checks.

Per `STEP3_DESIGN.md` option C, T runs in pipe 2's ingress. The front-panel ports, including FORWARD 9 and
RELAY 64, are all in pipe 0, so the response path's egress belongs in pipe 0's egress.
`read/compose_t_response.py` builds one multi-pipe program with `Switch(p0, p1, p2)`:
- p0 is the committed `protocol/case4_response_path.p4` pipeline. Its 1-stage forwarding ingress is a
  stand-in for N.
- p1 is a drop-only stand-in for M.
- p2 is T unchanged.

What it shows:
- **Compile.** It compiles on 9.13.1 and 9.13.2 (compile-only) with identical per-pipe results: p0 1 / 12
  stages, critical path 11; p2 11 / 0, critical path 9.
- **No metadata crosses.** T emits only the original Ethernet frame on every release and flush path
  (confirmed by the review on all paths), and the response path's egress parser starts at Ethernet.
- **T's holds and clones stay in pipe 2.** They use ports 326, 327 and 324 and run pipe 2's empty egress.
- **Model run `model_join_02`, 6 of 6.** The pipe-0 egress pass count rose by exactly the number of frames
  T released.
- **Model run `model_padded_01`, 14 of 14** (driver `read/model_drive_t_padded_flow.py`). With the
  connection armed in pipe 0's egress, a READ ran through T. T's released response left pipe 0 padded,
  byte-exact to the software oracle (`case4_response_mapper` with the pad58b codec), with exactly one
  pipe-0 egress outcome per released frame.

What it does not show (open):
1. **N's real traffic never reaches pipe 0's egress.** N's `route()` and every handoff action set
   `tm.bypass_egress = 1` (`installed_nf_05/source/nf.p4`). The padded run worked only because the stand-in
   forwarding stub leaves `bypass_egress` at 0. The handshake that arms the mapper went through the stub.
   With real N it would skip egress, the mapping would never be armed, and even T's released response
   would not be padded. A real N change is needed: clear `bypass_egress` on N's forwards to 9 and 64.
2. **PHV in pipe 0 is over budget, by measurement.** Counted from `installed_nf_05`'s
   `phv_allocation_summary_0.log`, 32-bit containers holding ingress fields: 48; egress fields (the final
   emitter): 14; 62 of 64 in total, matching `SELECTED_PATTERN.md` gate 4's "2 free". The response path's
   egress needs about 19 more 32-bit containers. That is about 67 / 64 if the emitter is retired, and
   about 81 / 64 if it stays (the review estimated about 84). Either way this is a real resource problem.
3. **Stages in pipe 0's egress.** The emitter's 4 stages plus the response path's 12 is 16 against 12 in
   the worst case. The two handle disjoint packets (the emitter only takes its prefixed port-2 traffic),
   so an `egress_port`-branched merge might fit, but that is a dedicated compile effort, not a small change.
4. **The M stand-in drops real traffic.** Real N sends SELECT, replay and reverse traffic to pipe 1
   (`activate_select`, `emit_replay`, `reverse_to_m`). The stub drops all of it, which would break SBO.
   Whether B' retires M (with N re-routed) or gives M a real interface into pipe 0's egress is an open
   design decision.
5. **The OPERATE legs are synthetic relative to the installed N.** The tests inject T's kind-12 OPERATE tev
   directly. The installed N (`nf.p4`, `n.p4`) hands only kinds 9, 10 and 11 to T; its internal kind 12 is
   replay (`emit_replay`). Only `connection/binding/native_binding.p4` maps N's OPERATE (internal kind 7)
   to T's kind-12 tev (`emit_tev(16w0x0c00)`; see `read/tests/test_n_operate_handoff.py`).
6. **OPEN: N's handling of a retransmitted response after T released the original.** This is separate
   from the review's original claim, which the source does not support: T drops a duplicate response only
   while the original is still held. After release, `resp_done == cur_gen` forwards a retransmitted
   response unchanged (`test_duplicate_response_is_suppressed_only_while_the_original_is_held`), so T does
   not block the mapper's replay path. What is unknown is N's part:
   - if N hands the outstation's retransmission to T, it reaches pipe 0's egress and the mapper replays
     the committed image;
   - if N forwards it natively with `bypass_egress = 1`, it skips the mapper, and a response lost after the
     switch has no recovery path through the mapper.

   This must be traced in N's source before the composition can claim loss recovery.
7. **Semantic gap, documented and not fixed.**
   - **Flushes look like releases.** T gives the mapper no signal that a frame is a stale or policy-off
     flush rather than a timed release, so a flushed response is committed and padded exactly like a
     released one.

**M's role: a bounded investigation (read-only, 2026-10-09).** Recommendation: retire M, the E cache and
the final emitter for the response-only B' profile.

All four N-to-M paths in `installed_nf_05/source/nf.p4` serve the old request-side padding design:
- `emit_select` sends the master's SELECT (kind 5) to port 196;
- `activate_select` sends SELECT readiness (event 0x0714);
- `emit_replay` sends replay (kind 12);
- `reverse_to_m` sends master-side segments of packet kinds 3 and 6 to port 199.

Evidence for that:
- M's own header reads "ordinary SELECT M prepare: actual N28 handoff, full native35 validation, captured
  decoy construction". M appends a decoy CROB to the native 35-byte SELECT (55-byte padded payload), E caches
  that image, and the final emitter (`f_captured_decoy_h`) sends it.
- `reverse_to_m` translates sequence numbers only because the request stream got longer.
- B' leaves requests native, pads only responses in the response path's egress, and does its own
  response-side sequence and ACK translation there.
- SELECT-to-OPERATE state is N's, not M's: `connection/binding/native_binding.p4` reaches the
  OPERATE-admitting owner state with a native SELECT and hands OPERATE to T (`test_n_operate_handoff.py`).
- `native_binding.p4` already has no `emit_select`, `activate_select` or `reverse_to_m`; only `emit_replay`
  still points at M.

Retiring them also frees N's ingress state for the protected SELECT (ready/activation/completion and
cached-owner handling) and its PHV. That is the resource pipe 0 is short of (item 2).

**The `bypass_egress` fix is NOT independent of this decision.** N's `route()` (`nf.p4`, `n.p4` and
`native_binding.p4` alike) sets `bypass_egress = 1`. Clearing it while the final emitter occupies pipe 0's
egress would drop all of N's forwarding: the emitter's parser rejects every packet not bound for port 2
(`select(eg.egress_port){9w2: emit_reference; default: reject;}`), `m.parsed` stays 0, and its `apply` calls
`deny()`. So the fix has to land together with retiring the emitter, or with giving it a pass-through
branch. It has not been made.

Rough scope of the re-routing, if M is retired:
- start N from `native_binding.p4`'s routing (native SELECT, OPERATE to T);
- remove `emit_replay` and the protected-SELECT ready/activation/completion paths and their state;
- clear `bypass_egress` on forwards to 9 and 64;
- pipe 0 = that N plus the response path's egress; pipe 2 = T.

Then compile it with real N and read the pipe-0 PHV and stage report.

**Approved and done (2026-10-09): response-only N and the first real pipe-0 compile
(`route_ab_01/response_only_01`).**

*N.* `core/response_only/make_n.py` derives `n_response_only.p4` from `native_binding.p4`, which is left
untouched. Each edit is asserted to match once:
- `route()` no longer sets `bypass_egress`. Every remaining `bypass_egress = 1` targets N's recirculation
  port 68, so the mapper sees each packet only on its final pass.
- The one-byte "replay_byte" segment is no longer classified as kind 12; it is forwarded natively.
- `STEP3_M_PORT`, `emit_replay` and its terminal row are removed, so N has no path into pipe 1.

*Composition.* `core/response_only/compose.py` builds:
- p0 = that N's ingress + the response path's egress;
- p1 = drop-only (M retired);
- p2 = T.

*Results.*
- **Standalone:** current `native_binding.p4` (`66e0be760966`) and the derived N (`3935e1a8e8ef`) each
  compile at 12 ingress / 0 egress, critical path 11. N alone fills pipe 0's ingress exactly. The response
  path alone is 1 / 12.
- **Joined:** the composite **fails PHV allocation** on both 9.13.1 and the switch's 9.13.2, identically:
  4 field slices unallocated (`ingress::m.packet_kind`, `ingress::m.work_op`, `egress::m.has_mss`,
  `egress::m.shape`, all 8-bit).
- **Container use in pipe 0:** every normal container is used. 8-bit 64 / 64 (ingress 40, egress 24);
  16-bit 96 / 96 (59, 37); 32-bit 64 / 64 (36, 26, plus 2 unattributed).
- **Stages:** both gresses fill exactly 12 each when alone. The joined placement attempts reached 13–14
  ingress and 11–16 egress under PHV pressure, so stages will need re-checking once PHV fits.

**Most promising reclaim, not yet attempted:** the request-padding residue still inside N. Two registers
(`frozen_decoy_off`, `frozen_decoy_object`), their store and compare actions for SELECT, OPERATE and
responses, and about 250 bits of metadata (`decoy_*`, `compare_frozen_decoy_*`, `diff_frozen_decoy_*`). In
the retired design these froze the appended decoy CROB so the OPERATE matched the SELECT. With native
requests there is no decoy, but the state sits inside N's SELECT-before-OPERATE comparison. It needs a
producer/consumer map before anything is removed.

**Producer/consumer map of N's decoy state (read-only, 2026-10-09): it is NOT simply dead, and N's
whole SELECT-before-OPERATE association assumes the retired request insertion.** Not removed.

*The decoy chain:*
- **Producer:** the control-plane action `data_connection.configure(index, code, repeat, on, off)` sets
  `m.decoy_*`.
- **On SELECT:** `compare_select_inputs` copies those values, and `frozen_decoy_object_t` /
  `frozen_decoy_off_t` store them.
- **On OPERATE:** `compare_operate_inputs` compares the same configured constants, which is a tautology.
- **On the response:** `compare_response_inputs` takes the response's own bytes (`hdr.second.w3`,
  `hdr.response_tail.w0/w1`), where the outstation echoes the decoy CROB of a padded SELECT, and compares
  them with the stored values.
- **Consumer:** the only reader is `object_match`, which requires both differences to be 0.

*Request-insertion offsets elsewhere in N* (`native_binding.p4`, carried into `n_response_only.p4`):
- SELECT: `native_end = seq + 55`, a native 35-byte SELECT plus the 20-byte inserted decoy.
- Response: `native_start = ack - 55` (the server ACKs the padded SELECT); the response is a 57-byte frame
  carrying the echo; `compare_server_start` for the OPERATE is `ack - 57`.
- OPERATE: positions `seq + 20` .. `seq + 75`.
- `sequence_guard`: `seq_ok_second` accepts the client advancing by exactly 20.
- N's own exchange test (`connection/binding/tests/test_step3_exchange.py`) says so: "after one insertion
  the server acknowledges native + 20, after two native + 40".

*Why this matters under B'.* The SELECT stays 35 bytes, so the server ACKs `seq + 35`, and responses carry no
decoy echo. Responses are padded only later, in pipe 0's egress, so the master's OPERATE reaches N with ACK
numbers in the padded response space, which N's ingress cannot translate. Removing the decoy state would
probably let pipe 0 compile, but N would still never admit an OPERATE, so it would not yield a working
system.

**Decision needed:** re-specify N's SELECT/OPERATE association for B'. Then rework N to it (which removes the
decoy state as a side effect), recompile pipe 0, and model-run the real composite. Something like:
- SELECT native, ACKed at `seq + 35`;
- the response checked in native (outstation-side) space at N's ingress;
- the OPERATE's ACK interpreted in the master's padded space, with the per-class padding delta, which is
  fixed for B' (CONTROL +19, READ +9).

The coordinator resolved this differently: N never sees padded coordinates. The decision is recorded below.

**Done (2026-10-10): N_ACK_RETURN loop, native-coordinate N, review fixes C1–C3 and W1–W2 (with W2's two
residual loop paths), an E checksum defect found and fixed, and the full composite passes on the local
model, 29 of 29 (`route_ab_01/response_only_10`).** Nothing is committed. Nothing was loaded on the switch;
9.13.2 was used compile-only. The model run is functional only: not hardware, not timing.

*N's binding, corrected at its generator.* `connection/binding/generate.py` gains
`generate(profile='response_only')`. The default `generate()` is unchanged: its output is still
byte-identical to the committed `native_binding.p4`, and the binding suite is unchanged at 85 passed. The
profile applies asserted single-match edits:
- the 37-byte native response (`rtail_h`, IP length 77); the second/response_tail headers are dropped;
- native offsets: SELECT end `seq + 35`; response `native_start = ack - 35`; OPERATE compare
  `server_start = ack - 37`; `next_response = seq + 37`; `ack_native = ack`;
- the `seq_ok_second` (+20) row is removed;
- the frozen-decoy registers, tables, the 12 `compare_frozen_decoy` assignments and `object_match`'s two
  decoy key columns are removed, as is the now-unused `hash_second`;
- **`response_profile` keeps the CROB-status requirement as `hdr.rtail.status == 0` (review C1).** The
  legacy key `second.w1[15:0] == 0x000c` was the real status byte plus the decoy group byte. A first version
  of the profile dropped it, so a SELECT the outstation refused still advanced N, and N then admitted the
  OPERATE.

*N_ACK_RETURN* (`core/response_only/make_n.py`, edit groups 4, 6 and 7):
- **Every master-side IPv4 TCP packet takes the lap (review C2).** `ports` is keyed
  `(ig.ingress_port, hdr.ip.isValid(), hdr.ip.proto)`. The master port's row `(9, valid, 6)` calls
  `normalize_ack`. A first version keyed on `hdr.tcp.isValid()` and the ACK bit, but N's parser extracts
  TCP only at the IP lengths it binds (40/44/75/77/60/89/41). Any other master segment (an unparsed length,
  IP options, a fragment) then skipped the reverse mapper and reached the outstation with a padded-space
  ACK.
- `normalize_ack` leaves `m.port_valid` at 0, so none of N's state tables run on that pass. E's egress
  parser handles any IPv4 TCP segment, including odd ones (`ip_odd`, `tcp_odd`, dropped through `odd_ip_t`
  once mapped).
- The packet re-enters N on port 70, whose row is a plain `route`. A routed segment N does not bind is
  forwarded natively, as before.
- **No recirculation loop, enforced in the P4 (review W2 and the follow-up review's two residual paths).**
  One gateway at the head of the chain, before `connection` can rewrite `tm.ucast_egress_port`, drops:
  - any packet that arrived on 70 or 68 whose `ports` row sends it to 70. That covers a `normalize_ack` row
    on 70 and a mistaken `route(70)` row on 68 or 70; the latter takes a route row, so the first version
    (which keyed on `m.port_valid == 0`) let it loop at line rate.
  - an envelope on 68 that parsed with `m.stage == 0` (epoch or generation 0, reachable only if N's 32-bit
    `allocate` counter saturates), which otherwise skipped the chain and routed back to 68 forever.

  It reads the `ports` row's target only. `cp.check_no_loop` refuses any `ports` or `connection` row that
  targets 70 (except the master's `normalize_ack`), a `RETURN_PORT` row that leaves 68, and `normalize_ack`
  on a recirculation port. No table is added.
- **Direction requires port provenance (review C3, N side).** `connection` gains `ig.ingress_port`, so a
  direction is granted only on a packet's first pass:
  - forward (master → outstation) only on port 70, where every master packet re-enters;
  - reverse only on the outstation's port.

  N's later passes arrive on `RETURN_PORT` 68 and look the direction up again. Each direction therefore
  also has a 68 row (size 2 → 4). Port 68 is reached only by N's own recirculation, which starts only after
  a first pass that matched with provenance.

  A response forged on the master link re-enters on 70 with no direction. N does not admit it, and it is
  never sent to the master.
- **Explicit priority (review W1).** `ports` is now a TCAM table. `core/response_only/cp.py` gives every
  ternary row an explicit `$MATCH_PRIORITY`, where the lowest value wins: SDE 9.13.1
  `p4-examples/p4_16_programs/tna_ternary_match/test.py`, `findHit()`. The normalize row is 1, plain routes
  are 100. The interpreter now picks the lowest priority among matching ternary rows, and it refuses a
  ternary row that has no priority.
- The bfrt.json of the compiled build has exactly these key names. `ports`: `ig.ingress_port`,
  `hdr.ip.$valid`, `hdr.ip.proto`, `$MATCH_PRIORITY`. `connection`: the 4-tuple plus `ig.ingress_port`.
- **Port 70 (pipe 0, local 70) is not confirmed (gate G-PORTS); see W4 below.**

*E* (`core/response_only/make_e.py`). The input is `protocol/case4_response_path.p4`, unmodified: commit
`f2315093`, file sha256 `d10e67d2f687…`. Three asserted edit groups:
1. The egress parser dispatches on egress intrinsic `egress_port`. It parses at 9 (master departure:
   forward mapper and padding) and at 70 (reverse mapper, once), and stays `accept` elsewhere.
2. **`conn` gains `eg.egress_port` (review C3, E side).** `cp.e_conn_rows` installs `fwd_conn` only at
   the master's port and `rev_conn` only at port 70. A packet carrying the outstation's 4-tuple on the
   normalization pass misses `conn` and touches no mapper state. It can no longer run the forward mapper at
   egress 70 and again on its final departure.

3. **The TCP checksum sums only the padding header that is present (found by the model run).** See the
   next paragraph.

No egress stage is added. The response path's own `Ingress.forwarding` rows are not used, because N routes
pipe 0.

*The E checksum defect: silent, compile-clean, found only on the model.* E updates the TCP checksum
incrementally, and its one update list includes every padding header (`rtp`, `ctp1`, `ctp2`). Tofino-1's
deparser sums those containers whether or not the header is valid, so they must hold zero when the header
is absent. E relied on `@pa_no_overlay` pins for that.

With N's ingress beside E in pipe 0 (32-bit containers at 64 of 64), bf-p4c 9.13 ignored those pins
silently. In the final allocation (`pa.results.log`), seven of those containers also held live metadata, for
example `m.ina`, which equals the arriving ACK, with `hdr.ctp2.filler_b[31:0]` in W26. E's own
`@pa_solitary` bits shared a container too.

The effect on the model (`response_only_07/model_03`): every reverse-translated ACK left E with its TCP
checksum short by exactly the ACK value (`c111` instead of `c496`). The SELECT was hit the same way, and real
N then refused it (wrong checksum), so nothing after the handshake worked. The earlier composite
(`compose_t_response_01`) had no such sharing, which is why its run was byte-exact.

Two candidate fixes did not work:
- Adding metadata-side pins, pipe-qualified or as `@pa_solitary` (`response_only_08`, `pin_probe/`),
  changed nothing.
- Zeroing absent headers late cost a 13th stage on both gresses (`response_only_09`).

What closed it: three mutually exclusive, single-term deparser updates. bf-p4c rejects `&&` in a deparser
condition.
- `m.changed == 1`: no padding; the list has no padding header.
- `hdr.rtp.isValid()`: READ padding; the list includes `rtp` only.
- `hdr.ctp1.isValid()`: control padding; the list includes `ctp1` and `ctp2` only.

Commit and replay (`m.pad = 1`) no longer set `m.changed`, so the three conditions cannot both fire;
`pad = 1` always validates exactly one of `rtp` or `ctp1`. Each padding header is an even number of bytes, so
dropping one keeps every later field's parity. In the compiled build the no-padding unit has no shared
containers. The remaining shares are in the unit whose padding header is present, where the container holds
the header value written after the metadata's last use.

*Why the ACK test lives in the `ports` table, and why N has one CRC table.* A first version used a separate
`if` and table after `ports`, and the composite needed 13 ingress stages (`response_only_03`). That is a
placement problem, not depth: the critical path is 11. Ingress and egress share each stage's logical-table
IDs, input crossbar and hash units. N alone fills ingress stage 1, and the response path's egress puts nine
CRC and profile tables in the same stage. Folding the test into `ports` was not enough on its own
(`response_only_04`: `input_head_t could not fit within the input crossbar`).

What closed it: N computed the same two CRCs in five tables.
- `rd_head_crc` and `input_head` hash identical link-header fields.
- `rd_first_crc`, `response_crc0` and `input_body` hash identical first-block bits; `input_body`'s byte
  slices concatenate back to `{w0,w1,w2,w3}`.

One table `crc_t`, keyed on `m.packet_kind`, replaces all five. It is applied once, after `connection`.

*Compile (`response_only_10`, source sha256 `55c8e4216ebc…`).* Exit 0 on local 9.13.1 and on the switch's
9.13.2, with identical results:

| pipe | contents | ingress / egress stages | critical path |
|---|---|---|---|
| p0 | N + response-path egress | 12 / 11 | 11 |
| p1 | drop stub | 1 / 0 | 1 |
| p2 | T | 11 / 0 | 9 |

Pipe 0 PHV: 32-bit 64 / 64 (100%), 16-bit 73 / 96, 8-bit 59 / 64. It fits, but the 32-bit containers have no
margin and ingress has no spare stage. Any 32-bit metadata added to pipe 0 will likely fail allocation.
Unchanged from `response_only_05`/`_06`/`_07`, before the checksum fix. bf-p4c places four egress deparser
checksum units: one for IP, three for TCP.

*Tests (source-level interpreter only; not the compiler, model or hardware).*
`core/response_only/tests/test_response_only_binding.py`, 26 passed. Every test installs port-bound
`connection` rows from `cp.py`, so C3's provenance binding is exercised by the whole suite. It covers:
- the execution document's vector: SELECT 101 → 136; response 901 (37 B, ACK 136) → server 938; OPERATE
  136 (ACK 938) handed to T as tev kind 12 → 171; response 938 (ACK 171) → idle, server 975;
- refusal of the legacy offsets (ACK 156, 958, 959; the 57-byte response);
- the OPERATE application-sequence check;
- bad link-header and first-block CRCs, which guards the `crc_t` merge;
- C1: a response with status 1, 2, 4 or 0x7f leaves N in select, and the next OPERATE is not handed to T;
- C2: a master segment of an unparsed IP length, and a master SYN, take the lap; non-TCP does not; after the
  lap an unparsed segment is forwarded natively;
- C3: the outstation's response re-entering on 70 gets no direction and never reaches the master, while the
  same bytes from the outstation port are admitted;
- C3, E side: the derived E keys `conn` on `eg.egress_port`, and `cp.e_conn_rows` puts `fwd_conn` at the
  master's port and `rev_conn` at 70 (text and rows only; E is not run by the interpreter);
- W1: the rows installed in reverse order behave identically; a ternary row without a priority is rejected;
- W2: a `(70, valid, 6) → normalize_ack` row at the highest priority leads to a drop, not a loop;
- W2 residual 1: a mistaken `(70, *, *) → route(70)` row drops the packet on its first pass, for both a
  bound SELECT and an unparsed segment;
- W2 residual 2: an epoch-0 envelope on 68 is dropped on its first pass;
- `cp.check_no_loop` refuses rows that target 70, `normalize_ack` on 70, and a 68 row leaving 68;
- W1, tightened: a row on a table with ternary keys needs a priority even with plain-integer terms;
- E edit 3: three TCP updates; each padding header appears only in its own update; commit and replay no
  longer set `m.changed`.

Teeth, run on scratch copies of the program text or rows:
- each of C1, C2, C3 and W2's tests fails when its fix is removed:
  - C1: status key wildcarded;
  - C2: key back on TCP validity;
  - C3: a reverse row added at 70;
  - W2 and its residuals: either half of the head-of-chain guard removed;
- N built from the legacy profile fails 5 of the original 9 tests;
- emptying `crc_t` fails 6 of 7 exchange tests.

Harness changes (`core/harness/interp_ext.py`, `driver.py`):
- `isValid()` is supported in expressions and keys.
- Ternary runtime rows with explicit priority, as above.
- The driver wildcards key columns a derived program adds (at the lowest priority). With no extra columns it
  installs exactly as before.

Suites: `read/tests` + `core/harness/tests` 195 passed; `connection/binding/tests` 85 passed;
`protocol/tests/test_response_path_cp.py` 10 passed.

*Model run of the full composite (`response_only_10/model_02`, driver
`core/response_only/model_drive_composite.py`, copied into the run directory): 29 of 29.* Real N, E and T
on the local Tofino-1 model; functional only. Every rule comes from `cp.py` and is installed through BF
Runtime (`Model.add`, real `$MATCH_PRIORITY` on N's TCAM `ports`). Every frame is predicted byte for byte
by the software mapper and padder oracles. The scenario is the execution document's vector, sent by the
endpoints themselves:
- handshake: SYN takes the lap (N phase 2); the SYN-ACK arms E (phase 4); the ACK is reverse-mapped (phase
  5, idle). The source-level interpreter gives the same phases;
- SELECT through the lap → phase 9 → outstation, byte-exact;
- response 901+37 → E commits and pads 37 → 58 → master, byte-exact (phase 10);
- the master's OPERATE carrying ACK 959 (padded space): E maps it to 938 at egress 70, N admits it (phase
  12) and hands it to T; T holds it (held laps observed) and releases it once (`OUT_OP_RELEASE` +1) to the
  outstation with ACK 938, byte-exact, about 1.3 s round trip on the model;
- response 938+37 → padded at master SEQ 959 (the document's master-side 1017 end), N back to idle;
- forged: a response carrying the OUTSTATION's 4-tuple, injected on the MASTER port. Traced in the model
  log: `ports` hit → `normalize_ack` → egress 70, where E's `conn` **misses** (no mapper action, outcome
  0 only) → recirculated → `ports` route on 70 → N `connection` **miss**, `guard` miss (no direction, no
  work) → out on 64. The frame left on the outstation port byte-identical to what was injected (91 bytes),
  and nothing reached the master. E's six registers and N's owner and epoch were unchanged. Its
  destination is the master's address, so the outstation will not accept it.

Teeth for the model test (`response_only_10/teeth_c3_no_egress_port`, scratch generator and driver in the
directory): the same composite with E's `conn` NOT bound to `egress_port` fails exactly the two forged-tuple
checks (E's forward mapper ran at egress 70, outcome 2, and E's state changed). The other 27 still pass.

Two setup lessons from the earlier model attempts:
- `MODEL_INT_PORT_LOOP` puts the front ports 9 and 64 into loopback, so every departure re-entered
  (`response_only_07/model_01`, `_02`). Pipe-local recirculation on 68 and 70 works without it.
- `response_only_07/model_03` exposed the E checksum defect described above.

*Documented, not fixed (review W3).* **The normalization pass is not state-free in E.** E's reverse mapper
(`acct_rev`) writes `acct.hi = lo - ack` for any ACK on a mapped 4-tuple. It does this at egress 70,
*before* N's ingress has checked the packet's IP/TCP checksums, TTL or DNP3 CRCs, and E's parser does not
verify checksums. A forged master-side ACK on a mapped connection can therefore steer E's next `acct_try`
grant even though N would later refuse the packet. What is state-free is N's side of that pass.

**Later on 2026-10-10: T moved to pipe 1 (`route_ab_01/two_pipe_01`).** The switch has two physical pipes.
The coordinator confirmed this two ways: a `Switch(p0,p1,p2,p3)` probe failed with "Pipeline p2 cannot be
assigned to device 0 pipe 2, only 2 pipe(s) available", and BFRT `$PORT` shows 68-71 and 196-199 present but
324-327 absent. 2cb6ecf9d's `Switch(p0, p1, p2)`, with T in pipe 2, therefore cannot load on this chip; every
model run before this used tofino-model's four-pipe default.

Now the program is `Switch(p0, p1)`: N + E in pipe 0, T in pipe 1.
- `read/ports.p4` is the two-pipe single source: `PKTGEN_RETURN` 196 (moved here from
  `read_queue_timing.p4`), `T_IN` 197, `HB_RETURN` 198, `HELD_RETURN` 199, `PKTGEN_PIPE` 1.
- The retired M constants `N_TO_M` / `T_TO_M` are removed, so no stale M route can land on T's input.
- N's `READ_HANDOFF_PORT` = 197 is set at the generator's `response_only` profile, read from `ports.p4`. The
  legacy profile, and the byte-pinned `native_binding.p4`, keep the old three-pipe 325.
- The derived slices were regenerated, and `mirror_probe.p4` takes the port from `ports.p4`.
- Port tests were adapted to the two-pipe layout with the same intent; the legacy N↔M agreement is now
  checked directly between `native_binding.p4` and the ordinary M.

Builds and runs:
- 9.13.1 and 9.13.2: exit 0, pipe 0 12/11, pipe 1 11/0, source `00fb7b98…`.
- **The conf's `pipe_scope` is p0 [0, 2], p1 [1, 3], not [0] / [1].** bf-p4c places a two-pipeline program
  that way, and the SDE's own 32Q two-pipe example (`tna_32q_2pipe`, `multipipe_custom_bfrt.conf`) uses the
  same scopes. It has not been loaded on the chip: whether the driver accepts it there, or the conf must be
  edited to [0] / [1] at deployment, is unverified.
- Model: 70/70 (the model still has four pipes, so this is necessary, not sufficient).
- Suites: 201 / 85 / 27 / 10.

**Provenance of the CRC edits (corrects 979b38fd1's message and an earlier version of this paragraph).**
The claim that 2cb6ecf9d already contained edit group 4 is wrong. Checked against git: 2cb6ecf9d's
`make_e.py` and `e_response_only.p4` contain no `0x3b2f`, and its own `make_e.generate()`, run from a clean
`git archive` of that commit, reproduces its committed `e_response_only.p4` byte for byte (sha256
`0a32f97a8d5310ab...`). 2cb6ecf9d is therefore exactly `_18`, as its message says. Edit group 4 first appears
in 17161e70b, verified as `_19` (70/70; all three checksum cases valid from emitted bytes). The error came
from comparing `_17`/`_18` against HEAD after 17161e70b had already landed. `two_pipe_01` is the first
two-pipe build of 17161e70b's `make_e.py`.

**Token and clone admission qualified by port AND format (`route_ab_01/token_admission_t_02`,
`token_admission_composite_02`).** The independent review found that the parser default was `parse_timer`
and the token branch keyed on `hdr.timer.isValid()`. Every frame on any pipe-1 front-panel port (164-191 are
enabled on the switch) therefore entered `token_verdict`. Now:
- **Parser:** `parse_timer` is reached only from `PKTGEN_RETURN` (196, after the marker check) and from
  `MODEL_PKTGEN_IN` (port 0, the ingress_port the model gives generator packets; a pipe-0 port, so it never
  reaches pipe 1 on silicon). `md.token_ok` is set only for the expected format: pipe `PKTGEN_PIPE`, app 0
  (READ) or 1 (OPERATE). Every other port parses nothing.
- **Apply:** the token branch requires `md.token_ok == 1`. Clones are admitted only by the exact 0xE1 marker
  on 196; an unexpected clone kind reaches `drop_clone`, not a parser `reject`. The final `else` is
  `drop_foreign()`: an explicit drop with nothing counted. The prologue's defaults only read.
- **Tests** (`P_ForeignIngressIsInert`): each case is compared with the same run without the foreign frame,
  with live READ and OPERATE state. On ports 164, 177 and 191: an ordinary frame, frames shaped as current
  READ and OPERATE timer headers, and a frame starting with 0xE1. On the generator ports: a wrong-pipe and a
  wrong-app token. Every register cell, counter, enqueue and emission is identical.
- **Teeth:** parser default back to `parse_timer`; no format check; the old `isValid` branch; a counting
  final else. Each fails.
- **Model** (`model_tok196_front164`): tokens with apps 0 and 1 on 196 are counted stale (+2); an app-3
  token counts nothing; three foreign frames on 164 change no T outcome counter; nothing is emitted. 6/6.
  Composite `model_01`: 70/70.
- **Builds**, exit 0 on both SDKs: T 11/0 (critical path 9); composite 12/11 + 11/0.
- `token_admission_*_01` are the first attempt: T compiled, but the composite failed with `t_reject:
  declaration not found`, because compose's role prefixer read the comment words "parser reject" as a
  declaration. The comment was reworded.
- **Still on parser `reject`, out of this change's scope:** `parse_tev` (T_IN) and `parse_ladder`
  (HELD/HB_RETURN) default to `reject` for unexpected kinds or roles on T's own internal ports.

**OPERATE generation safety across 0xFFFF -> 0x10000 (tests only; no P4 change was needed).**

Every OPERATE generation comparison, traced:

| comparison | width |
|---|---|
| ladder vs `op_gen` (`op_lgen_diff`) | 16 bits |
| generator token batch vs `op_gen` (`op_tok_diff`) | 16 bits |
| clone-tag low 16 → ladder generation (`admit_operate_held`) | 16 bits |
| `op_done_reg` vs `op_gen` (`op_done_read`, `op_done_try`) | 32 bits |

A 16-bit alias needs an item delayed by exactly 65,536 generations, while held items and tokens live for
milliseconds. The only long-lived state, `op_done_reg`, compares 32 bits, and it must: with its load-time value
0, a counter reaching 0x10000 after 65,535 RESET bumps would read as "already done" under a 16-bit compare.

Tests (`O_OperateGenerationBoundary`), all at the boundary:
- OPERATE at 0xFFFF then RESET: flushed once, not released, blockers stale.
- OPERATE at 0xFFFF superseded by one at 0x10000: the first flushed once, the second released once.
- A real delayed clone `e101ffff` replayed at 0x10000, and at 0x10001 after a RESET: flushed once, never
  released.
- A delayed app-1 token with batch 0xFFFF at 0x10000: stale, no blocker seeded.
- `op_done` = 0 and = 1 at the 0x10000 alias: released once.

Teeth, in memory:
- no ladder generation check fails three tests;
- no token generation check fails one;
- `op_done` narrowed to 16 bits fails two.

**OPERATE clone tag built by construction (`route_ab_01/op_tag_t_02`, `op_tag_composite_02`).**
`md.clone_tag = 16w0xE101 ++ md.op_gen[15:0]` replaces `op_gen | 0xE1010000`. Bits 31:16 are now exactly
0xE101 whatever op_gen is, which matters for two readers:
- the parser's exact 0xE1 marker match;
- the generator's OPERATE trigger pattern, 0xE101xxxx with mask 0xFFFF0000.

The OR corrupted the pattern from op_gen = 0x20000 (bit 17; 0x10000 coincides with the 0x01 half) and the
marker from 0x2000000. op_gen keeps its 32-bit lifetime; no allocator wrap, which the reviewer showed would
reuse generations against op_done_reg.

Evidence:
- Tests at op_gen 0xFFFF, 0x10000, 0x20000, 0xFFFFFF, 0x1000000, 0x2000000 and 0xFFFFFFFF: top half 0xE101,
  low half = op_gen[15:0], released exactly once.
- Teeth: the OR form fails at 0x20000, 0xFFFFFF, 0x2000000 and 0xFFFFFFFF.
- Builds exit 0 on both SDKs: T 11/0 (critical path 9); composite 12/11 + 11/0.
- Model 70/70. Suites 206 / 85 / 27. Generation safety across 0xFFFF -> 0x10000 is the separate next step.

**Clone vs generator token, now told apart by content (closes the blocker below; `route_ab_01/
clone_marker_t_01`, `clone_marker_composite_01`).** Two things in T keyed on the port, and both are now content
checks. Every clone tag starts with `CLONE_MARKER` 0xE1:
- read clone `16w0xE100 ++ new_gen[15:0]`;
- OPERATE clone `op_gen | 0xE1010000`.

Only the tag's low 16 bits are consumed (`ladder.generation`), so nothing downstream changes.
- **Parser:** on `PKTGEN_RETURN`, `select(pkt.lookahead<bit<8>>())` with an exact 8-bit match. 0xE1 goes to
  `parse_clone`; anything else goes to `parse_timer`. A Tofino-1 timer header's first byte is pad(3)=0 |
  pipe(2) | app(3), at most 0x1F; the exact full-byte match avoids Defense 2's 0x1F-mask aliasing.
- **Apply:** the clone branch is `hdr.clone.isValid()`, not `ingress_port == PKTGEN_RETURN`. The token
  branch is `hdr.timer.isValid()`, not `ingress_port == 0`. The second was a further silicon bug: the old
  branch assumed the model's pktgen port 0, so a token on 196 would have been unmatched even once parsed
  correctly. The source-level test found it.

Evidence:
- Tests (`M_CloneOrTokenByContent`): a pipe-1 timer token on 196 reaches the token verdict exactly as on
  port 0; an OPERATE clone carries 0xE1, is admitted and is released once; an unmarked clone-shaped frame on
  196 is not a clone.
- Teeth, in memory: by-port parsing fails the token test and the unmarked-frame test; port-0 token routing
  fails the token test; unmarked tags fail the clone test.
- The interpreter gained `pkt.lookahead<bit<N>>()`.
- Model: `model_tok196` (`model_drive_pktgen_port.py`, three tokens injected on 196 through a veth, since
  the model's own generator reports port 0): OUT_TOKEN_STALE +3, unmatched +0, nothing emitted. The same
  driver on the previous build (`two_pipe_01/model_tok196_teeth`): OUT_TOKEN_STALE +0, so it fails.
- Composite `model_01`: 70/70.
- Builds: T standalone 11/0 (critical path 9); composite pipe 0 12/11, pipe 1 11/0. Exit 0 on 9.13.1 and
  9.13.2.
- Suites: 204 / 85 / 27 / 10.

**Pre-hardware blocker (CLOSED by the change above; kept for the record).** T separated mirror clones from generator tokens by port
(`ingress_port == PKTGEN_RETURN` means `parse_clone`; everything else goes to the timer path). On this switch,
generated tokens arrive on the pipe's local 68 once `app_cfg.pipe_local_source_port = 68` is set, which was
required in Defense 2 on 9.13.2. That is the same port as `PKTGEN_RETURN` (196), so tokens would be parsed as
clones. Proposed fix, a T design change: tell them apart by content, as Defense 2 did (clone marker byte, a
value_set with an exact `0xFF` mask). The alternative, generating tokens on a different local port, depends
on unverified pktgen source-port freedom.

*Closed (review W4): port 70.* Confirmed by the coordinator on the physical switch, 2026-10-10: pipe-local
ports 68, 69, 70 and 71 are each a separate, independently enabled, dedicated internal recirculation port, not
lanes of one shared interface. make_n.py and cp.py now say so.

**Later on 2026-10-10: follow-up review, T close fix, composition acceptance. Composite
`route_ab_01/response_only_17` passes 70 of 70 on the local model; `_18` is the same program with corrected
comments (normalized assembly identical on all three pipes) and is what is committed.**

*Loop guards, now three, all in the P4:*
- head of chain: a packet from 68 or 70 whose `ports` row targets 70, or an epoch-0 envelope on 68, drops;
- `guard` table entry (make_n edit 8): `guard` gains the key `m.output_port`, and its first const entry
  drops any packet whose `connection` row names 70 (`forward_flow` / `reverse_flow` set the egress port from
  that value and `close_forward` copies it back). Implemented as a table entry because every gateway form
  cost a 13th ingress stage: `_11` tail guard (critical path 12), `_12` separate `if` after `connection`,
  `_13`/`_14` first arm of the `m.go` chain (stage-1 crossbar saturated; any new gateway reshuffles PHV and
  pushes `crc_t` out). `_15` onward: 12/11.
- `cp.check_no_loop` for rows. Test `test_a_connection_rewrite_to_n_ack_return_cannot_loop`; removing the
  entry fails exactly that test.

*T regression fixed (my Route B rewrite).* `read_queue_timing.p4` dropped every RESET event (`drop_tin`), so
N's qualified close never reached either endpoint (found on the model: the master's RST reached neither
side). The hardware-tested `read_timing.p4` forwarded it once by direction. `tin_verdict` now keys on
`hdr.tev.stage`:
- stage 1 (client close) goes to the relay;
- stage 2 (server close) goes to the master;
- stage 0 (synthetic reset, no original) is dropped as before.

These rows apply whatever `md.enabled` is. The generation bump and quarantine still run. `size` went 14 → 15:
bf-p4c compiled 15 const entries into `size = 14` without complaint, and the driver then failed at device add
(`_16/model_01`, "Not enough space"). New source-level tests (`L_QualifiedCloseForwarded`):
- a genuine master RST reaches the relay once;
- a genuine outstation FIN reaches the master once;
- a synthetic reset reaches neither, as a separate case.

Teeth: removing the stage rows fails exactly the two genuine-close tests; forwarding stage 0 fails exactly
the synthetic test. T standalone (`t_close_fix_02`): exit 0 on 9.13.1 and 9.13.2, 11/0, critical path 9.

*Late outstation traffic.* A new deterministic test,
`test_replies_arriving_after_the_readiness_window_are_delivered_once_each_promptly`, covers an ACK and a
response that both arrive after READINESS. Each is released once, in order, within one service lap of its
own arrival: the ACK by commit, the response by fallback.

*Composite model run (`_17/model_03`, 70 of 70).* Real N, E and T; rows from `cp.py`, including N's new
`read_connection` rows (`cp.n_read_rows`). Every frame was checked byte for byte against the oracles. After
the document's SELECT/OPERATE exchange:
- **Mixed READ/SBO on one connection, with enlarged ACKs.** READ1 carries master ACK 1017 (mapped to 975);
  READ2 carries 1075 (mapped to 1024). Each request was relayed once through T. The ACK and response came
  back to the master, the response padded 49 → 58 and byte-exact. This is the first model run of E's READ
  checksum unit (`tcp_read`). N's `read_app` follows each request's sequence.
- **Late outstation.** READ3, where the outstation answers 2 s after receiving the request, delivers the same
  frames once each.
- **Two independent connection slots.** N binds one connection by design. Connection B (master 10.0.0.3:
  E's `odd_ip_t` keys the host pair, so two slots cannot share one; the first attempt hit `ALREADY_EXISTS`)
  crosses N natively and is mapped by E slot 1. Its response was padded byte-exact, while slot 0's registers
  and N's state did not change.
- **Reset.** The master's genuine RST|ACK was mapped, closed N (phase 7) and reached the outstation exactly
  once.
- **Reconnect.** See *Pending* below.
- **The T check on the model is "released once each", not commit vs fallback.** On the model those two
  timing verdicts swapped between runs: on-time READs fell back and the late READ committed (`_17` model_01
  and model_02). The model's `global_tstamp` is coarse and N's multi-pass latency is large on the model, so
  it cannot rank them; the paths are asserted in deterministic time by `read/tests`.
- Also from `_17` model_01: sending the outstation's ACK 50 ms after injecting the request overlapped N's
  busy work record on the slow model, and the ACK bypassed T. The driver now sends the replies after the
  request is observed at the outstation.

*Suites:* `read/tests` + `core/harness/tests` 199; `connection/binding/tests` 85; `core/response_only/tests`
27; `protocol/tests/test_response_path_cp.py` 10. All pass.

*The `@pa_no_overlay` / `@pa_solitary` pins are NOT honored by the compiler in this composite.* The
protocol source's comment says the pins keep absent headers' containers clean. In the response-only build
they do not: `pa.results.log` shows live metadata in pinned padding-header containers. The current builds
are safe only because make_e edit 3 sums each padding header solely when it is present, and every container a
present padding header shares is fully overwritten by that header before the deparser runs. That is correct
for this code shape but is not a structural guarantee. A future edit that leaves part of a present padding
header unwritten would reopen the defect. The derived E now carries this note; the protocol source is left
unmodified. Cosmetic: compose's role prefixer also renames identifier-like words inside comments
(`r_containers`).

*Open follow-ups (documented, not fixed):*
- `cp.check_no_loop` does not reject an external port's `route(68)` row. An external frame could then
  enter N's envelope parser on 68 as if it were N's own recirculation.
- Coverage gap (review item 3): the legacy binding suites still wildcard `connection`'s port column.
- W3 above (E state written on the lap before N validates the packet).
- The post-release retransmission open item.

*Pending, separate commit: reconnect after reset.* N has no rearm from phase 7, so a fresh SYN on the same
4-tuple is refused (the model records the refusal). The rearm mechanism is the next, separate effort, per
Philip's spec:
- retire the old connection;
- invalidate its transaction and timing associations, and keep stale OPERATEs, work returns and tokens away
  from the new connection;
- admit a fresh handshake with a new epoch once the drain conditions hold;
- re-initialize the mapper before padding resumes;
- never treat a retransmitted SYN as permission to reset;
- no per-packet controller intervention, and no register presets as the implementation.

*Pre-hardware checklist (remaining):*
- Nothing other than N's own recirculation may ever arrive on 68 or 70: no pipe-0 packet-generator app, no
  mirror session, no T `keep_blocking(port)` value. Both the loop guards and C3's port-68 direction rows
  assume this.
- A real BF Runtime installer for the physical switch. `cp.py` produces the rows; only the model driver
  installs them today.

### Earlier on 2026-10-09 (superseded by the above)

**Whole-file compile** of `read_queue_timing.p4`, sha256 `323c5bc56bfa…`: exit 2 on both local 9.13.1
(`final5_full_local`) and the switch's installed 9.13.2, compile-only (`final5_full_switch_9132`): "Table
placement was not able to allocate tbl_read_gap_delta, tbl_mark_ack_commit_at in the same stage along with
Register Ingress.ack_commit_at_reg". No "Internal compiler error". The OPERATE slice compiles at 8 ingress /
0 egress stages; the capture slice at 3 / 0.

**What the crash was.** It hid ordinary errors. Stubbing whole top-level branches (`b6`), then pieces of the
generator-token branch (`b19`), exposed them:
1. The `~delta[31:31]` sign-bit slices (mitigation 2 below) split the whole now/t0/deadline chain,
   including `global_tstamp`, at bit 31 ("PHV allocation was not successful"). Fix: one-entry ternary
   `*_sign` tables (`b7`).
2. The generation counter's output was masked inside the action that receives it (IMPOSSIBLE_ALIGNMENT).
   Fix: a separate `make_request_tag` (`b8`).
3. **The crash trigger.** The generator-token staleness gateways compared two runtime fields with a mask on
   one side: `md.token_gen != (md.X_gen & 32w0xffff)`. Removing both (`p3`) gives readable errors; removing
   either alone still crashes. Fix: `tok_diff = batch_id ^ (bit<16>)gen`, then `tok_diff != 0`. This is the
   same test, because `token_gen` is the zero-extended 16-bit `batch_id` (`b20`).

**Behavior-preserving repairs.** Every one is source-checked, and tests stayed green after each.
- **One access per register per pass; read-then-dependent-write folded into one action.**
  - `op_done_try`, `ack_done_try` and `resp_done_try` return the old value and record the generation when a
    precomputed go flag is set (`b1`, `b4`).
  - `outcomes` is bumped by a single `outcome_count` table at the end of the pass (`b2`).
  - Quarantine has a read action and a RESET action, selected by a gateway on `hdr.tev.kind`. The read
    returns `q_diff = epoch ^ quarantine` (`b14`, `b26`).
  - `gen_alloc_reg`, `cur_epoch_reg` and `t0_reg` are each accessed by one ternary table (`gen_access`,
    `epoch_access`, `t0_access`), applied once after quarantine. The quarantine condition is decided inside
    the register action from `q_diff`. Rows are matched in order, so `enabled == 0` comes first and the rest
    mean `enabled != 0` exactly (`b17`, `b26`).
  - The ACK/response epoch gate is one register action, `epoch_check`. It returns 0 exactly when the epoch is
    current and not quarantined. The three-field gateway it replaces was split across stages by bf-p4c
    (`b27`).
  - The gap delta is read only on response-role passes, so a held ACK's commit pass no longer accesses
    `ack_commit_at_reg` twice (`b25`, code-review finding).
- **The resp_done → resp_mask → ack_done → resp_done ordering loop.** On T_IN, a response now marks its
  child in `resp_mask_reg` before reading `resp_done_reg`. The decision order is unchanged. The only new
  effect is a child bit set in a generation that has already released a response. That bit is not
  observable: the mask's only other consumer, the ACK gate, tests only "some child seen", which is already
  true there. Folding "released" into the mask would not break the loop (`b11`).
- **Shorter chains, exact mod 2^32.**
  - Deadline deltas are computed as `(now - X) - t0`.
  - The `ack_commit_at_reg` read returns the gap delta directly (`b13`).
  - `ack_go_check` and `resp_go_check` are single ternary tables. `ack_done_read` returns `value ^ cur_gen`,
    so "committed in cur_gen" is a match on 0 (`b18`, `b23`).

**Late 2026-10-09 changes** (each round recompiled, tests green after each):
- **`resp_deadline` removed (`b28`).** It was armed (only while zero, so once per RESET) and cleared, and no
  decision read it. Release is decided from `ack_commit_at_reg` plus the configured gap. The release decision
  has always used the gap configured at release time, not a gap frozen at a_commit; the frozen value existed
  only in this unread register. Its one test now checks `ack_commit_at_reg`
  (`test_duplicate_ack_records_a_commit_once`). Compile effect: none.
- **Generation-scoped a_commit (`b30`).** A genuine ACK commit writes `ack_commit_at_reg` (time) and the new
  `ack_commit_gen_reg` (READ generation). Response roles gate every gap use on `commit_diff == 0`, which means
  this generation had a genuine commit. There is no RESET-time clear.
  - A single `{gen, at}` pair register is not possible: a two-field stateful ALU may not return a computed
    value (`b29`).
  - **Intended counter change.** After a readiness-fallback ACK, or with a stale a_commit from an earlier
    generation, the response is now counted `OUT_RESP_FALLBACK`. The zero-clear design counted
    `OUT_RESP_RELEASE` from a zero or stale timestamp. Release times are unchanged
    (`b32/measure_reset.txt`).
- **RESET invalidates OPERATE by generation (`b32`).** RESET bumps `op_gen_alloc_reg` instead of zeroing
  `op_t0_reg`.
  - **Counter change.** A held OPERATE is flushed as stale: `OUT_HELD_STALE_FLUSH` instead of
    `OUT_OP_RELEASE`. Its blockers die stale (`OUT_TOKEN_STALE`).
  - **Flush time.** Unchanged at the tested offsets: 150,000 ns after a RESET 200 us after the OPERATE,
    and 180,000 ns at 20 us. This is not a general invariant. With a RESET 6 us after the OPERATE, the
    flush now comes 74,000 ns after the RESET, against 194,000 ns on the zero-clear `b28` source. It is earlier, and still
    a flush, not a timed release (`b34/reset_window.txt`).
  - **Bug found in review and fixed (`b34`).** `admit_operate_held` tagged the held original with a fresh
    `op_gen_peek()` instead of the generation the clone carries. A RESET landing between the OPERATE's
    admission and its clone's return (1–5 us in the simulator) therefore left the superseded OPERATE with
    a current tag. It was then released on its old deadline (about 625,000–629,000 ns after the RESET,
    counted `OUT_OP_RELEASE`). The tag now comes from `hdr.clone.tag`, whose low 16 bits are the admitted
    generation, and the PKTGEN branch no longer touches `op_gen_alloc_reg`. Test:
    `test_reset_just_after_an_operate_flushes_it_as_stale` (RESET at 1, 3 and 5 us). It fails on `b32` and
    passes now.
  - **A second pre-existing defect is fixed by the same change.** Before this fix, including at the
    committed HEAD, two OPERATEs 1–4 us apart (inside the first one's clone window) lost the first one. Its
    held original took the second's generation and was never released: one relay emission instead of
    two. Now the first is flushed as stale (at 770,000 ns) and the second is released on its own deadline
    (at 800,000 ns). Test: `test_two_operates_inside_the_clone_window_both_reach_the_relay`; it fails on
    HEAD `723bfd1ad` (`b34/two_ops.txt`).
  - **Tracked follow-up, not fixed (token path, not admission).** Once `op_gen` reaches 0x10000, its own
    bit 16 and above land in the 24-bit generator key, and the `| 0x10000` OPERATE marker no longer
    separates the OPERATE domain as intended. Each RESET now bumps `op_gen`, which brings that point
    closer.
  - **Defect fixed.** The RESET-near-clock-wrap defect, formerly the one expected failure, is fixed by this
    change. Its test now also checks the mechanism (`finished()`, `OUT_HELD_STALE_FLUSH` = 1,
    `OUT_OP_RELEASE` = 0) and covers the 0xC0000000 phase as well. It fails on the zero-clear `b28` source.
  - **Low-priority notes, not fixed.** Every RESET now bumps the OPERATE generation even when nothing is
    held, which uses up the 16-bit ladder generation field faster (wraparound is already a known
    follow-up). `ack_commit_gen_reg` depends on its 0xffffffff initial value: a clear to 0 would match
    generation 0. This is now stated in the source; a controller that clears registers must restore
    0xffffffff.
- **New tests**, class `J_GenerationScopedReset`:
  - a fallback ACK supplies no a_commit;
  - a stale a_commit from an earlier generation is not used;
  - RESET invalidates a held OPERATE by its own generation;
  - after RESET both domains start from their own anchors.

  All four pass on this tree and fail on the pre-redesign source (`b28`).

**What blocks the whole file now.**
- **Slack exists, but placement still fails.** The redesign gave `ack_commit_at_reg` two legal stages
  instead of one (dependency bounds: read 3..7, write 6..11; `b30`), but it still does not place.
- **The new limit is logical tables per stage.** The placement logs report "too many tables total" in the
  early stages (stages 2–4 full). This is the per-stage logical-table limit. Every bare action call and
  assignment in the apply block is its own table: 116 tables and 32 gateways (`b30`).
- **Two cheap tests did not resolve it.**
  - Merging the seven release+count pairs changed nothing, and was reverted (`b31`).
  - Removing whole early branches (port 0, PKTGEN, the policy-off block) lowers the pressure but still
    gives the same error (`b33_table_pressure_probe`).
- **Next options.** Consolidate the role and kind dispatch into decision tables with mutually exclusive
  actions, a substantial rewrite of the apply block. Or compose Route A's hardware-tested ingress with the
  new egress mapper.

**Tests:** `python3 -m pytest -q read/tests core/harness/tests` from `integration/`: 193 passed, 0 expected
failures (`final6_pytest.txt`; includes 10 tests in `read/tests/test_n_operate_handoff.py` added by another
workstream).

**Not done.** No model run of the regenerated capture slice. Nothing was loaded or run on the switch; the
9.13.2 build was compile-only.

## 2026-10-08 correction: "all 7 invariants established" was too broad

An external review of this file (audited at commit `5e848351c`) found, and this session independently
confirmed by direct source inspection plus live reproduction, three real gaps the original 18-test suite
did not catch: (F1) `IngressDeparser` sets `ig_dprsr_md.mirror_type`/`md.clone_tag` but never actually
emits a `Mirror()` clone — the interpreter's test simulator synthesizes the clone+blocker-token behavior
in Python, standing in for hardware behavior the file itself doesn't implement; (F2) `op_t0_arm` only
armed once per register lifetime, so a second OPERATE admitted without an intervening RESET inherited
the first operation's deadline (reproduced: released 399,808ns before its own earliest-permitted
release); (F3) `hdr.tev.wgen` was parsed and never read anywhere, flagged by the review as allowing a
stale response to satisfy a newer request's ACK gate.

**Investigation outcome, same day:**
- **F2 is fixed.** One-line change, see below.
- **F3 required no fix.** A deeper investigation (reading N's real implementation, `n.p4`/
  `native_binding.p4`, and replaying N's own real output bytes through `QueueSim` rather than injecting
  synthetic T_IN events) found the review's literal diagnosis was wrong: N allocates a new `wgen` per
  packet-processing operation, not per transaction, so a legitimate request/ACK/response can legitimately
  carry three *different* `wgen` values — an equality check against `wgen` would have rejected legitimate
  traffic. The real question (can a stale response reach T through the real N→T path) was answered
  empirically: **no.** N's own admission guarantees (single work slot; state-machine-gated READ admission;
  sequence/ack checks against live banks) already prevent a stale response from ever being forwarded to T
  in the real path. This boundary (T trusts N's filtering; T has no independent association check of its
  own) is now pinned by an explicit test (`H_NRealisticAssociation`, `test_t_queue_invariants.py`) rather
  than being an unstated assumption. OPERATE duplicate-detection was investigated for the same reason and
  found **not reachable today**: nothing in the real N implementation sends OPERATE events to T's input
  port at all (T's OPERATE path is exercised only by synthetic tests) — adding duplicate-detection now
  would mean designing against an interface that doesn't exist yet.
- **F1 is not yet fixed** — queued as the next step (Stream 1c), to be compiled and verified separately
  from F2 per this document's own standing discipline about isolating one new variable per compile attempt.
  *Update, same day: F1 is implemented and its mechanism is verified on the local model; see the next
  section. The whole file still does not compile.*

## 2026-10-08 (Stream 1c): F1 Mirror clone implemented; mechanism model-verified, whole file still crashes

**Change to `read_queue_timing.p4`.** `const MirrorId_t CLONE_SESSION_ID = 10w7` and `const bit<3>
MIRROR_TYPE_CLONE = 1`; a `MirrorId_t clone_ses` metadata field; `md.clone_ses = CLONE_SESSION_ID;` as its
own statement in `admit_request_gen()` and `hold_operate()`; `IngressDeparser` gains a no-arg `Mirror()
clone_mirror` and `if (ig_dprsr_md.mirror_type == MIRROR_TYPE_CLONE) clone_mirror.emit<clone_hdr_t>(md.clone_ses,
{ md.clone_tag });` before `pkt.emit(hdr)` (the `defense4_rrc_bor_unified12.p4` pattern). The empty egress
trio is unchanged. **One more change was forced by F1:** `hold_operate`'s tag went from `md.op_gen +
32w0x10000` to `md.op_gen | 32w0x10000`. Before the emit existed `clone_tag` was never read, so its write was
dead; once live, bf-p4c split `op_gen` over two 16-bit containers and rejected the carrying add ("requires too
many sources ... only one PHV source when action data/constant is present",
`evidence/mirror_f1_01/compile_slice_local/compile.log`). Same value while `op_gen < 0x10000`, the assumption
the action's comment already states. The harness interpreter (`core/harness/interp_ext.py`) learned
`MirrorId_t` (10 bits) the way it knows `PortId_t`; without it every test failed on the new constant.
Regression after all changes: read/tests 132 passed + 1 expected failure (unchanged); harness 42, binding 85,
controller 17, root 33 passed.

**Compile results** (all under `integration/evidence/mirror_f1_01/`):
- Standalone probe `read/mirror_probe.p4` (the new deparser + the unchanged empty egress trio + a stub
  ingress that rewrites a T_IN pass the way `hold_operate` does): **compiles, 0 errors**, SDK 9.13.1
  (`compile_probe_local`). The Mirror addition introduces no compiler complaint of its own.
- Whole `read_queue_timing.p4`, SDK 9.13.1 and the switch's installed 9.13.2 (compile-only), both before and
  after the `|` change (`compile_full_local`, `compile_full_switch_9132`, `..._02`): **the same unresolved
  crash** — exit 4, "Internal compiler error", `phv_allocation_0.log` zero bytes, dependency analysis max
  ingress stage 7. F1 did not change the signature. No further variant was attempted.

**Local-model results** (functional only, not timing, not silicon; mirror session bound on the local model only):
- `model_01` (probe, `read/model_drive_mirror_probe.py`), 15/15. Session 7 to a front port: exactly one
  clone, first 4 bytes = the tag (`0x00010005`), then the **pristine original as received** (tev + Ethernet +
  payload), not the ingress-modified image, while the original left once in its modified form. Session 7
  to 324 (`PKTGEN_RETURN`): nothing on the wire, the clone re-entered pipe 2 ingress on 324 exactly once,
  and `parse_clone` read tag `0x10005`, `tev.kind 12`, `epoch 5`. So the two assumptions `queue_sim.py`
  makes about the clone (arrives on 324; carries `tag + raw original`) hold on the model.
- `model_03` (`read/model_drive_operate_clone.py`), 21/21, on `read/operate_slice_capture.p4`, generated by
  `read/make_operate_slice.py --capture-hb`: the real prelude, parser, deparser, `hold_operate`,
  `admit_operate_held`, and the PKTGEN_RETURN and T_IN-OPERATE branches **copied verbatim** (the
  script checks each piece against this file); only HB_RETURN is replaced by an export to front ports. Two
  OPERATEs: each produced exactly one admitting blocker (role 13, its own generation, budget 240000, payload)
  and exactly one held original admitted from the clone (role 16, its own generation, followed by the pristine
  Ethernet + payload), with nothing on the relay. Policy off: one byte-identical passthrough to the relay,
  no clone, no blocker, generation not bumped. Negative control, mirror session removed: the blocker still
  appears and no held original does, so the held frames exist only because of the clone. `model_02` is
  the same run without that control (19/19).

**What this does not show.** The release itself (`mark_op_done`, exactly-once to the relay at the
deadline) was not model-run: the verbatim HB_RETURN branch does not place on its own (below). Generated
tokens (the packet generator's recirculation-pattern trigger on the clone) were not configured or tested;
nor was the request clone (`admit_request_gen`, kind 9, dropped by `drop_clone`); nor strict-priority queue
service. Nothing was configured or run on the physical switch.

**New lead on the whole-file crash (recorded, not acted on).** The full verbatim slice
(`read/operate_slice.p4`, `compile_slice_local_02`) gets past PHV allocation and then fails table
placement with a diagnosable error: "Table placement was not able to allocate ... `tbl_mark_op_done` in the
same stage along with Register `Ingress.op_done_reg`", and the same for the many tables bumping
`Ingress.outcomes`. `op_done_reg` is read into `md.op_done_g`, compared, and then written by a dependent
table; a Tofino register lives in one stage, so that read-then-dependent-write cannot place. The whole
file has the same shape for `ack_done_reg` and `resp_done_reg`. Note also that `table_dependency_graph.log`'s
"Maximum stage number according to dependences" is the dependency analysis, not a completed placement, so
the "placement succeeds at 8 stages" reading above may be stronger than that log supports. Inference, not
tested on the whole file: folding each read-compare-write into one RegisterAction (and the outcome bumps
into one table) is the next thing worth trying, ahead of register-count bisection.

**New, previously-undiscovered defect found as a byproduct of adding a timestamp-wrap test for F2's
fix**: RESET's fast-flush of a held OPERATE assumes a cleared `op_t0` register reads as "trivially
overdue." This breaks when the quantized 32-bit clock is in its upper half at the moment of the RESET:
`op_delta = now - OP_J` has its sign bit set in that range, so the flush is **late, not early** — measured
870µs to 1.56ms late near the wrap boundary, and up to ~2.15s late at worst. The release is always late,
never early (not a safety regression, but a real timing-accuracy defect). This is recorded as an
`expectedFailure` test (`test_reset_flush_near_the_clock_wrap`) rather than fixed — redesigning the RESET
path is a separate decision, out of scope for the bounded F2 fix.

## What is done and verified

**All 7 invariants from the integration prompt §4C, Phase C, are implemented and pass on the source-level
harness interpreter** (`integration/core/harness`, via `integration/read/tests/queue_sim.py` and
`test_t_queue_invariants.py`), now **133 tests, 132 passing + 1 expected failure** (up from the original
18, after today's F2/F3 investigation work added the `H_NRealisticAssociation` and
`I_OperateDeadlineAnchor` classes): residency (real ACK/response enqueue once, release once, under a
sufficient blocker reservoir; a degraded reservoir is detected and reported, not hidden); no early
response; both response children share one release decision; ACK/response/OPERATE have separate gates;
stale tokens and duplicate arrivals are rejected without disturbing a new transaction;
missing-response/missing-ACK/lost-blocker-service/budget-exhaustion fallback is bounded and
distinguishable from a normal completion; policy-off and reset both flush held originals and preserve
exactly-once delivery, with epoch quarantine correctly bypassing a superseded connection; the OPERATE
deadline is correctly anchored to the admitted operation's own generation; transaction association across
the real N→T path is explicitly tested, not assumed.

The full existing regression suite (root `tests`, `connection/binding/tests`,
`controller/tests`, `core/harness/tests`, `read/tests`) stays green with these changes — nothing
elsewhere in the tree was touched.

## What is not done: the local SDK 9.13.1 compile

Compiling against the real Tofino-1 target (`bf-p4c --target tofino --arch tna`) surfaced five
distinct classes of real hardware constraint. Four were fixed, with the fixes kept in the file
(they are real engineering, not reverted):

1. **Type mismatch** (`bit<4>` vs `bit<32>` constants) — fixed, cosmetic.
2. **One table may address at most one indirect extern** (a known constraint already recorded in
   project memory: "A Tofino table may access only ONE Register") — every action that bundled a
   state-register write with the `outcomes` counter bump, or that touched more than one state
   register, had to be split into separate single-register actions called as separate apply-block
   statements. Fixed across roughly a dozen actions (`release_ack`/`mark_ack_done`,
   `release_response`/`mark_resp_done`, `release_operate`/`mark_op_done`, `do_reset`,
   `admit_request`, `read_epoch_state`, and others).
3. **An action's ALU operations must fit in a single stage** — a combined mask-then-OR, and a plain
   add whose result fed directly into a stateful register call in the same action, both had to be
   split into separate single-operation actions (`hold_operate`'s clone-tag construction;
   `arm_resp_deadline`'s target computation split from `compute_resp_target`).
4. **A table cannot be `.apply()`'d from more than one place** (next-table propagation) — `gen_snapshot`,
   and later `da_check`/`readiness_check`/`gap_check`/`op_check`/`resp_seen_check`, all needed to move
   from being called inside several different branches to being applied exactly once, unconditionally,
   near the top of `apply{}` — harmless on passes that don't need the result, since each is a cheap
   register peek or deadline check.
5. **NOT CLOSED: a conditional/gateway complexity constraint, and what fixing it costs.**
   `if (md.now >= md.t0_v + md.da && ...) || md.now >= md.t0_v + md.readiness` failed with "condition
   too complex, limit of 4 bytes + 12 bits of PHV input exceeded" and "one operand ... must be
   constant" — Tofino's conditional-execution primitive (the apply-block `if`, compiled to a hardware
   gateway) cannot evaluate a live comparison between two fully dynamic values, especially not a
   compound `&&`/`||` of several. **The fix for this specific error is applied and is in the file**:
   `read_timing.p4` already solves exactly this, via its `deadline_deltas`/`heartbeat_eligibility`
   tables — compute `delta = now - deadline` as its own single-operation action, then turn the delta's
   sign bit into a 1-bit `*_ready` flag with a plain bit-slice assignment (`md.da_ready =
   (bit<8>)(~md.da_delta[31:31]);` — a pure data-plane ALU op, no table needed; see finding below for
   why this ended up simpler than a ternary-match table) for all five deadline checks (ACK `da`,
   shared `readiness`, response `gap`, OPERATE `op_j`), each then consumed by plain, narrow `== 1`
   comparisons.

   **This closed the specific diagnostic it targeted** (confirmed: stubbing the apply block down to
   just the unconditional top-of-pass computation, with no consuming branches, compiles with a
   *different*, later error — not this one). But the *fully assembled* file (every branch present)
   does not produce that later error either; it produces an **unhelpful internal compiler crash**
   ("Internal compiler error. Please submit a bug report with your code.", exit code 4, no file/line,
   no stack trace available — `ulimit -c` enabled and checked, no core dump; `--verbose 3` adds no
   useful detail) with no diagnosed cause after extensive bisection (stubbing each of T_IN's five
   sub-branches individually, both HELD_RETURN and HB_RETURN's four role branches individually, and
   the generator-token branch, one at a time — none of these in isolation reproduces a clean
   diagnostic in place of the crash; only stubbing enormous swaths, or the whole apply body, avoids
   it).

   **Follow-up evidence, confirmed on both local SDK 9.13.1 and the switch host's real installed SDK
   9.13.2** (compile-only, via `installed_sdk_build.py`, no activation — same authorized mechanism
   used throughout this effort): the crash is specifically and reproducibly in **PHV allocation, not
   table placement**. `out/pipe/logs/table_dependency_graph.log` on both SDK runs shows table
   placement actually succeeding, converging to **8 stages** (well inside the 12-stage budget) across
   two placement passes. `out/pipe/logs/phv_allocation_0.log` is **zero bytes** on both runs — the
   allocator crashes before writing anything, consistent with the crash happening at or immediately
   after PHV allocation starts.

   **Two independent mitigation attempts, both confirmed on both SDK versions, neither changed the
   crash at all:**
   1. Narrowing the `*_ready`/`resp_seen_mask`/`dup` fields from `bit<32>` to `bit<8>` and deleting six
      genuinely dead metadata fields left over from earlier iterations (`cap`, `child_bit`,
      `can_release`, `is_commit`, `stale`, `is_off`, `out_code`) — same crash, same signature (8
      stages placed, zero-byte PHV log), on both SDK versions.
   2. *(Superseded 2026-10-09: this bit-slice form was itself one of the hidden errors; the file now
      uses one-entry ternary `*_sign` tables again. See "Current state" above.)*
      **Eliminating all five ternary-match tables entirely** (`da_check`/`readiness_check`/
      `gap_check`/`op_check`/`resp_seen_check`), replacing each with a plain bit-slice assignment on
      the delta's sign bit (`md.da_ready = (bit<8>)(~md.da_delta[31:31]);`, a pure data-plane ALU
      operation, not a gateway/conditional construct at all) plus a direct `!= 0` comparison for
      `resp_seen_mask` (legal for a gateway on its own terms, since one operand is already the
      constant 0 — it never needed the sign-bit treatment). This removes the entire table-based
      mechanism the "gateway complexity" fix originally introduced, leaving only plain arithmetic and
      narrow flag comparisons. **Identical crash, identical signature, on both SDK versions.**

   Taken together, these two results rule out both of the obvious theories: it is not simply "too
   much live PHV data" (narrowing a third of the fields changed nothing), and it is not the
   ternary-match-table mechanism itself (removing all five tables changed nothing). Separately,
   re-examining the very first version of this file (before the gateway-complexity fix existed at
   all, using plain `if (md.now >= md.t0_v + md.da ...)` comparisons) confirms it hit the identical
   crash too — this is not something introduced by any of the fixes in this document; it was present
   from the first full compile attempt.

   3. **2026-10-08: the F2 fix (removing `op_t0_arm`'s `if (value == 0)` guard — a pure subtraction,
      zero new live metadata) also produced the identical crash signature on both SDKs** (table
      placement to 8 stages, zero-byte `phv_allocation_0.log`), confirmed by a direct compile of both
      the fixed and unfixed source on the same day. This is a third independent confirmation that small
      logic changes within existing registers do not move the needle at all — consistent with, and
      further supporting, the register-count bisection theory below rather than anything about this
      specific conditional.

   The true cause remains undiagnosed after five substantive, independent attempts to isolate or
   resolve it.

## Why this stops here rather than continuing

The dispatching task's own instructions named exactly this kind of outcome a legitimate stopping
point, not a failure to force past: "a partial, honestly reported result ... is a legitimate,
valuable stopping point." Here that is doubly true — the correctness of the design is fully
established at the level this phase actually needed (the interpreter is the authority the 18
invariant tests are written against, and nothing found in the real compile contradicts the logic; all
five findings above are hardware ALU/gateway/PHV resource constraints, not behavioral bugs the
interpreter missed). Four rounds of real, substantive fixes landed real progress (one-register-per-
table, single-stage ALU, table-applied-once, the gateway-complexity delta/sign-bit pattern — the last
of these confirmed correct in isolation and then shown, via two further independent mitigation
attempts, not to be the source of the remaining crash at all). Five separate things have now been
tried against the crash itself (bisection, cross-SDK confirmation, field narrowing, full table
elimination, the F2 register-guard removal) with no diagnostic information gained beyond "it happens
at the same point regardless."
Continuing to guess further structural variants with no new signal to act on is exactly the pattern
this project's own standing discipline (the M-mapper saga, `M_RECIRCULATION_VERDICT.md`) says to stop
rather than repeat. This crash is now a well-characterized, reproducible finding in its own right —
precisely where it happens (PHV allocation, after successful 8-stage table placement), what doesn't
cause it (table count, field width, the specific gateway-complexity fix), and that it is stable across
two SDK point releases — which is a legitimate basis for someone with access to the compiler's source
or Intel/Barefoot support to take further, rather than more blind source-level variation.

## Next concrete step (not performed here)

*Superseded 2026-10-09 by "Current state" above: the crash was diagnosed by branch bisection, not
register count, and the remaining blocker is stage budget on the ACK→response path.*

1. **Treat this as a compiler-level question, not a source-restructuring one.** Two independent,
   substantial restructuring attempts (narrower fields; zero tables, pure data-plane ops) produced
   the identical crash signature on two SDK point releases. That is evidence the remaining lever is
   not in this file's shape. A productive next step is bisecting by *register count* instead (this
   file declares roughly a dozen single-cell registers; try merging several into one wider struct
   register, or temporarily deleting whole domains' registers to see if the crash threshold is tied
   to total register count rather than anything examined here), or escalating to whoever maintains
   this SDK installation with the exact reproduction already assembled in this document.
2. Re-run the `bf-p4c` compile after each change on **both** SDK builds (local 9.13.1 via `bf-p4c`
   directly, and the switch's installed 9.13.2 via `installed_sdk_build.py`, compile-only) — every
   finding in this document held on both, so a fix should be confirmed on both too. The interpreter
   does not model any of the hardware constraints found in this session, so it cannot catch a
   regression here; only a real compile can.
3. Once it compiles, run it on the local Tofino-1 model (`integration/core/launch_model.sh`) with
   real packet inputs, per the original task.
