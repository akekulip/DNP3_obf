# ctl_timing_01: normalize SELECT and OPERATE CLRT, keep the OPERATE hold, bound piggyback latency (design, not built)

Status (2026-10-18): built through m10; the active candidate is m10_03 (section m10 at the end; evidence/m10_03/CLAIMS_20261017.md). Earlier status (2026-10-14): built as milestones m1 (SELECT), m2 (OPERATE) and m3 (piggyback bound); see "As built" at the end. Design reviewed before code; implementation reviewed after m3. Base source is the qualified candidate61, `seg61_02/evidence/full_04/response_only.p4` (SHA256 `1b2d62d1…65aa`). Line numbers below refer to that file. Contract: `rearm_01/TIMING_CONTRACT.md`. Decisions: Philip, 2026-10-14 (all three CLRTs normalized to `gap`, J kept as its own objective, piggyback bounded per response).

## What the code does today

**N routing.**
- `first_event` (339-341) classifies a packet by the owner state `m.observed[31:16]`. The states are 5 idle, 9 after SELECT, 0xa after the control response, 0xc after OPERATE, and 0xe after READ.
  - An outstation bare ACK reaches T (`first_read_ack`, 0x010a) only in state 0xe.
  - In states 5, 9, 0xa and 0xc it is `forward_original` (0x0108), kind 8, which never reaches T.
- `read_terminal_t` (427) sends kind 9 (READ request) through `commit_before_t(9)`, kinds 10 and 11 (READ ACK and response) through `emit_tev`, and kind 7 (OPERATE) through `commit_before_t(12)`.
- SELECT (kind 5), the control response in state 9 (kind 6) and in state 0xc (kind 16) all fall to `terminal_strip` and leave natively.

**T state.**
- The READ lane is a set of singleton registers: `gen_alloc_reg`, `t0_reg`, `ack_done_reg`, `ack_commit_at_reg`, `ack_commit_gen_reg`, `resp_done_reg` and `child_seen0..2_reg` (1670-1829).
- Only `t_KIND_REQUEST` opens a generation and arms t0 (`gen_access` 1732-1733, `t0_access` 1746). ACK and RESPONSE adopt the current generation.
- T checks only epoch and generation. Content binding lives in N (`read_app_t` plus owner state).
- OPERATE has its own registers (`op_gen_alloc_reg`, `op_t0_reg`, `op_done_reg`; 1879-1909) and its own blocker clone tag (0xE101++op_gen). A READ request clones with 0xE100++gen (`admit_request`, 1941), and `token_verdict` (2317) keys READ-lane blockers on it.

**Release and padding.**
- A released held ACK or response leaves T on port 9 (`export_held`, 2141) to pipe-0 egress.
- E pads purely from content and mapper accounting (`read_profile`/`ctl_profile`, `acct_t`, `classify_fwd`, 1303-1304). Whether a frame was held does not affect padding, so the 61-byte encoding is untouched by T routing.

**Stages.** N uses stages 0-10 (`first_event` is in stage 10) and T uses stages 0-10 (`outcome_count` in 10). Stage 11 is free in both ingress pipes.

## Proposed change (N table entries plus T rows; E byte-identical)

DNP3 masters keep one outstanding application request, so SELECT, OPERATE and READ never overlap on a connection. The design reuses the READ lane per transaction instead of adding a second lane. The singleton is already the authority, and Gate 2 showed the sequence READ → SELECT → OPERATE → READ is strictly serial on silicon.

1. **SELECT opens a lane transaction.** Add `read_terminal_t` entry `(8w5, 0, 0, _) : commit_before_t(8w9)`.
   - SELECT then enters T as a REQUEST (t0, a new generation, and the 0xE100 clone, so READ-lane blockers run). T forwards it to the relay as it forwards a READ.
   - `first_select`'s owner transition to state 9 is unchanged. Only the terminal event changes.
   - `read_terminal_t` grows from 10 to 11 entries.
2. **ACKs after SELECT and after OPERATE are lane ACKs.** In `first_event`, states 9 and 0xc map an outstation bare ACK to `first_read_ack` (0x010a) instead of `forward_original`.
   - States 5 and 0xa keep `forward_original`, so a stray ACK while idle is never held.
3. **Control responses are lane responses.** `read_terminal_t` entries map kind 6 (state 9) and kind 16 (state 0xc) to `emit_tev(16w0x0b00)` (RESPONSE).
   - The owner transitions in `first_response`/`first_response_op` are unchanged.
   - E still pads on the way out after T releases.
4. **OPERATE opens a lane transaction as well as its hold.** In T, kind `OPERATE` on T_IN also takes the READ-lane `gen_access`/`t0_access` rows that REQUEST takes (generation bump, t0 = admission), alongside its existing op-domain rows.
   - The OPERATE hold J (`op_go_check`) is unchanged.
   - Because `da` (2 ms) < J (2.4 ms), the outstation's ACK, which can only follow the released OPERATE, finds `da` passed. The ACK is held until the response is seen, then released (`a_commit`). The response is released at `a_commit + gap`.
   - OPERATE request→ACK therefore stays ≥ J, and OPERATE ACK→response = `gap`. These are two independent objectives.
5. **Piggyback bound (A4), per response.** N knows at the response whether a lane ACK preceded it: state 0xe/9/0xc without a prior `first_read_ack` in this transaction.
   - This needs one owner-state bit set by `first_read_ack` (inferred; to confirm in the owner actions 295-306).
   - A response with no prior ACK gets `emit_tev(0x0b01)` (RESPONSE, piggyback flag in the low byte that T currently ignores).
   - T adds one `resp_go_check` row: `piggyback && (now - t0) >= piggyback_bound` → go.
   - `piggyback_bound` is a new `set_params` argument, appended last so existing callers keep their order.
   - Separate-ACK responses keep `a_commit + gap`, with `readiness` (30 ms) as the fallback.

## Questions the model must answer before compile

- **Blockers for OPERATE (4).** Does an OPERATE-opened lane generation need its own 0xE100-tagged clone for `token_verdict`? The OPERATE path already clones with 0xE101. Options: the release of the held OPERATE emits the READ-lane clone, or `token_verdict` gets an OPERATE row. Model both; pick the one with no extra stage.
- **Stale flush.** Bumping the lane generation at SELECT or OPERATE must not stale a READ still in flight. This is excluded by serial DNP3 requests, but the model must cover a late READ response arriving after a SELECT: it is expected to be flushed (`flush_*_stale`) and counted, never released early.
- **Duplicates and old generations.** Retransmitted SELECT/OPERATE/ACK/response must hit the existing done and generation guards (`OUT_OP_DUP_DROP`, `done_diff`). Rerun the dup and rearm model suites unchanged.
- **Abandoned SELECT** (Gate 2 limitation). The lane generation opened by SELECT is closed by the next request's generation. N's owner-state stall is unchanged by this design and stays documented.

## Acceptance

- **Model.** All existing suites pass on the new build (smoke, packets, rearm, dup, repeat, abandon). A new `model_control_timing.py` shows, for READ, SELECT and OPERATE:
  - timely, late-ACK and readiness-fallback releases in order;
  - no early, stale or duplicate release, and no repeated mapper growth;
  - OPERATE relay arrival ≥ J;
  - piggyback released at the bound, and a slow separate ACK beyond the bound still gap-anchored.
- **Compile.** SDK 9.13.1 and 9.13.2 within 12 stages per gress, with the stage map compared to the baseline.
- **Silicon.** Three repeated-SBO blocks (4 arms × 64 cycles) plus piggyback blocks.
  - SELECT and OPERATE CLRT error p99 ≤ 100 µs in timed arms, matching READ.
  - OPERATE request→ACK ≥ J.
  - Piggyback request→response within the bound.
  - Profile-exact encoding, growth and restore unchanged.

## Review (2026-10-14, read-only P4 review against R = seg61_02 full_04) and revisions

**Correction.** SELECT (kind 5, direction 1) does not fall to `terminal_strip` today. `(_,0,0,2w1):terminal_ack()` (R:427) catches it first, so it leaves as 0xe4. E runs `acct_rev` on both 0xe4 and 0xe5 (R:918), so E's accounting for SELECT does not change under change 1.

| Change | Verdict | Revision |
|---|---|---|
| 1 SELECT via `commit_before_t(9)` | PASS with fixes | Put the new row before `(_,0,0,2w1):terminal_ack`. Raise `read_terminal_t` size from 10 to 13. `first_select` (R:325) leaves `hdr.t0` invalid: stamp it as `first_read_request` does, so model bytes are deterministic. Generation exhaustion now comes three times sooner (three lane generations per READ+SBO cycle); the headroom check must account for it. |
| 2 ACK in states 9/0xc via `first_read_ack` | PASS | Rows `(8w10,3w1,_,0x90000/0xc0000)` (R:341). Risk to measure: an ACK and response microseconds apart can make the ACK's `owner_diff` non-zero, so the ACK is aborted and the response falls back to `readiness`. |
| 3 Kinds 6/16 as RESPONSE | PASS with fix | T never parses the payload, so 77 B versus 89 B does not matter. `export_held` gives 0xe3 with `wgen` 0, which E ignores outside 0xe0. Rows go before `terminal_strip`. `first_response`/`first_response_op` also need t0 stamped. The model must confirm the 61-octet encoding. |
| 4 OPERATE opens the lane | RISK | Add rows to `gen_access` (R:1721, size 9→11) and `t0_access` (R:1740, size 3→5), with an `enabled==0` row first. Kind 15 gets no lane rows. Blockers: a plain `token_verdict` row does not work, because app-1 tokens carry `op_gen` and would be stale at once. **First option:** run the OPERATE lane without blockers (held frames lap until their deadline) and measure precision and loop load. **Fallback:** a new seed action that writes `cur_gen[15:0]`, plus app-1 packet_id rows and a pktgen batch change. Reject release-time cloning (the clone could misdecode as kind 12). |
| 5 Piggyback flag in `emit_tev` low byte | BLOCKER, replaced | The low byte is `tev.stage` (the response child index) and N has no spare owner bit. **Replacement, T only, N unchanged:** one register `ack_seen_gen` in its own table, using T's free stage 11. The T_IN ACK pass writes `cur_gen`; the RESPONSE pass reads it, and if it differs (no ACK came before this response) `admit_response` sets a ladder flag. `resp_go_check` and `held_verdict` (including the RESP_BLK rows) key on that flag and on a new `pb_delta = now - t0 - piggyback_bound`, computed beside `readiness_delta`. `piggyback_bound` is a new `set_params` argument. The control plane must always supply it, and a zero or missing value must be rejected before install, because 0 would release at t0. |

**Build order.**
- Changes 1–3 first, as one step: table entries only, with no new table or dependency. N stays at 11 stages, which matters because E uses all 12 in pipe 0.
- Then change 4, without blockers.
- Then the replacement for change 5. It adds a table, a register and wider keys in T, so it needs a compile check against T's 11-stage record.

**Falsification tests (model, in order):**
1. SELECT reaches the relay through T, byte-identical to the baseline; E's `acct`/`front` readback is unchanged; the lane generation goes up by 1.
2. SELECT: the ACK is held until the response is seen, and the response leaves at `a_commit + gap`.
3. OPERATE: relay arrival is at least J after admission; the response leaves at `a_commit + gap`; `op_gen` and the 0xE101 token behave as before.
4. A duplicate OPERATE (kind 15) before and after release: unchanged, and the lane generation is not bumped. A second outstation ACK causes no early response.
5. ACK and response microseconds apart in states 9, 0xc and 0xe: ACK aborts and `RESP_FALLBACK` are counted.
6. With T disabled: full passthrough, and no lane write for OPERATE.
7. A late READ response after a SELECT, and a RESET while a response is held: both flushed as stale and counted.
8. OPERATE lane without blockers: `TOKEN_STALE` counts, plus release precision and loop load measured.
9. Piggyback READ, SELECT and OPERATE responses released at the bound; a slow separate ACK beyond the bound still gap-anchored.
10. Stray ACKs in states 5 and 0xa still `forward_original`.
11. All existing suites (smoke, packets, rearm, dup, repeat, abandon), the 64-cycle repeat, and an exhaustion check at three generations per cycle.


## As built (2026-10-14)

`generate.py` produces `evidence/m1_02` (N only), `evidence/m2_01` (N + T) and `evidence/m3_01` (N + T + piggyback). E is byte-identical in all three, and all compile at N11/E12/T11 on SDK 9.13.1. m3 also compiles on 9.13.2 and passes the mirror guard.

**Deviations from the reviewed design.**
- **No t0 stamp on SELECT/response events.** N's loop parser (`envelope_event`) reads events 0x0105/0x0106 without `hdr.t0`, so stamping it shifted the loop packet and lost the SELECT (`m1_01`, retained). T never reads `t0q`.
- **Change 5 as built.**
  - `ack_seen_reg` is written on the T_IN ACK pass and read only on the held-response pass, giving `ack_seen_diff`.
  - `resp_go_check` gains two rows: ACK seen → no go; otherwise `t0 + pb` passed → go. No ladder flag and no `held_verdict` change.
  - The release therefore happens one held lap after the `resp_done` commit, through the existing `done_diff == 0` row.
- **pb range.** `pb` must satisfy `op_j < pb < readiness`. An OPERATE's piggybacked response cannot arrive before its J hold ends, so `pb <= op_j` would release it at once. Enforced by the installer (`t_config.check_params`) and the campaign config. bfrt name checking refuses an m3 install without `pb` and a `pb` sent to candidate61 (tested).

**Behaviour to disclose.**
- **Request→ACK carries the outstation's latency, for all three kinds.** The ACK is held until the response is seen. This is READ's existing property, now shared by SELECT and OPERATE. For OPERATE it is `J + execution latency`. CLRT (ACK→response) is normalized and J is a separate objective; request→ACK is not normalized.
- **Stranded SELECT blocker tokens.** Each SELECT seeds READ-lane blocker tokens. The OPERATE opens the next lane generation milliseconds later, so up to 2k of them are rejected as `OUT_TOKEN_STALE`. The runner bounds this explicitly for control-timed builds (2k per SBO cycle). Silicon `ctl_timing_repeat_sbo_950_b1`: 88 over 64 cycles, raw timer stale 0.
- **ACK and response microseconds apart.** Characterized in the model (`race_*` case). If N aborts such an ACK, the response is treated as piggybacked and leaves at `t0 + pb`.
- **Lane-generation exhaustion.** A READ+SBO cycle uses three lane generations. An OPERATE admitted when the lane generation is exhausted keeps its J hold but leaves its ACK/response untimed. Runs stay far below the 16-bit limit, and the per-run headroom precheck applies.

**Not implemented from the falsification list:** a duplicate outstation ACK in states 9/0xc (expected to fail closed on the exact counter check, not to release early), and a late READ response after a SELECT or a RESET while a response is held (covered by the existing generation and stale-flush guards; no new case).

## m4: selection lifecycle and fail-closed OPERATE exhaustion (2026-10-15, 9c4a2cfdc audit)

Source `evidence/m4_01/response_only.p4` (`35e896eb…79cf`), generated by `generate.py OUT m4`; E byte-identical (`a144cd30…1c10`); N11/E12/T11 on SDK 9.13.1 and 9.13.2, mirror guard PASS (`evidence/m4_01/resource_review.json`).

**N, IEEE 1815-2012 §4.4.4.3 Rule 4 / Table 4-9, while a selection is in effect (owner state 0xa, SELECT response delivered).** Two `first_event` rows ahead of the kind-5/kind-9 `count_refused` catch-alls:

| next request in 0xa | Table 4-9 action | m4 |
|---|---|---|
| neither SELECT nor OPERATE (READ) | terminate selection | admitted as a READ (`first_read_request`); owner leaves 0xa, so no later OPERATE can match |
| SELECT, new sequence or new octets | new selection replaces the old | admitted as a SELECT (`first_select`); the selection registers are re-stored |
| SELECT, same sequence and octets | valid retry | admitted as a SELECT; the outstation repeats its response |
| SELECT, same sequence, different octets | discard | admitted; the outstation discards it and sends nothing, so N waits in state 9 (unchanged limitation) |
| OPERATE, matching | execute | unchanged |
| OPERATE, not matching / after cancellation | no action | dropped by N (unchanged); a dropped request leaves its TCP slot outstanding, so the connection must be reset |

Owner state 9 (SELECT response still outstanding) is unchanged: admitting a request there would let the late response arrive in another state and be refused, which a TCP byte stream cannot survive. Selection timeout (Rule 1) is the outstation's; N has no timer.

**T.** An OPERATE admitted on an exhausted read lane (`new_gen` 0xffff) is dropped and counted (`GEN_EXHAUSTED`), as a READ or SELECT already was, instead of keeping its J hold with an untimed ACK/response. The generation precheck keeps exhaustion unreachable in a budgeted run; acceptance fails any trial with a nonzero `GEN_EXHAUSTED`.

**Model cases now asserted** (`model_control_timing.py`, `model_select_lifecycle.py`): cancellation, replacement, identical retry, stale OPERATE after cancellation (no release, no generation), new SBO after cancellation, a late copy of the old SELECT response after a replacement (dropped), a duplicate standalone ACK in states 9 and 0xc (no early or second release; for SELECT and OPERATE alike the duplicate may count a second ACK_COMMIT without moving the anchor, which the exact hardware counter check rejects), RESET while the ACK is held (nothing released; a relay-bound copy of the RST also leaves the master port in the model, origin unexplained), an OPERATE for a replaced selection (dropped), lane exhaustion for READ and OPERATE, and the ACK/response race, checked to take one of two known paths.

**Open N limitation (the race).** When the outstation's standalone ACK and its response arrive microseconds apart, N's single work cell can busy-drop the response (`count_busy[0]`). T's readiness fallback then releases the ACK, and the response is delivered only after the outstation's TCP retransmission, released on arrival by the response fallback, so its CLRT is not normalized (a retransmitted exchange; about 3 s on the SEL-751's measured RTO). The model takes this path in most runs because its N laps are slow. The committed path is the only one that keeps the timing objective; busy-drop is not acceptance evidence.

**Review suggestion not applied.** The new T row reads `md.new_gen`, which `gen_access` does not write when `enabled == 0`; the existing REQUEST row has the same dependency, and the compiled PHV keeps `new_gen` in its own containers, so it reads 0. Moving the row after the `enabled == 0` passthrough would remove the dependency but needs a recompile and a full model rerun; recorded for the next functional change.

## m5: bounded, validated busy-retry for responses (2026-10-15, PLAN_m5.md)

Built as `evidence/m5_10/response_only.p4` (`b758c981…e981`), generated by `generate.py OUT m5` (`transform_n_m5` = m4 N plus the edits below; T = `transform_t_m4`). Compiles on SDK 9.13.1 (local) and 9.13.2 (switch host) to N12/E12/T11, mirror guard PASS (`evidence/m5_10/resource_review.json`); E `a144cd30…` and T byte-identical to m4. The generator asserts E and T byte-identical to m4. N only; requests (kinds 1, 2, 5, 7, 9, 12) keep `busy_drop`, so request admission and the OPERATE hold are unchanged.

**Mechanism.** A response (kind 6 control, kind 11 READ) that finds the work cell busy becomes a retry frame on RETURN_PORT (egress bypassed, so it never reaches E): envelope epoch = the current epoch read on that pass, generation = the one `go_new` already allocated for it, expected_cell = lap budget, event `0x0400` (stage 0, kind 0), reserved 0. The parser recognises the form only on RETURN_PORT (`retry_input`, `m.retry = 1`), and only with nonzero epoch and generation and reserved 0.

| amendment | as built |
|---|---|
| 1 generation accounting | a retry pass claims with the carried generation (`go_retry`); it never calls `allocate`. Source test: the contended and the uncontended exchange end with identical N registers, generation counter included |
| 2 incarnation isolation | new register `retry_epoch`, before the work cell: written with the envelope epoch on the SYN lifecycle's stage-2 pass (reached only after stage 1 stored the epoch), cleared on every stage-1 close pass (kind 4 FIN/RST, kind 17). Its check writes the verdict straight into `m.retry` (1 current, 2 stale). A stale retry is caught before the guard: `go_stale` sets `work_op` 0, so the cell is read, not claimed, and no register is written; `busy_t` drops it and counts `count_busy[4]` |
| 3 budget | `n_RETRY_BUDGET` = 32 laps. A retry still busy with budget 1 is dropped and counted (`count_busy[3]`, exhaustion = failed delivery objective). `count_busy[2]` counts retry laps. Measured need (source, lap granularity): 3 laps at most for one contended response, 9 in total for a response plus a duplicate copy arriving with it (probe of 0/0, 1/1 and 5/6 lap offsets: 9, 7 and 2); the model and silicon runs report `count_busy[2]` per block |
| 4 strict validation | RETURN_PORT at stage 0 is denied unless `m.retry != 0`; a retry is stale unless its epoch matches `retry_epoch` and `retry_valid_t` finds direction outstation->master and a budget of 1..32 (ternary rows; bf-p4c allows no range match on a 32-bit key). A retry that fails N's port or network check (a corrupted frame; a genuine retry is byte-identical to a packet that passed them) never reaches the guard and is denied on its single pass, uncounted: admitting it to the guarded branch made PHV allocation fail. Every retry frame enters the guarded branch and every refused one is marked stale (`go_stale` sets `m.retry` 2), so it is dropped and counted on its single pass; none recirculates. Two loops were found and closed: a network-invalid retry (source test) and a valid retry whose connection rows the control plane removed mid-flight, which fell to `go_stale` with `m.retry` still 1 (review H1; source test removes the connection/read/data rows mid-retry) |
| 5 no E side effects | retries bypass egress; source test: E's cells after a contended exchange equal those after an uncontended one, no E pass sees RETURN_PORT, and the master receives byte-identical frames |

**Retried duplicates.** A retry that claims the cell and that `first_event` classes as a retransmission (`forward_original`, 0x0108) is turned into an abort on the same pass (kind 255: the cell is returned through the existing abort laps and `terminal_abort` drops the frame) and counted in `count_term[0]` (a register m4 declares and never uses; counting it through `busy_t` needed a merged branch flag that made PHV allocation fail). Without this, m5 would have forwarded such a copy untimed ahead of the timed original, a leak m4 did not have for copies arriving during the original's lifecycle (m4 busy-dropped them; review H2).

`count_busy` grows from 4 to 8 cells (index 2 retry laps, 3 exhaustion, 4 stale); indices 0 and 1 keep their meaning. `count_term[0]` counts retried duplicates aborted.

**Stage cost.** N grows from 11 to 12 stages, all of it from the duplicate abort, which must follow `first_event` (N's last stage in m4): every bisect variant without it compiles at N11, every one with it at N12 (compile journey below). PLAN_m5.md allows N12 when the composite fits with E and T unchanged and guards passing; the alternative (N11) would reopen the untimed-duplicate leak.

**Compile journey (retained as evidence, never overwritten).** `m5_01` gateway too wide (validation condition over 4 bytes + 12 bits of PHV input); `m5_02` range match on a 32-bit key unsupported; `m5_03`, `m5_05`-`m5_08` PHV allocation failed (`m5_04`: SALU assignments not mutually exclusive). Bisect (scratch variants, not retained) located the PHV pressure in two edits: widening the main guarded-branch condition with `m.retry`, and counting the duplicate abort through `busy_t`. `m5_09` removes both and compiles. `m5_10` (the successor qualified on the model) differs from `m5_09` in one action: a waiting retry keeps the epoch it carries on every busy lap instead of being re-stamped with the current epoch, so a retry created before a new incarnation can never be admitted into it, whatever the owner state (m5_09 review; source test `test_waiting_retry_keeps_its_own_epoch_across_a_new_incarnation` fails on m5_09, passes on m5_10).

**N generation exhaustion.** m4's `busy_t` row for a busy response with generation 0 (N's 31-bit counter exhausted) is gone: such a response becomes a retry frame with generation 0, which the parser does not accept as a retry, so it is denied on its next pass (dropped, not counted). Unreachable in a budgeted run (2^31 - 2 allocations).

**Known costs, safe direction (never admit a stale retry).** `retry_epoch` is cleared on any stage-1 close pass before the close is known to succeed, so a refused RST or a half-close FIN makes later contended responses on that connection fail delivery (counted stale) until the next SYN; a connection seeded without a SYN refuses every retry. A retry generation is claimed once in normal operation; a duplicated internal retry frame (not produced by N) could re-claim it, which the m4 epoch/owner checks then govern.

**Model evidence (m5_10, `evidence/m5_10/model_summary.json`).** Every driver passes on the compiled build: contention 223/223 (`model_contention_m5_10_02`: ACK then response at 0-120 ms wall for READ, SELECT and OPERATE, duplicates, a second unconfigured connection, RESET and same-tuple reconnect while the response waits, loss and recovery; no busy drop, no exhaustion, no stale; at most 7 retry laps in a case against the budget of 32), control_timing 141/141 (race path `committed`, the only path allowed for m5), select_lifecycle 120, smoke 30, packets 622, rearm 399, dup 102, repeat 523 -- the same counts as m4. The same final driver on m4 (`model_contention_m4_01_05`) fails exactly on delivery at small spacing (busy drops), the original race. On the model every m5 reset/reconnect case took the admitted-before-reset path; the refused-after-reset path (a waiting retry refused as stale) is proven at source level only.

**Source-level evidence** (`tests/test_contention_source.py`, `tests/contention_source.py`: N passes scheduled one lap at a time, so arrivals interleave with another packet's laps). m4 keeps the original race as a regression: a response 0-2 laps after the ACK is busy-dropped, only the ACK reaches the master (by T's readiness fallback). m5 delivers at offsets 0-4 for READ, SELECT and OPERATE through the committed path (ACK_COMMIT 1, RESP_RELEASE 1, no fallback), with the same release times as an uncontended exchange. Mutations of the retry form (event, reserved, budget 0/33/max, epoch, generation 0, another tuple, a front-panel arrival port) never claim and never change N state; stale ones are counted. A retry captured before a master RST, or before a same-tuple reconnect, is refused as stale. A cell held forever (forced) exhausts the budget exactly.

**Pre-existing behaviour surfaced, not changed (open, Philip's decision): RST after an admitted response.** Once N has admitted a response (T holding it for the timed release), a master RST that acks only the pre-response sequence -- what a master that has not yet received the response sends -- is refused: N's owner stays established, the RST never reaches the outstation, the held response is still delivered, and a later same-tuple SYN is refused until the connection is closed. m4 does this on its uncontended path (source test `test_rst_after_a_contended_response_matches_m4_uncontended`: response 6 laps after the ACK, RST 1-40 laps later). m4 escaped it on the contended path only because it busy-dropped the response; m5's contended path now equals m4's uncontended one. The model contention driver therefore records the RST outcome as an m5 verdict only when the retry was refused after the reset, and lists the admitted-before-reset cases under `rst_refused_after_admitted_response` in its meta; its cleanup RSTs (both master-visible acks) only let later cases run. Making N accept such an RST is outside this N-only correction.

**Pre-existing behaviour surfaced, not changed (open, Philip's decision).** An outstation retransmission of a response N has already admitted is forwarded natively at once by m4, ahead of T's timed release of the original (source test `test_m4_forwards_a_duplicate_response_untimed_once_the_original_was_admitted`; m4 busy-drops such a copy only when it lands inside the original's lifecycle). m5 leaves that native path unchanged; only copies that waited in retry are aborted (above). Making a natively arriving retransmission of a held response wait for, or be dropped behind, the timed original is a separate change outside this N-only correction.

## m6: reset, epoch boundary and held-duplicate corrections (2026-10-16, directive 72d85875b, PLAN_m5.md m6)

Successor candidate `evidence/m6_07/response_only.p4` (`3335479b…e142`), generated by `generate.py OUT m6` (`transform_n_m6` = m5 N plus the edits below; T = `transform_t_m4`; the generator asserts E and T byte-identical to m5). m5_10 stays immutable. N only. **Not frozen and not run on silicon**: the directive's hour-5 gate (a reviewed successor through compile and model by 03:11) passed without one, so no m6 hardware ran this night; and m6_07's model contention run failed one point (below), so its model gate is not passed.

| defect (m5) | m6 change |
|---|---|
| R: a master RST|ACK whose ACK covers only what the master received is refused once N has admitted a response (the server register already counts the response T holds), so the RST never reaches the outstation and the held response is still released | three `first_event` rows accept, in direction 1 only, flags exactly RST|ACK (20), SEQ exact (`client_diff` 0), and an ACK one response behind the server register in N's native coordinates (−49 or −37 in owner state 5; −37 in 0xa). **The reset is therefore validated by its exact SEQ**, as a bare RST (flags 4) already was on m4/m5 (RFC 9293 §3.10.7.4); the ACK restriction holds in native coordinates only, so in master-visible coordinates several ACKs pass: READ held {901, 913, 950}; after release 901–962 (an ACK inside the padded image normalizes to the native start); SELECT held {901, 938}; OPERATE held {962, 999} (m5: {950}, {962}, {938}, {999}). `tests/test_m6_lifecycle.py` pins these sets and refuses SEQ ±1 everywhere (review of m6_01, H2: the first text claimed every other ACK was refused) |
| R-busy: an RST at stage 0 that finds the work cell busy is denied | the RST becomes a retry frame (event `0x0800`, origin header kept, generation 1 = marker only, no allocation) validated by m5's retry checks (`retry_epoch`, budget 1..32, `retry_valid_t` now also direction 1) and re-enters `go_keep` for kind 4. The retried pass takes the snapshot path its first pass took: `snapshot_t` keys retry frames on `m.direction` (1 master, always lapped: `snapshot_lap`; 2 outstation, native: `snapshot`), so a master RST whose normalized epoch is 0 (E's unbound slot) dies on its retry exactly as on a free pass. m6_01 forced `m.lap` 1 and lost every busy outstation RST (H1); carrying the lap in the generation field failed to compile three ways (m6_02 parser match registers, m6_03 PARDE alignment, m6_04 PHV allocation); keying on `m.normalized_epoch` (m6_05, m6_06) let a busy master RST with normalized epoch 0 close where a free one is denied (review of m6_06). The retry covers every kind-4 segment `close_shape` admits, FIN|ACK included (m5 denied a busy FIN); a busy FIN ends exactly as a free one (test) |
| E: `retry_epoch` cleared on the stage-1 close pass, before the owner CAS shows the close succeeded, so a refused RST or half-close disables later contended responses on a live connection | `reset_boundary` keyed on stage: a stage-1 CAS success goes to `reset_continue` (next stage), the stage-2 pass clears `retry_epoch` and emits the reset; kind 17 clears on its stage-2 pass. The clear is conditional on the stored epoch being the close pass's own envelope epoch, so a delayed close pass of an older incarnation cannot clear a newer one's retry authority (test-matrix finding: m5's stage-1 clear and m6_01..m6_05's stage-2 clear both had this gap; m6_06 fixes it) |
| D: an outstation retransmission of a response T still holds is forwarded natively ahead of the timed original | in owner states with no newer transaction open (READ 0x5; control 0xa and 0x5) a `seq_retx` response copy takes new event `0x0119` (kind 25), routed to T as a RESPONSE (`read_terminal_t` → `emit_tev(0x0b00)`). T drops it while the original is held (`RESP_DUP_DROP`) and passes it after release (loss beyond the switch). N's `go_new` still allocates one N generation for the copy's lifecycle, as m5's `forward_original` did; T allocates nothing. 0xe/0xc keep `forward_original` (a newer transaction is open; T would take an old copy as the new response): a copy of an old response arriving after the next request still leaves untimed there |

**Retried-duplicate abort kept; N stays at 12 stages.** The m5 abort (0x0108, `count_term[0]`) is still needed in 0xe/0xc; in 0x5/0xa retried copies now carry 0x0119 and are dropped by T instead (source: `RESP_DUP_DROP` 1, `retried_duplicates()` 0). Replacing the abort to recover N11 was not attempted (directive: correctness first).

**Residuals recorded, not changed.** A busy RST before any epoch is bound (N epoch 0) produces a retry frame the parser refuses, dropped uncounted, where a free one would take `snapshot_lap` (pre-first-SYN only). `retry_epoch_t` runs before N's guard and checks; the conditional clear is safe because only `reset_continue` and the kind-17 close produce stage-2 kind-4/17 frames with the current epoch (a new producer would have to respect this). With T holding a response, an outstation RST that closes the connection is not forwarded to the master (E drops it), on m5 and m6 alike; with the cell free it is forwarded. A theoretical relabel remains in state 5 directly after a handshake (a segment at server−49 would be routed to T as a response; needs an ISN collision or an on-path injector). RST retries share `count_busy[2]` with response retries.

**Compile.** m6_01, m6_05, m6_06 and m6_07: SDK 9.13.1 local and 9.13.2 switch host, N12/E12/T11, mirror guard PASS, E byte-identical (`evidence/m6_*/resource_review.json`). m6_02–m6_04 failed (retained).

**Source evidence.** `tests/test_m6_lifecycle.py` (m5/m6 side by side on the lap-scheduled pipeline): master and outstation RST at laps 0/1/5/40 for READ, SELECT and OPERATE, then a fresh handshake and READ; the exact ACK sets above; RST retry exhaustion, stale RST retry after close and reconnect, RST during a response retry; a refused master FIN keeps retry authority and a later contended READ is delivered; delayed close passes of an old incarnation (0x0104, 0x0204) leave the new authority; duplicates during retry, while held, after release, after the next READ, after reconnect and across sequence wrap. `tests/test_contention_source.py` runs m4/m5/m6. Each fix's test fails on the build before it (the m6_06 epoch-0 case: `test_busy_master_rst_with_normalized_epoch_zero_ends_like_a_free_one`).

**Model evidence.** `model_contention.py` m6 expectations: the master's first RST must take effect in every reset and reconnect case (no "refused after admitted response" exemption); a third outcome `flushed_by_reset` (response admitted and held, flushed by the reset); a duplicate sent during the wait may reach the master only after the timed original with identical bytes (the model's laps take milliseconds, so the copy reaches T after the release; on silicon laps are about a microsecond against a 950 us hold, but that is a source-level statement, not a measurement); a post-release duplicate passes once with no T release or fallback (N generation delta recorded, not gated). Results per build in `evidence/model_*_m6_0N_01`; m6_01's contention run (234/241) failed on its own duplicate/generation expectations, since corrected, and on OPERATE sweep points at 8 and 45 ms (fallback, request not relayed) that did not recur on m6_05 (241/241) and were not diagnosed; m6_01's rearm run never started (bf_switchd gRPC did not come up while a compile ran). m6_06: contention 241/241, control_timing 141/141 (suite stopped there, superseded). **m6_07: contention 240/241 FAIL**, every other driver passes (control_timing 141, select_lifecycle 120, smoke 30, packets 622, rearm 399, dup 102, repeat 523). The failure is `sweep_SELECT_000ms`: the response retried 3 laps (no busy drop, exhaustion or stale) and then never reached the master; T counted ACK_FALLBACK 1 and neither RESP_RELEASE nor RESP_FALLBACK, so the response was lost without any counter (the master got it only from the driver's cleanup retransmission). The same point passed on m6_05 (1 retry) and m6_06 (0 retries). Not diagnosed: the source harness delivers 3-retry SELECT responses at microsecond laps, and its handshake does not run at model-scale laps. Until classified, a silently lost retried response is an open delivery defect of the retry path on the model, not attributed to the m6_07 delta. Model summaries: `evidence/m6_0N/model_summary.json`.

## m7: T time base without 32-bit aliasing, durations rounded up (2026-10-16, directive ba50eac69 C1)

`evidence/m7_03/response_only.p4` (`8f51fb67…d28b`), from `generate.py OUT m7`. It is m6's N with one changed T line
(`transform_t_m7`); E is byte-identical to m5/m6. Compiles on SDK 9.13.1 and 9.13.2 at N12/E12/T11, mirror guard PASS.
Model: all eight drivers pass (`evidence/m7_03/model_summary.json`, every attempt listed). Not frozen; not run on
silicon.

**Defect (shared by every earlier T; reproduced here on m6, not introduced by it).** T decides each deadline by the sign
bit of the 32-bit ns value now − D − t0. An anchor older than D + 2^31 ns reads as "not ready", and one older than
2^32 ns aliases to a fresh exchange. This caused the m6_07 model loss (`evidence/model_contention_m6_07_01/
TRACE_sweep_SELECT_000ms.md`). The exposure of earlier measurements is assessed separately in
`evidence/T_ALIASING_EXPOSURE_20261016.md`; no measured exchange was affected, and the stale-token runs are open.

**Change.**
- **Clock:** `md.now = global_tstamp[39:8] & ~1`. That is 256 ns units on a 512 ns sampling grid, with bit 0 left free for
  the OPERATE anchor flag. The signed horizon is 2^31 × 256 ns = 9.16 min and the full wrap 18.33 min. A passed deadline
  reads as passed until D + 2^31 units after its anchor; declared bound: T resolves every held packet within 9.16
  minutes of its anchor.
- **Placement:** the `[40:9]` slice, a shift and a two-word concatenation all failed PHV allocation (bisect in
  scratch). Shifting the action-data parameters in `set_params` crashed bf-p4c. The byte-aligned `[39:8]` slice places
  at the old stage counts.
- **Durations:** configured in ns everywhere and written in T units by one shared function,
  `core/response_only/hw/t_config.t_units`: ceil((D + 512 ns) / 256 ns). Its writers are the hardware bring-up
  (`dataplane_params_op`, which records ns, units and time base in the manifest), the model driver (`Model.set_default`,
  cross-checked against the source clock and logged to `t_params_written.json`) and the source pipeline (`LapPipeline`).
  A build declares its unit in `inputs.json` `t_time`. Earlier builds stay in ns.
- **Early decisions:** the anchor and now are both floored to the grid, so the bound covers anchor quantization and the
  unit conversion together. No deadline resolves before its ns duration. Tests (`tests/test_t_phase_sweep.py`):
  - an exact 1,024-phase sweep against the unquantized reference;
  - a check that the pre-m7 T (255 ns) and a naive >> 9 conversion (767 ns at J = 2.4 ms, Philip's counterexample) are
    early;
  - an end-to-end OPERATE J sample on the real P4, plus a full 1,024-phase end-to-end record in
    `evidence/m7_03/phase_sweep_end_to_end.json`;
  - rollover across the 2^40 ns wrap, and the lifetime bound.
- **Cost:** release up to about one grid later than the ns duration (≤ 2 grids + 1 unit).

**Harness corrections found while gating** (each retained with its trace):
- **contention:** the capture now waits for T's response release or fallback, and the work cell must be idle at each
  point.
- **control_timing, clock:** J calibration uses the shortest J sample (`model_control_timing_m7_03_01/TRACE_piggyback.md`).
- **control_timing, OPERATE:** the outstation ACK is sent only after the relayed command appears
  (`model_control_timing_m7_03_02/TRACE_operate_dupack.md`; the model lagged the driver under host load).

**m8** (= m7 + E reset at the frontier, `transform_e_m8`) is kept separate so that each resource failure has a single
cause. Its source tests are in `tests/test_m8_abort.py`. Its earlier compile attempts (m7_01 and m7_02, then labelled
m7) combined the E change with an older T draft and failed PHV allocation; they are retained.

## m8: outstation reset placed at the master's frontier (2026-10-16, directive ba50eac69 section 2)

m8 = m7 + one E change (`transform_e_m8`). An outstation RST that is exactly one held response ahead of E's frontier
(49 octets for READ, 37 for control) is written at the master's RCV.NXT and counted as E outcome 16. Before m8, E
dropped it as `OUT_DROP_AHEAD`.
- **What the rows key on.** The rows match the RST's distance from the frontier and the RST bit, not T's held state.
- **Explicit limitations:**
  - an RST at the distance of two held responses still drops;
  - a bare RST (no ACK bit) is forwarded untranslated;
  - with nothing held, the frontier is already the RST's position, so the rows do not fire.
- **Review findings:** `evidence/m8_02/REVIEW_GAPS_20261016.md`.

## m9: a master RST waits out a busy work cell (2026-10-16, completion plan gate 1)

m9 = m8 + one N change (`transform_n_m9`); E and T are byte-identical to m8.
- **The race.** A master RST closes in N over two passes. Stage 0 validates it without claiming the work cell; stage
  1 needs the cell idle. An event that claimed the cell in between (a same-tuple SYN one lap later, found in
  `model_contention_m8_02_02` and reproduced deterministically) sent the RST to `terminal_abort`. N then kept the
  old connection and denied every later SYN. The same race explains the 12/24-octet translation difference: N and
  E never armed the new connection, so the next RST was translated against the previous connection.
- **The fix.**
  - The stage-1 close now recirculates while the cell is busy and its owner and epoch are unchanged, counting laps in
    `event.reserved`, and closes once the cell is idle.
  - After 32 laps it aborts as before.
  - The parser and the guard accept `reserved` values 0–63, and `reset_continue` zeroes the field before stage 2.
- **Build and model results.**
  - Source `6590141f`; N12/E12/T11 on both SDKs, mirror guard PASS.
  - All eight model drivers pass, plus `model_abort` (79/79).
  - Model summary: `evidence/m9_01/model_summary.json`.
- **Coverage and open limitations:** `evidence/m9_01/NOTES_20261016.md`. In particular, an event that changes the
  owner during the wait still loses the RST; a compliant master sends nothing after its RST.
- **Abort profile** (`model_abort`, `model_contention` abort section):
  - Held READ and SELECT: the RST lands at RCV.NXT, E-16 counts +1, and T discards the held response as
    OLD_EPOCH_DROP.
  - Released branch, all kinds: one response, then the RST at the new frontier.
  - OPERATE responses are never held, because J > D, so an OPERATE abort is always the released branch.

## m10: a stage-1 master RST survives the response claiming N's cell (2026-10-17, review af7bd434 finding 1)

m10 = m9 + one N change (`transform_n_m10`); E and T are byte-identical to m9_01.
- **The race m9 left open.** A master RST's stage-0 pass found the cell idle. The response then claimed the cell
  before the RST's stage-1 pass, the owner had changed, and m9's wait did not apply, so the RST was lost. The
  compiled model showed this on m9_01: the first RST was lost and the response reached the master
  (`evidence/m10_03/diag_restart_case_on_m9_01_01`).
- **The fix.**
  - A stage-1 RST restarts at stage 0 as the 0x0800 retry when the epoch is unchanged, the low 16 bits of the owner
    difference are 0, and the RST bit is set. `count_busy[5]` counts restarts.
  - The lap counter rides in `event.reserved`. snapshot_t's retry rows keep it, and `first_close` no longer zeroes
    it. It is bounded at 32.
- **Attempts.**
  - m10_01 restarted FIN|ACK too, so the RST bit became a key.
  - m10_02 added a metadata field (`m.rst_laps`) that corrupted the compiled model (`evidence/m10_bisect_01`).
  - m10_03 carries the counter in the existing snapshot variants instead.
- **Build.** Source `d9b84fcc`; N12/E12/T11 on SDK 9.13.1 and 9.13.2, the same as m9_01.
- **Reset contract (Philip, 2026-10-17).** A reset takes effect for T's held traffic at T's reset-application pass
  (`close_epoch` + `live_reset_gen`). A response released by T before that pass may still reach the master: the
  N-to-T window, a stated limitation, with at most one copy. A release after that pass is a defect.
  `reset_application_check.py` judges this from each run's model log. The original "no response" result is kept,
  as recorded.
- **Results.**
  - Model gate passed: `evidence/m10_03/model_summary_v3.json`, contention attempt 07 413/413, abort 07 79/79.
  - Restart: exercised on the compiled model by the targeted section (first try, both kinds).
  - Silicon: recovery passes. The restart path is **not exercised on silicon** (`evidence/m10_03/CLAIMS_20261017.md`).
- **Open items** (`evidence/m10_03/NOTES_20261017.md`):
  - mutation3: a forged retry frame on RETURN_PORT, unreachable from outside, inherited from m9;
  - a master that sends after its own RST;
  - the model tests the 9.13.1 image while the switch loads the 9.13.2 image.
