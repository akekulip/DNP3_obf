# ctl_timing_01: normalize SELECT and OPERATE CLRT, keep the OPERATE hold, bound piggyback latency (design, not built)

Status: design reviewed 2026-10-14 (see the review section at the end; change 5 replaced). No P4, model or hardware work has started. Base source is the qualified candidate61, `seg61_02/evidence/full_04/response_only.p4` (SHA256 `1b2d62d1…65aa`). Line numbers below refer to that file. Contract: `rearm_01/TIMING_CONTRACT.md`. Decisions: Philip, 2026-10-14 (all three CLRTs normalized to `gap`, J kept as its own objective, piggyback bounded per response).

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
