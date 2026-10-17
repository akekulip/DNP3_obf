# Why the cleanup deadline is not needed for connection-isolation correctness (m10_03, 2026-10-17)

**Claim.** Stale tokens and blockers of an old incarnation cannot affect a new connection's correctness, however long
their retirement takes. Their only effect on the new connection is timing: a bounded pacing of its polling until each
stale blocker's next pass. The exact cleanup deadline (m9 isolation v3: INDETERMINATE, 14.82–15.13 s against
15.001 s) is therefore a timing bound, not an isolation condition. The m10i diagnostic stays deferred.

Line numbers are in `response_only.p4` of this build (T is pipe-1 ingress, `t_Ingress`).

## 1. Every release is gated on the live generation and the live epoch

- `held_verdict` (2399–2439) has a release row only for held originals: `release_ack_commit`,
  `release_ack_fallback`, `release_response_counted`, `release_response_fallback`. Each row's key requires
  `md.e_bad == 0` and `md.lgen_diff == 0`.
- `lgen_diff` is the packet's own ladder generation XOR the live lane generation (`read_lgen_diff`, 2140;
  OPERATE: `op_lgen_diff`, 2141).
- An old-generation held packet falls to `flush_ack_stale` or `flush_response_stale` (2432, 2438). An old-epoch
  packet falls to the final `drop_old_epoch` (2439). OPERATE is the same (`hb_verdict`, 2454, 2460).

So a held packet of an old incarnation is never released into the new one.

## 2. A new connection always advances the generation

- The T_IN pass of an OPEN and of a RESET event runs `live_reset_gen` (1765, 1767), which bumps `gen_alloc_reg`
  (`gen_bump`, 1710).
- `gen_bump` saturates at 0xffff (exhaustion reports `GEN_EXHAUSTED`), so generations never wrap and an old
  generation never equals a later live one.
- The RESET pass also seals the epoch (`close_epoch`, `epoch_close`: bit 31 of `cur_epoch_reg`).

## 3. Stale tokens and blockers release nothing and retire on their next pass

- **Tokens:** `token_verdict` (2384–2397) seeds a blocker only when `rd_tok_diff == 0` (`hdr.timer.batch_id ^
  cur_gen`, 2110) and `e_bad == 0`. Any other token is `drop_timer_stale`.
- **Blockers:** a blocker keeps blocking only on a row with `lgen_diff == 0`. A blocker whose generation is no longer
  live takes `stop_blocking_stale` (2417, 2424; OPERATE 2454) on its next pass and is gone.
- **No side effects on new state:** blockers carry no release action and write no commit register. The commit
  registers are compare-and-set to the live generation (`resp_done_try` 1842, `ack_done` / `op_done` likewise), and
  `ack_commit_at_reg` is written only by a live held ACK's genuine commit (`commit_at_write`, 1822). So no stale pass
  can commit or release the new connection's ACK or response.

## 4. The residual interaction is timing, and it is bounded

A stale blocker still in the strict-priority queue (qid 7/5 above the held originals' 6/4 on HELD_RETURN) delays the
new connection's polling until it is served once more. On that pass it retires (section 3). The effect is therefore
at most one extra service per stale blocker alive at the generation advance. It never adds a release, a hold or a
commit.

Measured on m9_01 (the same T as m10), `seg61_02/evidence/hw_campaigns/ctl_m9_iso20_poll_950_01/isolation_v3.json`:
- **old tokens:** 7 READ and 4 OPERATE tokens accounted (joint conservation PASS);
- **stale blockers:** 0 before the permit and 2 after it, within the source-derived allowance of 25;
- **traffic on the new connection:** correct (traffic PASS), with c1–c3 present.

## Consequence

How long retirement takes changes neither correctness nor what the new connection receives. It changes only when the
last stale pass happens. The deadline therefore stays INDETERMINATE in the claim table, with the m9 interval, as a
stated timing limitation. It would be reopened only if one of sections 1–3 were found false, and then as a
correctness question for Philip.
