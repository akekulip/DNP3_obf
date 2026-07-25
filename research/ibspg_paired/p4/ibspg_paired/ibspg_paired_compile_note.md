# Gate 11.1 — compile + resource fit [COMPILED] PASS

`ibspg_paired.p4` — paired ACK-before-response over the Part-9 controlled-drain state machine.
Designed by the p4-dataplane-engineer workstream, reviewed by the main session (ACK is a pure held role
parallel to RESP — no coupling to reg_active/gen/drain; state machine verbatim from Part 9; egress parses
eth+ib for the released frames).

## Provenance
- SHA-256: `9feae154a3cedccf14a5a0c984966a545c5a36c4c88c4131d7f6032f243b54c4`
- local bf-p4c 9.13.1 (SHA e558d01) and on-switch 9.13.2 — command `bf-p4c --target tofino --arch tna -g -o <out> ibspg_paired.p4`

## Result
| | local 9.13.1 | on-switch 9.13.2 |
|---|---|---|
| exit / errors | 0 / 0 | 0 / 0 |
| warnings | 2 (benign parser-unroll) | 2 (same) |
| ingress stages | **12 / 12** | **12 / 12** |
| egress stages | 0 | 0 |
| source SHA | 9feae154 | 9feae154 (byte-identical) |

No 9.13.2 drift. **Fits at 12/12 with zero spare stages** — tight but placed. The 12th stage is driven by
counter (Stats-ALU) density in the ACT block, not by the timestamp bank (measured: dropping a ts register
does not move the stage count; dropping 3 counters → 11/12). Reclaim lever held in reserve if ever needed:
merge `ctr_drain_reject_stale`→`ctr_drain_reject_unrelated` + drop `ctr_arm`/`ctr_block_loop` (all
diagnostic; the ordering proof does not depend on them).

## Register / counter inventory (for control-plane + reader)
State (3, bit<8>): `reg_gen`, `reg_drain_req`, `reg_active`.
Timestamp (6, bit<32> ns): `reg_ts_first_block`, `reg_ts_drain_match`, `reg_ts_block_term`,
`reg_ts_first_ack_release`, **`reg_ts_last_ack_release`** (overwrite), **`reg_ts_first_resp_release`** (write-if-zero).
Ordering invariant: **`reg_ts_last_ack_release` < `reg_ts_first_resp_release`**.
Counters (14): `ctr_arm, ctr_block_enq, ctr_ack_enq, ctr_resp_enq, ctr_drain_match, ctr_drain_reject_stale,
ctr_drain_reject_unrelated, ctr_block_loop, ctr_block_term_controlled, ctr_block_term_timeout,
ctr_block_term_stale, ctr_ack_release, ctr_resp_release, ctr_nonibspg`.
(Part-9 `ctr_hold_enq/release` → `ctr_resp_enq/release`.) Counters need a `SyncCounters` op before read.

## Queues / TM (control plane sets priority; P4 only sets qid)
dp8 loopback: Q_BLOCK qid7 (max_priority 7 HIGH) > Q_ACK qid5 (max_priority 3 MID) > Q_RESP qid1
(max_priority 0 LOW). The three distinct levels are the SOLE ACK-before-response mechanism — verify on the
Gate-11.2 readback before trusting any ordering result.
