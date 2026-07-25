# Gate 12.1 — compile + resource fit [COMPILED] PASS

`ibspg_hold_response.p4` — the HOLD_RESPONSE timing branch of the unified transaction state machine:
the ACK is forwarded immediately and stamps `t_ack`; only the response is held queue-resident; the
release trigger is a **data-plane deadline** `t_ack + G`, not an external drain packet (Part 9) and not
a paired-response event (Part 11).

## Provenance
- SHA-256: `fa073cf691a6beb45fa8ffa61146cf481fc81e42f6cf4640bcb44ae6fe08f947`
- command (both toolchains): `bf-p4c --target tofino --arch tna -g -o <out> ibspg_hold_response.p4`
- local bf-p4c 9.13.1 (`/home/philip/bf-sde-9.13.1`), on-switch bf-p4c 9.13.2 (`~/part12/` on 10.10.54.81)

## Result
| | local 9.13.1 | on-switch 9.13.2 |
|---|---|---|
| exit / errors | 0 / 0 | 0 / 0 |
| warnings | 2 (benign parser-unroll, same as Part 11) | 2 (same) |
| ingress stages | **12 / 12** | **12 / 12** |
| egress stages | 0 | 0 |
| logical tables / SRAM / TCAM / map RAM | 44 / 36 / 0 / 36 | 44 / 36 / 0 / 36 (identical) |
| source SHA | fa073cf6 | fa073cf6 (byte-identical, verified by `sha256sum` on both hosts) |

No 9.13.1 → 9.13.2 drift. The on-switch compile was run **non-destructively**: `bf_switchd` was not
restarted and stayed on `/home/decps/part11/part11_abs.conf` (PID 112251 before and after), so the
loaded Part 11 program was undisturbed.

Fits at 12/12 with zero spare stages — the same tight fit as Part 11, and for the same reason: the
final stage is the timestamp bank. The removal of the entire controlled-drain path (`reg_drain_req`
and its serial stage, `ROLE_DRAIN_M/U`, 3 drain counters) and of the ACK hold path (`Q_ACK`, the
ACK enqueue/release counters, the first/last-ACK ordering timestamp pair) is what paid for the new
deadline register and expiry test. **Reclaim lever held in reserve** if a later part needs a stage:
drop `reg_ts_first_block` (+ its `ev_first_block` flag), which is a timeline convenience only — no
gate depends on it.

## Two compile findings worth keeping (both cost a compile cycle here)
1. **A bit-slice in a gateway condition is rejected outright** — `if (... && meta.age[31:31] == 1w0)`
   gives `error: condition expression too complex`. The program's own rule (one isolated compare per
   line) exists for this.
2. **A bit-slice of a 32-bit arithmetic field breaks PHV allocation**, even when moved out of the
   gateway into an assignment (`meta.age_sign = (bit<8>)meta.age[31:31];`). It imposes a
   `[31:31]/[30:0]` split on every field sharing the cluster and the compiler reports
   *"PHV allocation was not successful — 12 field slices remain unallocated"*, naming `ts32`,
   `dl_val`, `dl_now`, `hdr.ib.seq` and `ingress_mac_tstamp`. This is the invalid-SuperCluster trap
   the Part 9/11 header warns about, reproduced exactly.
   **Fix that works:** decide expiry with a ternary match (`tbl_deadline_expiry`, key
   `dl_armed` exact + `age` ternary, one const entry `0 &&& 0x80000000`). The match unit tests the
   same bit under a TCAM mask without creating any PHV slicing constraint. The compiler then folds
   the single-entry const table into gateway logic — final TCAM usage is 0.

## Register / counter inventory (for control plane + reader)
State (3): `reg_gen` (8b), `reg_active` (8b), `reg_deadline` (32b, armed by a qualifying ACK).
Timestamp (4, bit<32> ns): `reg_ts_first_block`, `reg_ts_ack_arm`, `reg_ts_block_term`,
`reg_ts_first_resp_release`.
Counters (11): `ctr_arm, ctr_block_enq, ctr_block_loop, ctr_block_term_deadline,
ctr_block_term_timeout, ctr_block_term_stale, ctr_ack_arm, ctr_ack_bypass, ctr_resp_enq,
ctr_resp_release, ctr_nonibspg`. Counters need a `SyncCounters` op before read.

Derived measurements:
- **`G_observed = reg_ts_first_resp_release − reg_ts_ack_arm`** — the normalized ACK→response
  interval. The Part 12 result is `G_observed ≈ G` regardless of when the response arrived.
- `deadline_error = G_observed − G`
- `release_tail = reg_ts_first_resp_release − reg_ts_block_term` — reservoir drain + dequeue cost.

The 32-bit ns timestamps wrap every ~4.29 s; the deadline arithmetic is valid while
`|now − deadline| < 2^31` ns (2.1 s), far above any G under test.

## Queues / TM
Only **two** priority levels are required (the ACK is never queued): Q_BLOCK qid7
(`max_priority` HIGH=7) > Q_RESP qid1 (`max_priority` LOW=0). Leaving the Part-11 three-level
configuration installed is harmless — qid5 is simply never used by this program.

## Not yet done (Gate 12.2 onward)
Nothing has been loaded or run. Silicon gates require reloading the switch with this program, which
displaces the currently-loaded `ibspg_paired` (reversible: `sudo bash /home/decps/part11/launch_part11.sh`).
