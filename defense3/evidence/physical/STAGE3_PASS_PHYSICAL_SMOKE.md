# PHYSICAL STAGE 3 — one read-only Class-0 transaction at D = 2 ms · **PASS**

10/12 instrumented live build, kept loaded. Capture `evidence/physical/stage3b.pcap`.
The fix was the missing live arming step: `--arm-blockers` enables pktgen app 1 and
**leaves it on** (it implies `--no-cleanup`, because `cleanup_trial` disables it again —
which is exactly why the first attempt ran with an empty `Q_BLOCK`). In the live path
"armed" is a standing condition, not a per-transaction action, because the trigger is the
real master's READ.

## Internal decomposition, from the switch's own registers

| quantity | value |
|---|---|
| first blocker admission | 2 769 950 513 |
| **full 64-token reservoir** | 2 769 951 029 → **516 ns** after the first |
| relay ACK ingress (`t_ACK`) | 2 770 391 734 |
| **full reservoir standing BEFORE the real relay ACK** | **441 221 ns (0.441 ms)** |
| armed deadline | 2 772 391 425 = `t_ACK + 1 999 691 ns` = **D** within tick quantization |
| first blocker deadline termination | 2 772 391 430 → **detection error 6 ns** |
| final blocker termination | 2 772 393 123 → **drain 1 693 ns** (model `K/rate` = 1 711) |
| ACK commitment | 2 772 393 149 → **release tail 26 ns** |
| **actual hold** | **2 001 415 ns** vs `D + K/rate` = 2 001 583 → **corrected error −168 ns** |
| `reg_ack_rel` at the ACK release | **0x10** — the E1 **pending domain**: the early RESPONSE had marked the tag `0xC0 → 0x10` |
| `reg_tag` after | **0x00** — retired by the queued RESPONSE's release |

## Requirements

`pktgen app 1: app_enable = true, trigger_counter = 1, batch_counter = 1, pkt_counter = 64`
— **exactly one trigger**. `PKTGEN_ADMIT = 64`, `PKTGEN_DROP = 0`. `ACK_HOLD` for this
transaction, `ACK_DUP_HOLD = 0` (the capture shows exactly one relay pure ACK for the
transaction). Deadline armed **once**. Hold ≥ D, so **no ACK commitment before the
deadline**. `RESP_HOLD_EARLY = 1` — the RESPONSE arrived inside the window and was queued
**behind** the ACK, so **no current-transaction RESPONSE committed before the ACK**.
`RESP_DUP_SUPP = 0` — no real retransmission occurred, so nothing was suppressed.
`BLOCK_TERM_DL = 64`, `BLOCK_TERM_TMO = 0`, `BLOCK_TERM_STALE = 0`,
`RELEASE_DEADLINE = 1`, `ACK_RELEASE_FAILOPEN = 0`. Transaction retired. Queue drops
**0** on both queues. TCP healthy through close.

★ **Both E1 branches are now exercised on real relay traffic**: `ACK_RELEASE = 1` from this
run (a RESPONSE was pending, so the ACK did **not** retire) and `ACK_REL_RETIRE = 1` from
the earlier unarmed run (nothing pending, so the ACK retired) — the Gate 4C repair firing
on a physical transaction.

## Vision-side capture correlation

| event | offset from the READ | unarmed run, for contrast |
|---|---|---|
| relay ACK reaches Vision | **+2.548 ms** | +0.480 ms |
| relay RESPONSE reaches Vision | **+2.590 ms** | +5.015 ms |
| ACK → RESPONSE on the wire | **+42 µs** | +4.535 ms |

The relay's ACK is emitted at ~+0.48 ms in both runs; with the reservoir armed it reaches
the master at **+2.548 ms**, i.e. **~2.07 ms of added delay**, consistent with the switch's
internal hold of 2 001 415 ns. **ACK first, RESPONSE second**, and the RESPONSE follows only
42 µs later because it was queued behind the ACK in `Q_HOLD` rather than travelling
independently.

## Verdict — mechanism smoke test only

Defense 3's hold executes end to end against the physical SEL-751: the real DNP3 READ arms,
the reservoir stands 0.441 ms before the relay's own ACK, the ACK is retained to
`t_ACK + D`, the early RESPONSE queues behind it, both release in order with no drops, and
the transaction retires. **One transaction. No concealment, classifier, statistical or
general SEL-751 claim is made from it**, and CONSENSUS §9's evaluation constraints
(block within session, D = 1 ms as a null control, AUROC beside every concealment number)
remain untouched and unaddressed.

Counters are cumulative across the two Stage-3 runs (`ARM_FRESH = 2`, `ACK_HOLD = 2`,
`CLONE_SEEN = 2`, `ACK_REJECT = 5` from handshake and keepalive ACKs); the per-transaction
values above are from the registers, which were zeroed before this run.

Switch left with the 10/12 instrumented live Defense 3 loaded, app 1 **armed**, D = 2 ms.
Defense 2 not restored.
