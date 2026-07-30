# F01-a RESOLVED · new failure F02 open (tokens admitted then dropped)

Gate 2 re-run 2026-07-29T21:56Z. Switch restored to Defense 2, five facts verified.

## F01-a — RESOLVED

**Root cause: pktgen app 1 was never enabled.** `_trial_body` configures it with
`app_enable = False` (the Gate-1 contract: configure, arm nothing) and the trial never turned it on.
A generator whose `app_enable` bit is 0 does not respond to its recirculation-pattern trigger, so
the clone reached dp68, recirculated — that is the `CF_BAD_PORT = 1` in both runs' readback — and
hit a switched-off generator: `trigger_counter = 0` with `ARM_FRESH = 1`.

Fix: enable app 1 **before** app 2 is armed. The ordering is load-bearing, because the clone that
triggers app 1 is produced by app 2's very first packet. Nothing about the trigger path changed, so
the live build stays request-triggered.

| | before | after |
|---|---|---|
| `app_block.trigger_counter` | 0 | **1** |
| `app_block.batch_counter` | 0 | **1** |
| `app_block.pkt_counter` | 0 | **64** |

The K=64 request-triggered reservoir now generates exactly 64 tokens from one READ.

**Note this was NOT any of the three theories that preceded it** — not a failed arm write, not a
missing DNP3 layer in the template, not a `port_cfg` flag, and not the dp68-originated-trigger
hardware question that motivated constructions C1 and C2. **C1 and C2 were never needed.** The
generator was simply switched off.

## F02 — OPEN: all 64 tokens are admitted, then dropped

```
PKTGEN_DROP = 64      all 64 tokens reached the admission gate and were rejected
BLOCK_ENQ   = 0       none reached Q_BLOCK
deq counters  all zero    nothing ever circulated
```

Same record: `reg_tag = 255`, `ACK_REJECT = 1`, `RESP_BYPASS = 1`. Token admission is gated on an
**active transaction**, so the hypothesis is that the generation was already retired by the
`RESP_BYPASS` path before the tokens circulated — i.e. this is an **event-ordering** fault, not an
admission-logic fault.

That ties directly to **F01-c, still open**: `app_event.trigger_counter = 2`, 6 packets for 3
intended. If the event app fires twice, the second fire's RESPONSE retires the generation
underneath the first fire's tokens. **Fix F01-c first** and re-measure before touching the
admission gate.

## Also still open

**F01-b** — `ACK_REJECT = 1`. Cannot be separated from F02 until the event ordering is fixed, since
a retired generation fails the ACK's `generation active` conjunct for the same reason it fails token
admission.

## Order of work

1. **F01-c** — make the one-shot fire exactly once. Cheapest, and it plausibly explains both F02
   and F01-b.
2. Re-run Gate 2 and re-measure. If `BLOCK_ENQ = 64` and the ACK is admitted, both close.
3. Only if they persist: attack F02's admission gate and F01-b's header conjunct separately.

## Gate 2 status

Still **FAIL** — 6 of 11 requirements failed. What now passes: trial ran to completion, clean start
asserted, mandatory cleanup ran, dp8 speed correct on both MAC and TM, one READ, and
`ACK_RELEASE_FAILOPEN = 0`. The mechanism itself remains unmeasured: with nothing in `Q_BLOCK`
there is still no hold, and the analyzer again correctly refused to pass a null result.
