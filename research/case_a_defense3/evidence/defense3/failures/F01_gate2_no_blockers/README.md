# FAILURE F01 — Gate 2: zero blockers, ACK rejected, event app fired twice

Per `meeting_direction.md` §12. Switch restored to Defense 2 and verified before this was written.

| | |
|---|---|
| Source commit | `9bb8471` + the uncommitted Gate 2 harness |
| Build | `case_a_defense3_fixed_ack_delay.p4` `-DD3_SYNTH_EVENTS`, 9 ingress / 0 egress, 9.13.2 |
| Command | `D3_SKIP_RESTORE=1 ./run/run_defense3.sh --gate2` |
| Evidence | `evidence/gate2/gate2_20260729T184413Z/` |
| Verdict | **FAIL** — 0 PASS / 1 FAIL |

## Three distinct failures, ranked

### F01-a — app 1 (the K=64 blocker reservoir) NEVER FIRED  ← root cause

```
app_block : trigger_counter=0  batch_counter=0  pkt_counter=0
counters  : ARM_FRESH=1        BLOCK_ENQ=0      PKTGEN_ADMIT=0
registers : reg_ts_first_block=0
```

`ARM_FRESH=1` proves the READ **was** classified and the arm path **did** run. `trigger_counter=0`
proves the recirculation-pattern trigger never fired. That is exactly the localization the builder
pre-registered as `TODO(silicon)`: *"the app-1 trigger clone is now itself a dp68 packet — the
single point that could give a run zero blockers; `ARM_FRESH==1` with `trigger_counter==0`
localizes it."*

**Hypothesis H1:** in Defense 2 the trigger clone originated from a **host** port. In the synthetic
build the READ is itself a generated packet arriving on **dp68**, so its mirrored clone is a
dp68→dp68 packet. Either the generator does not re-trigger on its own output, or the clone is
consumed by the *second* value_set (`event_value_set`) before reaching `pgen_recirc`. **Two
value_sets now feed one parser select** — also a pre-registered `TODO(silicon)`.

With no blockers, `Q_BLOCK` is empty, so nothing could have been held regardless of F01-b:
`hold_ns = 0`, `CD_BLOCK_LOOP = 0`, both queue watermarks 0.

### F01-b — the synthetic ACK is REJECTED by the predicate

```
counters  : ACK_REJECT=1  ACK_HOLD=0
registers : reg_deadline=2 (UNARMED_WORD)  reg_ts_ack_arm=0
            reg_exp_relay_seq=287454020  reg_exp_ack=287454038  reg_session_port=51000
```

The trackers were seeded, but the ACK still failed §8.1. `reg_exp_ack − reg_exp_relay_seq = 18`,
which matches `--read-len 18`, so the `EXP_ACK` arithmetic is right and the mismatch is elsewhere —
most likely `tcp.seq` vs `EXP_RELAY_SEQ`, the flags/length pair, or the direction conjunct.
Independent of F01-a and must be fixed separately.

### F01-c — the event app fired TWICE, not once

```
app_event : trigger_counter=2  batch_counter=2  pkt_counter=6   (3 per fire)
            ipg=500000  packets_per_batch_cfg=2
```

Six events were generated where three were intended. This is why the reported "READ→ACK" is
**291.77 ms** rather than the 0.5 ms `ipg`: the analyzer measured across two separate fires, not
within one batch. `trigger_timer_one_shot` fired twice — either it was armed twice, or it was not
disarmed between the arm and the readback.

## What this does NOT indicate

Nothing about Defense 3's mechanism. Every scored quantity is downstream of a reservoir that was
never created. **No conclusion about the hold, the deadline, ordering or the release may be drawn
from this run**, and the analyzer correctly refused to pass it rather than reporting a small
measured delay as success.

Gate 1 is unaffected — it is a configuration gate and its evidence stands.

## Instruments that worked

- The `D + K/rate` correction reported `raw error = −1999872 ns` against
  `CORRECTED = −2001583 ns`, exposing the 1711.230 ns bias exactly as intended.
- The reservoir-standing check caught the anomaly directly: 291 769 556 ns against a &lt;100 µs bound.
- `ACK_RELEASE_FAILOPEN = 0` — the budget was not the cause.
- The analyzer's own negative controls had already been validated 15/15 offline.

## Smallest reproduction

One synthetic READ with app 1 enabled; read `app_block.trigger_counter`. Expect 1, observe 0. No
ACK, no RESPONSE and no deadline are needed to reproduce F01-a.

## Next per §12

Reconvene Panels A (parser/value_set interaction) and B (pktgen trigger semantics) on F01-a, and
Panel C on F01-b. Produce at least two technically valid Tofino-1 constructions for generating the
blocker burst when the trigger source is itself a dp68 packet, compile or microbenchmark both, and
select the simplest that preserves correctness.
