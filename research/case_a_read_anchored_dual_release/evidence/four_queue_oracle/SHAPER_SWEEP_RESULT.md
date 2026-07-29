# dp8 port-shaper sweep — result

2026-07-29T14:02–14:04Z. Evidence: `evidence/four_queue_oracle/shaper_sweep_20260729T140201Z/`.
Commit at run time: `5482301`. Equal queue priorities throughout — characterization only, controls
A–D were not run.

## Headline

**A zero-leak preload gate EXISTS on the dp8 port shaper, and the discriminator is `max_rate = 0`
— not burst size.**

| written | rate READ BACK | burst | dequeues before release | screening |
|---|---|---|---|---|
| PPS:1:0 | **1** | 0 | **5 — LEAK** | FAIL |
| PPS:1:1 | **0** *(SDE quantized)* | 1 | 0 | PASS → 5/5 |
| PPS:0:0 | **0** | 0 | 0 | PASS → 5/5 |
| BPS:1:0 | **0** *(SDE quantized)* | 0 | 0 | PASS → 5/5 |
| BPS:1:1 | **0** *(SDE quantized)* | 1 | 0 | PASS → 5/5 |

Every configuration that ended at `max_rate = 0` leaked nothing. The single configuration that
actually retained `max_rate = 1` leaked. **Burst size is irrelevant**: burst 0 and burst 1 both
hold at rate 0, and burst 0 leaks at rate 1.

Three of the four "passing" settings only passed because **the SDE silently quantized
`max_rate=1` to `0`** — the runner caught this and recorded it as
`gate max_rate readback: wrote 1, read 0`. Their labels do not describe what was tested. Only
`PPS:0:0` requested rate 0 and got it.

A prior prediction that burst-permitting settings would be *worse* was **wrong**, and this is why:
those settings were never running at the rate their labels claim.

## Post-release integrity — perfect on all five

```
total_dequeues / trace_entries_written / trace_overflow   = 128 / 128 / 0
per role [ABLOCK, ACK, RBLOCK, RESP]                      = [32, 32, 32, 32]
queue drops                                               = 0
pktgen trigger 1, packet count 128
```
The new three-value accounting works on silicon. `PPS:1:0`'s five leaked packets are individually
recorded with role, `pkt_id` and `ts_ns` (ABLOCK 0, ABLOCK 1, ACK 2, …).

## ⚠ Two findings that qualify the "ACCEPTED" verdicts

### 1. `usage_cells` is unusable on this port — it reads 0 always

In **all five** settings, including the failing one, `usage_cells = [0,0,0,0]` at the preload
check, while `watermark_cells` correctly reported 30–32 per queue. The live-occupancy gauge does
not report on dp8's queues here. This resolves the open `TODO(silicon)` about `usage_cells`
negatively: **do not build acceptance criteria on it.**

### 2. The runner accepted settings whose stated preload criterion was NOT met — a verdict bug

`RESUME_STATE.md` requires `usage_cells(Q_ABLOCK…Q_RESP) > 0`. Because of finding 1,
`all_queues_nonempty` was **False in all five settings**, including the four marked ACCEPTED. The
verdict logic did not enforce that criterion. **This must be fixed before the result is relied
on.**

**The substance is nevertheless sound, by a different and stronger argument** — stated explicitly
rather than substituted quietly:

> `total_dequeues` before release = **0** means *no packet had left any queue*. 128 packets were
> enqueued (watermarks 32 per queue, 32 per role confirmed in the trace). Therefore all 128 were
> simultaneously resident at the moment of release.

That inference rests on the dequeue counter — which demonstrably works — rather than on the broken
gauge. It is a better proof of simultaneous backlog than `usage_cells > 0` would have been. But it
is **not** the criterion as written, and the runner should assert it in those terms.

## Cleanup and restore

Cleanup ran on every trial in the specified order — disable pktgen → dp8 to line rate → drain
(1.00 s) → verify → reset. No trial started dirty; the contamination that invalidated pilot 5 did
not recur.

```
RESTORE VERIFICATION
  PASS   p4_name                    dnp3_timing_normalizer_pktgen
  PASS   strict_priority_verified   true
  PASS   app_enable                 false
  PASS   exactly one bf_switchd     1
  PASS   dp8 shaping restored       true
```

## Recommendation

Use **`max_rate = 0`** as the gate, requested explicitly — i.e. `PPS:0:0`, the only setting that
asked for rate 0 and was given it. Do not rely on the three settings that arrived there by
quantization.

`Q_GATE` is **not** required: the dp8 port shaper has a demonstrated, reproducible zero-leak
preload boundary (5/5 consecutive on four settings, 20 confirmations in total).

**Before controls A–D are re-run**, fix the verdict logic so acceptance asserts
`total_dequeues_before_release == 0` **and** the enqueued-packet count, instead of a `usage_cells`
comparison that can never be true on this port.
