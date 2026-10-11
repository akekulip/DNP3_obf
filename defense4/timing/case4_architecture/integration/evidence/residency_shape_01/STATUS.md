# Hold-queue shaping collapses original recirculation ~1,240x, correctness intact (2026-10-11)

Control-plane-only fix (commit 233a4650f + readback tolerance 6df3b304b): pace the three HOLD queues with
tf1.tm.queue.sched_shaping (PPS, max_burst_size 1) set once at bring-up, so the held original polls the clock a
handful of times across its hold window instead of re-circulating every ~1.7 us. No P4 edit, no allocator/marker
change. Diagnostic build residency_diag_01, T-on, 5 ms fixture, 10 READs + 1 SBO per block, fresh cold bring-up.

## Result: all three hold queues shaped at 232 PPS achieved (requested 200)

| role | original re-waits, K=2 unshaped | shaped (232 PPS) | reduction |
|---|--:|--:|--:|
| ACK  | 59,833 | 29 | ~2,060x |
| RESP | 8,988  | 27 | ~330x |
| OP   | 2,999  | 2  | ~1,500x |
| total | 71,820 | **58** | **~1,240x** |

Correctness fully preserved in the shaped run: OUT_ACK_COMMIT=10, OUT_RESP_RELEASE=10, OUT_OP_RELEASE=1,
**zero fallback**; master success, 10/10 READs match seed, one real SELECT + one real OPERATE, zero decoy. All
12 eligible responses padded to 58 (from the gate check). Achieved pacing read back 232 PPS on each hold queue.

## Rate granularity (measured, not assumed)

The TF1 TM shaper rate is coarse and non-linear near the bottom: request 200 -> achieved 232 (within the 25%
tolerance, accepted); request 500 -> 930 and request 1000 -> 930 (500 lands in a gap and the >25% gate correctly
refuses it; 1000 is within 7% of 930). So ~232 PPS (4.3 ms/lap) is the useful low setting and already gives
~2-3 polls per hold window — enough to detect release before the 12 ms readiness deadline (hence zero fallback)
and to stay late-never-early. Going lower is not expressible on this chip via PPS shaping.

- `ack200/` shaped ACK only: ACK re-wait 30, but RESP rose to 44,520 (unshaped RESP then dominates) — which is
  why all three queues must be shaped.
- `ack500/`, `ack1000/` (2nd attempt): fail-closed / refused; retained as the rate-granularity evidence.
- `all200/`: the result above.

## Open follow-up: blocker laps

Blocker laps are still large (ACK 302k, RESP 214k, OP 15k at K=2) — separate internal traffic from the blocker
reservoir, not original recirculation. Now that pacing (not blocker starvation) holds the originals, whether the
blocker reservoir is still needed for residency — or only for timing cover — is an open design question worth a
bounded test (it could remove the pktgen/blocker complexity entirely, or it may be load-bearing for the timing
normalization). K stays at 2 (smallest that keeps zero fallback) until that is settled. This does not block
folding the shaper into production.

Evidence per block: master/outstation/result JSON, both pcaps, before/after switch snapshots incl the `shaping`
and `diag` blocks. Rig restored to baseline after the sweep.
