# Recirc-clock audit — findings (2026-07-22)

Per direction: audit the ~4096-pass plateau and the 0.65-us/pass-vs-100000-PPS-cap conflict BEFORE
any 5/10/17/25/40 ms attempt, and do NOT apply the DCRN raise-MAX_PASS + HOLD-shaper change. This
supersedes the earlier `RESULTS_hold_timing.txt` "~3.17 ms ceiling" claim, which was **WRONG** (a
measurement artifact — see below).

Instrumentation added for the audit: `ctr_recirc` (a P4 counter incremented on every SEQ_HELD_DL
deadline-hold recirc pass; queue_microbench.p4 sha 6e2265ff, 7/12 ingress stages). Read via
`harness/mb_read.py`. Config driven by `harness/hold_probe.py` (sets hold_passes_reg + the dp68 HOLD
sched_shaping; `--restore`).

## ISSUE 1 — the "~4096-pass / ~3.17 ms plateau" — DOES NOT EXIST (my earlier report was WRONG)

Deterministic single-frame sweep (send 1 real, read the `ctr_recirc` delta):

| hold_passes | 1000 | 2000 | 4096 | 5000 | 8000 | 12000 | 20000 | 40000 |
|---|---|---|---|---|---|---|---|---|
| ctr_recirc passes | 1000 | 2000 | 4096 | 5000 | 8000 | 12000 | 20000 | 40000 |

**Every frame completes EXACTLY `hold_passes` passes and releases via `hold_passes==0` (grad+1).**
There is **no pass ceiling** and **no ~4096 limit**. `hold_passes_reg` also stores high values fine
(readback of 50000 = 50000), so it is not a register clamp either.

The earlier "~4096-pass / 3.17 ms plateau" (in `RESULTS_hold_timing.txt`) was a **burst-pcap
measurement artifact**: those runs sent 12–40 frames at 100–200 ms spacing while the true holds were
100s of ms, so the holds OVERLAPPED and the tx↔rx match-by-seq mispaired frames, yielding a spurious
fixed time. **Correction: there is no ceiling; the deadline scales fully.**

## ISSUE 2 — the 0.65-us/pass-vs-cap conflict — the cap DOES bind, after the burst credit

dp68 mapping confirmed (pg_id=17, pg_port_nr=0 → QID_HOLD = pg_queue 6). HOLD sched_shaping preserved:
unit=PPS, provisioning=UPPER, max_rate=100059 (~100000), max_burst_size=16384, min_rate=0; sched_cfg
max_rate_enable=True, scheduling_enable=True.

CLEAN isolated single-frame dumps (capture verified to contain exactly the 64 B out + 128 B return):
- hold_passes = 30000 → hold **135.5 ms**
- hold_passes = 40000 → hold **236.7 ms**

These fit **burst-then-throttle**: the first ~16384 passes drain within the burst credit (fast), then
the shaper throttles the remainder toward the 100000-PPS cap (~10 us/pass):
`30000 ≈ burst + 13616·10us ≈ 138 ms`; `40000 ≈ burst + 23616·10us ≈ 238 ms` — both match. So the
~0.65 us/pass figure was only the **sub-burst** regime; beyond the burst the cap binds. (The earlier
burst=1-vs-16384 test that looked identical was one of the corrupted burst-pcap runs — not reliable.)

## MEASUREMENT-METHOD FINDING (blocks the clean target sweep)

The dp9-hairpin pcap is reliable ONLY for a clean, isolated single frame whose capture contains
exactly 2 frames. Looped/burst sweeps gave inconsistent per-batch-constant values (2.54 ms for
4–12k, 8.70 ms for 14–20k in one batch) — corrupted by residual/reflected recirc frames on the shared
dp9 hairpin. `ctr_recirc` (deterministic) is the only trustworthy pass measurement; the hold-TIME
needs a cleaner receiver. **Vision is now powered on** → use Vision (dp8) as an independent receiver,
or a switch-side egress timestamp, before the target sweep.

## STATE / WHAT'S RESOLVED

- **Issue 1 RESOLVED:** no pass ceiling; passes = hold_passes exactly. The deadline scales to 100s of
  ms (40000 → 237 ms), so the 17–25–40 ms CLRT targets are reachable WITHOUT the DCRN fix.
- **Issue 2 RESOLVED (mechanism):** HOLD cap throttles after the 16384-pass burst credit; pass latency
  rises from ~0.65 us (sub-burst) toward ~10 us (cap). Exact calibration is nonlinear.
- **NOT done:** the clean 5/10/17/25/40 ms target sweep with target-error/jitter/passes/recirc-pps/
  occupancy/loss/ordering/concurrency/background-load — blocked on a reliable timer (Vision receiver).
- DCRN raise-MAX_PASS + HOLD-shaper change: NOT applied (per directive; and not needed for Issue 1).
- Case A note (design, unchanged): Defense 1 event-governed; Defense 2 refreshing-timestamp
  ACK-relative deadline; pass-count is a microbench stand-in; ceiling = fail-open bound only.

Switch left cover=off @ 2 ms (hold_passes=3076), metronome disabled, zero external filler, priority
verified. decoy displaced. Evidence: this file; ctr_recirc sweeps above; clean dumps 30k/40k.
