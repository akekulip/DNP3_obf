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

These are consistent with **burst-then-throttle** but the naive model does NOT fit exactly:
- Post-burst slope from the two clean points: (236.7 − 135.5)/(40000 − 30000) = **10.12 us/pass**,
  consistent with the configured 100000-PPS cap (~10 us/pass).
- The literal model (16384-pass breakpoint, 0.65 us/pass before, 10 us/pass after) predicts
  30000 → **146.8 ms** and 40000 → **246.8 ms** — i.e. ~10–11 ms ABOVE the measured 135.5 / 236.7 ms.
  So the model is APPROXIMATE, not exact: the effective breakpoint is LATER than 16384 (back-solving
  the 30000 point at 10.12 us/pass gives ~16.6k passes absorbed before throttling), and/or there is a
  small fixed baseline. The pre-burst (~0.65 us/pass sub-burst) contribution is minor.

**Do NOT claim the model "fits exactly."** The pre-burst slope, post-burst slope, fixed baseline, and
effective breakpoint must be estimated from a proper isolated sweep (12000–22000 passes incl. 16384) —
see the method below. (The earlier burst=1-vs-16384 test that looked identical was a corrupted
burst-pcap run — not reliable.)

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

## FOLLOW-UP (2026-07-22, rig back up): switch-side timer + transition + target sweep

Per direction: implemented the PREFERRED switch-side timer (point 3) instead of fighting the flaky
hairpin. Added `mb.t_in` (ingress global_tstamp low-32b captured at encap) + `last_hold_reg` (at
release: hold_ns = global_tstamp - mb.t_in, written to a register). Deterministic, host-clock-
independent. queue_microbench.p4 sha bdca672e, 7/12 ingress stages. Reader: `harness/last_hold.py`.
Also fixed the earlier hairpin sweep bug (stale pcap): the calibrated same-clock RTT with drain +
wide spacing works (bypass = 0.098 ms fail-open RTT) but the switch-side timer is used as authority.

**VALIDATION:** switch-side timer agrees with the clean isolated hairpin dumps — 30000 → 137.1 ms
(hairpin 135.5), 40000 → 234.3 ms (hairpin 236.7). Both methods agree; the switch-side is deterministic.

**TRANSITION CHARACTERIZATION (single-frame, switch-side ns):**

| hold_passes | 5000 | 12000 | 14000 | 16384 | 18000 | 20000 | 22000 | 30000 | 40000 |
|---|---|---|---|---|---|---|---|---|---|
| hold (ms) | 3.09 | 7.41 | 8.64 | 10.11 | 14.11 | 38.35 | 60.17 | 137.1 | 234.3 |
| us/pass | 0.617 | 0.617 | 0.617 | 0.617 | 0.784 | 1.92 | 2.74 | 4.57 | 5.86 |

- **Pre-burst slope: 0.617 us/pass, LINEAR** (5000..16384 all exactly 0.617 us/pass; baseline ~0).
- **Effective breakpoint: EXACTLY 16384 passes** (= max_burst_size), hold 10.11 ms.
- **Post-burst: ramps to ~9.7 us/pass** (the 100000-PPS cap; incremental 22000→40000 ≈ 9.6-9.7 us/pass),
  with a short transition just past the breakpoint.
- So the naive "0.65 us + 10 us at 16384" model was close but NOT exact; the measured pre-burst is
  0.617 us/pass and the post-burst approaches (does not instantly jump to) 10 us/pass.

**ISOLATED TARGET SWEEP (6 samples each, switch-side timer; release reason = deadline for ALL,
grad+6 each, ZERO fail-open — point 7 satisfied):**

| target | hold_passes | achieved mean±std | note |
|---|---|---|---|
| 5 ms | 8100 | **5.000 ± 0.000 ms** | pre-burst: EXACT, zero jitter |
| 10 ms | 16200 | **9.999 ± 0.000 ms** | pre-burst: EXACT, zero jitter |
| 17 ms | 18300 | 19.67 ± 1.44 ms | post-burst: jittery + calibration-sensitive |
| 25 ms | 18950 | 23.25 ± 1.22 ms | post-burst |
| 40 ms | 20150 | 36.94 ± 0.45 ms | post-burst |

**KEY DESIGN FINDING:** the pre-burst regime (≤~10 ms, ≤16384 passes) gives DETERMINISTIC sub-µs holds
(zero jitter); the CLRT targets (17–25 ms) fall in the STEEP post-burst region → reachable but jittery
(0.5–1.4 ms) and sensitive to hold_passes. To make 17–25 ms precise, shift the breakpoint (lower the
burst credit so the linear regime extends, and/or tune the shaper rate) — a design/config choice, NOT
the DCRN raise-MAX_PASS fix (which is still NOT applied).

**STILL TO DO (points 5 cont. / 7):** concurrent-held and background-load sweeps (with per-frame
release-reason + target-error/jitter/occupancy/loss/ordering). Case A semantics unchanged: Defense 1
event-governed; Defense 2 refreshing-timestamp ACK-relative deadline; pass-count = retention
microbench + fail-open bound only.
