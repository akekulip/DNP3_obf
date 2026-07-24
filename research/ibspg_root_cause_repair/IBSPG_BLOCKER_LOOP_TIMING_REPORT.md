# Part 4 — blocker-loop timing (measured on silicon)

Measured with `ibspg_ring_oracle` (RING mode) on dp8 MAC-near loopback, via the on-chip timestamp
trace (`ingress_mac_tstamp[31:0]`, ns on TF1). Each blocker token carries `seq` = pass budget
(decrement per loop; self-terminates — a runaway ring is impossible). N tokens seeded, budget sized so
total passes ≈ 256 (fills the 512-deep trace without overflow). Switch restored after. [OBS]

## Loop round-trip time (RTT) — the single-token case
N=1, one token looping 256 times (seq 256→0): consecutive dequeue timestamps are spaced by a **very
stable ~408 ns**:
- min 403, mean 408.5, median 409, p95 412, max 415 ns — jitter ≈ 12 ns (403–415).
This 408 ns is the dp8 MAC-near loopback RTT (egress → MAC loop → re-ingress → re-enqueue → dequeue) a
multi-token ring must cover to stay continuously backlogged.

## N-sweep dequeue-interval (dt) distribution
| N | min dt (ns) | median dt (ns) | p95 dt (ns) | max dt (ns) | large gaps (>3×median) |
|---|---|---|---|---|---|
| 1 | 403 | 409 | 412 | 415 | 0 (uniform RTT) |
| 2 | 167 | 230 | 409 | 412 | 0 |
| 4 | 51 | 200 | 411 | 45,270 | 1 (startup) |
| 8 | 25 | 244 | 411 | 53,891 | 2 (startup) |
| 16 | 24 | 153 | 410 | 65,992 | 2 (startup) |

## What the numbers mean
- **service interval (back-to-back dequeue) ≈ 24 ns** — the line-rate spacing when ≥2 tokens are ready
  in Q_BLOCK (min dt saturates at ~24 ns for N≥8, ~60 B frames on the 25 G loopback).
- **The ring SYNCHRONIZES (burst formation).** Tokens do not stay evenly phased: the scheduler dequeues
  the ready tokens back-to-back (24 ns bursts), they egress together, loop together (RTT), and return
  together — so `p95 dt ≈ 408 ns (= one RTT) at EVERY N`. i.e. ~5% of intervals are a full-RTT wait in
  which **Q_BLOCK is empty**. Adding tokens tightens the bursts (lower min/median) but does not remove
  the RTT-scale gaps.
- **The 45–66 µs "large gaps" are startup/injection-ramp artifacts (1–2 per run)**, not steady state:
  the host injects the N tokens over tens of µs, so the first inter-event spacing spans the injection
  window. Evidence: the contiguous small-dt run is 152–194 of ~256 intervals (the ring settles into a
  bursty-but-bounded regime after injection). These outliers are excluded from the steady-state model.
- **Token loss:** none observed — every seeded token looped its full budget then expired
  (`ctr_block_expiry` accounted for all tokens; `reg_overflow=0`).

## Consequence for the hold
A raw self-replenishing ring has **RTT-scale empty-gaps (~408 ns, p95)** because of burst
synchronization, at every tested N. During each such gap Q_BLOCK is empty and strict priority (now
correctly configured, Part 3) would serve Q_HOLD — i.e. the hold would leak once per burst cycle. The
fix is not "more tokens" (they synchronize) but **breaking the synchronization / keeping ≥1 token
resident at all times** — the Part-6 constructions (phased, preloaded reservoir, dual-bank,
upstream-paced). The quantitative target is derived in `IBSPG_EMPTY_GAP_MODEL.md`.
