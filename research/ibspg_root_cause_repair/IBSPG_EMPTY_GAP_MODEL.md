# Part 5 — empty-gap model (derived + measured)

## Distinguished quantities (measured on dp8, `ibspg_ring_oracle`)
| Quantity | Meaning | Measured value |
|---|---|---|
| loop RTT (`T_rtt`) | dequeue → egress → MAC loop → re-ingress → re-enqueue → next dequeue | **408 ns** (jitter 403–415) |
| service interval (`T_svc`) | back-to-back dequeue spacing when ≥2 tokens ready (line-rate) | **≈ 24 ns** |
| max jitter | RTT spread (max−min, N=1) | **12 ns** |
| token in-flight time (`T_fly`) | egress→re-ingress transit (RTT − queue wait) | ≈ T_rtt (queue wait ≈ 0 when sparse) |

**Physical-occupancy vs scheduler-eligibility vs in-flight vs enqueued vs dropped vs pass-budget-expired
vs shaping-credit vs burst-synchronization are distinct** (per directive): a token counts toward Q_BLOCK
occupancy only while *enqueued*; while *in-flight* (T_fly) it does not, even though it is "in the ring".
An empty-gap is an interval with **zero enqueued tokens** (all N simultaneously in-flight), regardless of
how many tokens exist.

## The condition
Q_BLOCK stays continuously non-empty iff at every instant ≥1 token is enqueued. With N tokens phased
uniformly over the RTT, a token returns every `T_rtt / N`; the scheduler drains one every `T_svc`. A
gap opens whenever the return interval exceeds the drain interval AND the last token has drained:

> **N_safe · T_svc  >  T_rtt + jitter_margin**  ⇒  **N_safe > (T_rtt + jitter) / T_svc**

With the measured values: `N_safe > (408 + 12) / 24 ≈ 17.5` → **≈ 18 uniformly-phased tokens** to keep
Q_BLOCK non-empty by a pure counting argument.

## Why the counting bound is necessary but NOT sufficient (the measured failure mode)
The N-sweep shows **burst synchronization**: the ring does NOT stay uniformly phased. The scheduler
dequeues ready tokens back-to-back (24 ns bursts), so they egress together, traverse T_fly together, and
return together — collapsing the phase. Result: `p95 dt ≈ 408 ns (= T_rtt) at every N up to 16`, i.e.
Q_BLOCK still empties for ~one RTT per burst cycle even when N ≥ 18 would satisfy the counting bound.
**So raw token count does not achieve continuous eligibility; the phase must be actively maintained.**

## What a correct construction must do (feeds Part 6)
1. **Prevent phase collapse** — stop the tokens from bunching into a single burst (they re-synchronize
   every RTT otherwise).
2. **Guarantee ≥1 enqueued at all times** — measured by the oracle as *no dt exceeding ~2×T_svc*, i.e.
   Q_BLOCK watermark/occupancy never observed at 0 across a long steady-state window.
3. Stay bounded/safe — pass-budget on every token; a data-plane drain stops replenishment.

Candidate mechanisms and their model prediction (tested in Part 6):
- **Phased multi-token (A):** inject at controlled offsets; *prediction — phase collapses back to a
  burst within a few RTTs* (needs measurement to confirm/refute the collapse rate).
- **Preloaded reservoir (B):** hold a bounded backlog in Q_BLOCK and replenish before depth hits a
  low-water mark from a source *outside* Q_BLOCK — decouples occupancy from the RTT so a single
  in-flight token can't empty it.
- **Dual-bank (C):** two high queues Q_BLOCK_A/Q_BLOCK_B both outranking Q_HOLD, phased so one is always
  backlogged while the other's tokens are in flight — covers the RTT gap structurally.
- **Upstream-paced (D):** leave Q_BLOCK unshaped/eligible; pace the *source/feeder* so returns are
  staggered rather than bursty.

## Acceptance metric (from the oracle, Part 6)
A construction passes the empty-gap test iff, over a bounded steady-state window, the dequeue-interval
trace shows **no dt > ~2·T_svc (≈ 50 ns)** attributable to Q_BLOCK emptying (excluding injection-ramp
startup) — equivalently, Q_BLOCK occupancy is never observed at 0 — at the **lowest** token population
and internal rate that achieves it (lowest safe cost, not "increase rate until overflow").
