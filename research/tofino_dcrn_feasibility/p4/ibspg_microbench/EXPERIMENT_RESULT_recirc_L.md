# IBSPG silicon result #1 — recirc-port loopback (Parts 4–7, first instantiation)

**Date 2026-07-24. Tofino-1, SDE 9.13.2, program `ibspg_mb` (sha 6baecac), loopback L = recirc dp68.
Switch restored to `queue_microbench_abs.conf` after the run (1 instance, both hosts reachable).**

## Verdict for THIS instantiation: PARTIAL → the hold sub-goal is REFUTED on the recirc port; the
## release/isolation sub-mechanisms all PASS. This is NOT yet a family-level verdict (see §6).

## What was configured / driven (all on silicon, host-injected from Hulk/dp11)
- Strict priority **VERIFIED**: `Q_BLOCK min_priority=7 (HIGH) > Q_HOLD=0 (LOW)`, readback clean
  (`strict_priority_verified: true`).
- Stimulus: **host injection** (both 25G NICs were in fact UP; Vision→dp9, Hulk→dp11 confirmed by
  per-port `$FramesReceivedOK` deltas — matching the direction's stated mapping). pktgen not needed.
- Blocker ring seeded at N = 1, 8, 64, 256; 1 HELD; wrong-gen drain; matching drain. Reps ×3 at N=8.

## Load-bearing measurements (verbatim counters)

| variant | Q_BLOCK use/wm (continuous) | HELD hold-loop rate | Q_HOLD use | ctr_held_release during hold | ctr_blk_drop Δ at drain | dp9 tx Δ (release) | dp11 tx (token escape) |
|---|---|---|---|---|---|---|---|
| N=1  | 0/4 | ~5.30 M/s | 0 | 0 | +1 | +1 | 0 |
| N=8 (×3) | 1–3/3 | ~5.3 M/s | 0 | 0 | +8 each | +1 each | 0 |
| N=64 | 9–13/13 | ~4.6→2.9 M/s | 0 | 0 | +64 | +1 | 0 |
| **N=256** | **126/127 (never sampled empty)** | **2.09→1.33 M/s** | 0–1 | 0 | +256 | +1 | 0 |

N=256 crux (verbatim): `q_Q_BLOCK use=126 wm=127` held continuously while `ctr_held_enq` climbed
172,335,607 → 173,665,351 over ~1 s (≈1.33 M hold-routings/s). Zero queue drops anywhere.

## §1. The hold sub-goal is REFUTED on the recirc port
`ctr_held_enq` never equalled the injected count (1). It climbed by **1.3–5.3 million per second** —
i.e. the HELD packet is **continuously recirculated**, never TM-queue-resident, for the entire hold
interval. Even with Q_BLOCK backlogged to buffer saturation (use=126, never sampled empty), Q_HOLD
was serviced at MHz rate. On the recirc port, Tofino-1 strict priority does **not** deliver the
**absolute** low-queue starvation the IBSPG hold requires. Against the direction's Part-10 REFUTED
criterion ("Q_HOLD receives service while Q_BLOCK is demonstrably nonempty"), this instantiation
fails, and it degenerates into exactly the continuous original-packet recirculation IBSPG set out to
avoid — **no advantage over the frozen recirc-hold on this port.**

## §2. What PASSED on silicon (reusable regardless of the hold outcome)
- **Release gate:** every matching drain released HELD — `ctr_held_release += 1`, `dp9 tx += 1`.
- **Ring teardown:** `ctr_blk_drop += exactly N` at each drain (8/8/8/1/64/256); `ctr_blk_loop` froze;
  `q_Q_BLOCK use → 0`. The data-plane drain kills the ring deterministically.
- **Generation check:** wrong-gen drain → `ctr_drain_badgen`, `reg_drain` stayed 0, no release.
- **Isolation / visibility (Part 7):** the blocker token (ethertype 0x88C1 / src 02:00:00:00:0B:0C)
  **never** egressed a protected port — `dp11 tx = 0` for the whole run, `dp9 tx == number of
  releases exactly`. Zero token escape. The internal-token model holds on silicon.
- **No drops:** `drop=0` on both queues and egport_68 throughout.

## §3. Why the recirc port fails (hypothesis, not yet disambiguated)
Two candidate causes, indistinguishable at bfrt sampling granularity (coarse polling cannot see
sub-µs queue states):
- **(H-gap)** the self-looping ring has an unavoidable loopback gap: while tokens are in flight
  (egress→recirc→re-ingress, latency `T_loop`) Q_BLOCK momentarily empties, and the recirc buffer
  (~126 cells) is too shallow to hold `R_deq·T_loop` tokens, so it cannot be kept gap-free by adding
  tokens (N=256 already saturates the buffer). → potentially fixable with a **gap-free continuous
  feed** or a **deeper-buffered / shaped** queue.
- **(H-sched)** the recirc-port scheduler does not implement absolute strict priority between queues
  (unlike a physical egress port). → fatal for any loopback-on-recirc IBSPG.

These have opposite implications, so they must be disambiguated before a family verdict (§6).

## §4. Measurement limitations (honest)
- bfrt occupancy is polled, not continuous — sub-µs Q_BLOCK empties are invisible; "never sampled
  empty" is not "provably never empty."
- N=256 saturated the recirc queue (~126 cells); larger N adds enqueue drops, not deeper continuous
  backlog, so the absolute-deepest backlog was not reached on this port.
- `ctr_held_rehold` in `ibspg_read.py` returns ERR (that counter was folded into `ctr_held_enq` in
  the final P4) — benign; `ctr_held_enq` is the gap metric.

## §5. Correction to the sub-agent's recommendation
The executing agent recommended "keep the hold off-Tofino (SmartNIC/host EDT)". **That contradicts
the current `direction.md`**, which forbids SmartNIC/DPU/host/eBPF/platform-split and withdrew the
"recirc is the answer" acceptance. It is NOT adopted. The off-switch path is out of scope; the
research question is whether an on-Tofino indirect construction exists.

## §6. This is NOT a family-level REFUTED — Part-10 requires the bounded variants first
Per direction Part 10 ("Do not declare the entire indirect design space impossible from one failed
variant… test multi-token and shaped-backlog variants… then evaluate two-stage or backpressure
alternatives"), the following IBSPG variants remain **untested** and are the gating next work:
1. **Physical MAC-near loopback port for L** (not the recirc port). The TM-config doc flagged strict
   priority as *proven on a physical port* (queue_microbench real>chaff) but *unknown on recirc* —
   this result confirms the recirc unknown resolved negative; the physical port is the documented
   strict-priority variant and is untested. Directly tests **(H-sched)**.
2. **Gap-free continuous feed** of Q_BLOCK (continuous pktgen tokens gated by a data-plane drop on
   drain), instead of a self-looping ring. Removes `T_loop` by construction. Directly tests
   **(H-gap)**: if Q_HOLD is still serviced under a provably-gap-free high queue → (H-sched) is true
   and the family is dead; if Q_HOLD is starved → (H-gap) was the cause and a gap-free variant works.
3. **Variant C (Q_BLOCK shaping)** — with the caveat that a shaped non-empty high queue may *yield*
   to the low queue during its shaped-off interval (possibly counterproductive); test to confirm.
4. If 1–3 all fail → the **two-stage / backpressure** alternatives (separate evaluation).

The decisive next experiment is **#2 (gap-free continuous feed)** because it disambiguates (H-gap)
vs (H-sched) with one clean silicon run, and #1 (physical port) which tests the same scheduler
question on the hardware where strict priority was previously observed to order correctly.
