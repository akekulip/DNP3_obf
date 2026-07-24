# P-SCHED safety-first microbench — result (Parts 5–6)

**The queue-resident hold EXISTS on Tofino-1 (scheduling-disable), but its actuation is
control-plane only: a data-plane matched-drain cannot release a packet from a scheduling-disabled
queue; only a control-plane re-enable can.** This empirically confirms the missing direct
data-plane release primitive — the hinge of the whole negative result.

Switch **10.10.54.81** (`ufispace`, SDE 9.13.2), program `ibspg_mb_physL` (physical dp8 loopback,
Q_HOLD qid1 on pg_id 2). Safe/bounded: **one** synthetic HELD frame, control-plane queue
enable/disable, Q_HOLD shaped to 50k pps as a loop safety cap, no PFC, no near-line-rate traffic,
immediate cleanup. Switch **restored** to `queue_microbench_abs.conf` (ASIC attached, hosts reachable).

## Sequence and verbatim measurements
| Step | Q_HOLD use/wm/drop | reg_drain | held_enq | held_rel | dp8 tx | dp9 tx |
|---|---|---|---|---|---|---|
| baseline | 0/0/0 | [0,0] | 0 | 0 | 0 | 0 |
| CP-disable Q_HOLD sched (readback False) → inject 1 HELD | **1/1/0** | [0,0] | 1 | 0 | 0 | 0 |
| +2 s | **1/1/0** | [0,0] | 1 | 0 | 0 | 0 |
| **data-plane** DRAIN_MATCH (slot 0, gen 0) | **1/1/0** | **[1,0]** | 1 | **0** | 0 | 0 |
| **CP-enable** Q_HOLD sched (readback True) | **0/1/0** | [1,0] | 1 | **1** | 1 | 1 |

## What each row proves
1. **Scheduling-disable is a true queue-resident hold.** With `scheduling_enable=false`, the injected
   HELD frame sits at `usage=1`, `drop=0`, `dp8 tx=0` — held in TM queue memory, not dropped, not
   egressed. Stable across 2 s.
2. **A data-plane event cannot release it.** The matched DRAIN_MATCH is processed (`reg_drain`→[1,0]),
   yet `usage` stays 1, `held_rel=0`, `dp9 tx=0` — the packet cannot dequeue while the queue's
   scheduling is disabled. The data plane set its register but was **powerless to actuate the release**.
3. **Only the control plane actuates the release.** The instant `scheduling_enable` is set true (a bfrt
   `tf1.tm.queue.sched_cfg` write), the frame dequeues (`usage`→0), and — with `reg_drain` already 1 —
   routes to dp9 byte-preserved (`held_rel`=1, `dp9 tx`=1). `held_enq` stayed 1 throughout (no loop).
4. **Isolation intact.** `dp11 tx = 0`; `dp8 tx == rx` exact; zero drops.

## Part 6 — acceptance-criteria evaluation
P-SCHED is a **diagnostic of the actuation locus**, not a shippable hold. Scored to show *why no
candidate passes*:

| Criterion | P-SCHED |
|---|---|
| original real packet in TM memory during hold | **PASS** (usage=1) |
| holding at a bounded low internal rate | **PASS** (zero internal rate — better than bounded) |
| no original-packet continuous recirculation | **PASS** (0 passes while held) |
| no external chaff | **PASS** |
| **no controller action after initialization** | **FAIL** — release requires a control-plane `sched_cfg` write |
| no packet drop as the hold mechanism | **PASS** (0 drops) |
| matching release works | PASS *only via control plane* |
| unrelated release does not work | **PASS** (data-plane drain did not release) |
| ACK-before-response enforceable | N/A (single frame) — FIFO sub-primitive proven separately (IBSPG) |
| timeout / fail-open | N/A for the diagnostic |
| internal resource use measured | **PASS** |
| restores cleanly | **PASS** |

The single **FAIL — "no controller action after initialization" — is the result:** the only clean
queue-resident hold on TF1 puts a controller in the release path, which the problem forbids.

## Part 7 — novelty framing (preserved)
This is the empirical capstone of a **systematic, evidence-backed negative result**: across strict
priority (IBSPG, two silicon instantiations), internal backpressure (SDE-evidenced audit), and
two-stage parking (architecture + the paced-recirculation innovation attempt), a bounded low-rate
data-plane-actuated queue-resident hold of a **sparse** original packet does not exist on Tofino-1 —
because the data plane sets a packet's fate only at enqueue and cannot actuate a hold on an enqueued
packet, and the one true hold (scheduling-disable) is control-plane only (**shown here on silicon**).
The reusable, silicon-proven sub-primitives survive for future designs: bounded internal token ring,
pass-budget termination, generation-safe data-plane drain, internal-token isolation, matched release.
A carefully demonstrated hardware limitation plus these safe, working components is the contribution —
not an unsafe mechanism forced to pass.

## The one remaining empirical question (gated, not run)
`P-PFC` — whether a *self-generated* PFC pause could hold a frame at low rate — is predicted negative
(needs sustained high-rate fill above threshold, per-CoS not per-transaction) and carries HIGH
PFC-deadlock risk on the shared chip. It is **not run autonomously**; it needs explicit authorization
and a spare pipe, and would at best reconfirm the architecture. See `NEXT_QUEUE_PRIMITIVE_EXPERIMENT.md`.
