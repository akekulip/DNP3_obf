# Tofino-1 / BF-SDE 9.13.2 — queue-release primitive capability audit (Part B)

Read-only audit of the live switch (`decps@10.10.54.15`, SDE `/home/decps/Downloads/bf-sde-9.13.2/install`),
using the SDE's own bfrt schemas (`bf_rt_*_tf1.json` = verbatim `table_info`), the TM interface headers
(`traffic_mgr_*_intf.h`), and the TNA architecture header (`tofino1_base.p4`) as authoritative. The running
`queue_microbench` program was NOT perturbed (no gRPC attach); nothing on the switch was changed.

## Central question & verdict

*Can a data-plane event (matching DNP3 response) or a wall-clock deadline make a packet ALREADY IN A TM
QUEUE eligible for dequeue — without a controller in the fast path, without external chaff, and without
continuously recirculating the original packet?*

**VERDICT: NO. This primitive does not exist on Tofino-1 / BF-SDE 9.13.2.** Once a packet is enqueued, its
only exit is the scheduler pacing it out per the priority/DWRR/shaping the **control plane** configured;
nothing in the data plane can reach in and change that packet's eligibility.

## The architectural spine (load-bearing evidence)

1. **The data plane's only handle into the TM is ingress `ingress_intrinsic_metadata_for_tm_t`, applied at
   ENQUEUE.** It sets `qid` ("queue id into which this packet will be deposited"), `ucast_egress_port`,
   `packet_color` (tail-drop input), `ingress_cos`, mcast — all chosen ONCE, before the packet enters the
   queue. No field references or re-targets an already-enqueued packet. (`tofino1_base.p4:124`)
2. **Egress sees the queue as read-only, post-dequeue telemetry only:** `enq_qdepth`, `enq_tstamp`,
   `deq_qdepth`, `deq_timedelta`, `egress_qid` — all observed AFTER the packet already left the queue.
   Egress runs after dequeue → it structurally cannot influence its own or any queue's scheduling.
   (`tofino1_base.p4:220`)
3. **No P4 extern touches TM scheduling.** The full TF1 extern set (Checksum, Hash, Meter/DirectMeter, Lpf,
   Wred, Register/RegisterAction, Mirror, Resubmit, Digest, …) contains nothing that writes a TM control.
   `Meter` only produces `packet_color`; `Mirror`/`Resubmit`/`Digest` inject a new copy / re-enqueue / CPU
   notify — they add work, they do not release a backlog.
4. **Every TM scheduling control is a CPU-only bfrt fixed table:** `tf1.tm.queue.sched_cfg`,
   `queue.sched_shaping`, `port.sched_cfg`, `port.sched_shaping`, `port.flowcontrol`, `queue.map`,
   `queue.cfg`, `counter.*`. Driven over gRPC/PD from the CPU; no data-plane write path exists to any.

## Primitive table (owner: CP=control-plane/CPU ms-latency, DP=data-plane per-packet)

| Primitive | API / source | Owner | Release one queue? | one packet vs backlog | no chaff? | needs recirc of original? | TF1+9.13.2 | Evidence |
|---|---|---|---|---|---|---|---|---|
| queue scheduling enable/disable (= pause/resume) | `tf1.tm.queue.sched_cfg.scheduling_enable`; `bf_tm_sched_q_enable/disable` | **CP** | yes (per queue) | whole backlog | yes | no | yes | `traffic_mgr_sch_intf.h:328` "If disabled, queue will not participate in scheduling" |
| queue shaping (max/min rate, burst) | `tf1.tm.queue.sched_shaping`; `bf_tm_sched_q_shaping_rate_set` | **CP** | paces one queue | rate-cap; **no per-packet deadline release** | yes | no | yes | token-bucket = cap only; cannot up-pace a sparse flow |
| strict priority | `sched_cfg.min/max_priority` | **CP** | priority tier | contention, not release | yes | no | yes | schema LOW..0-7..HIGH |
| DWRR weights | `sched_cfg.dwrr_weight` | **CP** | weight | bandwidth share | yes | no | yes | schema uint16 |
| port scheduling enable/disable | `tf1.tm.port.sched_cfg`; `bf_tm_sched_port_enable/disable` | **CP** | whole port | all-queue backlog | yes | no | yes | header doc |
| port shaping | `tf1.tm.port.sched_shaping` | **CP** | port cap | cap only | yes | no | yes | schema |
| flush all queues on a port | `bf_tm_port_all_queues_flush` | **CP** | port | backlog | — | — | **NO (TF2-only; no-op on TF1)** | `traffic_mgr_port_intf.h:384` |
| PFC / pause frames | `tf1.tm.port.flowcontrol`, PPG | **CP** cfg, HW-trig | class-level | backlog | yes | no | yes | buffer-threshold-driven; not P4-writable per packet |
| occupancy / watermark / drop counters | `tf1.tm.counter.queue` | **CP read** | read-only | — | yes | no | yes | usage/watermark live, drops batched ~4-6 s |
| per-packet enq/deq telemetry | `egress_intrinsic_metadata_t` | **DP read** (egress) | read-only, post-dequeue | observe only | yes | no | yes | `tofino1_base.p4:228-269` |
| async dequeue notification / egress event | — | — | — | — | — | — | **NOT FOUND** (searched; none in `bf_rt_tm_tf1.json`) | UNVERIFIED-ABSENT |
| qid assignment (choose queue) | `ig_intr_md_for_tm.qid` | **DP** (ingress) | picks dest AT ENQUEUE | directs new packet; can't re-target enqueued | yes | no | yes | `tofino1_base.p4:139` |
| move an enqueued packet between queues | — | — | — | — | — | — | **NO** (qid bound at enqueue; no re-queue primitive) | — |
| loopback ports | `$PORT.$LOOPBACK_MODE` | **CP** | port cfg | — | yes | — | yes | choices incl MAC_NEAR/FAR |
| recirculation port | recirc dev_port (dp68) | **DP** path | re-inject to ingress | moves the ORIGINAL through the pipe, not a queue-hold | yes | **yes (that's the point)** | yes | lab-proven |
| pktgen triggers | `tf1.pktgen.app_cfg` (timer one-shot/periodic, port-down, recirc-pattern) | **CP arm**, HW fire | generates NEW packets | injects new; neither releases a held one | yes | no | yes | `tofino1_base.p4:330-375` |
| Mirror (egress→ingress copy + md) | `Mirror` extern; `$mirror.cfg` | **DP emit / CP session** | copy steerable to port+qid | creates a COPY (new enqueue), not a release | yes | no | yes | `$mirror.cfg` sets qid/port/color for the copy |
| Resubmit (md back to ingress) | `Resubmit` extern | **DP** | re-enqueue original into ingress buffer | re-runs ingress; not a TM release | yes | no | yes | `tofino1_base.p4:~790` |
| **deadline (wall-clock) release of a specific queued packet** | — | — | — | — | — | — | **NOT SUPPORTED** (no EDT / earliest-departure in TM; only shaper rate + pktgen timers that generate new) | — |

## Direct answers to the crucial sub-questions

- **Ingress/egress P4 change TM queue eligibility dynamically?** No — ingress picks qid/color at enqueue;
  egress is post-dequeue read-only.
- **Any TM control writable from the data plane?** No — all are CPU-only bfrt tables; no P4 extern for it.
- **Move an enqueued packet between queues?** No.
- **A queue stay CLOSED until a packet-time event?** It can stay closed (`scheduling_enable=false`), but the
  RE-OPEN is control-plane only — no data-plane packet event can flip it.
- **One packet cause ANOTHER queue to receive service?** Only by INJECTING NEW WORK (mirror/resubmit/recirc/
  pktgen land a new packet there) or strict-priority contention — never by granting service to an existing
  held backlog.

## The pattern that DOES work on-switch, and why each is excluded by the constraints

1. **Recirc-hold (the frozen DCRN baseline):** the original is NOT held in a TM queue — it continuously
   recirculates; a matching-response event flips a `Register`, and a later recirc pass reads it (or a
   `global_tstamp` deadline) and emits. Genuinely DP event-driven, no controller, no chaff — but it IS
   continuous recirculation of the original (30000–40000 passes for 135–236 ms). **Excluded** by the
   no-continuous-recirc constraint.
2. **Control-plane per-queue hold/release** (`bf_tm_sched_q_disable/enable`): precise to one queue, but
   ms-scale CPU in the release path. **Excluded** by no-controller-in-fastpath.
3. **Shaper / pktgen metronome pacing:** the shaper only rate-CAPS (cannot up-pace a sparse flow — refuted
   on silicon, `QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md`); a pktgen metronome generates NEW trigger
   packets and can only *decide* (probe reads a Register) — it cannot ACTUATE a TM queue open, so to release
   it must mirror/inject a copy (changes packet identity = a form of chaff/regeneration) or fall back to
   recirc. **Excluded** by no-chaff / no-continuous-recirc.

## Verdict

Data-plane, event-driven, per-queue **release of an already-enqueued packet** is **not a Tofino-1
primitive**. A true queue-resident deadline release (skb-EDT / `fq`-style earliest-departure) has **no TNA
equivalent** and would have to move to a SmartNIC/host edge. On Tofino-1 the only realizable on-switch
timing holds are recirc-hold (DCRN) or shaper/metronome pacing — each of which violates at least one of the
task's four constraints. Durable copy of this audit also at
`~/.claude/agent-memory/p4-dataplane-engineer/tofino1-tm-queue-release-primitives.md`.
