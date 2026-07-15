# Agent E — Programmable-Hardware & Data-Plane Feasibility of DNP3 Response-Timing Normalization

_Design/literature analysis only. No code was written or modified. This report determines, per
platform, which of six timing-normalization mechanisms are actually implementable — separating
vendor-documented capability from engineering inference, and labelling speculative workarounds.
It is the hardware-realizability half of the ACK-timing-normalization study and becomes most of
`hardware_design.md`._

Platforms in scope: **Intel/Barefoot Tofino 1 (TNA)** — the key analysis and the lab's eventual
P4 target — plus **NVIDIA BlueField DPU**, **Netronome (Agilio/NFP) SmartNIC**, and **FPGA**. The
software replay server is referenced as the zero-hardware baseline but is out of hardware scope.

---

## 0. Method, evidence tiers, and the one-line answer

**Evidence labelling** (used inline throughout): `[vendor-doc]` = stated in a vendor manual/
datasheet; `[peer-reviewed]` = published measured result; `[preprint]` = arXiv/not-yet-refereed;
`[measured-rig]` = our own Vision↔Hulk numbers from `measured_timing_data.md`; `[inference]` = my
engineering deduction from documented primitives; `[speculative]` = plausible workaround I could
not ground in a primary source. Every capability claim carries one of these. I did **not** invent
any hardware capability; where the public record is silent (notably the detailed Tofino Traffic
Manager model, which Intel withholds "for legal reasons" in the public TNA doc) I say so.

**Classification vocabulary** (per the task): each `platform × mechanism` cell is one of
`directly-supported` · `via-Traffic-Manager-config` · `via-queue-pacing` · `via-recirculation` ·
`only-with-controller-assistance` · `impractical-or-unsafe`.

**The six mechanisms** (the timing-normalization primitive decomposed):
1. **Native pacing / rate shaping** — bound the *sustained rate* / burst of a flow.
2. **Inter-packet-gap (IPG) normalization** — regularize the *spacing between* successive frames.
3. **First-packet ABSOLUTE delay** — hold the *first* response of an exchange until a wall-clock
   deadline `request_time + target_delay` (this is what kills the request→response processing-time
   fingerprint — the crown-jewel leak measured at 1.01 ms mean, and linear in CROB count,
   R²>0.99 `[measured-rig]`).
4. **Per-flow stateful delay** — a *different* deadline per outstation/flow, held in on-device state.
5. **Full payload buffering** — store and later reconstruct/reorder the response bytes.
6. **ACK generation / TCP proxying** — synthesize/rewrite TCP ACK or seq/ack to decouple the ACK
   from the held response (this is the proxy line the phase rule forbids; assessed for completeness).

**One-line answer (RQ7 hardware portion):** mechanisms 1–2 are native on *every* target;
mechanism 3 (the one that matters most) is **native on BlueField and FPGA, absent as a primitive
on Tofino 1, and reachable on Tofino only through a non-idiomatic recirculation + register-deadline
loop that is nonetheless affordable *for DNP3 specifically* because the traffic is single-digit
kbps and small-frame**; mechanisms 5–6 are impractical/out-of-phase on Tofino and belong on the
DPU/FPGA (and, for the ACK/proxy step, outside the byte-preserving phase entirely).

---

## 1. Platform × Mechanism comparison table (the centerpiece)

Verdict per cell, then a one-line evidence-backed reason. "SW replay server" is included only as
the zero-hardware reference point.

| Mechanism | **Tofino 1 (TNA)** | **BlueField DPU** | **Netronome NFP** | **FPGA** | SW replay server |
|---|---|---|---|---|---|
| **1. Native pacing / rate shaping** | `via-Traffic-Manager-config` — port/queue shaper in bps or pps `[vendor-doc]`; also line-rate via **meters** with no queuing (Nimble) `[peer-reviewed]` | `directly-supported` — per-send-queue **Packet Pacing**, ns-granular `[vendor-doc]` | `via-config` — NFP rate-limiting in P4/Micro-C `[vendor-doc]`; toolchain caveat | `directly-supported` — HW TX scheduler (Corundum) `[peer-reviewed]` | `directly-supported` — it emits bytes; schedules directly |
| **2. IPG normalization** | `via-queue-pacing` — shaped egress queue evens spacing; time-gated release shown on Tofino 2 (P4-TAS) `[preprint]` | `directly-supported` — Packet Pacing / Accurate Send Scheduling `[vendor-doc]` | `via-config`/Micro-C timers `[inference]` | `directly-supported` — calendar/TDMA scheduler, µs-precise (Corundum) `[peer-reviewed]` | `directly-supported` |
| **3. First-packet ABSOLUTE delay** | `via-recirculation` — **not a TM primitive** (shaping bounds rate, *not* the latency of a lone frame — it leaves an empty shaped queue immediately `[inference]`); emulate with a self-clocked recirc loop + 48-bit-timestamp deadline register `[inference]`. Affordable *here* (§4.3). | `directly-supported` — **Accurate Send Scheduling**: HW transmits a packet at an app-supplied PTP time via a per-SQ fence `[vendor-doc]` | `only-with-controller-assistance` / Micro-C timer+memory `[inference]`; feasible, toolchain-risky | `directly-supported` — timestamped delay/calendar queue, deterministic release on a PTP timebase `[peer-reviewed]` | `directly-supported` — `release = max(ready, req+Δ)` in software |
| **4. Per-flow stateful delay** | `via-recirculation` + per-flow deadline in a SALU register `[inference]`; but ≤~8 unicast queues/port and scarce register memory (NetVRM) cap true per-flow *queueing* `[peer-reviewed]` | `directly-supported` — ARM state + per-queue send scheduling + DRAM `[vendor-doc]` | `directly-supported` — 480 threads, per-flow state in SRAM/DRAM `[vendor-doc]` | `directly-supported` — >10k HW queues w/ per-queue schedule (Corundum) `[peer-reviewed]` | `directly-supported` — per-flow policy in software |
| **5. Full payload buffering (store/reconstruct)** | `impractical-or-unsafe` — no addressable packet store; TM buffer (~20–22 MB) is transient egress buffering, not random-access; large state needs external DRAM via RDMA (TEA) `[peer-reviewed]`. (Holding an *existing* frame in-flight is fine; *storing/reconstructing* payload is not.) | `directly-supported` — up to 32 GB on-board DDR + ARM cores `[vendor-doc]` | `directly-supported` — on-board DRAM (~2 GiB) `[vendor-doc]` | `directly-supported` — on-chip BRAM/URAM (small) or external DDR/HBM (large) `[peer-reviewed]` | `directly-supported` — host RAM |
| **6. ACK generation / TCP proxying** | `impractical-or-unsafe` — no TCP stack; can forge a bare ACK header but not maintain seq/ack/RTO state; also **forbidden this phase** | `only-with-controller-assistance` — full TCP proxy runs in ARM/DOCA `[vendor-doc]`, but that is the proxy line (out of byte-preserving phase) | `impractical` in P4, heavy in Micro-C; out of phase | `only-with-controller-assistance` — needs a TCP-offload core; high effort | `impractical` here — it is a replay endpoint, not a proxy |

**How to read column "Tofino 1":** the first two rows are the good news (native, cheap,
spec-clean). Row 3 is the crux — the mechanism that actually erases the measured leak is the one
Tofino lacks as a primitive, and the recirculation workaround, though normally a bad idea, is
tractable *only because DNP3's traffic class is tiny* (§4.3). Rows 5–6 confirm the DPU/FPGA are the
home for anything that must store payload or speak TCP.

---

## 2. Tofino 1 architecture facts this analysis rests on

All from the public Open-Tofino P4/TNA release `[vendor-doc]` unless noted; the detailed TM model
is **not** in the public doc (Intel: withheld "for legal reasons"), so TM-internal claims below are
marked `[inference]` from documented shaper behavior.

| Resource | Fact | Source |
|---|---|---|
| Pipeline | PISA/RMT: programmable parser → ~12 MAU stages → TM → egress MAU → deparser | RMT (Bosshart 2013) `[peer-reviewed]`; Open-Tofino `[vendor-doc]` |
| Packet buffer | ~**20–22 MB** shared on-chip, in the **Traffic Manager** (transient egress buffering, not random-access storage) | Tofino specs `[vendor-doc]` |
| Egress queues | commonly **8 unicast queues/port** (UC0–UC7); TM is **"configurable but not programmable"** — port shaping in **bps or pps** | Open-Tofino / Netberg `[vendor-doc]` |
| Stateful state | Register arrays partitioned **per MAU stage**, one SALU op/packet/register; register memory is scarce and statically shared (motivates NetVRM) | NetVRM (Zhu 2022) `[peer-reviewed]` |
| **Timestamps** | ingress `ingress_mac_tstamp` **48-bit ns** (IEEE-1588, at ingress MAC); `global_tstamp` **48-bit ns** at ingress *and* egress; egress `enq_tstamp` **18-bit ns**, `deq_timedelta` **18-bit ns**, `enq/deq_qdepth` **19-bit** | Open-Tofino `tofino1_base.p4` `[vendor-doc]` |
| Recirculation | packet sent to a **loopback port** → full extra pipe pass; **costs bandwidth + fixed added latency**; on-chip recirc budget ~**1.6 Tbps** and ~2× faster than off-chip | Accelerated Service Chaining (Wu 2019) `[peer-reviewed]`; P4/TNA community `[vendor-doc]` |
| Resubmit | re-inject from ingress deparser to ingress parser; **no queuing/egress, no extra bandwidth**, but **once only** (≤8 B metadata carried) | Open-Tofino `[vendor-doc]` |
| Packet generator | on-chip **pktgen** with **one-time timer, periodic timer, port-down, and recirculation** triggers | Open-Tofino / P4 community `[vendor-doc]` |
| Precision | data-plane timestamps are ns-resolution; DPTP shows **19 ns median** cross-switch sync — timing *observation* on Tofino is excellent | DPTP (Kannan 2019) `[peer-reviewed]` |

**Key consequences for our primitive:**

- **Tofino can *observe* time superbly but cannot natively *wait***. There is precise ns-resolution
  timestamping (`ingress_mac_tstamp`, `global_tstamp`) and even a native measurement of how long a
  packet sat in a queue (`deq_timedelta`) — but there is **no packet-sleep, no per-packet buffer
  timer, no "release at wall-clock T" primitive** in TNA `[inference, well-established]`. Delay is
  achievable only by (a) TM queueing, which is rate-bounded, or (b) recirculation loops.
- **`deq_timedelta` is only 18 bits ≈ 262,143 ns ≈ 262 µs.** So the dataplane can *natively read*
  queue-induced delay, but only up to ~262 µs; a millisecond-scale hold **exceeds this field's
  range** and must be tracked against the 48-bit `global_tstamp` (which won't wrap for ~78 h) in a
  register `[inference from field widths]`. This is a concrete, non-obvious limit.

---

## 3. Tofino 1 — mechanism-by-mechanism (the KEY analysis)

### 3.1 Pacing / rate shaping (Mechanism 1) → native, cheap, spec-clean

The TM shapes each port/queue to a max rate (bps or pps) `[vendor-doc]`. Independently, **Nimble**
shows line-rate in-network rate-limiting on a 100 G Tofino using **meters** — explicitly **without
any dedicated queuing/buffering and without recirculation or packet-generator token refills** —
scaling to 100k rate-limiters `[peer-reviewed]`. For DNP3 (one meter/shaper per outstation, kbps
rates) this is trivially within budget. **Verdict: `via-Traffic-Manager-config` (native).** This is
the byte-preserving, low-risk, ASIC-idiomatic knob — but note what it does *not* do (next).

### 3.2 IPG normalization (Mechanism 2) → native via queue pacing

Feeding the split frames through a shaped egress queue evens their *spacing*; a controller-set
Gate-Control-List can gate release in cyclic windows. **P4-TAS** implements exactly this — an IEEE
802.1Qbv Time-Aware Shaper on a P4 ASIC (Tofino **2**), using an internally generated control-frame
stream to open/close egress queues on a ns-scale schedule `[preprint]`. This pairs directly with the
existing CRC-splitting primitive (the gaps are defined on the frames splitting already produces).
**Verdict: `via-queue-pacing` (feasible; demonstrated on Tofino 2, portable in principle to
Tofino 1's TM).** Caveat carried to §3.3: pacing regularizes *spacing*, it does not by itself set
the *absolute* time the first frame leaves.

### 3.3 First-packet ABSOLUTE delay (Mechanism 3) → the crux

**Why TM shaping does NOT solve this (confirming the brief's claim `[inference]`).** A TM
max-rate shaper is a leaky/token-bucket regulator: it only *delays* a packet when the queue already
holds enough backlog that draining at the shaped rate pushes this packet's turn into the future. A
**lone** response frame arriving at an **empty** shaped queue (with the token bucket replenished —
which it always is at kbps offered load) is forwarded essentially immediately: its inter-departure
constraint vs. the *previous* frame is satisfied because the previous frame left long ago. So
shaping **bounds sustained rate and burst, not the latency of an isolated first packet**. Since DNP3
polls are ~1 s apart and each response is a lone small frame, TM shaping leaves the request→first-
response processing delay (0.24 ms to ACK / 1.01 ms to response `[measured-rig]`) essentially
untouched. **This is the single most important negative result for Tofino:** the native, cheap knob
(pacing) cannot erase the crown-jewel leak. This is corroborated by design intent in Nimble, which
*chose* meters precisely to avoid relying on queue-delay for enforcement `[peer-reviewed, inference]`.

**The only Tofino mechanism that yields an absolute per-packet hold: recirculation + register
deadline `[inference]`.** Sketch (not built — phase rule forbids P4 now):

1. On the ingress pass that first sees the response frame, read `global_tstamp` (48-bit ns), compute
   `deadline = max(response_ready, request_time + target_delay)` and store it in a SALU register
   keyed by flow (the `request_time` per flow was stamped when the request passed).
2. Send the frame to a loopback (recirculation) port. On each recirc pass, re-read `global_tstamp`,
   compare to `deadline`. If not yet reached, recirculate again; once reached, emit to the real
   egress port.
3. The **self-clock granularity** = the per-pass latency. A bare loopback pass is sub-µs to ~1 µs,
   giving fine (≪ ms) resolution; to reduce pass count you can pace the loopback port so each pass
   takes ~100 µs (the brief's assumed self-clock), trading resolution for bandwidth.

**Quantified costs and limits (Tofino 1):**

- **Resolution:** ~100 µs is comfortably achievable and far finer than needed — the safe hold
  budget is up to the master's effective TCP RTO (≈200 ms floor, *measure on Vision*), and DNP3
  tolerances are ms-scale. `[inference]`
- **Deadline compare is not free.** A 48-bit (or even 32-bit) magnitude compare **cannot** sit in a
  gateway (≤44-bit predicate budget) and a range-match key is ≤20 bits — so the compare must be
  **sliced** (e.g. compare the ms-resolution high bits of the timestamp) or done in a **range-match
  table**. This is exactly bf-p4c constraint classes 1–2 from the lab's Tofino playbook; budget for
  it up front. `[inference, grounded in lab constraint doc]`
- **Recirc bandwidth (the §4.3 affordability argument, quantified):** per-outstation offered load ≈
  a few hundred bytes/second-ish → **single-digit kbps** (~1e-7 of a 100 G pipe). Because hold time
  (ms) ≪ poll interval (≥1 s), the **expected number of concurrently-held frames is < 1 per
  outstation** — a 64–256-entry held-frame register table has 1–2 orders of margin. Recirc traffic
  while a 200 B frame is held: at a 100 µs self-clock ≈ **16 Mbps per held frame**; even ~10
  simultaneously-held frames ≈ 0.16 % of a 100 G pipe against a ~1.6 Tbps on-chip recirc budget.
  At a bare-loopback ~1 µs self-clock it is ~1.6 Gbps per held frame — still <1 % aggregate given
  <1 frame held. **Negligible either way.** `[inference; Wu 2019 for the recirc budget]`
- **Impact on line rate / other traffic:** the recirc loop consumes one loopback port's bandwidth
  and a slice of pipe throughput; at DNP3 scale this is in the noise, so sibling pipelines and
  production forwarding are unaffected. `[inference]`

**Verdict: `via-recirculation` — non-idiomatic and resource-touchy, but tractable for DNP3.** The
framing worth keeping: *per-packet in-network timing normalization is impractical for datacenter TCP
and precisely because of that everyone avoids it — but it is affordable for OT/SCADA because the
traffic is low-rate and small-frame.* That inversion is itself paper-worthy. The closest published
precedent that manipulates/normalizes packet timing in a programmable data plane is **NetWarden**,
which detects and normalizes inter-packet-delay distributions to defeat covert *timing* channels at
line rate using a switch fastpath + software slowpath `[peer-reviewed]` — strong evidence that
in-network timing manipulation on this class of hardware is real, though NetWarden shapes an ongoing
IPD distribution rather than imposing a single absolute first-packet deadline.

### 3.4 Per-flow stateful delay (Mechanism 4) → feasible, bounded by queues/registers

A per-flow `deadline`/`request_time` register indexed by a hash of the 5-tuple gives each outstation
its own target `[inference]`. Two ceilings: (a) **only ~8 unicast queues/port**, so you cannot give
thousands of flows their own *queue* — flows share queues, and per-flow *timing* must come from the
recirc-deadline register, not from dedicated queueing; (b) **register memory is scarce and statically
partitioned** across the ~12 stages (NetVRM) `[peer-reviewed]`, so the held-flow table is sized in
the hundreds–thousands, not millions. For a substation with tens–hundreds of outstations this is
ample. **Verdict: `via-recirculation` + per-flow register (native for our scale);
`only-with-controller-assistance` if you needed 10^5+ concurrent per-flow deadlines.**

### 3.5 Full payload buffering (Mechanism 5) → impractical on Tofino

Tofino's ~20–22 MB buffer is **transient TM egress buffering**, not a random-access store you can
write a payload into and reconstruct later; there is no addressable packet memory and one SALU
op/register/packet. State-intensive functions that need real storage go to **external DRAM via
RDMA** (TEA) `[peer-reviewed]`, which is a heavyweight architecture unjustified here. **Crucial
distinction:** *holding an already-existing frame in flight* (recirc/queue) is fine and byte-
preserving; *storing and reconstructing the response payload* (needed for fused split+timing, or
any reorder/repad) is **impractical** on the ASIC. **Verdict: `impractical-or-unsafe` for
store/reconstruct; the byte-preserving hold in §3.3 is the supported subset.**

### 3.6 ACK generation / TCP proxying (Mechanism 6) → impractical + out-of-phase

Tofino has no TCP stack; it can rewrite header fields but cannot maintain seq/ack/RTO/reassembly
state to act as a real TCP endpoint. Forging a bare ACK to decouple it from a held response would
also **rewrite seq/ack** — which is proxy/MITM territory the phase rule forbids, and a passive IDS
would see the anomaly. **Verdict: `impractical-or-unsafe`** (both technically and by policy). If TCP
decoupling is ever authorized, its home is the DPU/FPGA, not Tofino.

---

## 4. NVIDIA BlueField DPU — the clean native home

Hardware `[vendor-doc]`: **BlueField-2** = up to 8× Arm Cortex-A72, 8/16 GB on-board DDR4, integrated
ConnectX-6 Dx (up to 200 Gb/s); **BlueField-3** = 16× Cortex-A78, up to 32 GB DDR5, ConnectX-7 (up
to 400 Gb/s). Deployment modes `[vendor-doc]`: **DPU/embedded (ECPF)** mode (Arm owns the datapath,
traffic flows through the DPU — the bump-in-the-wire we want), **zero-trust/restricted**, **NIC**
mode, and the now-obsolete **separated-host** mode.

The decisive capability is **Accurate Send Scheduling**: from ConnectX-6 Dx onward the NIC will
**transmit a packet at an application-supplied network (PTP) time**, implemented as a per-send-queue
fencing command against the NIC's real-time clock `[vendor-doc]`. This is *exactly* mechanism 3 —
first-packet absolute delay — as a **hardware primitive**, with a companion per-SQ **Packet Pacing**
rate-limiter (documented granularity ~500 ns–1 ms) `[vendor-doc]` for mechanisms 1–2, and line-rate
HW TX/RX **timestamping** on a true on-NIC PTP clock (~12 ns accuracy) `[vendor-doc]` for the
timebase. **DOCA Flow** offloads match/meter/steer pipes to the eSwitch at line rate `[vendor-doc]`.

Per-mechanism: **1 native** (Packet Pacing), **2 native** (pacing/send-scheduling), **3 native**
(Accurate Send Scheduling), **4 native** (Arm state + per-queue schedule + DRAM), **5 native** (up
to 32 GB DDR + cores), **6 feasible** (full TCP proxy in Arm software) — but 6 is the proxy line,
out of the byte-preserving phase. **Timing resolution**: sub-µs to ns for send scheduling; ARM-
software scheduling adds jitter (µs-scale) if you route through the cores rather than the HW fence.
**Packet-copy overhead**: if the response is *forwarded* rather than *generated*, holding it means
buffering in ARM/DRAM and re-injecting with a send timestamp — a copy per held frame, trivial at
DNP3 rates. **Verdict: BlueField is the recommended clean reference home** for constant-time /
size-decorrelation normalization and the natural place to *fuse* split+timing (it can store and
reconstruct payload, which Tofino cannot). It also serves as the ground-truth baseline the Tofino
recirc approximation is measured against.

---

## 5. Netronome (Agilio / NFP) SmartNIC — capable, toolchain-risky

Architecture `[vendor-doc]`: NFP-4000 (Agilio CX) = **60 32-bit flow-processing cores (microengines),
8 hardware threads each** (~480 threads), hierarchical memory (on-chip SRAM + on-board DRAM, ~2 GiB),
programmable in **P4 and Micro-C** (P4-only or P4-with-C-sandbox) via Programmer Studio. Real P4
dataplanes have been built and *latency-measured* on it — **P4CEP** implements stateful complex-event
operators on an Agilio at ~6.8 µs baseline latency, 10 GbE line rate `[peer-reviewed]`; a second INT
event-detection dataplane on an NFP-4000 is reported in a preprint `[preprint]`.

Capability-wise the NFP is a run-to-completion multithreaded NPU, so an explicit software delay/timer
per flow (Micro-C timers + per-flow state in SRAM/DRAM) is **more natural than on Tofino** and does
not need a recirculation trick: **1** via config rate-limiting, **2** via Micro-C timers `[inference]`,
**3** via Micro-C timer + memory (`only-with-controller-assistance`/software timer) `[inference]`,
**4** native (per-flow state across 480 threads), **5** native (on-board DRAM), **6** heavy but
possible in Micro-C. **The real limitation is toolchain maturity, not silicon:** Netronome's
independent SmartNIC business wound down and the NFP/Agilio line + software are now carried by
**Corigine**; community reports indicate the P4 SDK is effectively in maintenance/limited-support and
gated behind licensing `[vendor/community, med-confidence]`. **Verdict: technically viable as a
"does it generalize to a second target?" data point, not the primary platform** — the timing logic
is easy, the build/support surface is the risk.

---

## 6. FPGA — most deterministic, highest development cost

FPGAs are the reference for *deterministic* timed release. **Corundum** (open-source 100 Gb/s FPGA
NIC) provides **per-queue hardware TX schedulers** with **>10,000 queues**, native high-precision
**IEEE 1588 PTP** timestamping, and a demonstrated **microsecond-precision TDMA (time-based)
hardware scheduler enforcing a schedule at 100 Gb/s with no CPU overhead** `[peer-reviewed]` — i.e.
mechanisms 1–4 as first-class hardware. A **timestamped delay queue / calendar queue** (Brown's O(1)
calendar-queue structure `[peer-reviewed]`) gives exact deterministic release ordered by deadline;
the **802.1Qbv Time-Aware Shaper** `[standard]` is the standards analogue (gate-driven cyclic queue
release), and **IEEE 1588 PTP** `[standard]` is the timebase all of these reference. Platforms:
**NetFPGA-SUME** (Virtex-7) is the canonical research board for 100 Gb/s-class programmable packet
processing with HW timestamping `[peer-reviewed]`.

Per-mechanism: **1–4 directly-supported** (calendar/TDMA scheduler, per-queue timestamped release);
**5 directly-supported** (on-chip BRAM/URAM for small holds, external DDR/HBM for large); **6
only-with-controller-assistance** (needs a TCP-offload core — high effort). **Timing resolution**:
the best of any target — deterministic, sub-µs, jitter-bounded. **Resource overhead / cost**: also
the highest — RTL/HLS development, per-design place-and-route, and no P4 ergonomics unless you adopt
a P4→NetFPGA flow. **Verdict: the "what perfect looks like" reference** — ideal for a determinism
ceiling and a TSN-style claim, but the heaviest lift; not the pragmatic first hardware target.

---

## 7. RQ7 (hardware portion) — direct answer

**RQ7 (hardware): Which timing-normalization mechanisms are realizable on which programmable-hardware
targets, at what cost, and where does the crown-jewel first-packet delay actually live?**

1. **Pacing and IPG normalization (mechanisms 1–2) are universal.** Native on Tofino (TM
   config/meters), BlueField (Packet Pacing), FPGA (HW scheduler), and easy on Netronome. These are
   byte-preserving and spec-clean everywhere. They reshape the *rate/segmentation* channel — which
   the CRC-splitting primitive already partly addresses — but **do not** by themselves erase the
   processing-time fingerprint.
2. **The decisive mechanism (3, first-packet absolute delay) splits the field.** It is a **hardware
   primitive on BlueField** (Accurate Send Scheduling) and **on FPGA** (timestamped/calendar queue),
   but is **absent as a primitive on Tofino 1** — reachable there only via a recirculation +
   register-deadline loop. TM shaping cannot substitute: it bounds rate, not the latency of a lone
   frame.
3. **The Tofino recirc workaround is unusually affordable *here*.** DNP3's single-digit-kbps,
   small-frame, <1-concurrently-held-frame traffic class makes a technique that is prohibitive for
   datacenter TCP cost <1 % of the pipe (§3.3). This is the paper's crisp systems inversion.
4. **Payload buffering and TCP proxying (5–6) do not belong on Tofino.** Store/reconstruct needs
   DPU/FPGA memory; ACK/seq-ack rewrite is proxy territory the phase rule forbids and is unsafe
   in-fabric. If those are ever authorized, they live on the DPU.
5. **Recommended hardware path:** BlueField as the clean native home and correctness baseline
   (mechanism 3 in hardware, plus fused split+timing since it can store payload); Tofino for the
   in-network line-rate realization of pacing + the recirc-hold (the genuine data-plane systems
   contribution); FPGA as the determinism ceiling / TSN reference; Netronome only as a portability
   data point, gated on toolchain access. The software replay server remains the zero-hardware first
   deliverable (it *generates* bytes, so it schedules emission directly — no hold problem at all).

---

## 8. Speculative / low-confidence items (explicitly flagged)

- The exact Tofino recirc **self-clock period** achievable in practice (100 µs vs. ~1 µs) depends on
  loopback-port shaping behavior I could not pin to a public number — **`[speculative]`**; both
  bounds are given and both are affordable.
- The **detailed Tofino TM shaper model** (burst sizes, exact scheduling discipline, per-queue vs
  per-port shaping interactions) is **not public** (Intel withholds it); §3.1/§3.3 claims are
  `[inference]` from standard leaky/token-bucket behavior, consistent with Nimble's design choices.
- The `via-recirculation` mechanism 3 has **not been built or measured** on our chip — it is a P4
  design (forbidden this phase). Its cost estimates are `[inference]`; the closest *measured*
  in-network timing-manipulation precedent is NetWarden, which normalizes IPD, not a single absolute
  first-packet deadline.
- **Netronome support status** is `[vendor/community, med-confidence]` — no formal acquisition/EOL
  record, only the Corigine hand-off and community reports of limited P4 SDK support.

---

## 9. Hardware Feasibility — synthesis for `hardware_design.md`

The timing-normalization primitive decomposes into six mechanisms; the two cheap ones (pace, gap-
normalize) are native everywhere and byte-preserving, but they touch the rate/segmentation channel,
not the processing-time leak. The mechanism that actually destroys the measured leak — an **absolute
first-packet hold** to `request_time + target_delay` — is a **hardware primitive on BlueField and
FPGA** and an **emulated-only capability on Tofino 1**. Tofino observes time with ns precision but
cannot natively wait; its TM shaper regulates rate, not lone-frame latency; so absolute delay on
Tofino requires a recirculation + 48-bit-timestamp-deadline register loop, with the deadline compare
paying the gateway/range-match tax (bf-p4c classes 1–2). That workaround is normally uneconomical but
is **affordable for DNP3** because the traffic is single-digit kbps, small-frame, and holds <1 frame
at a time (<1 % of the pipe). Anything that must *store and reconstruct* payload, or *speak TCP*, is
off-ASIC by construction and (for TCP) out of the byte-preserving phase. Concrete recommendation:
**software replay server now (zero hardware) → Tofino for line-rate pacing + the recirc-hold (the
data-plane systems result) → BlueField as the native reference/correctness baseline and the fused
split+timing home → FPGA as the determinism ceiling; Netronome only as a portability check.**

---

## PAPER_MATRIX_ROWS
title | authors | year | venue | DOI | url | peer_reviewed | tier | target_protocol_or_traffic | attacker_model | defense_mechanism | timing_policy | sw_or_hw | platform | testbed | security_metric | overhead_metric | key_result | limitations | relevance_to_us | evidence_confidence
NetWarden: Mitigating Network Covert Channels while Preserving Performance | Jiarong Xing, Qiao Kang, Ang Chen | 2020 | USENIX Security Symposium | NA | https://www.usenix.org/conference/usenixsecurity20/presentation/xing | yes | 2 | general TCP/covert channels | active/passive covert-channel sender-receiver | in-network detect+normalize inter-packet-delay & storage channels | IPD normalization (shape distribution) at line rate, switch fastpath + SW slowpath | hw+sw | Barefoot Tofino + host software | switch ASIC | covert-channel bit-rate / detection | TCP throughput preserved | line-rate covert-timing-channel mitigation on a programmable switch without perf loss | shapes ongoing IPD, not a single absolute first-packet deadline; not DNP3 | closest published precedent for in-network packet-timing normalization on our target class | high
NetWarden: Mitigating Network Covert Channels without Performance Loss | Jiarong Xing, Adam Morrison, Ang Chen | 2019 | USENIX HotCloud Workshop | NA | https://www.usenix.org/conference/hotcloud19/presentation/xing | yes | 2 | general TCP/covert channels | covert-channel sender-receiver | programmable-data-plane covert-channel mitigation | timing+storage channel mitigation | hw+sw | programmable switch | switch ASIC | covert-channel mitigation | perf preserved | early/position version of NetWarden | workshop scope | shows the in-network timing-manipulation line of work | high
Nimble: Scalable TCP-Friendly Programmable In-Network Rate-Limiting | Vineeth Sagar Thapeta, Komal Shinde, Mojtaba Malekpourshahraki, Darius Grassi, Balajee Vamanan, Brent E. Stephens | 2021 | ACM SOSR | 10.1145/3482898.3483361 | https://conferences.sigcomm.org/sosr/2021/papers/s13.pdf | yes | 3 | TCP / datacenter | NA (rate-limiting, not adversarial) | in-network rate-limiting via meters | rate/pacing via meters + ECN-shaping, no queuing/recirc | hw | Barefoot Tofino 100G | switch ASIC | TCP-friendliness / utilization | 100k rate-limiters, no recirc | line-rate pacing on Tofino without dedicated queuing or recirculation | rate control only, not absolute per-packet delay | grounds mechanism-1 (pacing native/cheap on Tofino via meters) | high
SP-PIFO: Approximating Push-In First-Out Behaviors using Strict-Priority Queues | Albert Gran Alcoz, Alexander Dietmüller, Laurent Vanbever | 2020 | USENIX NSDI | NA | https://www.usenix.org/conference/nsdi20/presentation/alcoz | yes | 3 | general | NA | programmable scheduling on commodity queues | rank/deadline-ordered release approximated on strict-priority queues | hw | Barefoot Tofino | switch ASIC | scheduling fidelity | runs on real HW | PIFO-like programmable scheduling on existing Tofino strict-priority queues | approximation; scheduling order not absolute delay | shows deadline-ordered scheduling is feasible on Tofino queues | high
Programmable Packet Scheduling at Line Rate | Anirudh Sivaraman, Suvinay Subramanian, Mohammad Alizadeh, Sharad Chole, Shang-Tse Chuang, Anurag Agrawal, Hari Balakrishnan, Tom Edsall, Sachin Katti, Nick McKeown | 2016 | ACM SIGCOMM | 10.1145/2934872.2934899 | https://doi.org/10.1145/2934872.2934899 | yes | 3 | general | NA | PIFO programmable scheduler primitive | priority/deadline-ordered enqueue at line rate | hw | switch ASIC (design) | ASIC design/eval | scheduling expressiveness | ~4% area | single hardware primitive for programmable line-rate scheduling | scheduling order, not wall-clock hold | foundational for deadline-ordered release feasibility | high
Fast, Scalable, and Programmable Packet Scheduler in Hardware | Vishal Shrivastav | 2019 | ACM SIGCOMM | 10.1145/3341302.3342090 | https://doi.org/10.1145/3341302.3342090 | yes | 3 | general | NA | PIEO predicate-based scheduler | dequeue by predicate from arbitrary list position | hw | FPGA prototype | FPGA | scalability/expressiveness | >30x vs PIFO | generalizes PIFO to predicate-based dequeue, more scalable | scheduling, not absolute delay | supports deadline-indexed release primitives | high
Approximating Fair Queueing on Reconfigurable Switches | Naveen Kr. Sharma, Ming Liu, Kishore Atreya, Arvind Krishnamurthy | 2018 | USENIX NSDI | NA | https://www.usenix.org/conference/nsdi18/presentation/sharma | yes | 3 | datacenter | NA | approximate fair queueing in-switch | per-packet rank + rotating strict-priority queues | hw | reconfigurable/PISA switch | switch ASIC | fairness | line rate | fair-queueing approximated at line rate on programmable switches | scheduling discipline, not per-flow absolute delay | grounds per-flow scheduling feasibility (mechanism 4) | high
Forwarding Metamorphosis: Fast Programmable Match-Action Processing in Hardware for SDN | Pat Bosshart, Glen Gibb, Hun-Seok Kim, George Varghese, Nick McKeown, Martin Izzard, Fernando Mujica, Mark Horowitz | 2013 | ACM SIGCOMM | 10.1145/2486001.2486011 | https://doi.org/10.1145/2486001.2486011 | yes | 4 | general | NA | RMT programmable match-action architecture | NA (architecture) | hw | RMT ASIC (design) | ASIC design | feasibility/cost | terabit line rate | protocol-independent programmable switch ASIC is feasible at terabit rates | foundation, not a timing mechanism | the PISA/Tofino architecture our analysis assumes | high
Accelerated Service Chaining on a Single Switch ASIC | Dingming Wu et al. (full author list not verified this session) | 2019 | ACM HotNets | 10.1145/3365609.3365849 | https://doi.org/10.1145/3365609.3365849 | yes | 3 | general | NA | on-chip recirculation for multi-pass processing | NA | hw | Barefoot Tofino | switch ASIC | throughput | on-chip recirc ~1.6 Tbps, 2x vs off-chip | quantifies on-chip recirculation capacity/cost on Tofino | not a timing/delay system | grounds the recirc-bandwidth budget for the recirc-hold (mechanism 3) | high
Precise Time-synchronization in the Data-Plane using Programmable Switching ASICs (DPTP) | Pravein Govindan Kannan, Raj Joshi, Mun Choon Chan | 2019 | ACM SOSR | NA | https://praveingk.github.io/papers/DPTP_SOSR19.pdf | yes | 3 | general | NA | in-dataplane time synchronization | NA | hw | Barefoot Tofino | switch ASIC | sync error | 19 ns median / 47 ns p99 | ns-precision timekeeping fully in the Tofino data plane | provides time, not delay | grounds that Tofino can OBSERVE time at ns precision (timestamps) | high
NetVRM: Virtual Register Memory for Programmable Networks | Hang Zhu, Tao Wang, Yi Hong, Dan R. K. Ports, Anirudh Sivaraman, Xin Jin | 2022 | USENIX NSDI | NA | https://www.usenix.org/conference/nsdi22/presentation/zhu | yes | 3 | general | NA | dynamic register-memory sharing | NA | hw | commodity programmable switch | switch ASIC | memory satisfaction ratio | 1.6-2.2x | register memory is scarce and statically partitioned across stages | not a timing mechanism | grounds the per-flow-state ceiling for mechanism 4 | high
TEA: Enabling State-Intensive Network Functions on Programmable Switches | Daehyeok Kim, Zaoxing Liu, Yibo Zhu, Changhoon Kim, Jeongkeun Lee, Vyas Sekar, Srinivasan Seshan | 2020 | ACM SIGCOMM | 10.1145/3387514.3405855 | https://doi.org/10.1145/3387514.3405855 | yes | 3 | general | NA | external DRAM for switch state via RDMA | NA | hw | Barefoot Tofino + server DRAM | switch ASIC + RDMA | throughput/state size | line rate | switches reach large state only via external DRAM over RDMA | heavyweight; not timing | grounds mechanism-5 (no on-chip payload store on Tofino) | high
Carousel: Scalable Traffic Shaping at End Hosts | Ahmed Saeed, Nandita Dukkipati, Vytautas Valancius, Vinh The Lam, Carlo Contavalli, Amin Vahdat | 2017 | ACM SIGCOMM | 10.1145/3098822.3098852 | https://doi.org/10.1145/3098822.3098852 | yes | 4 | datacenter TCP | NA | timing-wheel deferred-completion shaper | timestamp/deadline-indexed release (timing wheel) | sw | end-host (software) | server | CPU overhead / accuracy | low CPU | scalable timestamp-deadline shaping at end hosts | end-host, not in-network | design pattern for the software scheduler / deadline release | high
Loom: Flexible and Efficient NIC Packet Scheduling | Brent Stephens, Aditya Akella, Michael M. Swift | 2019 | USENIX NSDI | NA | https://www.usenix.org/conference/nsdi19/presentation/stephens | yes | 4 | datacenter | NA | NIC hierarchical packet scheduler | per-flow hierarchical scheduling in NIC | hw | SmartNIC | NIC | policy enforcement | 100 Gbps, no CPU | offload per-flow scheduling into the NIC | scheduling, not absolute delay; NIC | supports SmartNIC-side scheduling feasibility | high
P4-TAS: P4-Based Time-Aware Shaper for Time-Sensitive Networking | Chair of Communication Networks, University of Tübingen (Steffen Lindner et al.) | 2025 | arXiv (preprint) | 10.48550/arXiv.2511.10249 | https://arxiv.org/abs/2511.10249 | preprint | 3 | TSN/Ethernet | NA | 802.1Qbv Time-Aware Shaper on P4 | time-gated cyclic egress-queue open/close via generated control frames | hw | Intel Tofino 2 | switch ASIC | schedule precision | ns-scale internal delay quantified | first TAS on a P4 ASIC; time-gated queue release feasible on Tofino-class HW | Tofino 2, preprint | grounds mechanism-2 (time-gated IPG normalization) on Tofino-class HW | med
Corundum: An Open-Source 100-Gbps NIC | Alex Forencich, Alex C. Snoeren, George Porter, George Papen | 2020 | IEEE FCCM | 10.1109/FCCM48280.2020.00015 | https://doi.org/10.1109/FCCM48280.2020.00015 | yes | 3 | general | NA | FPGA NIC with HW TX scheduler + PTP | per-queue timestamped/TDMA time-based release | hw | FPGA (Xilinx) | FPGA NIC | scheduling precision | µs-precision TDMA at 100G, no CPU | >10k HW queues, PTP timestamping, µs-precision TDMA time-based TX scheduler | high dev cost | grounds FPGA mechanisms 1-4 (deterministic timed release) | high
Calendar Queues: A Fast O(1) Priority Queue Implementation for the Simulation Event Set Problem | Randy Brown | 1988 | Communications of the ACM | 10.1145/63039.63045 | https://doi.org/10.1145/63039.63045 | yes | 4 | NA (algorithm) | NA | O(1) bucketed time-ordered priority queue | deadline-indexed release structure | NA | NA | NA | O(1) enqueue/dequeue | NA | canonical O(1) calendar/timing-wheel structure for time-ordered release | algorithm only | the data structure behind timestamped delay queues (FPGA/SW) | high
IEEE 802.1Qbv-2015: Enhancements for Scheduled Traffic (Time-Aware Shaper) | IEEE 802.1 Working Group | 2015 | IEEE Standard (802.1Q amendment) | NA | https://standards.ieee.org/ieee/802.1Qbv/6068/ | standards-doc | 4 | TSN/Ethernet | NA | time-aware shaper (gate control list) | cyclic time-gated egress-queue release | hw | bridges/switches | standard | determinism/bounded delay | NA | standardized time-gated frame release | standard, not an implementation | the standards analogue of hardware timed release (mechanism 2/3) | high
IEEE 1588-2019: Precision Clock Synchronization Protocol (PTP) | IEEE | 2019 | IEEE Standard | NA | https://standards.ieee.org/ieee/1588/6825/ | standards-doc | 4 | networked measurement/control | NA | precision time synchronization | NA (timebase) | hw | networked devices | standard | sync accuracy | sub-µs to sub-ns | the precise timebase that time-based schedulers reference | standard | the timebase for accurate send scheduling / TAS / TDMA | high
NetFPGA SUME: Toward 100 Gbps as Research Commodity | Noa Zilberman, Yury Audzevich, G. Adam Covington, Andrew W. Moore | 2014 | IEEE Micro | 10.1109/MM.2014.61 | https://doi.org/10.1109/MM.2014.61 | yes | 4 | general | NA | FPGA platform for line-rate packet processing | NA | hw | Xilinx Virtex-7 FPGA | FPGA board | platform capability | 100 Gbps-class | standard FPGA research board for programmable packet processing + HW timestamping | platform, not a mechanism | grounds the FPGA platform option | high
P4CEP: Towards In-Network Complex Event Processing | Thomas Kohler, Ruben Mayer, Frank Dürr, Marius Maaß, Sukanya Bhowmik, Kurt Rothermel | 2018 | ACM SIGCOMM NetCompute Workshop | 10.1145/3229591.3229593 | https://doi.org/10.1145/3229591.3229593 | yes | 3 | general | NA | stateful CEP operators as a P4 dataplane | NA | hw | Netronome Agilio SmartNIC | SmartNIC | latency | ~6.8 µs at 10 GbE | stateful P4-on-Agilio dataplane, latency-measured | not a timing-delay system | grounds Netronome (NFP) P4 dataplane capability | high
NVIDIA BlueField-3 DPU Datasheet | NVIDIA | 2023 | NVIDIA vendor datasheet | NA | https://docs.nvidia.com/networking/display/bf3dpu | vendor-doc | 3 | NA | NA | DPU: Arm cores + DRAM + ConnectX-7 | NA | hw | BlueField-3 | DPU | NA | 16x A78, 32GB DDR5, 400G | on-chip cores + up to 32GB DRAM + line-rate engine to host delay/buffer logic | vendor doc | grounds DPU buffering (mechanism 5) and compute for delay | high
NVIDIA BlueField-2 DPU Datasheet | NVIDIA | 2020 | NVIDIA vendor datasheet | NA | https://docs.nvidia.com/networking/display/BlueField2DPUENUG/Specifications | vendor-doc | 3 | NA | NA | DPU: Arm A72 + DDR4 + ConnectX-6 Dx | NA | hw | BlueField-2 | DPU | NA | 8x A72, 8/16GB DDR4, 200G | DPU hardware baseline for the bump-in-the-wire deployment | vendor doc | grounds the DPU platform option | high
NVIDIA Accurate Send Scheduling & Packet Pacing (5T for 5G) | NVIDIA | 2024 | NVIDIA vendor doc | NA | https://docs.nvidia.com/networking/display/NVIDIA5TTechnologyUserManualv10/Accurate+Scheduling | vendor-doc | 3 | NA | NA | HW timed transmit + per-SQ pacing | transmit at app-supplied PTP time via per-SQ fence; ns-granular pacing | hw | ConnectX-6 Dx+/BlueField | NIC/DPU | send-time accuracy | ns-scale | HARDWARE first-packet absolute delay + rate pacing primitive | vendor doc | grounds DPU mechanisms 1-3 as native hardware primitives | high
NVIDIA DOCA Flow Programming Guide | NVIDIA | 2024 | NVIDIA vendor doc | NA | https://docs.nvidia.com/doca/sdk/doca-flow/index.html | vendor-doc | 3 | NA | NA | HW flow steering/metering pipes | NA | hw | BlueField/ConnectX | DPU | NA | line rate | offload match/meter/steer pipes to the eSwitch | vendor doc | grounds DPU dataplane offload for pacing/steering | high
Open-Tofino: P4-16 Tofino Native Architecture (public) | Barefoot Networks / Intel | 2021 | vendor repo/spec | NA | https://github.com/barefootnetworks/Open-Tofino | vendor-doc | 3 | NA | NA | TNA arch: TM, timestamps, recirc/resubmit, pktgen | NA | hw | Tofino 1 | switch ASIC | NA | NA | authoritative TNA definitions (intrinsic metadata, TM configurable-not-programmable, recirc vs resubmit, pktgen triggers) | detailed TM model withheld | primary source for all Tofino-1 capability claims | high

## BIBTEX
```bibtex
@inproceedings{xing2020netwarden,
  title     = {{NetWarden}: Mitigating Network Covert Channels while Preserving Performance},
  author    = {Xing, Jiarong and Kang, Qiao and Chen, Ang},
  booktitle = {Proceedings of the 29th USENIX Security Symposium (USENIX Security '20)},
  year      = {2020},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/usenixsecurity20/presentation/xing}
}

@inproceedings{xing2019netwarden,
  title     = {{NetWarden}: Mitigating Network Covert Channels without Performance Loss},
  author    = {Xing, Jiarong and Morrison, Adam and Chen, Ang},
  booktitle = {11th USENIX Workshop on Hot Topics in Cloud Computing (HotCloud '19)},
  year      = {2019},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/hotcloud19/presentation/xing}
}

@inproceedings{thapeta2021nimble,
  title     = {{Nimble}: Scalable {TCP}-Friendly Programmable In-Network Rate-Limiting},
  author    = {Thapeta, Vineeth Sagar and Shinde, Komal and Malekpourshahraki, Mojtaba and Grassi, Darius and Vamanan, Balajee and Stephens, Brent E.},
  booktitle = {Proceedings of the ACM SIGCOMM Symposium on SDN Research (SOSR '21)},
  year      = {2021},
  doi       = {10.1145/3482898.3483361},
  url       = {https://conferences.sigcomm.org/sosr/2021/papers/s13.pdf}
}

@inproceedings{alcoz2020sppifo,
  title     = {{SP-PIFO}: Approximating Push-In First-Out Behaviors using Strict-Priority Queues},
  author    = {Alcoz, Albert Gran and Dietm{\"u}ller, Alexander and Vanbever, Laurent},
  booktitle = {17th USENIX Symposium on Networked Systems Design and Implementation (NSDI '20)},
  year      = {2020},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/nsdi20/presentation/alcoz}
}

@inproceedings{sivaraman2016programmable,
  title     = {Programmable Packet Scheduling at Line Rate},
  author    = {Sivaraman, Anirudh and Subramanian, Suvinay and Alizadeh, Mohammad and Chole, Sharad and Chuang, Shang-Tse and Agrawal, Anurag and Balakrishnan, Hari and Edsall, Tom and Katti, Sachin and McKeown, Nick},
  booktitle = {Proceedings of the ACM SIGCOMM 2016 Conference},
  year      = {2016},
  doi       = {10.1145/2934872.2934899}
}

@inproceedings{shrivastav2019fast,
  title     = {Fast, Scalable, and Programmable Packet Scheduler in Hardware},
  author    = {Shrivastav, Vishal},
  booktitle = {Proceedings of the ACM SIGCOMM 2019 Conference},
  year      = {2019},
  doi       = {10.1145/3341302.3342090}
}

@inproceedings{sharma2018approximating,
  title     = {Approximating Fair Queueing on Reconfigurable Switches},
  author    = {Sharma, Naveen Kr. and Liu, Ming and Atreya, Kishore and Krishnamurthy, Arvind},
  booktitle = {15th USENIX Symposium on Networked Systems Design and Implementation (NSDI '18)},
  year      = {2018},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/nsdi18/presentation/sharma}
}

@inproceedings{bosshart2013forwarding,
  title     = {Forwarding Metamorphosis: Fast Programmable Match-Action Processing in Hardware for {SDN}},
  author    = {Bosshart, Pat and Gibb, Glen and Kim, Hun-Seok and Varghese, George and McKeown, Nick and Izzard, Martin and Mujica, Fernando and Horowitz, Mark},
  booktitle = {Proceedings of the ACM SIGCOMM 2013 Conference},
  year      = {2013},
  doi       = {10.1145/2486001.2486011}
}

@inproceedings{wu2019accelerated,
  title     = {Accelerated Service Chaining on a Single Switch {ASIC}},
  author    = {Wu, Dingming and others},
  booktitle = {Proceedings of the 18th ACM Workshop on Hot Topics in Networks (HotNets '19)},
  year      = {2019},
  doi       = {10.1145/3365609.3365849},
  note      = {DOI verified via CrossRef; only first author verified this session --- complete the author list before camera-ready}
}

@inproceedings{kannan2019precise,
  title     = {Precise Time-synchronization in the Data-Plane using Programmable Switching {ASICs}},
  author    = {Kannan, Pravein Govindan and Joshi, Raj and Chan, Mun Choon},
  booktitle = {Proceedings of the 2019 ACM Symposium on SDN Research (SOSR '19)},
  year      = {2019},
  pages     = {8--20},
  url       = {https://praveingk.github.io/papers/DPTP_SOSR19.pdf},
  note      = {Best Paper, SOSR '19; ACM DOI not re-verified this session}
}

@inproceedings{zhu2022netvrm,
  title     = {{NetVRM}: Virtual Register Memory for Programmable Networks},
  author    = {Zhu, Hang and Wang, Tao and Hong, Yi and Ports, Dan R. K. and Sivaraman, Anirudh and Jin, Xin},
  booktitle = {19th USENIX Symposium on Networked Systems Design and Implementation (NSDI '22)},
  year      = {2022},
  pages     = {155--170},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/nsdi22/presentation/zhu}
}

@inproceedings{kim2020tea,
  title     = {{TEA}: Enabling State-Intensive Network Functions on Programmable Switches},
  author    = {Kim, Daehyeok and Liu, Zaoxing and Zhu, Yibo and Kim, Changhoon and Lee, Jeongkeun and Sekar, Vyas and Seshan, Srinivasan},
  booktitle = {Proceedings of the ACM SIGCOMM 2020 Conference},
  year      = {2020},
  doi       = {10.1145/3387514.3405855}
}

@inproceedings{saeed2017carousel,
  title     = {{Carousel}: Scalable Traffic Shaping at End Hosts},
  author    = {Saeed, Ahmed and Dukkipati, Nandita and Valancius, Vytautas and Lam, Vinh The and Contavalli, Carlo and Vahdat, Amin},
  booktitle = {Proceedings of the ACM SIGCOMM 2017 Conference},
  year      = {2017},
  doi       = {10.1145/3098822.3098852}
}

@inproceedings{stephens2019loom,
  title     = {{Loom}: Flexible and Efficient {NIC} Packet Scheduling},
  author    = {Stephens, Brent and Akella, Aditya and Swift, Michael M.},
  booktitle = {16th USENIX Symposium on Networked Systems Design and Implementation (NSDI '19)},
  year      = {2019},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/nsdi19/presentation/stephens}
}

@misc{lindner2025p4tas,
  title        = {{P4-TAS}: P4-Based Time-Aware Shaper for Time-Sensitive Networking},
  author       = {Lindner, Steffen and others (Chair of Communication Networks, University of T{\"u}bingen)},
  year         = {2025},
  howpublished = {arXiv preprint arXiv:2511.10249},
  doi          = {10.48550/arXiv.2511.10249},
  url          = {https://arxiv.org/abs/2511.10249},
  note         = {Preprint; not peer-reviewed. Implemented on Tofino 2. Full author list not verified.}
}

@inproceedings{forencich2020corundum,
  title     = {{Corundum}: An Open-Source 100-{Gbps} {NIC}},
  author    = {Forencich, Alex and Snoeren, Alex C. and Porter, George and Papen, George},
  booktitle = {2020 IEEE 28th Annual International Symposium on Field-Programmable Custom Computing Machines (FCCM)},
  year      = {2020},
  pages     = {38--46},
  doi       = {10.1109/FCCM48280.2020.00015}
}

@article{brown1988calendar,
  title     = {Calendar Queues: A Fast {O(1)} Priority Queue Implementation for the Simulation Event Set Problem},
  author    = {Brown, Randy},
  journal   = {Communications of the ACM},
  volume    = {31},
  number    = {10},
  pages     = {1220--1227},
  year      = {1988},
  doi       = {10.1145/63039.63045}
}

@misc{ieee8021qbv,
  title        = {{IEEE} Standard for Local and Metropolitan Area Networks--Bridges and Bridged Networks--Amendment 25: Enhancements for Scheduled Traffic},
  author       = {{IEEE 802.1 Working Group}},
  year         = {2015},
  howpublished = {IEEE Std 802.1Qbv-2015},
  note         = {Time-Aware Shaper; later consolidated into IEEE 802.1Q-2018},
  url          = {https://standards.ieee.org/ieee/802.1Qbv/6068/}
}

@misc{ieee1588_2019,
  title        = {{IEEE} Standard for a Precision Clock Synchronization Protocol for Networked Measurement and Control Systems},
  author       = {{IEEE}},
  year         = {2019},
  howpublished = {IEEE Std 1588-2019},
  url          = {https://standards.ieee.org/ieee/1588/6825/}
}

@article{zilberman2014sume,
  title     = {{NetFPGA} {SUME}: Toward 100 {Gbps} as Research Commodity},
  author    = {Zilberman, Noa and Audzevich, Yury and Covington, G. Adam and Moore, Andrew W.},
  journal   = {IEEE Micro},
  volume    = {34},
  number    = {5},
  pages     = {32--41},
  year      = {2014},
  doi       = {10.1109/MM.2014.61}
}

@inproceedings{kohler2018p4cep,
  title     = {{P4CEP}: Towards In-Network Complex Event Processing},
  author    = {Kohler, Thomas and Mayer, Ruben and D{\"u}rr, Frank and Maa{\ss}, Marius and Bhowmik, Sukanya and Rothermel, Kurt},
  booktitle = {Proceedings of the 2018 Morning Workshop on In-Network Computing (NetCompute '18)},
  year      = {2018},
  doi       = {10.1145/3229591.3229593}
}

@misc{nvidia_bf3,
  title        = {{NVIDIA} {BlueField-3} {DPU} Datasheet / Product Documentation},
  author       = {{NVIDIA}},
  year         = {2023},
  howpublished = {Vendor documentation},
  url          = {https://docs.nvidia.com/networking/display/bf3dpu}
}

@misc{nvidia_bf2,
  title        = {{NVIDIA} {BlueField-2} {DPU} Specifications},
  author       = {{NVIDIA}},
  year         = {2020},
  howpublished = {Vendor documentation},
  url          = {https://docs.nvidia.com/networking/display/BlueField2DPUENUG/Specifications}
}

@misc{nvidia_accurate_scheduling,
  title        = {Accurate Send Scheduling and Packet Pacing ({NVIDIA} 5T for 5G Technology)},
  author       = {{NVIDIA}},
  year         = {2024},
  howpublished = {Vendor documentation},
  url          = {https://docs.nvidia.com/networking/display/NVIDIA5TTechnologyUserManualv10/Accurate+Scheduling}
}

@misc{nvidia_doca_flow,
  title        = {{NVIDIA} {DOCA} Flow Programming Guide},
  author       = {{NVIDIA}},
  year         = {2024},
  howpublished = {Vendor documentation},
  url          = {https://docs.nvidia.com/doca/sdk/doca-flow/index.html}
}

@misc{opentofino,
  title        = {Open-Tofino: {P4-16} Intel Tofino Native Architecture (Public Version)},
  author       = {{Barefoot Networks / Intel}},
  year         = {2021},
  howpublished = {Vendor repository and specification},
  url          = {https://github.com/barefootnetworks/Open-Tofino}
}
```
