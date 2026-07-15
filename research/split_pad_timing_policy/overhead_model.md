# Overhead Model — Latency, Bandwidth, Compute, Buffering, Hardware

_Quantitative overhead model for the combined split/pad/timing policy, per platform. From Agent I
(overhead + optimization), Agent E (software), Agent F (Tofino), Agent G (DPU/FPGA), and measured
data. All figures are order-of-magnitude design estimates unless tagged [M]; nothing was benchmarked
on the eventual hardware. 2026-07-13._

## 1. Latency
- **Added latency is bounded by the timing target and capped by the measured effective RTO**, not by
  DNP3 timers. Operating point 15–25 ms per response; watchdog ≈0.5× the **measured** RTO.
- **The RTO constraint binds on the per-hop gap and the initial hold, NOT the cumulative sum**
  (three-inequality model). TCP RTO fires on a single unacked segment, and each paced chunk is ACKed as
  it arrives, so the measured **141×10 ms = 1.41 s split ran clean (0 retransmits)** — no segment waited
  longer than one 10 ms gap for its ACK. The cumulative span is bounded instead by the DNP3 app/select
  timeout (5 s / 10 s), which is 25×–70× looser. For a *split*, the binding side is the outstation/
  replay tail-RTO (Hulk); for a timing-only *hold*, the master request-RTO (Vision). **bpc=1 is
  RTO-feasible**; aggressive split is bounded from above by bandwidth/packet-count and the beacon leak,
  not by the RTO budget.
- Report added latency mean / median / p95 / p99 / max, plus SELECT→OPERATE interval and
  poll-cycle completion time.

## 2. Bandwidth and packet count
- **Timing normalization: 0 added bytes, 0 added packets.**
- **Split: 0 added application bytes; adds packet/segment count and header overhead.** Measured: a
  2407 B response at bpc=1 → 301 packets vs ~55 at bpc=8 [M]; header overhead ≈3–7× wire bytes at the
  finest granularity (Agent I). Split raises packet count **without changing total bytes** — so it
  does not reduce the size leak, and the packet-count increase is itself a (new) observable to budget.
- **Padding (future): the expensive axis.** Closing the CROB-count leak by constant-shape padding
  costs **~+219 B per SELECT and per OPERATE response (~+590%) for N=1→16** [M-anchored]. A
  differential-privacy tunnel (NetShaper-style) makes this a tunable dial rather than a fixed
  pad-to-peak. Cover traffic is the most bandwidth-expensive per unit privacy.

## 3. Compute and memory (software)
- CPU **≪0.1% of a core**, memory KB-resident, at DNP3's single-digit-kbps rate with <1 concurrently
  held frame (Agent E). One monotonic-deadline timer (or a tiny per-flow-head heap) suffices; timing
  wheels / calendar queues / DPDK are ~10⁷× over-provisioned and are cited to reject. Scheduling error
  is sub-ms in CPython — ample against a ms-scale target.

## 4. Buffering, queue, held packets
- **Software:** <1 held frame per outstation in expectation (hold ≪ poll interval); a 64–256-entry
  held-frame table is 1–2 orders of margin.
- **Tofino:** Stage 1+2 (classify + pace) use ~4–5 of 12 stages, 2 queues, 3 SALUs, 1 hash (Agent F).
  The unbuilt Stage-3 recirc-hold costs ~2k passes (loopback self-clock), 16 Mbps–1.6 Gbps per held
  frame, **<0.1% of the pipe** — affordable only because DNP3 is low-rate/small-frame. Register width,
  48-bit timestamp slicing, and bf-p4c gateway/SALU/range compare limits are the binding resources.
- **DPU/FPGA:** BlueField Accurate Send Scheduling granularity 500 ns–1 ms, max-future window ~4.19 s
  — ~3 orders of margin on our ms holds; the hardware fastpath enforces timed release without touching
  the ARM cores (whose kernel-space packet processing tops out at ~half line-rate, but never binds
  here). FPGA calendar queue: on-chip BRAM/URAM for the held-frame table.

## 5. The hardware-cost ↔ privacy coupling (Agent I)
Cheaper/coarser platforms leak *more*: scheduler timing error ε_sched propagates into the released
distribution (raising Wasserstein distance to the target), so a coarse clock is itself a residual
timing signal. This couples **hardware cost to privacy** and is why the evaluation produces a
**privacy-vs-hardware-cost Pareto** alongside privacy-vs-latency and privacy-vs-bandwidth.

## 6. Deadline-miss and bypass overhead
- Deadline-miss rate and **policy-bypass rate** are first-class metrics: frequent bypass (of controls,
  or under RTO uncertainty) is both a correctness/safety signal and a **leak channel** (an observer
  learns which transactions were bypassed). Budget and report them.

## 7. Summary table (order-of-magnitude)
| Mechanism | Latency | +Bytes | +Packets | CPU/mem | Buffering | Closes size leak? |
|---|---|---|---|---|---|---|
| Timing normalization | ≤ target (15–25 ms), < RTO | 0 | 0 | ≪0.1% core | <1 frame | No |
| Split (paced) | inter-chunk gaps, < tail-RTO | 0 app bytes | up to ~5–10× | ≪0.1% core | <1 frame | No (relocates to packet count) |
| Padding (future, tunnel) | ≤ shaping budget | +up to class-max (~+590%) | +chaff | tunnel endpoints | tunnel buffers | **Yes** |
| Cover traffic (future) | n/a | highest per unit privacy | +decoy pkts | endpoint | — | Statistically only |

_Plain language: normalizing timing is essentially free; splitting is cheap in bytes but multiplies
packets and doesn't hide size; actually hiding size (padding) is expensive and needs a future encrypted
tunnel. Everything must stay under the measured TCP retransmit timer, and a cheaper switch/NIC with a
coarser clock leaks a little more._
