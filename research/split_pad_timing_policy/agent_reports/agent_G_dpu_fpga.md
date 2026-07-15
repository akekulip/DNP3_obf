<!-- Agent G (DPU / SmartNIC / FPGA specialist), split_pad_timing_policy study, 2026-07-13.
Analysis/design only — NO harness source code changed. EXTENDS Agent E's hardware_design.md /
agent_E_hardware.md (ack_timing_normalization); does not re-derive Tofino. Every capability claim
is labelled [M] measured-rig · [S] standard · [V] vendor-doc · [P] paper-reported · [I] inference ·
[H] hypothesis. New verified works are listed in NEW_PAPER_MATRIX_ROWS / NEW_BIBTEX only. -->

# Agent G — DPU, SmartNIC, and FPGA Home for Split + Pad + Timing (extends Agent E)

_Primary author of `dpu_fpga_design.md` (spec §5). Scope: NVIDIA BlueField DPU, Netronome/Corigine
NFP SmartNIC, FPGA, and host software — compared for the split/pad/timing workload. Tofino 1 is
Agent E's centerpiece; I carry only a cross-reference column and do not repeat that analysis. I
extend Agent E on four fronts it left thin: (1) **quantitative** BlueField Accurate Send Scheduling
parameters (granularity, max-future window, clock mechanism, PHC precision); (2) the **two-datapath**
model of a DPU (hardware send-scheduling fastpath vs. ARM/DOCA slowpath) and which capability lives
on which; (3) **quantified** inline/ARM forwarding overhead from a measured BlueField-2 study; (4) the
**future-phase** homes for payload buffering, padding, and cover traffic, plus a host-software bridge
(`SO_TXTIME`/ETF) that borrows NIC hardware pacing without a DPU._

---

## 0. The six capabilities (this study's decomposition — distinct from Agent E's six timing mechanisms)

The lead asked for the cleanest hardware home of six *capabilities*, spanning split + pad + timing and
both phases:

| # | Capability | Phase | Byte-preserving? |
|---|---|---|---|
| **(a)** | First-response **ABSOLUTE delay** (hold first reply to `req_time + Δ`) | **NOW** | Yes (endpoint) / needs brief hold (inline) |
| **(b)** | **Payload buffering** (store/reconstruct a full response) | NOW for a brief unmodified hold; **FUTURE** for reorder/fuse | Yes only if bytes unchanged |
| **(c)** | **Padding** (inject apparent bytes/objects/packets) | **FUTURE** (protocol-modifying) | **No** |
| **(d)** | **Cover traffic / decoys** (synthesize dummy transactions) | **FUTURE** | **No** (new packets) |
| **(e)** | **Per-flow policy** (select mechanism/target per outstation) | **NOW** | Yes |
| **(f)** | **Accurate timed release** (the enforcement primitive under (a)/(e)) | **NOW** | Yes |

Note the split between **policy** and **enforcement**: (a) is *what* deadline to impose, (f) is the
*hardware primitive that fires* at that deadline. They separate cleanly across platforms, so I keep
them as distinct columns. **Split** itself (CRC-boundary, byte-preserving) is already demonstrated in
software `[M]`; on hardware it is just "emit these N frames," so the interesting hardware question for
split is *when* each frame leaves — i.e. capabilities (a), (e), (f). **Padding is a proven dead end
in the byte-preserving phase** `[M]` (invalid-index CROBs → OUT_OF_RANGE, not insertable), so (c)/(d)
are assessed only as FUTURE homes.

*Plain language: of the six jobs, three (hold the first reply, pick a per-device rule, fire at the
right time) are doable now and keep every byte; three (buffer-and-rebuild, pad, fake decoys) need a
future phase that is allowed to change bytes. This report says which box does each job best.*

---

## 1. The load-bearing insight: a DPU has TWO datapaths, and the capabilities split across them

Agent E treated BlueField as uniformly "native" and noted packet-copy overhead is "trivial at DNP3
rates" but did not quantify it or separate the paths. The correct model is that a BlueField DPU in
embedded/DPU (ECPF) mode exposes **two distinct processing paths**, and each capability belongs to
exactly one:

- **Hardware fastpath** — the ConnectX eSwitch + NIC transmit engine. Match/steer/meter via **DOCA
  Flow** offloaded to the eSwitch, and per-send-queue **Accurate Send Scheduling / Packet Pacing** on
  the transmit engine. Runs at line rate, **does not touch the ARM cores**, and is byte-preserving.
  This is where (a) first-response absolute delay, (e) the *match* half of per-flow policy, and (f)
  accurate timed release live. `[V]`
- **ARM/DOCA slowpath** — the 8–16 Arm cores + 8–32 GB on-board DDR. Full software: can store,
  reconstruct, craft, and inject packets, and (if authorized) run a TCP proxy. This is where (b)
  reorder/fuse buffering, (c) padding, (d) cover-traffic synthesis, and complex (e) per-flow logic
  live — and where throughput is *bounded by ARM compute*, not the line. `[V]` + `[P]`

**Why the split matters (quantified).** A measured BlueField-2 characterization (Liu et al., 2021)
found the embedded Arm cores **cannot sustain more than ~half the line bandwidth for kernel-space
packet processing**, and that general-purpose compute on the card trails a server CPU (crypto,
on-card memory, and IPC are the exceptions, which are strong) `[P, arXiv/tech-report]`. So *routing
every packet through the ARM cores has a real, measured throughput ceiling.* The good news for us:
**capability (a) does not need the ARM path at all** — the first-response hold is enforced by the NIC
transmit engine's send-scheduling fence, on the hardware fastpath, so the ARM ceiling never binds.
Only the FUTURE capabilities (b)/(c)/(d) require the ARM path, and at DNP3's single-digit-kbps offered
load `[I, from measured_evidence]` even a "half-line-rate" ARM ceiling is ~5–6 orders of magnitude of
headroom. The ceiling is real but irrelevant *here*; I flag it because it *would* bind on a
datacenter-rate workload and reviewers will ask.

*Plain language: a BlueField is really a fast hardware switch bolted to a small ARM computer. Holding
the first reply and pacing use the fast hardware and cost nothing; buffering, padding, and fake
traffic use the small computer, which is slow — but our traffic is so light that even "slow" is
thousands of times more than we need.*

---

## 2. Platform x capability comparison table (centerpiece)

Verdict vocabulary: **native-HW** (a documented hardware primitive) · **HW-fastpath** (offloaded to
line-rate engine, no host CPU) · **SW-on-card** (runs on the card's cores/soft-CPU) · **RTL/HLS**
(needs FPGA logic design) · **controller-assist** (needs off-path control-plane help at scale) ·
**out-of-phase** (protocol-modifying; FUTURE) · **n/a**. Each cell carries an evidence tag.

| Capability | **Host SW replay** | **BlueField DPU** | **Netronome NFP** | **FPGA** | Tofino 1 (xref Agent E) |
|---|---|---|---|---|---|
| **(a) First-response ABSOLUTE delay** | native — it *generates* the bytes, so `send() at max(ready, req+Δ)`; no live packet to hold `[M]` | **native-HW** — Accurate Send Scheduling: NIC transmits at app-supplied PTP time; inline hold buffers 1 unmodified frame in DRAM then re-injects with a tx-timestamp `[V]` | SW-on-card — Micro-C timer + per-flow state; run-to-completion, no recirc trick `[I]` | **native-HW** — timestamped/calendar delay queue, deterministic release on PTP timebase `[P]` | via-recirculation (unbuilt); not a TM primitive `[I]` |
| **(b) Payload buffering** (reorder/fuse) | native — host RAM `[I]` | HW-fastpath hold (1 frame) native; **reorder/fuse = SW-on-card**, 8–32 GB DDR `[V]` | SW-on-card — ~2 GiB on-board DRAM `[V]` | RTL/HLS — BRAM/URAM (small, on-chip) or DDR/HBM (large) `[P]` | impractical (no addressable packet store; TM buffer is transient) `[P]` |
| **(c) Padding** (FUTURE) | native (SW) but **out-of-phase** | SW-on-card (craft+inject in ARM/DOCA) — **out-of-phase** `[V]` | SW-on-card (Micro-C) — out-of-phase `[I]` | RTL/HLS — out-of-phase `[I]` | impractical + out-of-phase `[I]` |
| **(d) Cover traffic / decoys** (FUTURE) | native (SW) — out-of-phase | **native-HW pacing of injected decoys** (ASS can *pace* synthesized packets) + ARM synthesis — out-of-phase `[V]` | SW-on-card packet gen — out-of-phase `[I]` | native-HW packet gen + scheduler — out-of-phase `[P]` | pktgen (periodic/one-time/recirc triggers) — out-of-phase `[V]` |
| **(e) Per-flow policy** | native — dict keyed by 5-tuple `[I]` | **HW-fastpath match/steer** (DOCA Flow) + ARM for complex logic `[V]` | **native** — per-flow state across ~480 threads in SRAM/DRAM `[V]` | native-HW — >10k per-queue schedules (Corundum); PANIC hybrid scheduler `[P]` | via-register + controller-assist at 10^5 scale `[P]` |
| **(f) Accurate timed release** (enforcement) | SW timers (ms jitter) → **or push to NIC HW** via `SO_TXTIME`+ETF/taprio if NIC has LaunchTime `[S]` | **native-HW** — send-scheduling fence: granularity **500 ns–1 ms**, max-future window **≈ tx_pp × 2^23** `[V]` | SW-on-card timers `[I]` | **native-HW** — µs-precision TDMA/calendar at 100 G, no CPU `[P]` | via-recirculation self-clock (unbuilt) `[I]` |

**How to read this table.** The two capabilities we need NOW and that must be *precise* — (a) and
(f) — are **hardware primitives on BlueField and FPGA**, a software-timer job on Netronome and the
host, and an unbuilt recirculation workaround on Tofino. Everything in the FUTURE rows (c)/(d), plus
reorder/fuse buffering in (b), lands on the ARM/DOCA slowpath or FPGA logic and is *out of the
byte-preserving phase*. **No capability we need this phase requires leaving the hardware fastpath on a
DPU** — the ARM cores are only for future work.

*Plain language: for the two timing jobs we care about right now, the DPU and the FPGA both have a
dedicated hardware feature that does it exactly; the SmartNIC and a plain server do it in software
(good enough but jittery); the switch would need a not-yet-built trick. All the future stuff lands on
the slower software side.*

---

## 3. BlueField DPU — quantitative Accurate Send Scheduling (extends Agent E)

Agent E established that Accurate Send Scheduling *exists* and is "ns-scale." The concrete parameters
(from the DPDK mlx5 driver documentation, the authoritative programming reference) sharpen this into
a design that provably fits DNP3:

- **Granularity:** the scheduling clock `tx_pp` is configurable over **500 ns to 1,000,000 ns
  (1 ms)** `[V]`. Our timing tolerance is ms-scale, so even the *coarsest* setting is finer than we
  need, and 500 ns gives ~3 orders of margin.
- **Max-future ("too-distant-future") window:** a scheduled send time may sit at most **≈ tx_pp x
  2^23** ahead of "now" `[V]`. At tx_pp = 500 ns that is **≈ 4.19 s**; at 1 µs, ≈ 8.4 s. Our safe hold
  is bounded *above* by the master's effective TCP RTO (~200 ms floor — **measure on Vision** per the
  binding safety constraint), so the ASS window sits ~20x above our largest legal hold. The window
  never binds. This is a real limit worth stating precisely (a naive design that scheduled seconds
  ahead would silently drop packets — see the CX-6 forum report of truncated scheduled sends).
- **Mechanism:** enabling send scheduling makes the driver create a **Clock Queue + Rearm Queue** and
  drive transmit with a cross-channel wait-on-time; on ConnectX-6 Dx the `tx_pp` devarg is required,
  on ConnectX-7+ it is implicit `[V]`. So the DPU's absolute-delay primitive is a real, documented tx
  fence, not an inference.
- **Timebase precision:** the integrated PTP hardware clock reaches **sub-20 ns** accuracy and
  timestamps packets with **< 4 ns variance under load** `[V]`. Send-scheduling jitter is therefore
  far below any DNP3-relevant scale; jitter only enters if you route release through ARM software
  instead of the HW fence (µs-scale) `[V/I]`.

**Deployment mode for a bump-in-the-wire.** Use **DPU/embedded (ECPF) mode** so the ARM owns the
datapath and traffic physically transits the card `[V]`. NIC mode and zero-trust/restricted modes do
not give us the inline steering; separated-host mode is obsolete. In ECPF mode, DOCA Flow programs the
eSwitch match/meter/steer pipes at line rate for capability (e), and the transmit engine enforces (a)/
(f). `[V]`

**Inline hold is still byte-preserving.** For a *forwarded* (not generated) response, imposing (a)
means briefly holding one unmodified frame — buffer it in DRAM, then re-inject with a send timestamp.
The bytes are untouched, so this stays inside the byte-preserving phase; it is a "copy one small frame
per poll," negligible at DNP3 rates `[I]`. This is the one nuance that distinguishes an inline DPU
from the host replay server, which *generates* the bytes and so never holds a live packet.

*Plain language: NVIDIA's cards can be told "send this packet at exactly time T," accurate to well
under a microsecond, up to about 4 seconds in the future — far more precise and far longer than we
need. That single feature is exactly the "hold the first reply" primitive, done in hardware for free.*

---

## 4. FPGA — determinism ceiling, plus a toolchain-maturity data point (extends Agent E)

FPGAs remain the determinism reference. Agent E cited Corundum (>10k HW queues, µs-precision TDMA at
100 G, PTP) and Brown's O(1) calendar queue. Two extensions relevant to the DPU/FPGA comparison:

- **PANIC** (OSDI 2020) is a 100 Gbps FPGA programmable-NIC prototype whose core is a **hybrid
  push/pull hardware scheduler** feeding a switching interconnect of offload engines `[P]`. It shows
  that per-flow, deadline-ordered scheduling with performance isolation is a first-class *hardware*
  object on an FPGA NIC — directly grounding capabilities (e) and (f) on FPGA beyond Corundum's TDMA,
  and giving a decoy/cover-traffic scheduler (d) a home if that phase is ever built.
- **On-chip vs external memory (capability (b)).** On-chip **BRAM/URAM** is the fast, deterministic
  store but small (tens of Mb aggregate on a large device) — ample for holding a few DNP3 frames
  (hundreds of bytes each), so a byte-preserving inline hold fits entirely on-chip with deterministic
  latency `[I]`. **External DDR/HBM** is needed only for large payload buffering / reorder / cover-
  traffic queues — i.e. FUTURE work — at the cost of non-deterministic access latency `[P]`. This
  mirrors the DPU's on-chip-fastpath vs. DRAM-slowpath split.
- **Toolchain maturity (the FPGA's real cost).** Agent E's verdict — "heaviest lift, no P4
  ergonomics" — is fair, but **hXDP** (OSDI 2020, Best Paper) is a concrete counter-datapoint: it runs
  unmodified Linux eBPF/XDP programs on an FPGA NIC using **~15% of FPGA resources at 156.25 MHz**,
  matching a high-end CPU core's throughput at **10x lower forwarding latency** `[P]`. So a
  byte-preserving split/hold datapath expressed as eBPF could target an FPGA without hand-written RTL,
  narrowing (not closing) the ergonomics gap versus the DPU/switch. It remains more effort than DOCA
  or P4, and place-and-route is per-design.

**Resolution / overhead:** FPGA timed release is the best of any target — deterministic, sub-µs,
jitter-bounded — with zero CPU involvement (Corundum) `[P]`. The cost is development effort and
per-design synthesis, not run-time overhead.

*Plain language: FPGAs give the most exact timing of anyone and can hold our tiny frames entirely in
fast on-chip memory. The catch is they are the hardest to program — though a recent result (hXDP)
shows you can now run ordinary Linux packet programs on them, which softens that objection.*

---

## 5. Netronome / Corigine NFP SmartNIC — easy logic, toolchain risk (confirms Agent E)

Nothing in the split/pad/timing framing changes Agent E's verdict; I confirm and add the split/decoy
angle. The NFP-4000 (Agilio CX) is a **run-to-completion NPU: ~60 flow-processing microengines x 8
threads (~480 threads), on-chip SRAM + ~2 GiB on-board DRAM, programmable in P4 and Micro-C** `[V]`.
P4CEP measured a stateful P4 dataplane on an Agilio at **~6.8 µs latency, 10 GbE line rate** `[P]`.

- **(a)/(f):** a per-flow Micro-C timer + memory is *more natural than Tofino's recirc trick* — a
  software timer per flow, no self-clock loop `[I]`. Precision is software-timer-bounded (µs), which is
  fine for ms holds.
- **(b)/(c)/(d):** on-board DRAM + Micro-C can store/craft/inject — feasible but FUTURE.
- **(e):** per-flow state across ~480 threads is native `[V]`.
- **Split:** emitting N CRC-boundary frames with per-frame Micro-C-timed release is straightforward.

**The blocker remains toolchain, not silicon.** The independent Netronome SmartNIC business wound down
and the NFP/Agilio line + software moved to **Corigine**; community reports put the P4 SDK in
maintenance/limited-support behind licensing `[V/community, med-confidence]`. **Verdict (unchanged):
a "does it generalize to a second target?" portability data point, gated on toolchain access — not the
primary platform.**

*Plain language: the SmartNIC could do all of this in ordinary C with no tricks, but the software you
need to program it is barely supported anymore, so it is a backup, not a first choice.*

---

## 6. Host software replay server — the current deliverable, and a hardware bridge

The software replay/split server is the zero-hardware baseline and the **current deliverable**. Because
it is an *endpoint that generates the bytes*, capability (a) is trivial: `send()` at
`max(response_ready, req_time + Δ)`. There is **no live packet to hold, no buffering problem, no proxy**
— which is exactly why it is spec-clean today `[M]`.

Its one weakness is **timing determinism**: userspace timers on a general-purpose OS have ms-scale
jitter, so the *enforcement* primitive (f) is soft. Two mitigations, both without a DPU:

- **Push release into NIC hardware** via Linux **`SO_TXTIME` + the ETF (Earliest TxTime First) qdisc**
  (and **taprio** for 802.1Qbv-style cyclic gating). If the host NIC exposes a LaunchTime engine —
  which a ConnectX-6 Dx/7 does, via the same `tx_pp` mechanism as the DPU — the kernel hands each
  packet a launch timestamp and the NIC fires it, giving sub-µs release from a plain server `[S/V]`.
  **This means the software path can borrow the DPU's hardware timed-release primitive without a DPU**,
  provided you verify LaunchTime support on the specific Vision NIC.
- Failing that, a busy-wait / high-resolution timer bounds jitter to tens of µs at the cost of a core.

*Plain language: the plain-server version already does the timing job because it makes the reply
itself, so it never has to catch a packet in flight. Its only flaw is slightly sloppy timing, and even
that can be fixed by letting the network card fire the packet at the exact moment — a standard Linux
feature — if the card supports it.*

---

## 7. Cleanest hardware home per capability (the direct answer)

| Capability | Cleanest home | Runner-up | Evidence |
|---|---|---|---|
| **(a) First-response absolute delay** | **BlueField** (Accurate Send Scheduling, HW fence) for inline; **host replay server** (`send()` schedule) for the endpoint case | **FPGA** (calendar/TDMA queue) | `[V]`/`[M]`/`[P]` |
| **(b) Payload buffering — brief unmodified hold** | **Host RAM** (endpoint) / **BlueField DRAM** (inline) | FPGA BRAM/URAM | `[V]`/`[P]` |
| **(b') Payload buffering — reorder/fuse (FUTURE)** | **BlueField** (8–32 GB DDR + ARM) | FPGA DDR/HBM | `[V]` |
| **(c) Padding (FUTURE)** | **BlueField** ARM/DOCA (craft + inject) | FPGA RTL | `[V]` — out-of-phase |
| **(d) Cover traffic / decoys (FUTURE)** | **BlueField** (ARM synthesis + ASS-paced injection) | FPGA packet-gen + PANIC scheduler; Tofino pktgen | `[V]`/`[P]` — out-of-phase |
| **(e) Per-flow policy** | **BlueField DOCA Flow** (HW eSwitch match/steer) + ARM logic | Netronome (480-thread per-flow state); FPGA per-queue | `[V]`/`[P]` |
| **(f) Accurate timed release** | **BlueField** (500 ns–1 ms granularity, sub-20 ns PHC) / **FPGA** (µs-deterministic TDMA) | Host `SO_TXTIME`+ETF on a LaunchTime NIC | `[V]`/`[P]`/`[S]` |

**One-line synthesis.** For the byte-preserving phase we need now, **BlueField is the clean native
home for the timing capabilities (a)/(e)/(f) and the brief inline hold, using only its hardware
fastpath — the ARM cores stay idle.** The **host replay server** covers the same ground today for the
endpoint case with no hardware at all (and can borrow NIC LaunchTime for precision). **FPGA** is the
determinism ceiling and the natural home if a TSN-grade guarantee is wanted, at the highest build cost
(softened, not erased, by hXDP). **Netronome** is a portability check gated on toolchain. Everything in
capabilities (b')-(c)-(d) — reorder/fuse, padding, cover traffic — belongs on the **DPU/FPGA slowpath
and the FUTURE protocol-modifying phase**, never on the current byte-preserving line. This confirms and
sharpens the lead's stated position; the one correction is that BlueField's *inline* (a) does require a
minimal one-frame hold (still byte-preserving), which the endpoint replay server avoids entirely.

---

## 8. Low-confidence / caveats (explicit)

- The **BlueField-2 half-line-rate ARM ceiling** (Liu 2021) is for *kernel-space* packet processing;
  DPDK/DOCA userspace paths do better, and the number is workload-specific `[P, med-confidence]`. It is
  cited to bound the *slowpath*, which we do not use this phase — do not over-read it as a limit on the
  fastpath capabilities (a)/(f).
- The ASS **max-future window ≈ tx_pp x 2^23** and **500 ns–1 ms granularity** are from DPDK mlx5
  driver docs `[V]`; exact behavior at the boundary (silent drop vs. error) should be confirmed on the
  target ConnectX/BlueField firmware before relying on long holds.
- **`SO_TXTIME`/ETF/taprio + NIC LaunchTime** is a well-established Linux TSN feature `[S]`, but
  LaunchTime support is **NIC- and driver-specific** — verify on the actual Vision NIC before claiming
  hardware-accurate host release.
- No capability here was **built or measured on our hardware** this phase; DPU/FPGA numbers are
  vendor-doc `[V]` and peer-reviewed `[P]`, not `[M]`. The only `[M]` facts are the software-rig
  split/size/timing results carried from `measured_evidence.md`.
- Padding (c) and cover traffic (d) are assessed as FUTURE homes only; the byte-preserving phase has a
  **proven-negative** padding result `[M]` and neither capability is recommended now.

---

## NEW_PAPER_MATRIX_ROWS
title | authors | year | venue | doi | url | peer_reviewed | evidence_level | split_relevance | padding_relevance | timing_relevance | protocol | attacker_model | mechanism | sw_or_hw | platform | experiment_type | security_result | overhead_result | limitations | relevance
Performance Characteristics of the BlueField-2 SmartNIC | Jianshen Liu, Carlos Maltzahn, Craig Ulmer, Matthew L. Curry | 2021 | arXiv preprint / Sandia tech report (arXiv:2105.06619) | 10.48550/arXiv.2105.06619 | https://arxiv.org/abs/2105.06619 | no (preprint/tech-report) | P (preprint) | NA | NA | high (bounds DPU inline/ARM overhead for timed-hold datapath) | NA | NA (measurement study) | measured throughput/latency of BlueField-2 ARM cores vs host/server | hw | NVIDIA BlueField-2 DPU | testbed measurement | NA | ARM cores sustain ~half line bandwidth for kernel-space packet processing; crypto/on-card mem/IPC strong, general compute behind server CPUs | not adversarial; kernel-space path; workload-specific | quantifies the DPU ARM slowpath ceiling — why capability (a) must use the HW fastpath, not ARM; irrelevant at DNP3 kbps
PANIC: A High-Performance Programmable NIC for Multi-tenant Networks | Jiaxin Lin, Kiran Patel, Brent E. Stephens, Anirudh Sivaraman, Aditya Akella | 2020 | USENIX OSDI | NA | https://www.usenix.org/conference/osdi20/presentation/lin | yes | P (peer-reviewed) | med (per-frame scheduling of split output) | low (decoy scheduler if built) | high (hardware per-flow deadline scheduler) | NA | NA (isolation, not adversarial) | hybrid push/pull hardware packet scheduler + switching interconnect for offload chains | hw | FPGA-based programmable NIC prototype (100 Gbps) | prototype eval | NA | 100 Gbps FPGA prototype; cross-tenant isolation + low-latency load balancing | NIC scheduling/isolation focus, not timing obfuscation | grounds capabilities (e) per-flow policy and (f) timed release as first-class HW on a SmartNIC/FPGA, beyond Corundum TDMA
hXDP: Efficient Software Packet Processing on FPGA NICs | Marco Spaziani Brunella, Giacomo Belocchi, Marco Bonola, Salvatore Pontarelli, Giuseppe Siracusano, Giuseppe Bianchi, Roberto Bifulco, and others | 2020 | USENIX OSDI (Best Paper); CACM 65(8) 2022 | 10.1145/3543668 | https://www.usenix.org/conference/osdi20/presentation/brunella | yes | P (peer-reviewed) | med (byte-preserving split datapath as eBPF on FPGA) | NA | med (low-latency forwarding for timed release) | NA | NA | run unmodified Linux eBPF/XDP on FPGA via optimizing compiler + soft-CPU | hw | FPGA NIC (soft-CPU) | prototype eval | NA | ~15% FPGA resources at 156.25 MHz; matches high-end CPU-core throughput; 10x lower forwarding latency | soft-CPU throughput ceiling; not a timing system | FPGA toolchain-maturity data point — narrows the "no P4 ergonomics / heavy RTL" objection to FPGA
NVIDIA MLX5 Ethernet Driver Documentation (Accurate Send Scheduling / tx_pp) | DPDK Project | 2024 | DPDK Programmer's Guide (living document) | NA | https://doc.dpdk.org/guides/nics/mlx5.html | no (vendor/project doc) | V (vendor-doc) | NA | NA | high (quantitative parameters of the HW absolute-delay primitive) | NA | NA | send scheduling on mbuf timestamps via Clock Queue + Rearm Queue (cross-channel) | hw | NVIDIA ConnectX-6 Dx / ConnectX-7 / BlueField | vendor documentation | NA | granularity 500 ns–1,000,000 ns; max-future window ~ tx_pp x 2^23 (~4.19 s at 500 ns); CX-6 Dx needs tx_pp devarg, CX-7+ implicit | doc, not measured on our HW; boundary behavior firmware-specific | authoritative quantitative spec for capability (f) on the DPU — proves ms-scale holds fit with orders of margin

## NEW_BIBTEX
```bibtex
@misc{liu2021bluefield2perf,
  title        = {Performance Characteristics of the {BlueField-2} {SmartNIC}},
  author       = {Liu, Jianshen and Maltzahn, Carlos and Ulmer, Craig and Curry, Matthew L.},
  year         = {2021},
  eprint       = {2105.06619},
  archivePrefix= {arXiv},
  primaryClass = {cs.NI},
  doi          = {10.48550/arXiv.2105.06619},
  url          = {https://arxiv.org/abs/2105.06619},
  note         = {arXiv preprint / Sandia technical report; measured BlueField-2 networking and compute characteristics}
}

@inproceedings{lin2020panic,
  title     = {{PANIC}: A High-Performance Programmable {NIC} for Multi-tenant Networks},
  author    = {Lin, Jiaxin and Patel, Kiran and Stephens, Brent E. and Sivaraman, Anirudh and Akella, Aditya},
  booktitle = {14th USENIX Symposium on Operating Systems Design and Implementation (OSDI '20)},
  year      = {2020},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/osdi20/presentation/lin}
}

@inproceedings{brunella2020hxdp,
  title     = {{hXDP}: Efficient Software Packet Processing on {FPGA} {NICs}},
  author    = {Brunella, Marco Spaziani and Belocchi, Giacomo and Bonola, Marco and Pontarelli, Salvatore and Siracusano, Giuseppe and Bianchi, Giuseppe and Bifulco, Roberto and others},
  booktitle = {14th USENIX Symposium on Operating Systems Design and Implementation (OSDI '20)},
  year      = {2020},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/osdi20/presentation/brunella},
  note      = {Jay Lepreau Best Paper Award. Extended version: Commun. ACM 65(8), 2022, doi:10.1145/3543668. Full author list to be completed before camera-ready.}
}

@misc{dpdk_mlx5,
  title        = {{NVIDIA} {MLX5} Ethernet Driver Documentation (Accurate Send Scheduling, {tx\_pp})},
  author       = {{DPDK Project}},
  year         = {2024},
  howpublished = {DPDK Programmer's Guide (living document)},
  url          = {https://doc.dpdk.org/guides/nics/mlx5.html},
  note         = {tx\_pp granularity 500--1{,}000{,}000 ns; max scheduled-future window approx tx\_pp x 2\textasciicircum 23; Clock Queue + Rearm Queue; CX-6 Dx requires tx\_pp, CX-7+ implicit}
}
```
