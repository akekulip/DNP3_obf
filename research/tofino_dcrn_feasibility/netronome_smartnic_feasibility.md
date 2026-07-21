# Netronome SmartNIC / DPU on Vision as a Tofino replacement — feasibility brief (2026-07-20)

Decision-grade study (sdn-networks-expert, source-verified). Question: can a Netronome (Agilio) NFP
SmartNIC on the Vision host replace the Intel Tofino-1 for the DNP3 timing-obfuscation testbed?

## Verdict — viable-with-caveats, but not the card to buy new
The NFP is architecturally a BETTER fit than Tofino-1 for our problem: it removes the two walls blocking
us. (1) **No 12-stage MAU budget** — the NFP is a run-to-completion multithreaded processor, not an RMT
pipeline, so timing + size-padding + split are just sequential code, not a stage-allocation puzzle.
(2) **Gigabytes of packet-addressable memory** — per-flow state for 65,536 flows is trivial (room for
millions). It has **no native "transmit at time T" primitive** either, but a millisecond hold is far more
natural to build than on Tofino: park the packet descriptor in a memory ring, release it from a
housekeeping thread polling a free-running µs timer — **no recirculation loop, no TM-shaper drain-offset**
(the ~47 ms Case-B offset we measured is a Tofino artifact, not fundamental).

Caveats that decide the buy: (1) the clean delay path is **Micro-C in Corigine's proprietary Agilio P4C
SDK** — you REWRITE, not port, the Tofino P4; (2) eBPF/XDP hardware offload offloads only a **subset** and
is in maintenance mode; (3) **vendor risk** — the NFP line is now under **Corigine** (smaller vendor);
new-buy availability/support/pricing for 2025-2026 need a direct sales quote.

## Capability table — Tofino-1 vs Netronome NFP vs BlueField-3
| Required primitive | Tofino-1 | Netronome NFP | BlueField-3 |
|---|---|---|---|
| Per-flow state (~65,536 flows) | yes (SALU/SRAM-bounded) | yes (IMEM/EMEM, no SALU limit; millions) | yes |
| Exact pure-ACK match | yes | yes | yes |
| Hold ms, release on event OR deadline | **hack** (recirc loop + shaper; no timer; ~47 ms drain offset) | **build-it** (descriptor ring + timer-poll thread; no recirc/shaper) | **native** (ConnectX accurate scheduling ±900 ns; or Arm-core hold) |
| Strict byte-preservation | yes | yes | yes |
| DNP3-rate traffic (~1 poll/2 s) | yes (overkill) | yes (overkill) | yes |
| **★ timing + size-padding + split TOGETHER** | **NO** (blows 12 stages / SRAM) | **YES** (run-to-completion, no stage wall) | **YES** (Arm cores / DOCA) |

The ★ row is the decision: our "timing+size+split can't co-reside" problem is a direct artifact of the
Tofino RMT 12-stage architecture and **does not exist** on a run-to-completion NFP or a DPU. That is the
real reason to consider the move; the timer convenience is secondary.

## NFP facts (sources in the study)
NFP-4000 (Agilio CX class): 60 Flow Processing Cores (5 islands x 12), 8 HW threads each, ~800 MHz;
memory CLS 64 KB/island, CTM 256 KB/island, IMEM ~4 MB, EMEM ~2 GB (DRAM-backed). NFP-3800 is the current
Agilio GX/CX chip. Programming: Agilio P4C SDK 6.0 (P4-16 + Micro-C sandbox) = the realistic hold-logic
path; eBPF/XDP offload (subset, maintenance mode, needs BPF-offload firmware); Micro-C/NFP SDK (lowest
level). The nfp driver is still in Linux mainline (NFP3800/4000/5000/6000, copyright now Corigine).

## Vision data-path sketch (on-NIC hold; mirrors the Tofino single-host rig)
- **Bump-in-the-wire:** outstation (Hulk) -> Agilio port0 -> NFP datapath (per-flow state + hold/release)
  -> host PCIe -> Vision = DNP3 master. Hold sits on-path in the outstation->master direction (where both
  the pure ACK and the response originate); byte-preserving (defer delivery, touch no header).
- **Single-host loopback (exact analogue of the Tofino loopback rig):** master + outstation in two netns
  on Vision; the NFP's two ports looped (cable or MAC/VEPA hairpin); hold program on the outstation->master
  port. The existing harness + capture methodology port over with minimal change.

## Availability / EOL risk (load-bearing procurement fact)
Netronome the product line is ALIVE but moved to **Corigine** (founded 2015), which markets Agilio
CX/LX/FX/GX + CoreNIC firmware + Agilio P4C SDK 6.0 and maintains mainline nfp-drv-kmods. NOT dead — but
new multi-year buy risk is real: smaller vendor / China nexus (Western support, export-control, RMA terms
uncertain), eBPF-offload in maintenance mode, proprietary toolchain lock-in (Tofino P4 does not port).
Risk verdict: acceptable if we already own the card (research value, no procurement exposure);
NOT-recommended as a fresh multi-year buy when BlueField-3 exists at comparable capability with a
first-tier vendor and a documented roadmap.

## Recommended next step (ranked)
1. **If an Agilio card is on-hand:** pilot Agilio CX (2x25G, NFP-4000/3800) with the P4C SDK 6.0 + Micro-C
   sandbox. Milestone: reproduce Case A (hold pure-ACK in a memory ring, release on response event) on the
   loopback layout, prove byte-identity + 0 retransmits, then MEASURE the hold jitter (replaces the Tofino
   shaper offset with the NFP's own memory/thread jitter — characterize, don't assume zero). Then stack
   size-padding + split to demonstrate the co-residency claim the meeting is about.
2. **If buying hardware:** pilot NVIDIA BlueField-3 (fallback BlueField-2). Case B via ConnectX Accurate
   Scheduling (stamp release = t_ACK + G_i, measured ±900 ns on DOCA 3.3/DPDK 25.11/kernel 6.8); Case A via
   an Arm-core hold-and-release; DOCA Flow / DPL for fast-path classification. Native ms timer the NFP
   lacks, actively supported SDK, no EOL cloud — at DPU price + a DOCA learning curve.
3. **FPGA (Alveo / OpenNIC):** only for true deterministic sub-µs timing; overkill for DNP3-rate ms holds.
4. **Host eBPF-EDT (already prototyped):** cheapest but OFF-PATH — it paces the host's OWN transmit, so it
   cannot reshape the outstation->observer timing unless Vision is a forwarding bump-in-the-wire. That gap
   is exactly what an on-NIC hold closes. Keep as the software baseline.

## Honest unknowns to confirm (do not paper over)
(a) exact NFP deferred-queue/timer mechanism + its jitter — needs SDK + bench confirmation;
(b) current eBPF-offload feature set on our specific card + kernel — needs confirmation;
(c) Corigine new-buy availability, pricing, support-contract terms for 2025-2026 — needs a direct quote;
(d) ConnectX accurate-scheduling at a ~100 ms future horizon (the arXiv paper measured 100 µs spacing;
    scheduling ~100 ms ahead should work via the send-queue timestamp but was not explicitly measured).
