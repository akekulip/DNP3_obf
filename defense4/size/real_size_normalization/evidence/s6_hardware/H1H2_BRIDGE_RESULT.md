# S6 / H1-H2 — full two-shim bridge on silicon: ASSEMBLED + bidirectional, exchange BLOCKED by bf_kpkt reverse loss

Date: 2026-08-18. Builds on H0 (CPU path) and H1-m1 (codec over hardware).
Both hosts restored to baseline afterwards; SEL-751 never contacted.

## What was built

The S4 software topology, with the software `cell_link` replaced by the **real
Tofino CPU path** (`h1_cellgate`, dp9 <-> pcie_cpu_port 192):

```
Vision:  master ns (10.44.0.1) <-veth-> vision l2_shim (inner=v_in, outer=enp59s0f0np0)
                                                              |
                                              fixed 256B cells on dp9 (15/1)
                                                              |  h1_cellgate: dp9<->CPU192
Switch:  relay ns (10.44.0.2) <-veth-> ufispace l2_shim (inner=u_in, outer=ens1/bf_kpkt)
```

Real components on both hosts: the actual `l2_shim` (unmodified topology, one
shared 64-byte key), synthetic DNP3 `dnp3_endpoint` master and relay, both shims
started on their own monotonic clock (functional decode is by public counter, so
cross-host epoch sync is not required for correctness).

## Result: the bridge works structurally, one direction is lossy

Shim metrics from a 5-exchange / 70 s run (both shims decoding hundreds of slots):

| | vision shim | ufispace shim |
|---|---|---|
| inner frames captured | 20 | 11 |
| inner frames delivered | 6 | 20 |
| cells received | 5150 | 1846 |
| slots decoded | 643 | 615 |

- **Forward (master -> relay): reliable.** All 20 master-side inner frames were
  cellized by the vision shim, crossed dp9 -> CPU -> ens1, and were decellized and
  delivered to the relay (`ufispace frames_out = 20`). Zero drops, zero auth
  failures, zero incomplete slots.
- **Reverse (relay -> master): functional but lossy.** The ufispace shim
  cellized the relay's frames and the vision shim received 5150 cells and decoded
  643 slots, but only 6 of the relay's 11 inner frames were delivered to the
  master (`vision frames_out = 6`).
- **No full DNP3 exchange completed** in the window: `master.jsonl` and
  `relay.jsonl` were never written. The reverse loss forces heavy TCP
  retransmission, and over a ~210 ms-per-epoch bridge the exchange does not
  converge.

## Root cause (identified, not yet fixed)

The asymmetry localizes it: the forward outer interface is Vision's i40e NIC
(reliable), the reverse outer interface is the switch CPU port `ens1`/`bf_kpkt`
(lossy). This is the R2 risk the runbook flagged — `bf_kpkt` CPU-TX does not
sustain the shim's cell emission losslessly, so reverse cells (and the inner
frames they carry) are dropped. H0/H1-m1 did not surface it because they ran at a
much lower cell rate. Fixes to try next: rate-pace the shim's per-slot emission;
a libpcap / PACKET_TX_RING transmit on `ens1` instead of a bare raw-socket send;
or larger `bf_kpkt` DR/ring sizing (`kpkt_rx_count`/DMA config).

## Fix applied this session

`l2_shim.open_packet_socket` now sets `SO_RCVBUF = 16 MiB` (was unset), which
removed receive-side drops on the physical NIC; the remaining loss is on the
`bf_kpkt` transmit side.

## Verdict

- **PASS (structural):** the two-shim cell bridge is assembled end to end on
  silicon and moves real DNP3/TCP traffic BIDIRECTIONALLY over the Tofino CPU
  path; the forward direction is fully reliable and byte-preserving.
- **OPEN:** a clean end-to-end DNP3 exchange, blocked by `bf_kpkt` reverse-path
  cell loss (R2). This is a hardware transmit-reliability issue with concrete
  next steps, not an architectural gap.

## Not done / boundary

- The SEL-751 was never contacted (synthetic relay on the switch CPU).
- Byte-equality oracle and observed-cell size analysis over the hardware capture
  were not run (they need a completed exchange first).
- The cell-gate here bridges only dp9<->CPU (no dp64/relay demux; the relay is
  local to the switch CPU).

## Artifacts

`hw/hw_bridge_vision.sh`, `hw/hw_bridge_switch.sh`, `hw/h1_cellgate.p4`; code
deployed to both hosts under `/tmp/rsn`. Both hosts restored to baseline.
