# H0 (Tofino CPU punt/reinject path) — PASS on silicon

Date: 2026-08-18. Authorization: Philip "full go" + "keep going till you achieve the goal".
Switch restored to the RRC baseline afterwards.

## Verdict: PASS

The Tofino CPU punt/reinject path is proven **endpoint-transparent and bounded** on
the real switch. This is the mandatory feasibility condition S1 named as the gate
for the whole hardware line: **real total-length hiding is feasible on this testbed.**

## What ran

- Resolved the CPU port from the live bfrt device table: BFN-T10-032D, 2 pipes,
  **`pcie_cpu_port = 192`** (the `bf_kpkt`/`ens1` port; not 64 = relay dp64).
- `hw/h0_cpu_path.p4` — minimal TNA cell-gate: dp9 + EtherType `0x88b6` -> CPU 192;
  CPU 192 -> dp9. Compiled clean first try (bf-p4c 9.13.2), loaded via
  `swap_generic.sh` (RRC displaced), dp9 up (25G RS-FEC).
- CPU echo shim on the switch (`ens1`) + a Vision-side round-trip driver on
  `enp59s0f0np0`.

## Round-trip result (100 frames, Vision -> dp9 -> CPU/ens1 -> shim -> CPU -> dp9 -> Vision)

```
sent=100  recv=100  loss=0
rtt_ms  median=0.290  p95=0.309  max=0.323  min=0.234
```

- **100% delivery, 0 loss**, both directions through the CPU.
- **RTT median 0.29 ms** — sub-millisecond, far inside one 210 ms epoch. Bounded.
- Punt independently confirmed by tcpdump on `ens1` (40/40 frames captured).
- Reinject direction independently confirmed by a diagnostic that stamped the
  ingress port into the frame: CPU-injected frames arrive on **ingress port 192**
  and forward to dp9 (`hw/h0_diag.p4`).

## Two gotchas found and fixed (recorded so the next cycle skips them)

1. A returning frame whose **src MAC equals Vision's own MAC** is dropped by the
   Vision NIC as a self-loop. The driver must use a non-Vision src MAC (and the
   sniffer must be promiscuous for a non-Vision dst).
2. A **plain Python `AF_PACKET` raw socket on `ens1` intermittently misses punted
   frames** after repeated program swaps; a fresh program reload restores it, and
   tcpdump/libpcap is reliable throughout. The real relay-edge CPU shim should use
   a libpcap-backed (or `PACKET_RX_RING`) receive, not a bare `recvfrom` loop.

## Boundary (still not claimed)

- This proves the CPU path is transparent and bounded for a marked test frame. It
  does NOT yet carry the fixed-cell protocol, the two-shim cell bridge, RRC/BOR
  timing, or the SEL-751 (never contacted). Those are H1-H4 of the runbook.
- Overload / sustained cell-rate through `bf_kpkt` is untested (H0 used a low
  frame rate; R2 remains open at scale).

## Switch state after

Restored: `swap_generic.sh` reloaded `defense4_rrc_kernel`; dp8/dp9/dp64 re-added
and UP (matches the pre-H0 snapshot). SEL-751 never contacted; test processes
killed. Compiled `h0_cpu_path` and `h0_diag` remain installed for H1.
