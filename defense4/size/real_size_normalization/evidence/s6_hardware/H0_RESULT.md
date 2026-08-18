# H0 (Tofino CPU punt/reinject path) — executed on silicon: PUNT proven, REINJECT open

Date: 2026-08-18. Authorization: Philip "full go: build + load H0". Switch restored after.

## What ran on the real switch

- Resolved the CPU port authoritatively from the live bfrt device table:
  BFN-T10-032D, 2 pipes, 12 stages, **`pcie_cpu_port = 192`** (the `bf_kpkt`/`ens1`
  port; NOT 64, which is the relay dp64).
- Wrote `hw/h0_cpu_path.p4` (minimal TNA cell-gate: dp9 ingress + test EtherType
  `0x88b6` -> CPU 192; CPU 192 ingress -> dp9; else drop). It **compiled clean on
  the first try** (bf-p4c 9.13.2, no constraint-class issues), `make install` OK.
- Snapshotted, then swapped the running `defense4_rrc_kernel` for `h0_cpu_path`
  (`swap_generic.sh`); brought dp9 up (25G RS-FEC, link UP to Vision).
- Ran a CPU echo shim on the switch (`ens1`) and a Vision-side driver on
  `enp59s0f0np0`.

## Result — one direction proven, one not

- **PUNT (data plane -> CPU) PROVEN.** Frames sent from Vision on dp9 with the
  test EtherType were steered to the CPU port and arrived on `ens1`: the switch
  echo shim received 55 frames (`echo_rx=55`). The `dp9 -> P4 -> 192 -> bf_kpkt
  -> ens1` path works on this silicon.
- **REINJECT (CPU -> data plane -> Vision) NOT working.** Frames written to
  `ens1` (which should ingress on port 192 and be forwarded by the P4 to dp9)
  did not reach Vision: the Vision driver received 0 echoes, and a direct
  switch-CPU injection with a Vision sniffer also showed `vision_rx_88b6=0`.

## Honest read

Half of the CPU path is proven on hardware (the pipeline can punt to the CPU and
the CPU sees the frames). The reinject half — the CPU injecting a frame back into
the data plane toward a front-panel port — is not delivering, and the exact cause
was not localized in this session. Candidate causes (not yet distinguished):

1. `bf_kpkt` kernel-mode TX may not present CPU-originated packets to P4 ingress
   with `ingress_port == 192` (so my rule falls through to `drop`); the CPU TX
   injection path / DMA-ring config may need a different handling than a plain
   raw-socket write on `ens1`.
2. A required CPU/TX metadata header on injected packets that the P4 must parse to
   set the egress port.
3. dp9 egress of CPU-originated frames (less likely; dp9 link is UP).

Localizing this needs another compile/load cycle (e.g. a dp9->dp9 loopback rule to
isolate dp9 egress, and a permissive "any CPU-ingress -> dp9" plus a port-counter
read to confirm the CPU-TX ingress port). The bfrt `port_stat` field names also
need resolving for a clean per-port TX/RX read.

## Go/no-go

**H0 is NOT yet a pass.** The bidirectional endpoint-transparent CPU path the
design requires is not proven. It is also NOT a clean negative — the punt half
works and the reinject failure is most likely a tractable CPU-TX-injection detail,
not a fundamental impossibility. Verdict: **H0 PARTIAL — resume with the reinject
localization above.**

## Switch state after

Restored: `swap_generic.sh` reloaded `defense4_rrc.conf` (`defense4_rrc_kernel`),
and dp8 (loopback, MAC_NEAR), dp9 (Vision, 25G RS), dp64 (relay, 1G) re-added and
UP — matching the pre-H0 snapshot. SEL-751 never contacted. Test processes killed.
Compiled `h0_cpu_path` remains installed in the SDE for the next debug cycle.
