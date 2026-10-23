# Result (2026-10-23): no meaningful hardware-timestamp measurement of the DNP3 path is possible as configured

Run 01 (result_01.json; script sha256 6a6986ab..., testbed lock held, ownership clear, production program loaded):
- NIC config before: tx_type 0, rx_filter 0. Enabled: tx_type 1, rx_filter 12 (the driver widened PTP_V2_L4_EVENT
  to PTP_V2_EVENT). Restored and read back: tx_type 0, rx_filter 0 (restore_ok true; also read back separately).
- Hardware TX timestamps: 200/200. Received: 0/200 -- every probe (UDP 319, mvA .61 -> mvB .62) was dropped.

Why no variant of this probe can measure the path:
- The NIC hardware-stamps received packets only for PTP (no "all" receive filter; tcpdump offers host stamps only).
- The production program (case4_response_path) does not forward the Vision namespace hairpin (.61 <-> .62); its
  health path is Vision .1 -> relay .7, and the relay returns no PTP packet.
- With a candidate loaded, N admits only parsed TCP/DNP3 (table `network`, response_only.p4:218; default NoAction;
  forwarding default deny at :713), so UDP probes are dropped there too.
A meaningful hardware-stamped measurement therefore needs either a probe pass-through in the P4 (a candidate change)
or a NIC with an all-packet receive filter. Neither was done. The next escalation in the directive (kernel A/B/A
reboot) still needs Philip's separate authorization; not executed.
