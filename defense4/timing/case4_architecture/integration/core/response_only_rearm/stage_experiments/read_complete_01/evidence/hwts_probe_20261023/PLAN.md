# NIC hardware-timestamp probe (2026-10-23), written before running

**Question.** The intermittent ~1-2 ms Vision -> switch -> Vision transit delay (c25, c26 and the m11_09 controls;
`../timing_reanalysis_20261022/`): is it incurred between the two NIC hardware timestamps (wire + switch), or in the
host (before the NIC's transmit timestamp / after its receive timestamp)?

**Capability (read-only check, 2026-10-23).** `ethtool -T enp59s0f0np0`: hardware-transmit, hardware-receive,
hardware-raw-clock, PTP hardware clock 2 (i40e); receive filters are PTP-only (no "all"); tcpdump offers only host
timestamps. So DNP3 TCP cannot be hardware-stamped; PTPv2-format UDP event messages (port 319) can, on transmit and
receive.

**Clock alignment.** Sender (master namespace ns_vepa_a, mvA, 192.168.10.61) and receiver (outstation namespace
ns_vepa_b, mvB, 192.168.10.62) are macvlans of the same parent NIC: both hardware timestamps come from one PHC, and both
software timestamps from one system clock. Reported quantities are differences within one clock only:
- nic_us = hw_rx - hw_tx (NIC transmit to NIC receive: wire + switch)
- host_us = sw_rx - sw_tx (application send to application receive)
- host_overhead_us = host_us - nic_us (host transmit + host receive paths)
No cross-clock difference is used.

**Held constant.** Production switch program loaded (no candidate), restored testbed (ownership clear), current host
settings (no other diagnostic), same path as the DNP3 flow (mvA -> port 9 -> switch -> port 9 -> mvB).

**Runs (bounded).** 200 probes: 100 isolated (>= 200 ms after the previous receive) and 100 sent ~30 us after the
previous probe's receive. Stop at 200, or at once if hardware timestamps cannot be enabled or are absent on either side.

**Discriminating observation.** If the >= 0.25 ms mode appears in nic_us, the delay is between the NIC ports (wire or
switch); if nic_us stays tens of microseconds while host_us shows it, the delay is in the Vision host stack.

**Setting change and restore.** The only change: SIOCSHWTSTAMP on enp59s0f0np0 (tx_type ON, rx_filter PTPV2_L4_EVENT).
The original config is read (SIOCGHWTSTAMP) and saved first, restored at the end (also on error), and read back; the
script exits nonzero if the read-back differs. The testbed lock (active.lock) is held for the whole run.
