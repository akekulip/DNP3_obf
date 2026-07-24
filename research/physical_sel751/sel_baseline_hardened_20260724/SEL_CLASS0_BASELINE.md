# Read-only SEL-751 Class-0 baseline — 2026-07-24 (post-GATE-1)

Bounded, read-only Class-0 integrity poll from Vision to the physical SEL-751, run after Phase-1 GATE-1
completed. Confirms the relay path and a clean read-only DNP3 exchange. No writes/controls.

## Configuration
- Source (master): Vision `192.168.10.1` (eno1), DNP3 master addr 1.
- Destination: SEL-751 `192.168.10.7:20000`, outstation addr 0.
- Probe: `native_class0_probe.py` — one `ScanClasses(CLASS_0)`, all automatic behaviours pinned OFF
  (empty startupIntegrityClassMask, empty unsolClassMask, disableUnsolOnStartup=False, ignoreRestartIIN=True,
  timeSyncMode=None), no-retry, one TCP session. Bounded 60 s.
- Switch on `queue_microbench_abs.conf` (SEL is on the ordinary lab switch, NOT the Tofino).

## Result — SUCCESS
- **DECODED points = 69** (Group 30 Var 4 analog inputs) — a full Class-0 integrity response from the relay.
- Clean session: `OnTaskComplete` → `OnReceiveIIN` → channel CLOSED → SHUTDOWN, no retry, no reconnect.
- Master-side capture on eno1 (`sel_class0.pcap`): SYN → ACK → **DNP3 READ func 0x01 (plen 18)** → ACK.
  (Capture recorded the master direction; the outstation responses were decoded by the probe — 69 points.)
- No SELECT/OPERATE/DIRECT-OPERATE/CROB/output/restart/time-write/config-write issued; no SEL config changed.

## Interpretation
The physical SEL-751 answers a read-only Class-0 poll from the configured master `192.168.10.1` and returns
its analog inventory (69 points), consistent with the earlier 300-poll baseline
(`clrt_300poll_20260723T152242`, which holds the detailed CLRT/IIN/timing distribution). This baseline
re-confirms relay connectivity + read-only exchange after the GATE-1 topology/parser work; it is not a new
timing characterization.

Evidence: `sel_class0.pcap` (master-side), probe stdout (69 points, clean close).
