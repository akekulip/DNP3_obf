# VEPA same-port reflection on hardware: source-pruning A/B (2026-10-11)

**Result.** The switch reflects frames back out the port they arrived on, and they reach the wire.
Vision's i40e NIC then drops any reflected frame whose source MAC is one of its own addresses
(source pruning). With pruning disabled on that NIC, two macvlan namespaces on one physical port
exchange frames and IP traffic through the ASIC, and deleting one switch row stops that traffic.
This replaces the "wire/PHY" explanation recorded on 2026-10-10, which was wrong: the earlier run read
only the P4 registers and never looked at the port's MAC counters or the NIC's port-level counters.

## Setup

- Switch: `xpipe_reflect_probe` (`core/xpipe/xpipe_reflect_probe.p4`, single pipeline, conf
  `xpipe_reflect_probe_v2_conf.json`, pipe_scope [0,1]) loaded from the `case4_response_path`
  baseline. Pre-swap snapshot `/tmp/pre_ab_reflect_snapshot_20261010.json` on the switch (403 tables).
  `fwd_mac` rows: (dev 9, dst mvA) and (dev 9, dst mvB), both `go_reflect(port 9)`.
- Vision: test NIC `enp59s0f0np0` (i40e, 25G, dev_port 9). Macvlans in VEPA mode:
  `mvA` d2:9d:1d:1c:f4:dd 192.168.10.61 in `ns_vepa_a`, `mvB` ee:df:16:18:b0:a5 192.168.10.62 in
  `ns_vepa_b`.
- Each case: `sudo python3 ab_vision.py CASE SRC_MAC TAG` sends one 60-byte 0x88b5 frame from `mvA`
  to mvB's MAC, listens on `mvB`, runs tcpdump on the parent (`ab_<CASE>.pcap`) and diffs
  `ethtool -S`. Switch counters come from `ab_counters.py` (`$PORT_STAT` dev 9, read `from_hw`).
- The `A` and `B` runs used a listener that compared the wrong bytes (16:20 instead of 18:22), so
  their `listener: TIMEOUT` lines mean nothing. The conclusions below rest on counters and the pcaps.
  `B2` onward used the corrected listener.

## Observations

| case | source MAC | pruning | switch dev 9 TX | Vision port-level rx | Vision driver rx | parent pcap | mvB |
|---|---|---|---|---|---|---|---|
| A | mvA (own) | on (default) | 0 -> 1 | `port.rx_unicast` +1, `port.rx_bytes` +64 | 0 | send only | not received |
| B / B2 | 02:00:00:00:00:5a | on | 1 -> 2 | +1 | `rx_packets` +1 | send + reflection ~110 us later | received (B2) |
| A2 | mvA (own) | **off** (`disable-source-pruning on`) | 3 -> 4 | +1 | +1 | send + reflection | received |

Negative control, with pruning disabled:

| step | frame to mvB | `ping -c5` .61 -> .62 in namespaces | switch dev 9 TX |
|---|---|---|---|
| both rows | — | 5/5 | 14 |
| mvB row deleted (`ab_row.py del`) | not received (`ab_NEG`) | none received | 14 (flat) |
| mvB row reinstalled | received (`ab_POS`) | 5/5 | 25 (+11: 1 frame, 5 requests, 5 replies) |

With the flag set back to `off`, an own-source frame was again not delivered (`ab_OFFCHK`).

## NIC flag (Philip authorized it on the test NIC only, if the A/B confirmed pruning)

- apply: `sudo ethtool --set-priv-flags enp59s0f0np0 disable-source-pruning on`
- restore: `sudo ethtool --set-priv-flags enp59s0f0np0 disable-source-pruning off`
- Each change triggers an i40e PF reset; the link came back at 25G both times with 10.0.1.1 and
  192.168.10.1 intact. Management traffic runs over eno1 and was not touched.
- State at the end: `off` (the original value), confirmed with `ethtool --show-priv-flags`.

## Restoration

`case4_response_path` relaunched with its own script, `bf_switchd: initialized 1 devices`, ports
restored from the snapshot (dp9 25G up, dp64 1G up), slot 0 reinstalled (6 rows, read back),
`ping -I 192.168.10.1 192.168.10.7` 3/3.

## Consequence

The software-endpoint padding path can use one physical port: run the outstation and master in two
VEPA namespaces on `enp59s0f0np0`, set `disable-source-pruning on` for the run, and set it back
`off` afterward. A second port is not required. The composite's forwarding still has to tell the two
endpoints apart by tuple instead of by ingress port (plan step 6).

## Files

`ab_vision.py` (Vision side), `ab_counters.py` and `ab_row.py` (switch side, bfrt_grpc), `swap.sh`
(program swap by PID), and `ab_*.pcap` (parent-NIC captures per case).
