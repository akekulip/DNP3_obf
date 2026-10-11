# Controls for active padding through the ASIC (2026-10-11)

Same setup as `../hw_vepa_padding_01/STATUS.md` (program `case4_response_path`, software OpenDNP3 endpoints in
two VEPA namespaces on dev_port 9, clean TCP profile, `disable-source-pruning on`). Driven by `../../hw_vepa/run.py`,
one new master source port per run. Each run directory holds `out.pcap` (as sent), `in.pcap` (as returned by the
switch), `master.json`, `outstation.json`, `state.txt` (NIC flag and namespace sysctls at the start of the run),
`switch.json` (slot rows read back from hardware, counters and registers before and after), `wire.json`
(`wire_check.py`) and `summary.json`.

| run | switch setting | endpoint | switch deltas | wire |
|---|---|---|---|---|
| `policy_off_10b` (port 54402) | slot installed with `enable=0`: **padding policy off, transport mapping still active** | 10/10 READs match seed, SBO success, 1 real SELECT, 1 real OPERATE, 0 decoy | COMMIT +0, growth 0, unacknowledged 0, ARM_MAP +1, TRANSLATE +14, REV_TRANSLATE +16, dev 9 rx +32 / tx +32 | master received the native 49-byte READ and 37-byte SELECT/OPERATE responses, CRCs valid, 0 checksum errors; all 15 outstation-to-master and all 17 master-to-outstation frames byte-identical; seq and ack shift 0 |
| `forwarding_off` (port 54403) | same slot rows, `Ingress.forwarding` empty | master could not connect (rc 2 after 5 s), outstation `opens` 0 | dev 9 rx +5, **tx +0**; every outcome and register unchanged | 5 SYNs sent, 0 frames returned |
| `recovery_on_10` (port 54404) | forwarding 9 -> 9 reinstalled and read back, `enable=1` | 10/10, SBO success, 1 real SELECT, 1 real OPERATE, 0 decoy | COMMIT +12, ARM_MAP +1, growth 132 B, unacknowledged 0, rx +32 / tx +32 | 12 responses at 58 B, CRCs valid, 0 checksum errors, 17/17 frames byte-identical the other way |

What the controls show:
- The 58-byte image comes from the switch's per-connection policy: with the policy off on the same rows, the
  same endpoints exchange native lengths and the mapper adds nothing.
- The traffic between the two namespaces crosses the ASIC: without the forwarding row the switch receives the
  SYNs and transmits nothing, and the peer never sees a connection.

Forwarding-off is a port-level control, not a per-flow one: this program's ingress forwards by port only, so the
row it removes carries everything arriving on dev 9.

An earlier attempt, `policy_off_10` on port 54401, ran on Vision but its switch snapshots were lost to a copy
error in the driver, so it is not part of this record. Its run directory is still on Vision under
`/home/decps/pad58b_20261011/runs/`.
