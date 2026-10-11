# Active padding through the ASIC with software endpoints (2026-10-11)

**Result.** The switch pads DNP3 responses to one 58-byte image on a live TCP connection between a real
OpenDNP3 master and outstation. READ responses go 49 -> 58 bytes and SELECT/OPERATE responses 37 -> 58
bytes, requests pass unchanged, and the switch translates sequence and acknowledgment numbers so both TCP
stacks stay consistent. No software proxy is involved. This is size only: no timing mechanism is in this
program.

## What ran

- **Switch program:** `case4_response_path` (padding plus transport mapper, all in egress), launched
  2026-10-11 00:52:09 switch time from `/home/decps/Philip_repo/logs/bringup_20261005/case4_response_path_conf.json`
  (pipe_scope [0,1,2,3], one broadcast pipeline). Hashes of what the conf names are in
  `state/switch_state_20261011.txt`: `bfrt.json` c7b61f6e..., `pipe/tofino.bin` cb8b5ff4...
  - The `bfrt.json` hash equals the repo build `evidence/transport_mapper_02/fused_12/out/bfrt.json`.
  - The source recorded by both build manifests (`fused_12`, `response_path_9132_01`) is sha256 d10e67d2...,
    which is the current `protocol/case4_response_path.p4`.
  - **Gap:** the loaded `tofino.bin` is not `fused_12`'s (8196b7d3...), and `response_path_9132_01/manifest.json`
    records no artifact hash, so the loaded binary is tied to its source by the bfrt.json and the bring-up
    notes, not by a tofino.bin hash in the repo.
- **Endpoints:** `SocketGatePad58B` built from commit f3ab78b3a (binary sha256 1a0af013..., libopendnp3.so
  79e1f695...), on Vision in two network namespaces on one NIC:
  master `ns_vepa_a` / `mvA` 192.168.10.61, outstation `ns_vepa_b` / `mvB` 192.168.10.62:20000, both macvlan
  VEPA on `enp59s0f0np0` (dev_port 9). The outstation serves 23 Binary Output Status points and uses the
  production command handler. Link addresses: outstation 10, master 1.
- **TCP profile, set per namespace only:** timestamps, SACK and window scaling off (the profile the mapper
  arms on). The master's source port is pinned by `ip_local_port_range = 54400 54400` in `ns_vepa_a`.
- **NIC:** `disable-source-pruning on` on `enp59s0f0np0` for the runs (see `integration/evidence/
  vepa_reflect_01/hw_ab_20261011/STATUS.md` for why).
- **Switch rows** (`tools/pad_slot.py vepa install`, slot 0): `Egress.conn` forward and reverse for
  .62:20000 <-> .61:54400, `Egress.odd_ip_t` both ways, and one `Ingress.forwarding` 9 -> 9. Direction comes
  from the 4-tuple, not from the port. The relay's slot (.1:54321 <-> .7:20000, 9 <-> 64) was removed for
  the runs and must be reinstalled afterward.
- **Capture:** tcpdump on the parent NIC, split by direction. `*_out.pcap` (`-Q out`) is what the endpoints
  sent, before the switch. `*_in.pcap` (`-Q in`) is what the switch returned.

## Runs

| run | workload | endpoint result | switch | wire (`*.wire.json`) |
|---|---|---|---|---|
| `persist10` | 10 READs then one SELECT/OPERATE, one connection | 10/10 READs match the seeded points; SBO success; outstation saw 1 real SELECT, 1 real OPERATE, 0 decoy | ARM_MAP +1, COMMIT +12, growth 132 B = 10x9 + 2x21, unacknowledged 0 | 12 responses, all 58 B, DNP3 CRCs valid; 17/17 master-to-outstation frames returned byte-identical; 0 IP/TCP checksum errors on returned frames; response seq shifted 0..132, master ACKs translated back |
| `sustained300` | 300 READs then one SELECT/OPERATE, a second connection on the same tuple | 300/300 match; SBO success; 1 real SELECT, 1 real OPERATE, 0 decoy | ARM_MAP +1 (re-armed), COMMIT +302, growth 2,742 B = 300x9 + 42, unacknowledged 0 | 302 responses (300 from 49 B, 2 from 37 B), all 58 B, CRCs valid; 307/307 frames byte-identical the other way; 0 checksum errors; seq shift reaches 2,742 |

Growth is `acct.lo - front` for slot 0. Counter codes: 1 COMMIT, 2 TRANSLATE, 9 REV_TRANSLATE, 12 NATIVE,
13 ARM_MAP (`case4_response_path.p4:25-33`). Reflection latency through the switch, measured between the
two captures on one NIC clock: 22 to 122 us, median 35 to 40 us.

Notes on reading the files:
- `checksum_bad_sent` equals the frame count in every run. Sent frames are captured before the NIC fills in
  TCP checksums (transmit offload), so that field says nothing about the endpoints.
- `*.run.json` endpoint results and counter snapshots for these two runs were transcribed from the session's
  command output, because the first version of the runner printed them instead of saving them.

## Open at the time of this record

- **Policy-off control (`enable=0`).** Ran once: the endpoint succeeded, COMMIT stayed at 314, growth
  0 (`front == acct.lo`), TRANSLATE and REV_TRANSLATE kept counting. Both captures came back empty, so the
  native 49/37-byte lengths on the wire are not shown yet. The capture files of that label already existed in
  `/tmp`, owned by the tcpdump user, from an attempt that failed before sending anything (the pinned source
  port was still in TIME-WAIT); they were not rewritten.
- **Forwarding-off control.** Not run yet.
- Both follow in `hw_vepa_padding_02/` with a runner that takes the master port as an argument and writes each
  run into its own directory.

## Files

`captures/` (four pcaps, `SHA256SUMS`), `tools/` (`pad_run.py` Vision side, `pad_slot.py` / `pad_ctl.py` /
`pad_counters.py` switch side, `pad_wire.py` independent analyzer using scapy and its own DNP3 CRC),
`*.run.json`, `*.wire.json`, `state/` (switch and Vision configuration read at 01:10 UTC, after the
policy-off attempt, hence `enable: 0`).
