# Retained old-packet replay

`replay_old_packets.py` selects the software flow `192.168.10.61:<master-port>`
to `192.168.10.62:20000` from retained **c1** parent-NIC OUT/IN captures. It
preserves each selected Ethernet frame exactly, including the original endpoint
source/destination MACs, flags, sequence/ACK coordinates, payload, and checksums.
It never constructs a switch-private header or changes switch configuration.

The default is offline: print a JSON manifest without opening a raw socket.

```bash
python3 replay_old_packets.py /retained/c1/out.pcap /retained/c1/in.pcap \
  --master-port 31337 --dedupe --json old-packets.json
```

The manifest records SYN, SYNACK, READ request/response, pure ACK, FIN, and RST
counts; missing classes; SHA-256 and capture position for every selected frame;
old tuple/ISNs; MACs, flags, sequence/ACK, and payload lengths; and reasons for
excluded frames. A missing RST is reported and never invented. `--dedupe`
removes only byte-identical frames. Without it, captured retransmissions remain.
The capture must contain one unambiguous old SYN/SYNACK pair and a matching final
handshake ACK. Multiple old incarnations are refused.

Malformed/truncated captures, non-Ethernet captures, IPv4 fragments, private
EtherTypes, other flows, and invalid IP/TCP/DNP3 checksums cannot be replayed.
Kernel TX offload placeholders are reported and skipped, without checksum repair.
Consequently, a native OUT response may be absent while its checksum-valid,
padded IN reflection is selected. `payload_bytes: 58` does **not** establish an
old native 49-byte response rejection test. Inspect packet classes and lengths
before deciding what hardware coverage this replay can provide.

The root operator owns the ASIC test. After a fresh same-tuple handshake, pause
new endpoint READ traffic with `CASE4_READ_PAUSE_MS=5000`, retain a complete,
checksum-valid fresh IN handshake capture, and snapshot N/E/T before replay.
The fresh capture must contain SYN, SYNACK, and the final ACK. Both declared new
ISNs must match that capture and lie outside the old observed sequence ranges.
Only the existing Vision parent interface `enp59s0f0np0`, connected to external
switch dev 9, is accepted. Namespace and switch loop interfaces are refused.

```bash
sudo env DEFENSE4_HW_AUTHORIZED=1 python3 replay_old_packets.py \
  /retained/c1/out.pcap /retained/c1/in.pcap --master-port 31337 --dedupe \
  --apply --interface enp59s0f0np0 --new-pcap /fresh/in.pcap \
  --new-client-isn 900000 --new-server-isn 800000 --json replay.json
```

Use measured ISNs and the actual installed c1 master port, not these example
values. Deploy `wire_check.py` beside the helper on Vision if the repository
layout is unavailable. The helper verifies raw captured bytes itself; it does not
accept an external manifest as authorization or packet-validation evidence.

After replay, the root operator snapshots N/E/T again, verifies old frames did
not change the new incarnation, resumes READs, and checks application/wire
completion. A mock send test or successful `send()` return supplies no ASIC
rejection claim; receiver captures and state/application evidence are required.

Offline verification:

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/tests -v
```
