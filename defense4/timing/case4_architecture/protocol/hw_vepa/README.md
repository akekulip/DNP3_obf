# Software-endpoint runs through the switch (one port, two VEPA namespaces)

Runs a real OpenDNP3 master and outstation (`framework/size/endpoint_gate/SocketGatePad58B.cpp`) on Vision
through the Tofino, with both endpoints behind dev_port 9. First used for the padding evidence in
`../evidence/hw_vepa_padding_01` and `_02`.

| file | where it runs | what it does |
|---|---|---|
| `run.py` | workstation | one run end to end: slot rows, counters before, endpoints, counters after, copy, wire check |
| `vision_run.py` | Vision, `sudo python3` | namespace TCP profile, NIC flag, endpoints, direction-split captures |
| `switch_slot.py` | switch | clears and installs slot 0 (`vepa` tuple or the rig's `relay` slot) |
| `switch_counters.py` | switch | outcome counter, slot-0 mapper registers, dev 9/64 port counters (read-only) |
| `wire_check.py` | workstation, scapy | independent check of lengths, DNP3 CRCs, checksums, seq/ack translation |

```bash
python3 hw_vepa/run.py deploy
python3 hw_vepa/run.py setup          # clean TCP profile in the namespaces, disable-source-pruning on
python3 hw_vepa/run.py run NAME --master-port 54410 --reads 10 --out evidence/<dir>
python3 hw_vepa/run.py restore        # sysctls and NIC flag back, relay slot reinstalled
```

Facts the runner depends on:
- **Source pruning.** Vision's i40e NIC drops reflected frames whose source MAC is its own unless
  `disable-source-pruning` is on. Changing the flag resets the NIC's PF; the link returns in a few seconds.
  Original value: `off`.
- **One master port per run.** The switch matches the exact 4-tuple, and a tuple whose master just closed stays
  in TIME-WAIT for 60 s. `--master-port` pins the port through `ns_vepa_a`'s `ip_local_port_range` and installs
  the matching rows, so take the next port for the next run. The runner still waits if the port is busy.
- **Clean TCP profile.** The mapper arms only on a handshake without timestamps, SACK or window scaling. These
  are set inside the two namespaces only. Originals: 1/1/1 and port range `32768 60999`.
- **Fresh run directories.** A label is never reused. Capture files that already exist in a sticky directory
  under another owner are silently not rewritten on this kernel.
- **While the `vepa` slot is installed, the relay path is down:** dev 9 forwards to dev 9, so 192.168.10.1 cannot
  reach the SEL-751. `restore` puts the relay slot back.
- On Vision, `decps` has passwordless sudo only for python3, tcpdump and iptables, which is why everything
  privileged goes through `sudo python3`.
- Never stop the switch daemon with `pkill -f` over ssh: the pattern matches the remote shell itself.
