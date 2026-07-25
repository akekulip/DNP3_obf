# Example PCAPs

Two real captures from the timing deliverable, provided so the tutorial's Wireshark and analysis
steps can be followed without access to the switch. Both are **real replayed DNP3 frames** captured
from the physical SEL-751 relay's traffic (evidence level: real replayed DNP3 — not synthetic markers,
not a live inline session). Outstation (relay) = 192.168.10.7, master = 192.168.10.1, DNP3 TCP port
20000. (`protected_demo.pcap` is response-direction only — every frame is outstation → master.)

| file | contents | packets | SHA-256 |
|---|---|---:|---|
| `native_demo.pcap` | native timing (mechanism OFF): ACK→RESPONSE interval varies per transaction | 486 | `106315fb81cacd734443df0fdcbbcc95a0574757416014bca0b54f5b6e3de1c1` |
| `protected_demo.pcap` | protected timing (mechanism ON, G = 25 ms): every ACK→RESPONSE interval normalized to 25 ms | 200 | `c64836cde8d1a1cdf6f2b6249894581f70802add33822f3a51cdbacbaa3e3bb2` |

Source commit: `acbb778`. These are copies of `research/timing_final/evidence/native/native120.pcap`
and `research/timing_final/evidence/protected/final100_g25.pcap`.

## Quick look

```bash
# all DNP3-carrying TCP:
tshark -r native_demo.pcap -Y "tcp.port==20000" | head
# DNP3 responses only (function code 129):
tshark -r protected_demo.pcap -Y "dnp3.al.func==129"
# confirm NO blocker tokens leaked onto the wire (EtherType 0x88c1):
tshark -r protected_demo.pcap -Y "eth.type==0x88c1"   # expect: no output
```

See ../WIRESHARK_GUIDE.md for the full walkthrough and ../CODE_WALKTHROUGH.md §15 for how the analyzer
pairs transactions and rejects ambiguous pairings.
