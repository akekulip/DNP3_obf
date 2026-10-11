# hw_range_read_01 — real-relay ScanRange(G10V2,0,22) evidence, and the .1-vs-.50 controlled comparison

## The request

Byte-for-byte identical in every test below: `05640dc400000100f387c0c0010a020000165a2c`
(link dest=0/outstation, source=1/master; transport+application ScanRange(G10V2,0,22)).
CRC-valid, confirmed against the repository's own `rrc.dnp3_crc()` (polynomial `0xA6BC`) before
any of these tests — an earlier attempt used a hand-rolled CRC with the wrong polynomial (`0x3D65`)
and produced a different, invalid frame; this was caught and fixed before drawing any conclusion
from it.

## Result from Vision's real native IP (192.168.10.1), 2026-10-10

`native_ip_retest_20261010.pcap` — a complete, normal exchange, captured with `tcpdump` on
`enp59s0f0np0` (the real test-facing interface, no namespace involved):

1. SYN (full options: mss 1460, sackOK, TS, wscale 7) → SYN-ACK (mss, wscale 0, sackOK, TS) → ACK.
2. 20-byte request sent, ACKed by the relay.
3. **49-byte response received** ~25ms later (normal processing delay) — the padding-eligible
   native shape the mechanism targets.
4. Response ACKed by the client.
5. ~6s later, an orderly close: client FIN → relay ACK → relay FIN → client ACK. No RST anywhere.

This is a fresh, directly-observed result, not a recollection — the earlier claim that this exact
byte vector produces a 49-byte response from .1 existed only as a recalled note with no saved
artifact; this capture closes that gap.

## Result from the test namespace's macvlan IP (192.168.10.50), earlier tonight

Two runs (`padtest_handshake2.pcap`/`padtest_handshake3.pcap`, referenced in `WORKING_NOTES.md`),
single-variable controlled test — same IP, same port (54322), same request, only the TCP options
profile toggled:

- Namespace sysctls disabled (no timestamps/SACK/wscale): SYN offers only `[mss 1460]`; relay's
  SYN-ACK echoes only `[mss 1460]`; relay ACKs the 20-byte request; **RST 4.7ms later.**
- Namespace sysctls restored to default (full options, matching the normal profile exactly): SYN
  offers `[mss,sackOK,TS,wscale]`; relay's SYN-ACK echoes the same; relay ACKs the identical
  request; **RST 4.8ms later.**

Switch-side register readback after both runs confirmed the switch itself (not yet carrying any
VEPA/reflection logic, the then-standalone `case4_response_path.p4`) behaved correctly in both
cases (armed on the MSS-only shape, fell back to native on the full-option shape) — ruling out
switch-side mishandling as the cause.

## Conclusion

With the request, the relay, and (in the second .50 run) even the full TCP options profile held
identical, the only remaining variable between a clean 49-byte response with an orderly close and
an immediate post-ACK reset is the source IP (192.168.10.1 vs 192.168.10.50). This is a controlled,
fresh, directly-observed comparison, not an inference from memory. It does not, on its own,
identify the relay's exact mechanism (an allowed-master-IP list is the most natural explanation for
a TCP-layer-complete, application-layer-rejected exchange, but no direct visibility into the
relay's own configuration or logs exists to confirm the specific mechanism) — that distinction is
preserved deliberately rather than overclaimed.
