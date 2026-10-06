# BMv2 inserted-tail ACK repair, 2026-10-06

This evidence is separate from the earlier canonical Case 4 run. It retains a
regression that fails the earlier P4 source and packet captures from the repaired
source. The previous run's source, driver snapshots, 22-test results and 138-file
integrity manifest remain unchanged.

An ACK within an inserted tail must leave the last native byte unacknowledged.
For the first 35-byte native request expanded to 55 bytes, wire ACK offsets
35 through 54 now map to native offset 34. Wire offset 55 maps to native 35.
After the second insertion, wire offsets 90 through 109 map to native 69;
wire offset 110 maps to native 70. The window right edge uses the same map.
Zero wire windows remain zero; a window reaching the complete wire boundary
can advertise the remaining native byte.

The loss fixture injects partial-tail ACKs and a retransmission of that native
byte through the actual P4 switch, for bases 1000 and 0xfffffff0. BMv2 replays
its complete cached 55-byte image at the original wire sequence. After duplicate
prefix trimming, that image supplies the missing suffix and reconstructs the
CRC-valid frame. It does not emit a standalone 21-byte replay packet. These are
raw packet fixtures with an explicit receive/reassembly check; they do not prove
that a kernel TCP sender autonomously retransmits after downstream tail loss.
The separate SELECT/OPERATE test uses actual kernel sockets and Python codec
endpoints, with no injected tail loss. Neither test uses physical hardware or
the production OpenDNP3 gate.

`red.json` and `red.*.log` record the failing test and earlier source. `green.json`
records the initial focused checks before explicit zero-window fixtures were
added. `final.json` and `final.*.log` record one final combined suite after the
source, fixtures and independent transport oracle were finalized. Its retained
packet captures, compiled JSON, compiler command/log, input fixtures and source
snapshots are identified in the verification record. No timing tolerance was
changed. The new source's test outcomes must be read from that record rather
than transferred from the earlier source.

This repair remains bounded to the two cached images for one SELECT/OPERATE
pair. Initial segmented requests, conflicting or out-of-cache overlaps, general
connection recovery and old-epoch same-tuple FIN/RST rejection remain outside
the established coverage. The Tofino size kernel and compiler-only probes were
not modified by this lane.

The single final suite completed in 247.077 s: all 14 Case4 tests passed;
8 of 9 historical cases passed (22/23 total, zero skips). The sole failure
measured an ACK forwarding delay of 1.242183 ms against a strict bound below
1 ms. Its exact source-current packet captures remain in
`final_captures/legacy_response_focused_failure/`. No rerun or tolerance
change replaced that result. `final_captures/sbo_12/` contains the successful
source-current paired SELECT/OPERATE capture. `verification.json` records
the tail ACK/window positions, replay geometry, source and compiled hashes.
