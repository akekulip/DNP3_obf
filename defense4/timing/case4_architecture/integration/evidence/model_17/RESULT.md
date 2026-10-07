# model_17: summary of model_03 .. model_16 (local Tofino-1 model, SDE 9.13.1, p4c e558d01)

Tooling: `integration/core/launch_model.sh` (generic launcher; `-p <out dir> -o <new dir> -P "<dev ports>" -d <driver>`; ports.json maps
each dev port N to veth(2N)/(2N+1), including 64 and 68; kill-child pid namespace, hugepages return to 196 after every run),
`integration/core/model_driver.py` (ports, entries, registers, inject/capture, Report), `integration/core/frames.py` (independent builders),
drivers in `integration/core/cases/`. Functional model execution only: not hardware, not timing, not stage-fit.

Command pattern: `cd integration && DIRECTION=n ./core/launch_model.sh -p <program>/out -o evidence/<new> -P "<ports>" -d core/cases/<driver>.py`

## Programs (source sha256 / tofino.bin sha256)
| program | source | tofino.bin |
|---|---|---|
| validator_05 | 2788c885...6011 | 09891feb...c01c |
| handshake_14 (as retained) | 6cc2765c...7c14 | a090898e...c175 |
| handshake size-fix (model_05/compile, sequence_diff size 8 -> 16, nothing else) | 850fb021...cce3 | bc3eb86e...90dc3 |
| forward_03 | a64e2769...9f9d | 65090991...92f3 |
| reverse_12 | 9d847934...552 | 791fd916...e1a9 |
| egress_selected_wire_04 | 1cdf9ac6...2ac1 | 5612b8f5...7505 |
(full values in the manifests; recomputed with sha256sum of out/pipe/tofino.bin.)

## What each directory proved
* model_03: validator_05, 34/34 cases (valid req/resp, bad IP csum, bad TCP csum / 0xffeb rule, ttl 0, fragment, flags, urgent, every DNP3 CRC block,
  wrong tuple, wrong link dst/src, wrong port/profile/function/range). Counter deltas equal the independent oracle; original frame always forwarded identical.
* model_04: handshake_14 AS RETAINED DOES NOT LOAD: `Error Not enough space adding static entry 8 in dev 0 pipe ffff table Ingress.sequence_diff`,
  `bf_device_add failed(9)`. Cause: table size=8 with 9 const entries. Same defect in 11 other retained builds (handshake_07/09/10/14, native_03, native_02,
  stage_fit_analysis_01 exp_a/b/c; ownership protected_recirc_04/05/06 have owner.event size 2 with 3 entries). Scan: static_entries > size in context.json.
* model_05: compile of handshake with only sequence_diff size=16 (12 stages still); probe_01 shows recirculation via port 68 works (counter/owner/epoch/client/work registers move,
  SYN forwarded). hs_01..hs_04: 78 handshake cases against connection/reference.py Connection oracle (hs_04 is the final classification: 75 pass, 3 fail).
  hs_02/hs_03: single-scenario traces used to diagnose.
* model_06: mapping run that failed: model default port list has no veth for port 68, injection never arrived. model_07: failed: output route 69 is itself looped back (recirculated), nothing leaves.
* model_08: forward_03, 89/89 (70 sealed vectors replayed at port 68 with independent expected packets + 19 refusal cases: bad IP csum, version, IHL, proto, fragment, FIN, urgent, offset, epoch, zero generation,
  reserved, tuple, ethertype, route denied, bad geometry, wrong ingress port).
* model_09: reverse_12, 153/153 (134 vectors + 19 refusals). Together 204/204 sealed vectors.
* model_10: egress_selected_wire_04 loads with zero driver errors. model_11/model_13: composition runs with harness bugs fixed in turn (flag 0x18 vs the composed role's 0x10-only parser; Ethernet pad accounting).
* model_14: egress_selected_wire_04 composition 385/385: read role (16), forward and reverse pure-ACK mapping vs serial-arithmetic oracle (all positions, windows, valid 0/1/3, two bases),
  cache role native35->padded55 (SELECT, OPERATE), one-byte tail replay, refusals (bad IP/TCP csum, CRC, tuple).
* model_15: carving first run (JSON serialization bug, kept). model_16: carving role: refusals 7/7 PASS and the two split frames are byte-exact (28 + 29, seq, flags, lengths, checksums),
  BUT every split also emits a third stray frame (see defects).
* model_12: single-packet trace used to find the composed-role flag rule. model_02 is untouched.

## Defects / findings (model-observed, program-level)
1. Retained handshake_14 (and 11 other builds) cannot load: static entries exceed declared table size. Reproducer: model_04/switchd.out. Fix source size.
2. Handshake: a stray valid-looking SYNACK/ACK/SYN-with-ack!=0 at fresh state (right tuple, valid checksums) mints a work generation, claims WorkRecord and the packet exits the server port with the 16-byte
   private prefix still attached (`00000000 00000001 00000000 01ff0000` + original); work phase stays 1 (pinned forever; no recovery). Cause: the second-pass fallback deny (`tbl_deny_2`, stage!=0) executes in the model but
   does not drop (no Drop primitive logged), while other deny sites drop. Needs confirmation on the compiler/hardware side. Cases: hs_04 syn_ack_nonzero, synack_first, ack_first.
3. Handshake mints before validating: refused duplicates/out-of-order packets burn generation counter (counter ahead of oracle by one per refusal; 2^32 budget). State otherwise equals oracle (cell, epoch, client, server).
4. Handshake non-qualifying packets (bad checksums, bad flags, etc.) are forwarded untouched with no state change: matches the original-forwarding design; oracle states equal.
5. Carving split emits a third stray frame: route sets ucast_egress_port and split sets mcast_grp_a, so the TM also sends a unicast copy; egress parser dispatches on egress_rid (1/2 carving, default cache_state),
   so the rid-0 copy is parsed as a cache packet and leaves corrupted (12 bytes of MAC missing, bytes altered). Source: egress_selected_wire.p4 EgParser start. Needs the unicast copy suppressed or dropped by role.
6. Short-frame padding: the model pads <60-byte frames (54 -> 62); a program that lengthens a short frame (replay of a 55-byte input) leaves the padding as a zero trailer after the IP datagram. Recorded, harmless to IP receivers.

## Recirculation / private return (task 4)
Egress to port 68 with bypass_egress is recirculated natively by the model ("Tx Pkt to port 68 recirculated"): no veth needed for the internal loop; handshake runs 2-4 passes and ends with registers equal to the oracle
(happy path, FIN, RST, close variants all MATCH). `$PORT` entry for 68 is refused (not needed). To INJECT at port 68 map it with ports.json (launcher does). Ports 69 also loop back; use a front port as output.

## Target-model verified (exact program, exact command pattern above)
validator_05 (model_03), forward_03 (model_08), reverse_12 (model_09), egress_selected_wire_04 read/forward/reverse/cache roles (model_14) with the tables/frames listed; carving pair bytes (model_16);
handshake size-fix variant (850fb021...) multi-pass behaviour (hs_04). NOT verified: handshake_14 as retained (does not load); handshake with SELECT-bearing ACK (not in that P4); carving without the stray copy;
anything about timing, hardware stage placement beyond the compiler, PRE behaviour on silicon, ECMP of real traffic, the retained binaries' behaviour on a physical device; the size-fix variant is a changed program (not the retained binary).
