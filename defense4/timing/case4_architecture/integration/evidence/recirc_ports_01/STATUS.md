# Which internal ports recirculate on this Tofino-1, measured (2026-10-11)

**Result.** Each pipe has exactly one recirculating internal port: dev_port 68 in pipe 0 and 196 in pipe 1.
Dev_ports 69, 70, 71, 197, 198 and 199 have `$PORT` entries (`recirc`, enabled, valid) but frames sent to them
never re-enter the pipeline, and a `$LOOPBACK_MODE` write on them does not take. An earlier note in
WORKING_NOTES concluded from the entries alone that all eight were usable; that was never tested with traffic
and is wrong. The local model loops any port, so no model run could show this.

**How it surfaced.** The response-only composite (N + E in pipe 0, T in pipe 1; build
`route_ab_01/shared_port_01/shared_compile_switch_9132`) loaded and was installed on the switch (31 writes read
back, packet generator enabled). The first connection then failed: dev 9 received the master's 5 SYNs and
transmitted nothing, N's counter and every T outcome stayed 0, and E counted 9 packets with no mapped outcome.
N sends master TCP on a lap through dev 70 (`N_ACK_RETURN`), and nothing sent there comes back.

**Test.** Program `xpipe_reflect_probe`; `recirc_probe.py set P` installs `fwd[9] -> P` and `fwd[P] -> 9`, so a
frame from Vision returns only if P loops. One 60-byte 0x88b5 frame per port from `ns_vepa_a`, listener on `mvB`
(`ab_vision.py`, captures `ab_RC<P>.pcap` / `ab_LB<P>.pcap`):

| dev_port | kind | frame returned |
|---|---|---|
| 68, 196 | pipe-local recirculation port | yes |
| 69, 70, 71, 197, 198, 199 | other `recirc` entries | no |
| 70 after `$LOOPBACK_MODE = BF_LPBK_MAC_NEAR` | write read back as `BF_LPBK_NONE` | no |
| 48 (pipe 0), 180, 181, 182 (pipe 1) after `BF_LPBK_MAC_NEAR` | front-panel 25G, empty cage, link was down | yes; `$PORT_UP` becomes True |

Free ports on this switch (enabled, link down, media UNKNOWN = empty cage): 16, 48-51 in pipe 0; 164, 172,
180-183, 188-191 in pipe 1. In use: 9 (Vision), 10, 11, 64 (SEL-751); 8 is cabled (copper) but down.

**Consequence.** The composite must take its extra looping ports from front-panel ports in MAC loopback, as the
earlier silicon work in this repository did with dev 8 and 10: `N_ACK_RETURN` 70 -> 48, `T_IN` 197 -> 180,
`HB_RETURN` 198 -> 181, `HELD_RETURN` 199 -> 182. `RETURN_PORT` 68 and the generator port 196 stay. Loopback is
volatile: a cold restart clears it, so bring-up has to set and read it back.

**Also learned on first contact with the installer (all fixed and committed):**
- `tf1.pktgen.port_cfg` and `tf1.pktgen.pkt_buffer` have no hardware read on SDE 9.13.2; software-state reads work.
- Action parameters the P4 never reads are not stored and read 0: T's `set_params(cap)` and the five
  `configure()` fields of N's `data_connection`.
- Strict-priority writes on pipe-1 queues, the mirror session, the generator apps (written, verified, enabled)
  and the teardown (read back 31 of 32; the two generator apps cannot be put back to their default one-shot
  trigger and are left disabled) all worked against the real driver.
