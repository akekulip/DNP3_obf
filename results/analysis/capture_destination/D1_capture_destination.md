# D1: relay-side capture destination (read-only inspection, 2026-10-28)

Question: is there a tap, a SPAN, or a usable mirror destination for observing the relay leg (switch dev 64 ↔
SEL-751)? Today every capture is taken at the master NIC. Every step below read state only. Nothing was written to
the switch or to Vision, and no traffic was sent.

**Recorded state.** The production pre-run port snapshot (`results/hardware/blocks/*_prerun.json`, program
`case4_response_path`) has link up on three ports:

| Dev port | Name | Speed | Peer |
|---|---|---|---|
| 9 | 15/1 | 25G | Vision master interface |
| 10 | 15/2 | 25G | not recorded |
| 64 | 33/0 | 1G | SEL-751 relay |

- Ports 8 (15/0) and 11 (15/3), on the same 4×25G copper breakout as 9 and 10, are down.
- `build_ports.py` lists `NEVER_LOOP = (9, 10, 11, 64)`, but does not say what 10 and 11 connect to.
- `$mirror.cfg` is empty.

**Live state.** All of it was read-only:
- **Switch:** `live_snapshot.py` against the running production program (`entry_get` only) found the same port
  states. Frame counters since `bf_switchd` started at 07:05:25 UTC:
  - dev 10: received 1,126, transmitted 0;
  - dev 9: received 1,189, transmitted 5,706;
  - dev 64: received 5,711, transmitted 1,159;
  - dev 8 and dev 11: 0.
- **Vision:** two 25G Direct Attach Copper ports, both with link, auto-negotiation off, on the same i40e NIC
  (0000:3b:00.0 and .1):
  - `enp59s0f0np0` is the master interface (10.0.1.1, 192.168.10.1);
  - `enp59s0f1np1` has no address, and its kernel counters show 0 received and 0 transmitted packets since boot
    (2026-10-19).
  - Firmware LLDP is enabled on both ports (`disable-fw-lldp: off`). The i40e firmware sends LLDP every 30 s, and
    those frames are not counted by the kernel.
- **LLDP cadence:** the 33,605 s between the `bf_switchd` start and the snapshot predict about 1,120 LLDP frames
  at a 30 s interval. dev 10 received 1,126.
- **Capture rights:** `decps` may run `tcpdump` under sudo without a password (sudoers NOPASSWD), as the existing
  harness does on the master interface.

**Conclusion.**
- No tap and no SPAN device was found on the relay leg. Dev 64 links directly to the relay at 1G. Only Philip can
  rule out physical hardware that the switch and hosts cannot see.
- Dev 10 is very likely cabled to Vision `enp59s0f1np1`. The evidence:
  - it is the only other live lane on the breakout whose lane 9 is Vision's master port;
  - speed, media and auto-negotiation match;
  - its receive count matches Vision's firmware LLDP cadence;
  - Vision's port is otherwise idle;
  - the switch never transmits on dev 10.
- That makes dev 10 a candidate mirror destination that needs no physical change. It is an inference, not a proof.
  It is confirmed or refuted by the first step of D3: mirrored frames must appear on `enp59s0f1np1`, and nowhere
  else.
- Both Vision ports share one host and one kernel clock, which helps compare mirror timestamps with master-NIC
  timestamps. Different ports and capture paths still have to be characterised in D3.
- No physical connection change is required at this point.

Next (plan Phase D2, after A/B/C): a separately named diagnostic mirror build (`c72_diag_mirror`). It mirrors
requests leaving toward dev 64 and responses arriving from dev 64, before transformation, to a dedicated session
on dev 10. c72 and its evidence stay untouched.

**Raw evidence on disk** (`raw/`, collected read-only at 17:59 UTC, after the first inspection):
- `switch_port_tables.txt`: the `$PORT`, `$PORT_STAT` and `$mirror.cfg` tables of the live production program, plus
  the `bf_switchd` start time.
- `vision_interfaces.txt`: Vision's interfaces, link settings, NIC driver and LLDP flags, kernel packet counters
  and sudo rules.

The cadence check repeats on this snapshot. 39,241 s after the `bf_switchd` start, a 30 s LLDP interval predicts
about 1,308 frames; dev 10 had received 1,315 and transmitted 0. Vision `enp59s0f1np1` still shows 0 received and
0 transmitted kernel packets.
