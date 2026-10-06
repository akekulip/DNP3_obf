# Case 4 isolated BMv2 evidence

Run `run_lab.py` through its normal entry point. It creates a private
unprivileged user/network/mount namespace; all interfaces and endpoint
processes belong to that namespace. The endpoint programs are Python codec
emulators. The separate pinned OpenDNP3 endpoint gate is the production-stack
acceptance evidence; it is not executed by this lab.

The switch P4 performs the fixed control request expansion 35→55 bytes,
repairs DNP3 CRCs and TCP/IP checksums, maintains two insertion boundaries,
translates reverse ACK/window edges, and carves the echoed 57-byte response
into contiguous [28,29] TCP segments. The size Python modules validate
captured output as independent oracles; they do not transform packets on the
lab forwarding path. The legacy 49→[28,21] READ split is retained.

Mode 4 has a 30 ms absolute readiness timeout. A separate internal service
packet enters port 4 every requested 1 ms, independently of blocker tokens and
their pass budget. This 1 ms service deliberately differs from the Tofino
candidate's requested 100 us pulse. `artifact.heartbeat_observed` records
observed service count and maximum spacing; the configured period is not a
wall-clock guarantee. A normally released ACK anchors the full configured
response gap. Completion cleanup waits beyond that gap and allows a 2 ms
software drain interval. Actual wire timing comes from kernel-timestamped
pcaps; BMv2 is not physical-switch timing evidence.

Each transaction has its own `transaction_id`, `switch_ev_us` and
`release_outcome` in `result.json`. `switch_ev_us` at the top level is only the
final register snapshot. With `wait_fallback=true`, the emulator sends a late
response only after a watcher observes that transaction's own timeout slot.
This avoids mixing a final timeout with earlier normally released traffic.
Evidence slots are bounded to 32 transactions.

The insertion profile admits one SELECT/OPERATE pair per connection, one
complete 35-byte native control frame per initial request, no negotiated SACK,
window scaling or timestamps, and no IP/TCP options on admitted control data.
MSS-only SYN is allowed. The isolated decoy is index 201 with a 100 ms CROB
body; this fixture does not establish an inert physical point.

Two cached expanded images support whole, partial, resegmented and overlapping
retransmissions inside committed native spans, including an overlap crossing
the SELECT/OPERATE boundary and TCP sequence wrap. Partial retransmissions may
replay a larger cached image; duplicate prefixes retain identical stream
bytes. Tests also compare partial/cumulative ACKs and unscaled window right
edges with the transport oracle. FIN/RST translation records persist until a
new SYN after closure. Initial segmented controls, conflicting overlaps,
overlaps extending outside the committed cache, general byte-ledger recovery,
and old-epoch same-tuple FIN/RST rejection are not established. These gaps
block a general transport or joint physical-switch candidate claim.

`raw_profile` is a packet-fixture predicate/translation probe. If mode 4 is
selected for association predicates, its heartbeat is deliberately disabled
and `service_enabled=false` is reported. It does not prove timeout behavior;
the socket-based `step5` scenarios provide that evidence.

Validation:

```sh
python -m unittest discover -s defense4/timing/framework/tests -p test_case4_bmv2.py
python -m unittest discover -s defense4/timing/framework/tests -p test_bmv2_artifact.py
```

Historical modes 2/3 and D_A=0 remain explanation-only regression history.
No new Case 1/2 or mode-3 campaign is added. Retained canonical Case 4 evidence
belongs under `framework/results/case4_bmv2_20261006`; the historical
120-transaction software population remains unchanged.
