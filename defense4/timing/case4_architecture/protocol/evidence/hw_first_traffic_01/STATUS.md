# First real hardware traffic through case4_response_path.p4 (2026-10-09)

The first physical-hardware run of tonight's combined size+transport mechanism. A real DNP3 Class 0
READ request was sent from Vision (the real DNP3 master host) through the physical Tofino-1 switch,
now running `case4_response_path.p4` in place of the baseline, to the real SEL-751A outstation at
192.168.10.7:20000, and a real, valid response came back.

## What this establishes

- The program loads and runs correctly on real silicon with real physical links.
- The control-plane connection/forwarding registry (`response_path_cp.py`'s `Registry`) correctly
  installs a real TCP 4-tuple's worth of table entries (`Egress.conn` forward+reverse,
  `Egress.odd_ip_t` both directions, `Ingress.forwarding` both directions) via real BFRT writes.
- A real, unmodified TCP handshake and DNP3 application-layer exchange completes end to end through
  the new program.
- Port-level counters (`$PORT_STAT`) on both dev_port 9 (master) and dev_port 64 (relay) show clean
  traffic: zero drops, zero CRC errors, zero FCS errors, frame counts consistent with a real TCP
  handshake plus one DNP3 request/response pair.
- Egress table-hit counters confirm the mechanism's own classification logic actually processed this
  traffic, not a bypass: `pipe.Egress.classify_fwd` hit 19 times, `pipe.Egress.conn` hit 11 times,
  `pipe.Egress.count_t` hit 19 times (see `post_traffic_table_hits.txt`).

## What this does NOT establish

- **This is a native-passthrough result, not a padding-mechanism result.** The real SEL-751's actual
  configured points produce a 134-byte DNP3 response (see the response hex below) — this does not
  match `case4_pad58b.py`'s expected 49-byte/23-point READ-response shape the padding transform is
  built around, so the frame was correctly and legitimately classified as ineligible and passed
  through unmodified (the `classify_rev` table showing 0 hits is consistent with this: the reverse/ACK
  path for a non-padded exchange takes a different route through the egress logic than a padded one
  would). Demonstrating the padding transform itself on real hardware needs either a software-handler
  outstation configured with the expected 23-point shape, reachable through the switch, or a real
  outstation whose configuration happens to match it — neither was attempted in this run.
- **No TCP sequence/ACK translation was exercised.** Since this connection was never padding-eligible,
  the transport mapper's commit/replay logic never activated. This run proves the mechanism doesn't
  break a real, unrelated exchange; it does not prove the mapper's sequence/ACK rewriting works on
  real hardware with a real TCP stack on both ends (the model-level and loopback-socket evidence
  already cover that separately).
- Only a single request/response exchange was run. No retransmission, loss, or sustained-session
  behavior was exercised here.

## Exact commands and evidence

- Connection install: `install_connection.py --master-ip 192.168.10.1 --master-port 54321
  --master-dev-port 9 --outstation-ip 192.168.10.7 --outstation-port 20000 --outstation-dev-port 64
  --slot 0` (run on the switch host; see `install_connection_output.txt`).
- Traffic: `dnp3_read_client.py --local-ip 192.168.10.1 --local-port 54321 --remote-ip 192.168.10.7
  --remote-port 20000 --master-addr 1 --outstation-addr 0` (run on Vision; see `read_client_output.txt`).
- `pre_load_snapshot.json` / `post_load_snapshot.json` / `post_traffic_snapshot.json`: read-only BFRT
  snapshots before loading the new program, immediately after loading (before any connection/traffic),
  and after this traffic run.
- `post_traffic_table_hits.txt`: the nonzero counter tables extracted from `post_traffic_snapshot.json`.
