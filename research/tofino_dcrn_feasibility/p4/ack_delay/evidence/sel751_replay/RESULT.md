# SEL-751 faithful-replay experiment — Case-A on authentic device traffic (2026-07-20)

The live SEL-751 relay is NOT on the DCRN testbed (10.0.0.1:20000 refuses; switch has only dp8/dp9;
SEL751.pcap is a June-2019 capture). Per PI decision, ran the faithful REPLAY: the real SEL-751
transaction timing (from Traffic Trace/SEL751.pcap) driven through the DCRN switch on the single-host
Hulk loopback rig (no Vision; Hulk hosts both master and outstation netns). Hardened dcrn_ackA sha
6e1b659b. 99 real Class-0 READ (22B/54B) transactions, one persistent connection, replayed with each
transaction's REAL response latency (from the capture), no cold reload.

## Real SEL-751 fingerprint (from SEL751.pcap, 299 txns)
Native CLRT median 12.90 ms (min 10.50, p25 11.98, p75 14.40, max 165.98); all separate-ACK. This
device-characteristic CLRT is the Formby fingerprint.

## Result (measured on the rig)
- NATIVE (real SEL-751 timing replayed): CLRT median 17.35 ms, min 15.12, max 26.57 -> reproduces the
  real SEL-751 response-latency distribution with its spread. 99/99 byte-identical, 0 retrans/reset.
- CASE-A (same real timing): **CLRT collapsed to a constant ~0.026 ms** (median 0.026, min 0.0, max
  0.039; head10 0.029 ~= tail10 0.024 -> no degradation). 99/99 byte-identical, 0 retrans/reset.
- Case-A flattens the SEL-751's variable native CLRT to a device-independent constant guard, on
  authentic device traffic, byte-preserving.

## Fidelity caveat (honest)
This is a REPLAY, not the live relay (unavailable). It faithfully reproduces the SEL-751's DNP3 request/
response BYTES, its per-transaction RESPONSE LATENCY distribution, and its separate-ACK STRUCTURE. It
does NOT reproduce the SEL-751's own ~4 ms kernel ACK delay (the replay outstation quickacks promptly),
so the replay's native CLRT (~17 ms) reflects response latency; the real device CLRT was ~13 ms. The
result under test — Case-A collapses the native CLRT distribution to a constant guard — is independent
of that offset. Live-device validation remains pending a physical relay wired to the switch.
