# Experiment 1 — methodology

Offline TCP/IP-header attribution and deterministic PCAP transformation. Read-only over the frozen
Defense 4 corpus (`/home/philip/Projects/DNP3` at `7c4a5a7`). No hardware, no live traffic, no Tofino.
Everything here is offline packet analysis; nothing claims that a transformed trace would be accepted
by real endpoints (that is Experiment 3).

## Tooling and reproducibility

- Python: `~/.venvs/research/bin/python` (research venv), scapy for parsing/serialization.
- Deterministic: sessions are keyed by the sorted 4-tuple; packets are processed in capture order;
  no randomness; timestamp/ISN offsets are derived from the first observed value per flow/endpoint.
- Run order: `run_attribution.py` (phases 1-3) -> `run_transform.py` (phase 4) ->
  `run_validate.py` (phases 5-6). Each writes JSON/CSV into `out/`; transforms write pcaps into
  `pcaps/`.
- The outstation is the TCP-port-20000 endpoint of each session (DNP3 listens on 20000).

## Corpus

The authoritative multi-device corpus is `Traffic Trace/{SEL751,ION7550,AB1400}{,L}.pcap` in the frozen
repo: three physical outstations plus a longer "L" capture of each. `CORPUS_MANIFEST.md` records source
paths, SHA-256, session/transaction counts, operation coverage, and checksum/FCS notes. Originals are
never modified; only their hashes and paths are recorded.

Each capture contains two outstation sessions: the real physical device (SEL751 at 10.0.0.1, ION7550 at
10.0.0.11, AB1400 at 10.0.0.12) and a shared reference endpoint at 10.0.0.2 that presents an identical
Linux-like stack in every capture. The reference is detected automatically (an outstation IP appearing
under two or more device labels) and excluded from device attribution; it is a natural canonical target.

## Phase 2 — attribution

For every session and direction, the per-packet IPv4 and TCP header fields are extracted to
`out/packet_features.csv`. For each distinct `data_offset` the exact TCP option layout (ordered option
kinds) is recorded, so every `data_offset` value is explained by the option bytes and padding that
produce it, not merely reported as a number. Comparisons are conditioned on the same public context:
packet direction, TCP lifecycle state (SYN / SYN-ACK / pure ACK / DATA / retransmission / teardown), and
DNP3 operation class. IP addresses, MAC addresses, ports, and plaintext DNP3 content are not treated as
stack-fingerprint features.

## Phase 3 — baseline observer test (header-only)

Five feature groups are evaluated separately over the real-device sessions: (G1) TCP option layout and
`data_offset`; (G2) window / MSS / window scale; (G3) timestamp rate and quantization; (G4) TTL / IP-ID /
DF; (G5) combined. Explicit identifiers, plaintext content, packet size, and interarrival timing are
excluded from the header-only test. Because the corpus has one physical unit per model and only a few
real-device sessions each, this is reported as **exploratory**: a deterministic per-device signature and
a leave-one-session-out 1-NN, not a generalizable device-family classifier. Splits are by complete TCP
session to prevent packet-level leakage.

## Phase 4 — deterministic transformations

Each transform is a byte-clean rebuild: the real TCP segment payload (DNP3 bytes) is extracted using the
original `ip.len` as ground truth, the packet is reconstructed with normalized headers, and IPv4/TCP
lengths, `data_offset`, and checksums are recomputed by serialization. Short frames are padded to the
60-byte Ethernet minimum. Originals are never overwritten; outputs go to `pcaps/`.

- **T0** length-preserving IP normalization: canonical TTL (64), IP-ID policy (0 with DF set), IPv4
  checksum recomputed.
- **T1** T0 plus timestamp translation: each flow's TSval is shifted to a public per-endpoint origin
  and the matching TSecr on the opposite direction is shifted by the peer's origin. The option layout is
  preserved. A fixed offset hides the absolute timestamp origin but not the clock rate or quantization.
- **T2** T0 plus canonical TCP option layout: TS, window scale, and SACK-permitted are suppressed in the
  handshake, SYN/SYN-ACK carry only a public MSS (1460) at `data_offset` 6, established segments carry no
  options at `data_offset` 5, and IPv4 total length and both checksums are corrected. This is a
  counterfactual trace; it does not prove the endpoints would negotiate or operate this way.
- **T3** T2 plus per-flow ISN normalization: sequence numbers are shifted to a public origin and the
  reverse acknowledgment is shifted by the peer's origin.

## Phase 5 — validation

For every transformed packet, independently reparsed: the real DNP3 payload is byte-identical to the
original; `ip.len == ihl*4 + data_offset*4 + payload` (ties total length, data offset, and payload
together); the frame meets the 60-byte Ethernet minimum; and IPv4 and TCP checksums recomputed from the
transformed bytes match the stored values. Original checksum validity is measured separately to
distinguish real errors from capture offload artifacts (the source captures show a large fraction of
invalid TCP checksums, a transmit-offload artifact; the transformed copies are 100% valid by
reconstruction). Packet counts are compared to confirm nothing was silently lost, duplicated, or
reordered.

## Phase 6 — post-transformation observer test

The Phase-2/3 header-only analysis is repeated on each transformed corpus. The collapse summary reports,
per transform, the number of distinct real-device signatures over the full signature, over
handshake-captured sessions, and over established-only features. A reduced count is reported as
fingerprint removal on the tested corpus, explicitly not as proof of indistinguishability, and the
surviving features are enumerated.
