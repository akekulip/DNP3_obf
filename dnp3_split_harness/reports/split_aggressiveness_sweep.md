# Split-Aggressiveness Sweep — CRC-Boundary Granularity

_Run: 2026-06-18 (gambit-driven over SSH). Rig: Vision `10.10.54.19` master →
Hulk `10.10.54.158:20000` request-aware split server. Refactored code path
(`tcp_split_replay_server.py` + `captured_exchange.py`)._

## What was tested
The same captured READ response (2407 B, 9 link frames) was replayed split on
existing DNP3 CRC boundaries at four granularities by varying
`--blocks-per-chunk` (N = 1, 2, 4, 8) on `dnp3_split_replay_server.py`. Everything
else was held constant: `--split-mode crc-boundary`, `--delay-between-chunks-ms 10`,
one `run_master.py` scan-all-classes READ per run. Byte preservation
(`b"".join(chunks) == response`) is enforced by the splitter on every run.

`blocks_per_chunk` = how many whole CRC blocks per TCP chunk. N=1 is the **most
aggressive CRC-boundary split possible** — every CRC block (header block or ≤16 B
data block) becomes its own TCP segment. Larger N groups more blocks per write
(coarser, less fragmented). Cutting finer than N=1 is impossible without splitting
*inside* a CRC block, which would break a boundary and is out of the current phase.

## Results — master accepts every granularity, byte-preserving

| blocks_per_chunk | READ chunks | outstation data segments | total pkts | measurements delivered | master CONFIRM | TCP retransmits | TCP resets |
|---|---|---|---|---|---|---|---|
| 1 | **141** | 145 | 301 | +800 | yes | 0 | 0 |
| 2 | **71**  | 75  | 161 | +800 | yes | 0 | 0 |
| 4 | **36**  | 40  | 91  | +800 | yes | 0 | 0 |
| 8 | **18**  | 22  | 55  | +800 | yes | 0 | 0 |

READ chunk counts follow ⌈141 / N⌉ exactly. Outstation data segments = READ chunks
+ 3 single-write startup responses + 1 continuation response. Proof pcaps:
`captures/replay/sweep_bpc{1,2,4,8}.pcap` (pulled to gambit); server logs:
`logs/replay/split_replay_server_*.log` (each shows `Byte-preservation check: PASS`,
`Chunk count`, and `Received CONFIRM`).

## Conclusion
Across the full 1–8 range the live OpenDNP3 master **reassembled the identical
application message, delivered all 800 measurements, and sent a DNP3 CONFIRM** — on
a completely clean TCP connection (0 retransmissions, 0 resets) — with **no DNP3
byte modified and no CRC recomputed**. CRC-boundary splitting is transparent to the
master's link+transport reassembly regardless of how finely the response is chopped.

The obfuscation envelope for byte-preserving CRC-boundary splitting is therefore the
full block-grouping range, with the maximum size/segmentation distortion at
**blocks_per_chunk = 1** (one 2407 B response presented as 141 tiny ≤18 B segments
instead of OpenDNP3's native 9 frames). Pushing fragmentation past this point, or
changing per-frame *sizes* arbitrarily, requires the next phase (frame rebuild +
CRC recompute), which remains gated by the governing spec.
