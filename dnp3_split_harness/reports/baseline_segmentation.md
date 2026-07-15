# Baseline Segmentation Results

Live results from the Vision↔Hulk rig (management network), not loopback.

## Setup
- **Master:** Vision `10.10.54.19` (`run_master.py` / `experiment_master.py`, startup
  integrity poll + disable-unsolicited suppressed, so the capture is only the issued reads)
- **Slave:** Hulk `10.10.54.158` (`experiment_outstation.py`, unsolicited OFF, controls rejected)
- **Capture:** Vision `eno1`, `tcp port 20000`
- **Action:** a single Class 0 integrity poll (one READ)
- pydnp3 = ChargePoint fork, OpenDNP3, Python 3.12 (pybind11 v2.13 swap)

## Small READ (clean baseline)
- DB: 5 analog + 5 binary (`run_slave.py`)
- Response: one application fragment, a few link frames (≈292 B + a short trailing frame),
  delivered in 1–2 TCP segments. Single-frame-class behavior; no meaningful segmentation.

## Large READ (segmentation probe)
- DB: **200 analog + 50 binary + 50 counter** (`--db-size 300`)
- Single Class 0 READ. Measured from `captures/baseline/large_read.pcap`
  (analysis: scapy, counting `0x0564` link frames + transport FIR/FIN):

| Layer | Result |
|---|---|
| Total response bytes (outstation→master) | **12 204 B** |
| **DNP3 application fragments** (transport FIR/FIN) | **9** |
| **DNP3 link frames** (`0x0564`) | **49** |
| Link frame sizes | 46 × **292 B** (the DNP3 max frame) + per-fragment short tails (72/73 B) + 3 × 17 B |
| **TCP segments** (response) | **20** |
| TCP segment sizes | 17, 17, 17, 292, **1448**, 596, 72, 292, **1448**, 668, 292, **1448**, 668, 292, **1448**, 669, 292, **1448**, 669, 111 |

### Interpretation
- **OpenDNP3 segments at the DNP3 layer by itself.** The application response is split
  into **9 transport fragments** (each ≤ ~2 KB of application data), and every fragment is
  carried as a run of **292-byte link frames** — 292 B is the DNP3 link-frame ceiling
  (8 B header + 2 B header CRC + 250 B user data + 16 B of per-16-byte-block CRCs).
- **TCP segments independently.** The kernel packs those link frames into TCP segments up to
  **1448 B** (1500 MTU − 20 IP − 20 TCP − 12 TCP-timestamp = 1448 = MSS). One 1448-B segment
  carries ~5 link frames.
- **The two boundaries do NOT align.** A single 292-B DNP3 link frame routinely straddles a
  TCP segment boundary, and a single TCP segment carries multiple (partial) link frames.

## Range Sweep (dose–response: `scan-range g30v1 0..N` on a 200-analog DB)
Each range captured separately on Vision `eno1` (`captures/baseline/range_0_N.pcap`):

| read range | analog points | response bytes | DNP3 link frames | TCP segments |
|---|---|---|---|---|
| 0..9   | 10  | 129  | 4 | 4 |
| 0..49  | 50  | 332  | 3 | 3 |
| 0..99  | 100 | 625  | 4 | 3 |
| 0..199 | 200 | 1211 | 6 | 3 |

- Response size grows **linearly** with the number of points read — ≈ **5.7 bytes per analog
  point** (g30v1 = 16-bit value + flags + index overhead). This is the lever for forcing
  larger responses (research Q2).
- Frame/segment counts rise once the response crosses the structural limits: > ~250 user
  bytes spills into additional **292 B DNP3 frames**; > 1448 bytes would spill into additional
  TCP segments (the 1211 B case stays near one MSS, so the extra segments are the small
  control frames). The big all-types read (above) crosses both limits hard → 49 frames / 20
  segments.

## Conclusions
1. **Yes — OpenDNP3 naturally splits a large response into multiple DNP3 frames** (49 link
   frames / 9 application fragments here) **and** the response is independently split into
   multiple TCP payloads (20 segments). (Research questions 2 and 3: answered, yes to both.)
2. Response size scales with database size, so DB size is the lever to force segmentation:
   5+5 points → effectively one frame; 200+50+50 → 49 frames / 20 TCP segments.
3. Implication for later splitting/padding work: the **DNP3 link frame (292 B max, per-block
   CRCs) is the real unit of structure**, and it is already independent of TCP segment
   boundaries — so TCP-level split replay (Phase 7) is orthogonal to DNP3-aware splitting.
