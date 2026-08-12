# READ vs SBO normalization on the physical SEL-751 — pcap-examined result

Goal: prove that, to a passive observer master-side of the outstation-edge Tofino, a **READ** and an
**SBO** transaction on the SEL-751 look the same in **size** and **timing**. Test driven from Vision,
captured on the observer vantage `enp59s0f0np0` (192.168.10.1), examined at the packet level.
Evidence: `evidence/hw_rrc_readsbo_20260812T212234Z/` (read.pcap, sbo.pcap, verify.pcap, analysis.json,
switch/). Switch left in the working size-carve state (`shape_enable=1, mode=0`, PRE RID1/RID2 → dp9).

## Test design

| | Trial A (READ) | Trial B (SBO) |
|---|---|---|
| Request | 23-point G10V2 READ (`0A 02 00 00 16`) | 2-CROB SELECT, real pt0 + decoy pt1 (**non-actuating**, no OPERATE) |
| Count | 30 over one persistent conn, src 192.168.10.1:40000 | 30 over one persistent conn, src 192.168.10.1:40000 |
| Native response | 49 B TCP payload | 49 B TCP payload (32 B G12 echo + link framing + block CRCs) |
| Safety | READ-only | SELECT-only; pt0/pt1 read OPEN before **and** after — nothing actuated |

## SIZE — normalized, identical (PASS)

Packet-level, from the pcaps (socket layer reassembles TCP, so segmentation only lives in the capture):

| Observable | READ | SBO | Same? |
|---|---|---|---|
| Response segment histogram | 30×**28** + 30×**21** | 30×**28** + 30×**21** (+ 2×58 state-reads, correctly **unsplit**) | **yes** |
| Reassembled units | 30 × exactly 49 B | 30 × exactly 49 B | yes |
| Segmentation vector | `[28, 21]` | `[28, 21]` | **identical** |

The 2 all-points state-reads in the SBO trial return 58 B and stay **unsplit** — proof the RRC
eligibility is **size-specific** (keys on the 49 B TCP payload), not "split everything." An
`O_count+segmentation` observer cannot tell a READ response from an SBO response: same count, same
sizes, same segment boundaries.

## TIMING — currently native, not yet enforced (HONEST PARTIAL)

The persisted switch state is **size carve ON, timing hold OFF** (`mode=0`), so the measured
request→first-response latency is the SEL's **native** timing, not a clamped deadline:

| | READ | SBO |
|---|---|---|
| median | 2.84 ms | 2.57 ms |
| mean | 5.27 ms | 2.59 ms |
| max | **22.0 ms** (cold first poll) | 7.9 ms |
| std | 4.31 ms | 1.33 ms |

The medians are close, but that is *native similarity*, not enforcement: the READ trial carries a
22 ms cold-poll tail and a wider spread. A timing-aware observer could still separate the two on the
tail. To make timing **identical** requires the D4 hold to clamp both to a common deadline.

**D4 attempt this session (documented in `switch/d4_timing_attempt.txt`):** enabling D4 on top of the
running size-only state failed to re-arm the caseA pktgen blocker reservoir (`app_enable` read back
false on the re-enable-after-OFF path) and was cleanly restored. The D4 hold mechanism itself is
silicon-proven separately (caseA Defense-4, 240/240) and gate **R4 already showed D4 hold + `[28,21]`
together on this kernel** from a fresh bring-up. The joint live demonstration needs the correct
**bring-up order** — D4 timing first (fresh pktgen), then layer the size carve — which entails a gated
program (re)load.

## Verdict against the observer

- **O_count+segmentation, response direction:** READ **==** SBO in **size/segmentation** (proven, pcaps).
  **Timing** is native-similar but not yet enforced-identical (needs the D4 hold; mechanism proven).
- **Honest residuals (unchanged claim boundary):**
  - **Request direction differs:** READ request = 20 B, SELECT request = 45 B — the transaction type
    still leaks on the *forward* channel (this defense shapes the outstation's *response*, the device
    fingerprint; the request is the master's).
  - **Parser (DPI) observer** still separates G10 (READ) from G12 CROB (SBO). Claim is
    size+segmentation parity, **not** DPI equality, and **no device-anonymity claim**.
