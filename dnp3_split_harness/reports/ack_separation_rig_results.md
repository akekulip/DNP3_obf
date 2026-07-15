# Phase-2A Socket-Level ACK Separation — Rig Results (Vision ↔ Hulk)

_Generated 2026-07-14 (late). Executes `ack_delay.md` §5A on the real two-host rig,
now that privileged capture is available (sudo on the rig hosts). Previously deferred
because the dev box lacked capture privilege._

## Question (§5A)

For a flow where the outstation currently **piggybacks** its TCP ACK onto the DNP3
response (one combined ACK-bearing segment), can we induce the host TCP stack to
emit a **pure TCP ACK before the DNP3 response** — `request → pure ACK → response` —
purely by **delaying the application `write()`**, with **no packet forging**?

## Method

- **Server (delay injector):** `ack_separation_probe.py --server` on Hulk
  `10.10.54.158:20051`. Receives a request, waits the client-stated delay, writes a
  fixed 2407 B response. No sudo (no capture on the server).
- **Client (measurer):** `ack_separation_probe.py --client` on Vision, connecting
  over the 1 G mgmt net (`eno1`). One-factor-at-a-time socket sweep (baseline,
  server `TCP_NODELAY` on, server `TCP_NODELAY` off), 30 reps per (config, delay).
- **Capture:** the probe's own capture path produced empty pcaps under
  sudo-over-SSH, so capture was done **independently with `tcpdump` on Hulk `eno1`**
  (`tcp port 20051`, full frames) — the outstation's own egress, the ground truth
  for whether it emits a pure ACK. Captures analysed with tshark.
- Two passes: coarse delays `0,1,2,5,10,20,50 ms` (844 transactions) and a fine grid
  `25,30,35,38,40,42,45,50 ms` (964 transactions) to locate the threshold.

## Result — a sharp threshold at the Linux delayed-ACK timeout (40 ms)

Separate-ACK fraction = fraction of transactions where a pure ACK (outstation
egress, zero payload, no PSH) precedes the response. Aggregated across socket
configs (the factor did not move the threshold).

| app-write delay (ms) | transactions | separate-ACK fraction | median req→resp (ms) |
|---:|---:|---:|---:|
| 0 | 123 | 0.02 | 0.028 |
| 1 | 121 | 0.01 | 1.103 |
| 2 | 120 | 0.00 | 2.242 |
| 5 | 120 | 0.00 | 5.244 |
| 10 | 120 | 0.00 | 10.250 |
| 20 | 120 | 0.00 | 20.261 |
| 25 | 124 | 0.03 | 25.255 |
| 30 | 120 | 0.00 | 30.287 |
| 35 | 120 | 0.00 | 35.251 |
| 38 | 120 | 0.00 | 38.262 |
| **40** | 120 | **0.93** | 40.258 |
| 42 | 120 | 1.00 | 42.261 |
| 45 | 120 | 1.00 | 45.261 |
| 50 | 120 | 1.00 | 50.287 |

**0 TCP resets across all 1808 transactions.**

Raw-packet verification (from `acksep_refine.pcap`):
```
--- delay 38 ms (COMBINED) ---
  +0.000 ms  REQUEST(C->S)   len=32
  +38.31 ms  RESPONSE(S->C)  len=2407     # ACK piggybacked, no separate ACK

--- delay 40 ms (SEPARATE, delayed-ACK timer fires) ---
  +0.000 ms  REQUEST(C->S)   len=32
  +40.20 ms  pureACK(S->C)   len=0        # standalone ACK at the 40 ms timer
  +40.27 ms  RESPONSE(S->C)  len=2407

--- delay 50 ms (SEPARATE, quickack after the first timer-driven ACK) ---
  +0.000 ms  REQUEST(C->S)   len=32
  +0.031 ms  pureACK(S->C)   len=0        # near-immediate ACK (quickack engaged)
  +50.24 ms  RESPONSE(S->C)  len=2407
```

## Interpretation

- **Yes — delaying the application write induces a pure TCP ACK before the response,
  with no forging.** The transition is sharp and sits exactly at **40 ms**, the Linux
  delayed-ACK timeout (`TCP_DELACK_MAX`) on this stack (Ubuntu 24.04, kernel 6.8).
- Below ~38 ms the outstation writes the response before the delayed-ACK timer
  expires, so the pending ACK **piggybacks** onto the response (one combined
  segment, separate-ACK fraction ≈ 0).
- At/above 40 ms the delayed-ACK timer fires first, emitting a **standalone ACK**;
  once the stack has done so it tends to switch to quickack, so subsequent held
  transactions get a near-immediate ACK followed by the delayed response. Either
  way the observable becomes `request → pure ACK → response`.
- The server-side `TCP_NODELAY` factor did not move the threshold (it governs the
  sender's Nagle behaviour on the response, not the receiver's delayed-ACK timer for
  the request).

## Why this matters (links to Phase 1 and Phase 2)

- **Bounds Phase 1.** The Phase-1 normalization targets validated on the rig
  (10–25 ms) are **below** the 40 ms threshold, so they keep the flow in the
  **combined** regime — the outstation still piggybacks its ACK, and the observable
  ACK→response gap (the Formby CLRT fingerprint) stays ~0. Normalization pins the
  request→response time without accidentally creating a separate-ACK signature.
- **Enables Phase 2 without forging.** To operate on the ACK→response gap (the
  separate-ACK regime the real SEL-751 exhibits), a host-side defense can hold the
  write **≥ 40 ms**, which *naturally* produces a pure ACK before the response — no
  synthesized ACK, no P4 recirculation. The cost is a ≥40 ms floor on the visible
  request→response time.

## Honest limits (per §12)

- This is a **host/kernel behaviour on this stack**, not a protocol guarantee. The
  40 ms threshold is the Linux delayed-ACK timeout; other stacks/OSes differ.
- Measured on the **replay/probe server**, not a real device; a physical outstation
  may ACK differently.
- Capture is host-side (Hulk egress); it is authoritative for emission but is not a
  mid-path observation.
- No forging was performed; the pure ACK is entirely the kernel's own.

## Artifacts

`reports/ack_separation_rig/` — `acksep_serverside.pcap` (coarse), `acksep_refine.pcap`
(fine grid), `ack_separation_client_matrix.csv` (client-side req→resp timing per
config/delay). Reproduce: server `python3 ack_separation_probe.py --server --port
20051`; client `sudo python3 ack_separation_probe.py --client --connect-host
10.10.54.158 --iface eno1 --port 20051 --delays … --reps 30 --method none`; capture
`tcpdump -i eno1 -s0 -w cap.pcap tcp port 20051` on Hulk.
