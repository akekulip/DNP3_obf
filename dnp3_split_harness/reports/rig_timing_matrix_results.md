# Phase-1 Timing Normalization — Rig Validation (Vision ↔ Hulk)

_Generated 2026-07-14 (late). Real two-host rig run of the `ack_delay.md` Phase-1
response-time normalization. This is the rig bar the loopback matrix
(`reports/ack_timing_implementation_report.md` §6) was deferring to._

## Setup

- **Master:** Vision `10.10.54.19`, real pydnp3 stack (`run_master.py --action
  scan-all-classes`, an integrity poll). Python 3.12.3.
- **Outstation:** Hulk `10.10.54.158:20000`, the timing-enabled `split_server.py`
  (request-aware replay of the captured integrity-poll exchange). Python 3.12.3.
- **Transport:** DNP3 over the 1 G management net (`eno1` on both hosts); does not
  traverse the Tofino data plane.
- **Driver:** gambit orchestrates over SSH. Each rep restarts the Hulk server
  (it replays one captured exchange then exits) and runs one integrity poll from
  Vision; the server appends one row per replayed response to
  `logs/timing_rig/<config>/timing_decisions.jsonl`.
- **Rep count:** 30 integrity-poll invocations per config → ~5 timed response
  transactions each (full delivery) or ~3 (crc-boundary). **930 timed transactions
  total.**
- Normalized configs carried the fail-open safety flags `--rto-safe-ms 105
  --max-hold-ms 100 --max-queue-depth 8`.

**Important scope note.** The outstation here is the **replay server**, not a real
device, so the *native* request→response time is replay-fast (~1 ms), **not** the
real device's ~16 ms processing time. This run therefore validates the **timing
mechanism, safety, byte preservation, and TCP health on real two-host
hardware/network** — it does **not** measure closure of a real device's
size/timing leak, which requires the physical SEL-751 / AB1400 / ION7550 (separate
future step).

## Server-side matrix (authoritative per-transaction, from `timing_decisions.jsonl`)

`visible_ms` = `actual_release − request_received` (observer-visible request→response
time, measured on the outstation). All timing figures in milliseconds.

| config | delivery | n | vis median | vis p95 | vis p99 | vis max | hold median | miss | bypass | resets |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| native | full | 150 | 1.127 | 1.314 | 1.328 | 1.335 | 0.0 | 0 | 0 | 0 |
| fixed-10ms | full | 150 | 10.000 | 10.000 | 10.000 | 10.000 | 8.877 | 0 | 0 | 0 |
| fixed-25ms | full | 150 | 25.000 | 25.000 | 25.000 | 25.000 | 23.871 | 0 | 0 | 0 |
| bounded-10-15ms | full | 150 | 10.934 | 14.387 | 14.387 | 14.387 | 9.747 | 0 | 0 | 0 |
| bounded-15-25ms | full | 150 | 16.869 | 23.773 | 23.773 | 23.773 | 15.677 | 0 | 0 | 0 |
| native-crc-split | crc-boundary | 90 | 1.119 | 1.306 | 1.362 | 1.363 | 0.0 | 0 | 0 | 0 |
| bounded-15-25ms-crc-split | crc-boundary | 90 | 15.859 | 22.094 | 22.094 | 22.094 | 14.75 | 0 | 0 | 0 |

**Totals: 930 timed transactions — 0 deadline-misses, 0 bypasses, 0 TCP resets.**
Byte-preservation check PASS on every response (150 full / 120 crc-boundary
byte-preservation log lines per config; the split invariant `b"".join(chunks) ==
response` held throughout). Master completed 120 integrity polls per config
(`OnTaskComplete`) and decoded the full outstation database (~808 measurements per
30-poll batch).

Reading: under `fixed` mode the visible request→response time is pinned to the
configured target with essentially zero spread (fixed-25: median = p95 = p99 = max
= 25.000 ms) for **both** full and CRC-split delivery. Because every transaction —
regardless of native ready time or response size — is released at the same target,
the response-content→timing dependence is removed on the held path. The fail-open
RTO-safe bound (105 ms) was never hit because all targets (≤25 ms) are far below it.

## Wire-level validation (tshark on Hulk `eno1`, 20 reps × 3 configs)

Independent `tcpdump` capture on the outstation NIC while the reps ran. 440 packets
per capture; 100 request→response pairs each.

| capture | packets | resets | retransmit | fast-rtx | dup-ack | out-of-order | zero-window |
|---|---:|---:|---:|---:|---:|---:|---:|
| pcap-native | 440 | 0 | 0 | 0 | 0 | 0 | 0 |
| pcap-fixed25 | 440 | 0 | 0 | 0 | 0 | 0 | 0 |
| pcap-bounded1525 | 440 | 0 | 0 | 0 | 0 | 0 | 0 |

**Wire request→response time (ms), paired from the capture:**

| capture | n | median | p95 | max | min |
|---|---:|---:|---:|---:|---:|
| pcap-native | 100 | 1.36 | 1.57 | 1.66 | 1.05 |
| pcap-fixed25 | 100 | 25.36 | 25.39 | 25.43 | 25.32 |
| pcap-bounded1525 | 100 | 17.22 | 24.13 | 24.14 | 16.06 |

The wire timing tracks the server-side `visible_ms` offset by only the ~0.2–0.4 ms
LAN leg: fixed-25 is pinned at **25.36 ms on the wire with a ±0.1 ms spread**
(min 25.32, max 25.43). A passive observer on this link sees every response arrive
at the same normalized time. **Zero retransmissions and zero resets under the
25 ms hold confirm the hold is safely below the TCP RTO** (measured ≈211 ms on this
stack), matching the loopback RTO analysis.

## What this run establishes vs. leaves open

**Established on the real rig (previously loopback-only):**
- The Phase-1 mechanism holds each response to a class-independent target from
  request arrival, driven by a **real DNP3 master** over a **real network**, for
  both full and CRC-split delivery.
- Byte preservation and DNP3 application correctness (integrity poll completes, DB
  decodes) are intact under normalization.
- The defense is **TCP-safe**: 0 retransmits / 0 resets / 0 dup-acks / 0
  out-of-order on the wire, 0 deadline-miss / 0 bypass server-side, across 930
  transactions and 3 wire captures.
- Fixed-mode pinning is tight enough (±0.1 ms at the wire) to collapse the visible
  request→response distribution to a point.

**Still open (needs real devices / more instrumentation):**
- Closure of an actual device's size/processing-time leak (Formby CLRT
  fingerprint) — the replay outstation has no size-dependent native time, so that
  effect cannot be reproduced or defended here. Requires the physical SEL-751 /
  AB1400 / ION7550.
- Phase-2 (separate pure-ACK manipulation) remains rig/P4 work: a user-space server
  cannot move a kernel-owned pure TCP ACK.
- Attacker-accuracy drop against a *live* defended device (as opposed to the
  trace-based `attacker_eval.py`).

## Reproduce

Server-side matrix (per config, from gambit):
```
# Hulk:   python3 split_server.py --host 0.0.0.0 --delivery {full|crc-boundary} \
#           --timing-mode {native|fixed|bounded} [--target-delay-ms 25 | \
#           --target-min-ms 15 --target-max-ms 25 --timing-seed 20260714] \
#           --rto-safe-ms 105 --max-hold-ms 100 --max-queue-depth 8 \
#           --log-dir logs/timing_rig/<config>
# Vision: python3 run_master.py --host 10.10.54.158 --action scan-all-classes \
#           --wait-after-action 1 --phase custom --no-csv --no-summary
# (restart the server each rep; timing_decisions.jsonl appends)
```
Wire capture (Hulk, needs sudo): `tcpdump -i eno1 -nn -s128 -w cap.pcap tcp port 20000`.

Artifacts: `reports/rig_timing/` — `rig_matrix_results.json`, per-config
`*_timing_decisions.jsonl`, and `pcap-{native,fixed25,bounded1525}.pcap`.
