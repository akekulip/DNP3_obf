# Experiment 1 — results

All numbers are from `out/*.json` and `out/packet_features.csv`, reproducible with the three scripts.
Offline only. No claim is made that a transformed trace would be accepted or operated correctly by real
endpoints.

## 1-2. Attribution: which options produce the fingerprint, and why each data_offset occurs

Every outstation `data_offset` is attributed to the exact TCP option layout (from `out/attribution.json`
and `out/session_signatures.json`). The three physical outstations have pairwise-distinct stacks; a
shared reference endpoint (10.0.0.2) is common to all captures and excluded from device attribution.

| Device (IP) | outstation SYN-ACK options (data_offset) | established data_offset | TTL | MSS | TS rate |
|---|---|---:|---:|---:|---:|
| SEL751 (10.0.0.1) | `MSS,NOP,WScale,NOP,NOP,SAckOK,NOP,NOP,Timestamp` (11) | 8 (carries Timestamp) | 64 | 1460 | 1000 Hz |
| ION7550 (10.0.0.11) | `MSS` (6) — MSS only, no TS/SACK/WScale | 5 (no options) | 64 | 1460 | none (no TS) |
| AB1400 (10.0.0.12) | `MSS,NOP,NOP,NOP,EOL` (7) | 5 (no options) | 128 | 1478 | none (no TS) |
| reference (10.0.0.2) | `MSS,SAckOK,Timestamp,NOP,WScale` (10) | 8 | 64 | 1460 | 1000 Hz |

So `data_offset` is not a device tell by itself; it is a shorthand for the option bytes:
- `data_offset=5` = a 20-byte TCP header with **no options** (ION7550/AB1400 established segments).
- `data_offset=8` = 20 + `NOP,NOP,Timestamp` (12 bytes) = SEL751 (and reference) established segments.
- The SYN-ACK layouts differ per stack: SEL751 negotiates the full option set with a distinctive
  ordering; ION7550 replies with MSS only (declining TS/SACK/WScale); AB1400 replies with MSS plus
  NOP padding and an explicit EOL.

## Strongest pre-transformation fingerprint

The outstation **SYN-ACK option layout** is the strongest single tell (three pairwise-distinct values),
reinforced by four independent header features: established `data_offset` (SEL751=8 vs others=5), TTL
(AB1400=128), MSS (AB1400=1478 vs others=1460), and TCP window (AB1400 constant 2048; ION7550 small,
often zero; SEL751 7218-8688). The device fingerprint is over-determined: several header features each
partly separate the devices, so no single normalization suffices.

## 3. Baseline header-only observer test (EXPLORATORY)

Over real-device sessions only (`out/baseline_classification.json`). One physical unit per model and ~2
real-device sessions each, so this is exploratory, not a device-family claim. Deterministic per-device
signatures are pairwise-distinct; the leave-one-session-out 1-NN is limited only by one SEL751 session
captured mid-connection (no SYN-ACK). Feature groups G1 (option layout + data_offset), G2 (window / MSS /
window-scale), and G5 (combined) each uniquely identify the device on this corpus; G4 (TTL/IP-ID) is
weak (only AB1400's TTL=128 stands out); G3 (timestamp rate) separates SEL751 (has TS) from the
TS-less devices.

## 4. Transformation and validation

`out/validation.json`. All 12 short-capture transforms PASS: the real DNP3 payload is byte-identical,
`ip.len == ihl*4 + data_offset*4 + payload`, frames meet the 60-byte Ethernet minimum, and IPv4/TCP
checksums are 100% valid after reconstruction. Checksum-offload artifact: the source captures show only
~33-43% of TCP checksums valid (transmit offload); the transformed copies are 100% valid. Packet counts
are preserved (nothing lost, duplicated, or reordered). Large "L" transforms were validated at the
signature level (collapse summary); their per-packet validation was skipped for cost, the short captures
being representative.

## 5-6. Post-transformation observer test — what is removed, what remains

`out/collapse_summary.json`. Distinct real-device signatures (handshake-captured / established-only):

| Transform | handshake-captured distinct | established-only distinct | option-layout fingerprint |
|---|---:|---:|---|
| original | 3 | 3 | present (3 distinct devices) |
| T0 (IP norm) | 3 | 2 | **not removed** (TTL normalized only) |
| T1 (TS translate) | 3 | 2 | **not removed** (layout preserved) |
| **T2 (canonical option layout)** | **1** | **1** | **removed** |
| T3 (T2 + ISN norm) | 1 | 1 | removed |

Under T2, every device with a captured handshake collapses to the single public profile
`SYN-ACK=[MSS] (data_offset 6), established data_offset 5 (no options), TTL 64, MSS 1460, no Timestamp`.
The option-layout, established `data_offset`, TTL, MSS, timestamp-presence, and IP-ID-progression tells
are all removed. **T0 and T1 do not remove the option-layout fingerprint** (handshake distinct stays 3):
length-only IP normalization and timestamp-origin translation are insufficient.

### Remaining identity leaks after T2 (this is the honest residual ledger)

- **TCP window value** — device-specific and **not normalized** by T2: AB1400 constant 2048, ION7550
  small/zero windows, SEL751 7218-8688. T2 suppressed window *scale* but not the window *value*.
  Normalizing the value is a flow-control change (a fixed public window) whose live-safety is an
  Experiment-3 question.
- **Timestamp rate/quantization** — removed by T2 (TS suppressed), but under T1 it **survives** a fixed
  offset (the offset hides absolute origin, not clock frequency); this confirms the pre-registered note
  that a timestamp offset alone is insufficient.
- **DNP3 response size and packet count** — untouched (this is the size axis, out of scope for the
  header experiment); the dominant residual overall and the reason header normalization alone does not
  make the device anonymous.
- **Interarrival / CLRT timing** — untouched (the Defense 4 axis, out of scope here).
- **Can the observer tell a packet was transformed?** On this corpus the T2 profile (MSS-only handshake,
  no established options, IP-ID 0) is a plausible real stack (it resembles the ION7550 native profile),
  so a transformed packet is not obviously synthetic in isolation; but a mid-stream loss of a
  previously-negotiated Timestamp option would be anomalous to an observer tracking the handshake, which
  is exactly the live-correctness issue Experiment 3 must address.

### Does this generalize?

Only exploratory. The collapse is demonstrated for these three physical units on this corpus. A
device-family claim needs at least two units per model and more independent sessions (Open Question in
`../../OPEN_QUESTIONS_FOR_PHILIP.md`). The attribution mechanism (data_offset = option bytes) is general;
the specific per-device layouts are corpus observations.
