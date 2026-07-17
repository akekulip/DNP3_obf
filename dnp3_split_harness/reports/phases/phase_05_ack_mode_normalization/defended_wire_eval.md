# Phase 05 — Per-Device Defended-Wire Fingerprint Evaluation: Result

**PASS** (human-authorized, 2026-07-17). Turns the Phase-05 trace-transformation effectiveness
number into a **genuine defended-wire measurement**: each device's real request/response bytes are
replayed through a loopback replay server under three wire conditions, captured on `lo`, and the same
capture-level-split classifier is run on the **defended captures** — not a software transform.
Socket-side ACK-mode normalization (coalescing) is confirmed to close the categorical separate-ACK
fingerprint on the real wire, byte-preservingly, with **zero dropped or retransmitted packets**;
**response size is the confirmed residual**. `next_phase_allowed = false`.

## Method

`phase05_defended_wire_eval.py` (run under `sg wireshark` — no sudo, no BPF, no netns, no drops).
For each of the six real device PCAPs (SEL751 / AB1400 / ION7550, base + L), the first 120 real
transactions' **request and response first-segment bytes** are extracted (`tshark -e tcp.payload`)
and replayed verbatim through a loopback server. Byte-identity (`b_sent == b_device`) isolates the
ACK-mode / timing change from the payload. Three wire conditions:

- **native** — reproduce each transaction's native ACK mode (SEL-751 separate via server
  `TCP_QUICKACK`; AB1400 / ION7550 combined) + native request→response timing.
- **coalesced** — socket-side coalescing: no quickack, response written inside the delayed-ACK
  window → ACK mode normalized to **combined** for every device; native timing kept.
- **coalesced_edt** — coalescing + response timing normalized to a common 25 ms target (the socket
  analog of the Phase-4 EDT timing normalization).

Each capture is re-characterized with the existing extractor (`characterize_ack_traces.run_tshark`
+ `build_transactions`) and classified with the existing capture-level-split classifier
(`ack_fingerprint_eval.supervised`: train on base captures, test on the disjoint L captures). The
first transaction per TCP stream is excluded (a fresh connection starts in quickack mode → the first
post-handshake exchange carries a separate ACK regardless of policy — a loopback-harness artifact,
not a device property; the same non-first rule the coalescing demo used).

Canonical run `20260717T142828Z_phase05_defended_wire`. Classes are balanced (119 test transactions
per device), so **chance = 0.333** and raw accuracy ≈ balanced accuracy.

## Wire integrity (measured)

| condition | separate-ACK fraction (SEL / AB / ION) | byte-identical | retrans | resets | dup-ACKs |
|---|---|---:|---:|---:|---:|
| native | **1.00** / 0.00 / 0.00 | 720/720 | 0 | 0 | 0 |
| coalesced | **0.00** / 0.00 / 0.00 | 720/720 | 0 | 0 | 0 |
| coalesced_edt | **0.00** / 0.00 / 0.00 | 720/720 | 0 | 0 | 0 |

Overall **2160/2160 byte-identical**; **0 retransmissions / 0 resets / 0 duplicate ACKs** across all
714 non-first transactions in each condition. Coalescing flips SEL-751's separate-ACK fraction
**1.00 → 0.00 on the wire** with no packet loss and no byte change.

## Classifier on the defended wire (Random Forest, capture-level split, chance 0.333)

| feature family | native | coalesced (ACK mode normalized) | coalesced_edt (+ timing) |
|---|---:|---:|---:|
| ACK structure (`ack_only`) | 0.728 | **0.389** | **0.344** |
| timing | 0.465 | 0.389 | 0.344 |
| response size | 0.667 | 0.667 | 0.667 |
| **all** | **1.000** | **0.767** | **0.700** |

All-features confusion (rows = true device, cols = predicted; 119 test transactions each):

```
[native]           AB1400  ION7550   SEL751       [coalesced]        AB1400  ION7550   SEL751
  AB1400              119        0        0          AB1400               76        0       43
 ION7550                0      119        0         ION7550                0      119        0
  SEL751                0        0      119          SEL751               40        0       79
```

## Reading

- **The native defended-wire fingerprint is strong** (`all` 1.000): the reproduced observables —
  SEL-751's separate ACK, plus each device's real response sizes and native timing — separate the
  three devices cleanly on the wire.
- **Socket-side ACK-mode normalization closes the categorical channel on the real wire.** Under
  `coalesced`, SEL-751's separate ACK is gone (`is_separate` 1.00 → 0.00, measured), so the classifier
  loses SEL-751's dominant tell: `ack_only` falls **0.728 → 0.389** and the joint fingerprint falls
  **1.000 → 0.767**. In the confusion matrix, **SEL-751 and AB1400 collapse into mutual confusion**
  (76/119 and 79/119) — exactly the two devices whose only strong separator was the ACK mode.
- **Response size is the confirmed residual.** **ION7550 stays 119/119 correctly identified in every
  condition**, purely by its distinctive response size; the `size` family is unchanged at 0.667
  throughout (size is never touched — the out-of-scope padding line). Adding timing normalization
  (`coalesced_edt`) removes the residual timing structure (`all` 0.767 → 0.700) but cannot touch size.
- **This is the wire anchor for the trace-transformation.** The software transform reported that ACK
  suppression closes the ACK-mode channel that timing normalization could not, leaving size; this
  defended-wire eval confirms the same conclusion on real captures — the ACK-mode fingerprint is
  removable byte-preservingly at the socket, and **size is the last residual**.

## Scope and honesty

- **Loopback reproduction of measured observables, not a physical multi-device capture.** Each
  device's real response bytes, response sizes, native ACK mode, and native timing are reproduced
  through the real kernel TCP stack (so the ACK-mode behaviour and TCP health are genuine wire
  behaviour), but all three "devices" are the same loopback host. The native `all` = 1.000 reflects
  the low-noise loopback reproduction; a physical multi-device network would be noisier. The value is
  (1) proving the coalescing primitive on the real wire per device (byte-preserving, no breakage) and
  (2) the classifier consequence (ACK-mode tell removed; size residual).
- **Sample cap:** first 120 transactions per capture (preserves capture order and the real response-
  size distribution); reported counts are 714 non-first test/train transactions per condition.
- **Run-to-run variation:** the timing-derived features carry loopback jitter, so `ack_only` / `all`
  vary by ≈ ±0.03 across runs (three runs: `all` coalesced ∈ {0.737, 0.759, 0.767}); the categorical
  `separate-ACK` result (1.00 → 0.00) and the `size` floor (0.667, ION7550 always 119/119) are stable.
- Response **size** is out of scope (separate padding line); a per-device *physical* rig eval
  (SEL-751 / AB1400 / ION7550 hardware) remains the stronger, still-deferred validation.

Evidence:
- `defended_wire_eval.json` — full per-condition results (this directory).
- `defended_wire/` — representative committed captures (the run's per-condition pcaps live under the
  git-ignored `runs/20260717T142828Z_phase05_defended_wire/pcaps/`):
  - `SEL751_native.pcap` — sha256 `6f6631d0a008de32ad8fdd5671ce5d32859d34fc71a0734d79c25d7a59010d56` (separate ACK).
  - `SEL751_coalesced.pcap` — sha256 `96cab1eedeaebabdf0e27b82ea0a5a851d88d92e69260f1e8aa51986f93e4463` (ACK coalesced → combined).
  - `ION7550_coalesced.pcap` — sha256 `20e1c8c81dc3c9d834b72bc56f025ecad13bd495294143ee986a4eb1d883cd28` (still size-identified).
- Tool `phase05_defended_wire_eval.py`; classifier `ack_fingerprint_eval.py`; extractor `characterize_ack_traces.py`.

## Status

Per-device **defended-wire** ACK-mode normalization is now **measured on the wire** (not a transform):
socket coalescing removes the separate-ACK fingerprint byte-preservingly with no packet loss, driving
the joint classifier from a perfect 1.000 toward the response-size floor; **size is the confirmed
residual**. `next_phase_allowed = false`.

```
STOP: per-device defended-wire ACK-mode normalization validated (loopback reproduction of measured observables); physical multi-device rig eval remains deferred; size padding remains the out-of-scope residual line.
```
