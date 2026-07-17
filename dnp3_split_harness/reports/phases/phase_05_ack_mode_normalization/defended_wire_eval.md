# Phase 05 — Per-Profile Loopback Defended-Wire Evaluation: Result

**PASS.** Each device **profile** (SEL-751 / AB1400 / ION7550, base + L) is replayed — real
request/response bytes, reproduced ACK mode — through the coalescing server on `lo`; the defended
captures are re-characterized and classified. Socket coalescing removes the categorical request-ACK-mode
feature on the wire, byte-preservingly, with no packet loss; response size is the dominant stable
residual. See the authoritative closeout `phase_05_ack_mode_normalization.md` (Section 5) for context.
Run `20260717T165759Z_phase05_defended_wire2`. `next_phase_allowed = false`.

_Scope: a loopback reproduction of each device's measured observables (real bytes, response sizes,
native ACK mode, native timing) through the real kernel TCP stack — not the physical target devices._

## Method

`phase05_defended_wire_eval.py` under `sg wireshark` (no sudo, no BPF, no netns, no drops). Per profile
the first 120 real transactions' request bytes and **complete logical response** (reconstructed across
segments; all single-segment here — see the reconstruction audit) are replayed under three conditions:
**native** (reproduce each profile's native ACK mode + native timing), **coalesced** (ACK mode
normalized to combined), **coalesced_edt** (+ response timing normalized to a common target). Each
capture is re-characterized (`characterize_ack_traces`) and classified (`ack_fingerprint_eval.supervised`,
capture-level split train base / test L; RF `n_estimators=200`, seed 0; chance 0.333; 119 test
transactions/profile; balanced accuracy = raw accuracy). The first transaction per stream is excluded
(fresh-connection quickack artifact).

## Wire integrity

| condition | separate-ACK (SEL / AB / ION) | byte-identical | retrans | resets | dup-ACKs |
|---|---|---:|---:|---:|---:|
| native | 1.00 / 0.00 / 0.00 | 720/720 | 0 | 0 | 0 |
| coalesced | 0.00 / 0.00 / 0.00 | 720/720 | 0 | 0 | 0 |
| coalesced_edt | 0.00 / 0.00 / 0.00 | 720/720 | 0 | 0 | 0 |

Overall 2160/2160 byte-identical; no resets within established replay sessions.

## Classifier (Random Forest, capture-level split, chance 0.333)

| feature family | native | coalesced | coalesced_edt |
|---|---:|---:|---:|
| mode_only | 0.667 | **0.333 (constant / non-discriminating)** | 0.333 (constant) |
| ack_timing | 0.709 | 0.490 | 0.233 |
| ack_combined (was ack_only) | 0.709 | 0.490 | 0.233 |
| timing | 0.448 | 0.490 | 0.233 |
| size | 0.667 | 0.667 | 0.667 |
| all | 1.000 | 0.759 | 0.322 |

- **`mode_only` (the categorical ACK-mode feature alone) is removed by coalescing:** 0.667 native →
  0.333, and it is a zero-variance constant feature after coalescing (flagged non-discriminating; the
  0.333 is the majority-class baseline, not a learned score).
- **Response size is the residual:** `size` stays 0.667 (ION7550 61 B distinct; SEL-751 / AB1400 both
  54 B) — SEL-751 ↔ AB1400 collapse once the ACK mode is gone, ION7550 stays identifiable.
- **`coalesced_edt` joint `all` (0.322) is unstable on loopback** — loopback timing-normalization
  jitter differs across the capture-level split, so the normalized timing features mislead. The
  categorical `mode_only` and `size` results are stable; the **two-host rig
  (`rig_defended_wire_eval.md`) is the authoritative joint measurement** (`all` 1.000 → 0.756 → 0.681).

Evidence: `defended_wire_eval.json` (full per-family results incl. balanced accuracy, macro-F1,
per-family training variance, confusion); representative captures `defended_wire/{SEL751_native,
SEL751_coalesced,ION7550_coalesced}.pcap`; full run under the git-ignored
`runs/20260717T165759Z_phase05_defended_wire2/`.
