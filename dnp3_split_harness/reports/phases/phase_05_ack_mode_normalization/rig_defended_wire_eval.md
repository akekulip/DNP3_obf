# Phase 05 — Two-Host RIG Defended-Wire Fingerprint Evaluation: Result

**PASS** (human-authorized, 2026-07-17). The real-hardware sibling of the loopback defended-wire eval:
the same per-device replay runs across the **real Vision ↔ Hulk 1 G network** — Hulk (outstation side)
replays each device's real request/response bytes and reproduces its ACK mode, Vision (master side)
drives the client, and Hulk captures on `eno1`. The result **confirms the loopback finding on real
server NICs and a switched path**: socket-side ACK-mode normalization removes the categorical
separate-ACK fingerprint byte-preservingly, driving the joint classifier toward the response-size
floor. `next_phase_allowed = false`.

## Honesty / scope

This is **not** the physical SEL-751 / AB1400 / ION7550 hardware — those devices are external
captures on a different network and are not connected to this rig. It is a faithful reproduction of
each device's **measured observables** (real bytes, response sizes, native ACK mode, native timing)
driven over **real server-grade NICs and a real switched 1 G path** (Vision `10.10.54.19` master ↔
Hulk `10.10.54.158` outstation, management net). Hulk stands in for each device in turn. This removes
the loopback low-noise / single-kernel caveat; the still-stronger **physical** multi-device eval
(three real devices) remains deferred.

## Method

`phase05_rig_defended_wire.py` (dev box) builds a replay spec from the six real PCAPs and ships it +
`phase05_rig_replay.py` to both hosts. One `dumpcap` on Hulk `eno1` (non-sudo; `decps` is in the
wireshark group) captures all **18 sessions** (3 conditions × 6 device captures) as distinct TCP
streams; sessions run strictly sequentially, so the k-th stream is session k. Each capture is
re-characterized (`characterize_ack_traces`) and classified (`ack_fingerprint_eval.supervised`,
capture-level split: train base, test L). Conditions identical to the loopback eval: **native** ACK
mode, **coalesced** (ACK mode normalized), **coalesced_edt** (+ response timing normalized). The
first transaction per stream is excluded (fresh-connection quickack artifact). Canonical run
`20260717T162006Z_phase05_rig_defended_wire`; chance 0.333 (balanced 119 test txns/device).

## Wire integrity (measured on real hardware)

| condition | separate-ACK (SEL / AB / ION) | retrans | resets | dup-ACKs |
|---|---|---:|---:|---:|
| native | **1.00** / 0.00 / 0.00 | 0 | 0 | 0 |
| coalesced | **0.00** / 0.00 / 0.00 | 0 | 0 | 0 |
| coalesced_edt | **0.00** / 0.00 / 0.00 | 0 | 0 | 0 |

Client replay **2160/2160 byte-identical**; **0 retransmissions / 0 resets / 0 duplicate ACKs**
across all 714 non-first transactions in each condition; 18/18 streams mapped. Coalescing flips
SEL-751's separate-ACK fraction **1.00 → 0.00 on the real wire**, byte-preservingly, no packet loss.

## Classifier on the real-wire captures (Random Forest, capture-level split, chance 0.333)

| feature family | native | coalesced (ACK mode normalized) | coalesced_edt (+ timing) |
|---|---:|---:|---:|
| ACK structure (`ack_only`) | 0.751 | **0.524** | **0.317** |
| timing | 0.501 | 0.524 | 0.317 |
| response size | 0.667 | 0.667 | 0.667 |
| **all** | **1.000** | **0.756** | **0.681** |

All-features confusion (rows = true, cols = predicted; 119 test txns each):

```
[native]           AB1400  ION7550   SEL751      [coalesced]        AB1400  ION7550   SEL751
  AB1400              119        0        0         AB1400               67        0       52
 ION7550                0      119        0        ION7550                0      119        0
  SEL751                0        0      119         SEL751               35        0       84
```

## Reading

- **The finding reproduces on real hardware.** Native joint fingerprint is perfect (1.000); socket
  coalescing removes SEL-751's separate-ACK tell (`is_separate` 1.00 → 0.00 measured on the wire;
  `ack_only` 0.751 → 0.524; joint **1.000 → 0.756**), collapsing **SEL-751 ↔ AB1400** into mutual
  confusion. **ION7550 stays 119/119 identified by response size** in every condition (`size` family
  0.667, untouched) — **size is the confirmed residual**. Adding timing normalization drops the joint
  further to 0.681.
- **Consistent with loopback** (`defended_wire_eval.md`): joint `all` loopback 1.000 → 0.767 → 0.700
  vs rig 1.000 → 0.756 → 0.681; size floor 0.667 in both. The real-hardware path does not change the
  conclusion.
- **Clean transport on real NICs:** 0 retransmissions / resets / dup-ACKs; 2160/2160 byte-identical —
  the coalescing mechanism is safe on a real switched network, not just loopback.

## Comparison to loopback (joint `all`, RF, chance 0.333)

| | native | coalesced | coalesced_edt | size floor |
|---|---:|---:|---:|---:|
| loopback (gambit) | 1.000 | 0.767 | 0.700 | 0.667 |
| **two-host rig (Vision↔Hulk)** | 1.000 | **0.756** | **0.681** | 0.667 |

## Evidence

- `rig_defended_wire_eval.json` — full per-condition results, stream→session mapping, TCP health.
- `defended_wire_rig/rig_capture.pcap` — the single real-wire capture of all 18 sessions
  (sha256 `89afba00d317ffb3641ed1652064b04cb588e29c91cc10c204cd0bd5646817ab`).
- Tools: `phase05_rig_defended_wire.py` (orchestrator) + `phase05_rig_replay.py` (rig server/client);
  extractor `characterize_ack_traces.py`; classifier `ack_fingerprint_eval.py`. Full run under the
  git-ignored `runs/20260717T162006Z_phase05_rig_defended_wire/`.

## Status

Per-device defended-wire ACK-mode normalization is now confirmed on **real two-host hardware**
(byte-preserving, no packet loss, joint fingerprint 1.000 → 0.756 → 0.681, size floor 0.667). The
physical three-device eval remains the only stronger, still-deferred check. `next_phase_allowed = false`.

```
STOP: two-host RIG defended-wire ACK-mode normalization confirmed (real Vision<->Hulk hardware, replay of real device bytes); PHYSICAL three-device eval still deferred; size padding remains the out-of-scope residual.
```
