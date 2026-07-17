# Phase 05 — Two-Host Vision–Hulk Defended-Wire Replay Evaluation: Result

**PASS.** **Two-host defended-wire replay evaluation on Vision and Hulk using profiles derived from
captured SEL-751, AB1400, and ION7550 traffic.** The per-profile replay runs across the real switched
1 G management path: Hulk (outstation side) replays each profile's real bytes and reproduces its ACK
mode, Vision (master side) drives the client, Hulk captures on `eno1` (non-sudo, wireshark group). This
is the **authoritative joint measurement** for Phase 05. See the closeout
`phase_05_ack_mode_normalization.md` (Section 6). Run `20260717T162006Z_phase05_rig_defended_wire`.
`next_phase_allowed = false`.

_Scope: real server-grade NICs and a real switched two-host path, but a reproduction of each device's
measured observables — **not** the three physical target devices (external, not on this rig)._

## Method

`phase05_rig_defended_wire.py` (dev-box orchestrator) + `phase05_rig_replay.py` (stdlib rig
server/client). One `dumpcap` on Hulk `eno1` captures all 18 sessions (3 conditions × 6 profile
captures) as distinct TCP streams (sequential sessions → k-th stream is session k). Each capture is
re-characterized and classified exactly as the loopback eval (capture-level split, RF `n_estimators=200`,
seed 0, chance 0.333, 119 test transactions/profile, balanced accuracy = raw accuracy).

## Wire integrity (real hardware)

| condition | separate-ACK (SEL / AB / ION) | retrans | resets | dup-ACKs |
|---|---|---:|---:|---:|
| native | 1.00 / 0.00 / 0.00 | 0 | 0 | 0 |
| coalesced | 0.00 / 0.00 / 0.00 | 0 | 0 | 0 |
| coalesced_edt | 0.00 / 0.00 / 0.00 | 0 | 0 | 0 |

Client replay **2160/2160 byte-identical**; **18/18 streams mapped**; **0 retransmissions / 0 resets /
0 duplicate ACKs** across 714 non-first transactions per condition on real NICs (no resets within
established sessions).

## Classifier (Random Forest, capture-level split, chance 0.333)

| feature family | native | coalesced | coalesced_edt |
|---|---:|---:|---:|
| mode_only | 0.667 | **0.333 (constant / non-discriminating)** | 0.333 (constant) |
| ack_timing | 0.751 | 0.524 | 0.317 |
| ack_combined (was ack_only) | 0.751 | 0.524 | 0.317 |
| timing | 0.501 | 0.524 | 0.317 |
| size | 0.667 | 0.667 | 0.667 |
| **all** | **1.000** | **0.756** | **0.681** |

All-features confusion (rows = true, cols = predicted; 119 test txns each):

```
[native]           AB1400  ION7550   SEL751      [coalesced]        AB1400  ION7550   SEL751
  AB1400              119        0        0         AB1400               67        0       52
 ION7550                0      119        0        ION7550                0      119        0
  SEL751                0        0      119         SEL751               35        0       84
```

- **`mode_only` 0.667 → 0.333 (constant / non-discriminating):** the categorical ACK-mode feature is
  removed on the real wire.
- **Joint `all` 1.000 → 0.756 → 0.681:** coalescing collapses **SEL-751 ↔ AB1400** (they share a 54 B
  response); **ION7550 stays 119/119 by its distinct 61 B response** — response size is the dominant
  stable residual.
- Consistent with loopback on the stable channels (`mode_only`, `size`); the rig is more reliable for
  the joint `all` because its capture is deterministic and the path is a real network.

Evidence: `rig_defended_wire_eval.json` (full per-family results + stream mapping + TCP health);
`defended_wire_rig/rig_capture.pcap` (sha256 `89afba00…`); full run under the git-ignored
`runs/20260717T162006Z_phase05_rig_defended_wire/`.
