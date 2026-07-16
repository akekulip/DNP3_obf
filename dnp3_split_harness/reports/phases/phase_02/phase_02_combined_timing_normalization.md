# Phase 02 — Combined ACK-Bearing Response Normalization (corrected)

Normalize the visible request→response time of piggybacked-ACK (combined) traffic without
changing response bytes, and measure it. This is the **corrected** Phase 02: the earlier
bounded run reset the PRNG every repetition (target coupled to transaction position) and a
log-directory collision cross-contaminated the crc-split configs' server-side timing. Both
are fixed; this run is from a clean committed state.

- **Experiment code commit:** `3306bbaa` (manifest `dirty_tree = false`); analysis
  (projected/figures) at child commit `62b7e979`.
- **Run:** `20260716T123500Z_phase_02_combined_timing_normalization` (git-ignored, regenerable),
  `--reps 50 --run-seed 20260716`.
- **Mechanism:** existing `timing_policy.py` (native/fixed/bounded) + `split_server.py`; Phase 02
  adds only orchestration/analysis (`phase02_*`), no timing/ACK/split change.
- **Tooling:** Python 3.8.10, tshark 4.4.9, scapy 2.4.3, pydnp3.
- **Environment constraint:** loopback packet capture is permission-denied (`dumpcap`
  `root:wireshark`, user not in group) and the two-host rig is unavailable, so the
  **sniffer-PCAP** gate items (wire timestamps, ACK-mode-after-normalization) cannot be
  completed here — the standing CONDITIONAL-PASS blocker.

## Correctness of the corrected bounded sampling

Bounded targets are now drawn from a per-repetition unique seed (`--run-seed` + config + rep,
never from size/type):

- **250 distinct targets across 250 transactions** (bounded/full), mean **24.86 ms**, std
  **2.735 ms** (uniform expectation 2.887), min 20.01 / max 29.99 — a uniform spread over
  [20, 30]. bounded/crc-split independent (mean 24.92, 249 distinct).
- The 2407 B READ now receives **50 distinct targets across 50 reps** (was a single 22.99 ms
  value). No transaction-position → target mapping (`fig06_target_by_position`), and target is
  independent of response size (`fig05_target_vs_size`).
- Determinism: the same `--run-seed` reproduces the whole target sequence; a different seed
  changes it (8 regression tests in `tests/test_phase02_experiment.py`).

## Results (loopback, 2407 B Class-0 READ, n=50 reps/config)

| config | byte-identical | bypassed | deadline miss | READ client-visible median (ms) | p5 / p95 | CI (median) |
|---|---:|---:|---:|---:|---:|---|
| native/full | 100% | 0 | 0 | 0.60 | 0.47 / 0.64 | [0.59, 0.61] |
| fixed25/full | 100% | 0 | 0 | 25.31 | 25.22 / 25.46 | [25.31, 25.31] |
| bounded20-30/full | 100% | 0 | 0 | 25.12 | 20.90 / 29.57 | **[24.06, 26.27]** |
| native/crc-split | 100% | 0 | 0 | 0.74 | 0.43 / 0.78 | [0.73, 0.75] |
| fixed25/crc-split | 100% | 0 | 0 | 25.29 | 25.20 / 25.44 | [25.23, 25.31] |
| bounded20-30/crc-split | 100% | 0 | 0 | 25.62 | 20.69 / 29.68 | **[24.08, 26.60]** |
| fixed300-rto105 (bypass) | 100% | 250 | 0 | 0.64 | 0.33 / 0.71 | [0.63, 0.65] |

The bounded CI is now **wide** (~24–26 ms) and the p5/p95 span ~21–30 ms — reflecting the true
uniform distribution, not the artificially-narrow interval the PRNG defect produced.

## Research questions

- **RQ1 (leakage reduction, measured):** loopback (wide response sizes 17 B–2407 B), visible-time
  correlation with response size drops from **−0.35 (native) to +0.02 (bounded)**, and with
  native-ready time from **+0.69 (native) to +0.009 (bounded)** — the randomized bounded target
  now decorrelates the visible time almost completely (`fig08`, `phase02_decorrelation.json`).
- **RQ2 (correctness):** byte-identity **100% (250/250 per config)**; and a **real pydnp3 master**
  completes a genuine DNP3 integrity poll through the timing path for all 6 native/fixed/bounded ×
  full/crc-split configs (OnTaskComplete + database decode + held-to-target + byte-preservation) —
  see `validation/phase02_pydnp3_integration.md`. So correctness is DNP3 task-level, not just
  replay byte-identity.
- **RQ3 (does a target induce a separate ACK?):** **BLOCKED — needs a sniffer PCAP.** Never asserted.
- **RQ4 (native-tail / deadline leakage):** measured and reported as four distinct metrics
  (below).
- **RQ5 (overhead):** the deliberate hold dominates (≈ target − native); scheduler compute is
  negligible; split delivery adds the existing per-chunk pacing with byte identity preserved.

## Four native-tail metrics (separated)

Projected over the 7,195 real Phase 01 COMBINED transactions (shipped scheduler, real arrival
times; `phase02_projected_leakage.md`). native has no target, so its tail metrics are N/A.

| mode | deadline-miss (scheduler flag) | native>selected (direct) | native>lower bound | native>upper bound |
|---|---:|---:|---:|---:|
| native | n/a | n/a | n/a | n/a |
| fixed25 | 0.0022 | 0.0022 | 0.0022 | 0.0022 |
| bounded20-30 | 0.0032 | 0.0032 | 0.0095 | 0.0006 |

The scheduler flag (col 1) equals the direct native>selected computation (col 2), confirming
semantics. The earlier "0.95%" was **native > 20 ms (lower bound)**, not native > selected
target; the true over-selected-target (deadline-miss) rate is **0.32%** for bounded. For fixed,
lower = upper = selected = 25 ms, so all four coincide.

## Fail-open / bypass

The unsafe config (300 ms target, RTO-safe 105 ms) bypassed **250/250** as `UNSAFE_TARGET`
(visible ≈ native, byte-identity 100%).

## Tests

**54 unit tests pass** on Python 3.8.10 (22 timing_policy + 8 run_manifest + 9 phase01_stats +
7 phase02_policy + **8 phase02_experiment**: rep-seed determinism, position-not-fixed, seed
reproduces sequence, size-independence, uniform distribution mean≈25/std≈2.89, separated tail
metrics, native N/A).

## Figures

Distribution-based (`figures/`), each with a full metadata sidecar (producing_script,
command, source table + SHA-256, run id, git commit, run seed, filters, n, transformation):
target distribution (uniform), client-visible ECDF + box, target-vs-visible, target-vs-size,
target-by-position (the defect check), projected correlation (renamed), and an honest BLOCKED
panel for ACK-mode-after-normalization.

## Measured vs projected vs blocked

- **Measured (loopback):** byte identity; client-observed visible pinned to target; bounded
  target uniform + position/size-independent; decorrelation; fail-open bypass; deadline
  accounting. **Real pydnp3 DNP3 task completion** (loopback).
- **Projected (shipped policy over real device data):** median pinned; size dependence ≈0; the
  four native-tail metrics.
- **Blocked (needs PCAP / rig):** wire timestamps; ACK-mode-after-normalization (RQ3);
  retransmission/reset on the wire.

## Phase 02 gate (§11)

| Requirement | Status |
|---|---|
| bounded sampling correct (PRNG lifecycle) | PASS (250 distinct targets, uniform, position-independent; 8 regression tests) |
| run produced from a clean committed state | PASS (commit `3306bbaa`, `dirty_tree=false`) |
| fixed & bounded modes preserve response bytes | PASS (100%, 250/250 per config) |
| DNP3 task correctness (not just byte identity) | PASS on loopback (real pydnp3, 6/6 configs) |
| native-tail metrics correctly defined | PASS (four separated metrics) |
| timing leakage reduction measured, not asserted | PASS (bounded corr(vis,native) 0.69→0.009) |
| no unsafe timeout / all bypasses reported | PASS (0 deadline miss; bypass 250/250 logged) |
| **wire timing verified by PCAP** | **BLOCKED** — capture permission-denied / no rig |
| **ACK-mode-after-normalization measured** | **BLOCKED** — needs a sniffer PCAP (RQ3) |

**Status: CONDITIONAL PASS.** All software defects are corrected and the run is reproducible
from a clean committed state; DNP3 task correctness is now demonstrated with a real pydnp3
master. The only remaining requirements are the two **wire-capture** items, which cannot be
produced in this environment (no capture permission, no rig) and must be run on Vision/Hulk.
`next_phase_allowed = false`.

```
STOP: Awaiting rig PCAP validation (wire timing + ACK-mode-after-normalization) and human
authorization before Phase 03.
```
