# Phase 04B — DCRN Target Calibration

_Derived from the six authoritative device PCAPs; eligible class = routine solicited READ (function code 1). No target is hard-coded; every value below comes from the real captures._

## Effective RTO and guards
- Measured effective TCP RTO: **211 ms** (`rto_probe.py`, TCP_RTO_MIN). **Must be re-measured on the Vision master before the rig runs.**
- Scheduler guard: **3.0 ms** (PROVISIONAL — re-derive from a real fq/EDT calibration run).
- RTO safety guard: **60.0 ms** → **Dhigh < 151.0 ms**.

### How Dhigh = 151 ms was derived
`Dhigh = effective_RTO - rto_safety_guard = 211 - 60 = 151 ms.` The 60 ms guard (~28% of the measured
RTO) is deliberately generous because: (a) the 211 ms figure is the Linux `TCP_RTO_MIN` floor measured
by `rto_probe.py` and is **provisional** — the real Vision master's effective RTO must be re-measured
during the privileged campaign and may differ; (b) RTO is not constant (it adapts to RTT/variance), so a
single measured value should not be approached closely; (c) a hold that reaches the RTO would risk a
spurious retransmission, which is a hard safety failure on control traffic. The guard trades a slightly
smaller usable window for a wide safety margin. Since the derived target (32.4 ms) sits far below Dhigh
(151 ms), the margin costs nothing here. If the re-measured Vision RTO is materially lower, Dhigh and the
target are recomputed from that value before any run.

## Pooled request→response readiness (all three profiles, READ class)

| bucket | n | median | p90 | p95 | p99 | p99.9 | max |
|---|--:|--:|--:|--:|--:|--:|--:|
| all | 5694 | 16.01 | 17.75 | 19.31 | 23.01 | 29.39 | 97.99 |
| first-in-connection | 6 | 16.50 | 18.80 | 19.57 | 20.18 | 20.32 | 20.34 |
| non-first | 5688 | 16.01 | 17.75 | 19.30 | 23.02 | 29.39 | 97.99 |

## Per-profile readiness (median / p99 / max, ms) and ACK mode

| profile | READ txns | ACK mode | median | p99 | max |
|---|--:|---|--:|--:|--:|
| SEL751 | 2098 | separate (2098 sep / 0 comb) | 15.96 | 25.72 | 35.06 |
| AB1400 | 1198 | combined (0 sep / 1198 comb) | 16.33 | 17.91 | 95.29 |
| ION7550 | 2398 | combined (0 sep / 2398 comb) | 15.96 | 19.11 | 97.99 |

## Derived target window

- Pooled **p99 = 23.01 ms**, **p99.9 = 29.39 ms**, **max = 97.99 ms**.
- **Cover p99.9:** Dlow = p99.9 + guard = **32.39 ms** → deadline-miss rate **0.0702%**.
- **Cover p99:** Dlow = p99 + guard = **26.01 ms** → deadline-miss rate **0.3688%**.
- **Window feasible below RTO:** True (Dlow 32.39 < Dhigh 151.00).

**Recommendation:** P1_FIXED target **32.39 ms**; P2_COMMON_BOUNDED **[32.39, 42.39] ms** — one distribution for every profile, seeded, never device-dependent. The residual tail above the target (chiefly SEL-751 slow responses up to 98.0 ms) is retained and passed native as a **reported deadline miss**.

```
STOP: calibration only. Targets derived, not yet applied. eBPF DCRN implementation + PI-run wire campaign pending.
```
