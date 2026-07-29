# Defense 3 — baseline inventory and freeze

Created 2026-07-29T17:02Z per `meeting_direction.md` §5, before any P4 was written.

## Branch and commits

| Item | Value |
|---|---|
| New branch | `research/case-a-defense3-fixed-ack-delay` |
| Forked from | `research/case-a-read-anchored-dual-release` @ `caa3ecc` |
| **Exploratory artifact — DO NOT LOAD** | `caa3ecc` (READ-anchored dual release) |
| Four-queue oracle — CLOSED | `6ffd5e5`, closure record `47d83de` |
| Proven Defense 2 pktgen baseline | `a163e81` (silicon PASS), P4 introduced `d95f731` |
| Stripped baseline (the Defense 3 START POINT) | `3c50549` — `research/case_a_read_anchored_dual_release/p4/case_a_stripped_baseline.p4`, **8 ingress / 0 egress / critical path 8 / 57 tables** |

## Compilers

| Where | Version |
|---|---|
| Local (gambit) | bf-p4c **9.13.1**, SHA `e558d01`, `~/bf-sde-9.13.1` |
| Switch (ufispace) | bf-p4c **9.13.2**, SHA `1baf055`, `/home/decps/Downloads/bf-sde-9.13.2` |

Both required to PASS per §13 Gate 1. No 9.13.1→9.13.2 drift has ever been observed on this line of work.

## Current switch state (read-only, at freeze)

| Item | Value |
|---|---|
| Program | `dnp3_timing_normalizer_pktgen
1` |
| `bf_switchd` count (`pgrep -cx`) | see above — must be exactly 1 |
| Conf | `/home/decps/defense2_pktgen_compile/pktgen_abs.conf` |
| dp8 shaper (original) | `max_rate_enable=False, max_rate=25010000, BPS, burst 9216, BF_SPEED_25G` |
| Ports configured | dp8 (loopback 25G), dp9 (Vision 25G), dp64 (relay 1G). **dp11 is NOT configured.** |

## Rollback procedure

```bash
research/case_a_read_anchored_dual_release/run/run_four_queue_oracle.sh --restore-only
```
Converge-to-known-good: it does NOT cycle a healthy switch, and it re-asserts the control plane and
verifies five facts — `p4_name`, `strict_priority_verified`, `app_enable=false`, exactly one
`bf_switchd`, dp8 shaping restored. Proven repeatedly, including from real failures.

Manual equivalent: `sudo /home/decps/defense2_pktgen_compile/launch_pktgen.sh` then re-run
`dnp3_timing_normalizer_pktgen_setup.py --config --mode native`.

## FROZEN — do not modify

- `research/defense2_pktgen/` — the proven Defense 2 implementation
- `research/case_a_read_anchored_dual_release/` — the READ-anchored branch, four-queue oracle evidence, prior PCAPs and reports
- `research/ibspg_root_cause_repair/` — prior P3 oracle evidence

Defense 3 copies only what it needs into `research/case_a_defense3/`.

## Carried-forward measured facts (not assumptions)

| Fact | Value | Source |
|---|---|---|
| Per-token blocker pass time at K=64 | **1.715 µs** | Defense 2 gate f: 100000 passes → fail-open at 171.5 ms |
| Blocker aggregate load | ~37.4 Mpps ≈ 25 Gbps on dp8 | derived, cross-checked two ways |
| Deadline release accuracy | ~1.7 µs, ~23 ns spread | Part 12 |
| Release tail | ~1.72 µs | Part 12 |
| Four-level strict priority | behaviorally PROVEN (C reversed) | `FOUR_QUEUE_ORACLE_CLOSED.md` |
| `usage_cells` on dp8 queues | **UNUSABLE — reads 0 always** | five shaper settings incl. one that leaked |
| `pgrep -f bf_switchd` | **OVERCOUNTS (3 for one daemon)** — use `pgrep -cx` | measured |
| Native CLRT (n=100 steady) | min 1.0208, median 1.401, p95 6.863, max 21.695 ms | `out_C3` |
| Native READ→ACK | min 0.400, median 0.505, p99 1.607 ms | `out_C3` |
| `increment_source_port=False` | LOAD-BEARING (else batch caps at 59) | SDE source |
| Relay keepalive | every ~10.02 s, `seq = SND.NXT − 1` | `COLD_WARM_IDLE_CHARACTERIZATION.md` |
