# Hold-continuity K-sweep — the measured floor is K = 44, at every D

**2026-08-03. Final repaired SYNTHETIC build (`d3_final_synth.conf`, p4_name
`case_a_defense3`), one Gate-2 synthetic transaction per trial, entirely in-chip.
96 trials: {D = 2 ms: K ∈ {1..64}, D = 8/16 ms: K ∈ {8..64}} × 3 reps, plus the
36–48 refinement and the K = 44 cross-D check. The K = 64 safety pin was relaxed BY NAME
(`--allow-reduced-k-hold`; every manifest carries `reduced_k_hold_sweep: true`); the
budget was scaled per (K, D) as B = max(18000, ceil((D + 6.5 ms)·rate/K)) so the horizon
never binds — coverage is the only variable under test. Switch restored to Defense 2 and
verified afterward. Hardware run explicitly authorized by Philip this session.**

## The question

At each D, how many reservoir tokens K keep the held ACK in Q_HOLD all the way to the
deadline t_ACK + D? The fig13 model predicted K_req(D) = max(K_cov, ceil((D + c)·rate/B))
with a coverage floor K_cov ≈ 16 *estimated* from the Part-12 loop RTT (408 ns).

## The result

| D (ms) | last EARLY K | first CLEAN K | floor (3/3 reps) |
|---|---|---|---|
| 2  | 40 | 44 | **44** |
| 8  | 40 | 44 | **44** |
| 16 | 40 | 44 | **44** |

- **The floor is D-independent, as the model's structure predicts — but it sits at 44
  tokens, not the estimated ~16.** The 408 ns RTT this estimate borrowed from the Part-12
  program does not transfer: the Defense 3 build's recirculation loop is ~3× longer.
- **CLEAN trials** (K ≥ 44): all K tokens terminate DEADLINE, `RELEASE_DEADLINE = 1`, and
  the release bias equals the τ = K/rate model: +1.7 µs at K = 64, +1.1–1.3 µs at 44–48.
  **The R5 release-bias model is confirmed on silicon at four K values.**
- **EARLY trials** (K ≤ 40): the ACK escapes after almost exactly K/rate (e.g. 847 ns at
  K = 32 vs. τ = 856 ns; 1036 ns at K = 40 vs. 1069 ns): the TM drains the reservoir once
  at line rate and Q_BLOCK sits empty until the first token returns from its loop — the
  hold never re-establishes. The orphaned tokens keep recirculating until the early
  release retires the generation, then all K terminate STALE (K of K, zero DEADLINE) —
  the counters match this account exactly. Zero fail-opens anywhere (B never binds).
- **Implied loop RTT of this build: (1036, 1176] ns** — from hold(K=40) still gapping and
  K = 44 · (1/37.4 MHz) = 1176 ns covering. The continuity condition is K/rate ≥ RTT_loop,
  i.e. K_cov = ceil(RTT_loop × rate) = 44 at the measured rate.

## What it changes

- fig13's coverage floor is corrected from "≈16 (estimated)" to **44 (measured)**; the
  per-D requirement becomes K_req(D) = max(44, budget bound) — at the deployed B = 18000
  the budget bound overtakes 44 only above D ≈ 15.2 ms.
- **The deployed K = 64 stands**, now with a *measured* margin: 64/44 ≈ 1.45× the floor
  (20 tokens). K = 44 itself has zero margin and must not ship; K = 48 held cleanly at
  every tested D but with only 4 tokens of headroom.
- The negative-result note (`negative_results/kmin_refused_by_safety_pin/`) is superseded
  in one respect: the sweep it said "requires explicitly relaxing that pin" has now been
  run, with the relaxation on the record.

## Provenance

- Runner: `run/ksweep_hold.sh` (+ `run/ksweep_hold_refine.sh`), one Gate-2 transaction
  per trial via `run_defense3.sh --gate2` with `KVAL`/`D_MS`/`BUDGET`/
  `D3_ALLOW_REDUCED_K_HOLD=1`, `D3_SKIP_RESTORE=1`.
- Classification: `analysis/analyze_ksweep_hold.py` → `summary.json`
  (CLEAN / EARLY / FAILOPEN / INVALID, ±1 µs tolerance on the deadline).
- Per-trial records: `gate2_*/gate2_txn.json` (registers `reg_ts_ack_arm`/
  `reg_ts_ack_release`, termination counters, full manifest); `manifest.jsonl` maps
  (K, D, B, rep) → record directory.
- Sweep-only B values are NOT deployment values; deployment stays K = 64, B = 18000.
