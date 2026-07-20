# M1 — `dcrn.p4` compile-fit PASS on bf-p4c 9.13.1 (local) AND 9.13.2 (on-switch)

_Date: 2026-07-20. The local 9.13.1 compile (unprivileged, no switch) was confirmed against the
authoritative on-switch **SDE 9.13.2** compiler — see "On-switch 9.13.2 confirmation" below._

## ✅ On-switch 9.13.2 confirmation (2026-07-20) — the authoritative parity result
Philip authorized the on-switch M1 confirm. Ran the **direct `bf-p4c 9.13.2`** (`p4c 9.13.2 SHA 1baf055`)
on the switch `decps@10.10.54.15` (`ufispace`), work dir `/home/decps/dcrn_m1`, **non-destructively**
(direct compile only — `bf_switchd` NOT restarted, the running program untouched). Source `dcrn.p4` sha256
`204823d8b42fee6bdf49785c99a02ddea70727ddeaa5e71e7f6112a74405ebbf` — **byte-identical on both machines**.
- **Result: 0 errors, 2 warnings** (same benign parser unroll notices as local).
- **Resource fit IDENTICAL to local 9.13.1: 9 ingress stages, critical path 9, 33 logical tables,
  37 SRAMs, 0 TCAMs.** No 9.13.1→9.13.2 lowering drift. Evidence: `p4/build_switch_9.13.2/logs/`.
- **This resolves the "9.13.2 is the final compile confirm" risk in full.** The compile half of M1's
  on-switch acceptance is met. Still pending for full M1: `make install` (loadable artifact) + the
  dp8↔dp9 byte-identical **wire-forwarding** test (needs the gated `bf_switchd` restart displacing
  the co-resident program + a `dcrn.conf` + host harness). Nothing on the switch data plane was altered.

---


## Command
```bash
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o <OUT> dcrn.p4
```
- Compiler: `bf-p4c 9.13.1`, target `tofino`, arch `tna`.
- `dcrn.p4` sha256 `8a22c0c535cbb9ed51a8800ca970de0da094e6a283d91ad1c93a0bce46373405`.
- Result: **0 errors, 2 warnings** (both benign parser `max_loop_depth` unroll notices). Compile 5.1 s.

## Resource fit (from `logs/table_summary.log` + `logs/metrics.json`, copied to `build_local_9.13.1/logs/`)
| Resource | Used | Tofino-1 budget | Note |
|---|---|---|---|
| Ingress stages | **9** | 12 | critical path length 9; 3 stages headroom |
| Egress stages | 0 | 12 | egress is pure pass-through |
| Logical tables | 33 | — | 33 allocated, all within scope (no `*` over-scope flag) |
| SRAMs | 37 | 80/stage × 12 | comfortable |
| TCAMs | 0 | 24/stage × 12 | no ternary match used |
| Map RAMs | 34 | — | register/counter backing |
| Ingress latency | 221 cycles | — | |
| Power estimate | 1.73 (ingress) | — | low |

## The two genuine unknowns M1 was meant to resolve — both RESOLVED (on 9.13.1)
1. **17-deep dependency chain > 12 stages** (the prior blocker). The restructure — one unconditional
   prologue (`now_tick`/`dir`/`payload_len`/`flow_id` computed once, in parallel) + mutually-exclusive
   `if/else-if/else` with no early `return` + a **single** `check_deadline` call site (reg_deadline down
   to arm-write + check-read) + one indexed events Counter — collapses the chain. **Fits in 9 stages.**
2. **`check_deadline` runtime-operand SALU predicate** — `meta.now_eff >= dl` compares a runtime PHV
   operand against the stored 32-bit register word (the one SALU shape not seen in lab code, where SALUs
   only compare against constants). **It lowered cleanly (0 errors)** → the constant-biased two-RegisterAction
   fallback is NOT needed. Resolves the compile-side of **Q1**.

## Honest deviation from the plan's soft estimate
- Plan M1 acceptance target: **ingress ≤ ~7 stages**. Actual: **9**. Within the hard 12-stage wall
  (3 stages of headroom) but **above the ~7 estimate** in `on_switch_dcrn_implementation_plan.md` and the
  `~5-7 stages [I]` note in `dcrn.p4`. Not a failure (12 is the constraint), but the code comment/plan
  estimate should be corrected to "9 stages measured." Tightening below 9 (if ever needed for coexistence
  headroom) would push telemetry counters to egress and/or merge the guard-bias into the compare — not
  required for a standalone DCRN load.

## What M1 does NOT yet establish (still GATED / pending)
- On-switch **SDE 9.13.2** compile + `make install` (9.13.1 vs 9.13.2 can differ on lowering/idioms).
- dp8↔dp9 **byte-identical forwarding** on the wire (needs the switch — the M1 forwarding acceptance test).
- M2+ (recirc-hold, clock-refresh probe, dual-case, fail-open, rig campaign) — all unbuilt/gated.

## Verdict
**M1 compile-fit PASS on the local 9.13.1 compiler.** The Tofino/P4 realization of DCRN is
resource-feasible as written: it compiles, fits in 9/12 stages, and the runtime-operand deadline
compare lowers. The remaining risk moves off "will it compile" and onto the **on-switch confirm +
hardware behavior** (9.13.2 parity, clock-refresh-on-recirc, sparse-frame pacing) — all requiring
explicit authorization to touch the switch.
