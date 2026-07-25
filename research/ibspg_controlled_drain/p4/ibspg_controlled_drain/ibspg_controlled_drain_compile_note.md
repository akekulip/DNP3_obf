# Gate 9.1 — compile + resource fit [COMPILED]

`ibspg_controlled_drain.p4` — controlled data-plane drain state machine. Source designed by the
p4-dataplane-engineer workstream on the frozen ring-oracle skeleton, reconciled and reviewed by the
main session (state-machine logic + negative-control correctness verified by inspection before compile).

## Provenance
- SHA-256: `3632264f79b640242620d9c5945423d04d170012f85ef01c6b6a967432f85e21`
- Local compiler: bf-p4c 9.13.1 (SHA e558d01), `/home/philip/bf-sde-9.13.1/install/bin`
- On-switch compiler: bf-p4c from BF-SDE 9.13.2 (`/home/decps/Downloads/bf-sde-9.13.2`)
- Command (both): `bf-p4c --target tofino --arch tna -g -o <out> ibspg_controlled_drain.p4`

## Result
| | local 9.13.1 | on-switch 9.13.2 |
|---|---|---|
| exit | 0 | 0 |
| errors | 0 | 0 |
| warnings | 2 (benign `min_parse_depth_accept_loop` unroll — identical to the oracle) | 2 (same) |
| ingress stages | 11 / 12 | 11 / 12 |
| egress stages | 0 | 0 |
| PHV | ~2% | (identical fit) |
| SHA of source | 3632264f… | 3632264f… (byte-identical) |

**No 9.13.2 drift** — identical placement, consistent with the prior project finding that 9.13.2 fit
matches 9.13.1 for this switch.

## Stage structure (why 11 stages) — honest, no hidden placement iterations
First-compile success, no manual placement iteration was needed. The 11 stages are inherent to the
program's data dependencies, NOT a placement failure:
- **Serial state chain (stages 2–7):** `reg_gen` (s2) → `gen_mismatch` compare (s3) → drain-write
  driver (s4) → `reg_drain_req` (s5) → active-clear driver (s6) → `reg_active` + the terminate/loop/
  release/enqueue decision (s7). Each state register read must complete before the next register's
  gate can test its metadata result (the ordering resolution from the design), so they cannot fold.
- **Timestamp bank (stages 8–11):** the 7 fixed-slot ts registers are guarded by event flags set by
  the stage-7 decision, so they place after it; 7 single-call-site SALUs partly serialize into 4
  stages.

Fits with 1 stage of headroom. Acceptance met (within Tofino-1, 0 errors, no unsafe parser, pass-budget
watchdog present and bounded by `seq`). **Shrink levers held in reserve for Part 11** (which adds state):
drop the two informational `reg_ts_*_hold_admit` registers (not used in any required latency calc) to
recover ~1–2 stages; or fold first/last ts pairs. Not applied now — all directive-listed timestamps are
retained and the program fits.

## Register / counter inventory (for the harness name lists)
State registers: `reg_active`, `reg_gen`, `reg_drain_req`.
Timestamp registers (7): `reg_ts_first_block`, `reg_ts_first_hold_admit`, `reg_ts_last_hold_admit`,
`reg_ts_drain_match`, `reg_ts_block_term`, `reg_ts_first_release`, `reg_ts_last_release`.
Counters (12): `ctr_arm`, `ctr_block_enq`, `ctr_hold_enq`, `ctr_drain_match`, `ctr_drain_reject_stale`,
`ctr_drain_reject_unrelated`, `ctr_block_loop`, `ctr_block_term_controlled`, `ctr_block_term_timeout`,
`ctr_block_term_stale`, `ctr_hold_release`, `ctr_nonibspg`.

## Pass-budget safety (code review) [OBS]
`hdr.ib.seq` is the pass budget; a looped BLOCK re-enqueues only in the else-branch after `seq-=1`, and
`budget_zero` (seq==0) forces termination (`ctr_block_term_timeout`) — a runaway ring is impossible
regardless of drain/state. Independent of the drain path (fail-open watchdog).
