# Defense 4 §4 Gate-2B — result: complete contract does NOT fit ≤12 ingress stages

**Verdict: Gate-2B = FAIL the ≤12-ingress-stage fit.** The complete, reachable Defense 4 §4 timing
contract (all six modes, dual loopback shims, exact matching, generation-qualified qid4 retirement
barrier, bounded watchdogs) is valid P4 — **0 language errors** — but its placement **fails on
register co-location**, not on dependency depth or capacity. State consolidation reduced the register
count (9 vs the failed integration's 11) yet **worsened** placement by concentrating access sites and
metadata pressure. No forbidden lever was taken to force a fit; the failing source and logs are
preserved; the smallest behavior-preserving alternatives are presented; **stopping for a decision**.
No hardware, TM, Gate 3, or size work. R11 OPEN; complete Defense 4 NOT DEMONSTRATED.

## Exact-commit compile (independently reproduced)

| item | value |
|---|---|
| source | `defense4/timing/probes/gate2b_timing_probe.p4` |
| source commit | `38b81dd` |
| source sha256 | `a6399bc38b0ef8b143e514fbad8dad06e80a8cab0d19cce9d9bfdf0c2951c564` (committed blob == HEAD == compiled) |
| compiler | `p4c 9.13.1 (SHA e558d01)`, command `bf-p4c --target tofino --arch tna -o <out> gate2b_timing_probe.p4` |
| **P4-language errors** | **0** (2 benign parser-unroll warnings) |
| **placement** | **FAILS** — `error: Table placement was not able to allocate tbl_…969/993/1023/1051 in the same stage along with Register Ingress.reg_deadline` |
| **critical path (true dependency depth)** | **9** — comfortably < 12, so NOT depth-bound |
| PHV | group **W0-15 (32-bit) = 100% containers / 120% bits — saturated**; overall only 42% |
| resources | SRAM ~71 cells, TCAM 3, ~9–12 SALUs of 48 — all far under budget (NOT capacity-bound) |
| `tofino.bin` | **not produced** ("Skipping assembler, assembly file is empty") |

The exact-commit transcript is `gate2b_exact_compile.log`. Independently recompiled (both `-o` and
`-g`) — the error is deterministic.

## The wall — register CO-LOCATION, precisely (from compiler evidence, not register count)

A Tofino `Register` occupies ONE MAU stage; every RegisterAction on it executes in that stage. Two
accesses to one register at **different control-flow depths** cannot co-locate. The binding failures:

1. **`reg_deadline` has FOUR access sites at different depths** — `dl_reset` (ARM), `dl_arm`
   (native ACK), `dl_read` (held-ACK self-clock loop), `dl_read` (held-RESP self-clock loop). This is
   the direct consequence of the single-`reg_deadline`-serves-both-`T_A`-and-`T_RESP` design. Four
   sites > the 2-phase co-location budget, so it **cannot** share a stage with `reg_pop_packed` — the
   exact placement error. Contrast: in `min_ack_deadline_probe` (12/12) the deadline had only **2**
   sites and co-located with `pop` at stage 8.
2. **`reg_lifecycle` (the C1 consolidation) has ~8 access sites** across native ACK/RESP, both loops,
   ACK-commit, cleanup, and the watchdog — one over-constrained register that pins the tail and
   forces the placement round to ~19 stages.
3. **PHV group W0-15 (32-bit) is saturated at 120% bits** — the ~40 metadata fields concentrate in
   the 32-bit group, and container conflicts there further block the container-sharing that
   co-location needs. (Overall PHV is 42%; the per-GROUP column is the real signal, the same class
   that binds D3/MB-1.)

**The counterintuitive finding: register COUNT is not the fit constraint — per-register
access-site-count × depth-spread (and per-group PHV pressure) is.** Consolidation for count (C1's
`reg_lifecycle`, and the single dual-purpose `reg_deadline`) *reduced* the register total from 11 to
9 but *increased* the access-site concentration, making co-location strictly harder. A confirming
micro-result: merging the two `exp` read-scratch fields to save PHV **coupled** the ACK-only and
RESP-only paths and pushed placement 18→19 / critical path 9→10 — so it was reverted (a direct hit
on the directive's "no shared-metadata coupling ACK/RESP" guardrail).

## What was built (complete + reachable — verified)

9 registers (`reg_txn`, `reg_ident_resp`, `reg_resp_stage`, `reg_ident_ack`, `reg_pop_packed`,
`reg_deadline`, `reg_exp_ack`, `reg_exp_seq`, `reg_lifecycle`) + a static `tbl_flow_own`. No dead
tables; all six modes stay live behind a runtime params table. Independently verified in source:
- **C1** `reg_lifecycle` consolidates `reg_failopen`+`reg_flags`; generation-qualified **by
  construction** (reset at every ARM + every `life_rmw` call-site gated on identity match + one active
  transaction/domain) — the 31-bit gen is NOT truncated into the flag word, and overlapping/duplicate/
  stale/nonmatching packets never reach `life_rmw`.
- **C2** the 16-bit runtime `reg_flow_fp` is removed; `tbl_flow_own` is a static exact-match on the
  bidirectional tuple (no per-transaction controller, no collision window).
- **C3** `reg_exp_ack` and `reg_exp_seq` are separate 32-bit registers (two TCP sequence spaces).
- v5 invariants preserved (atomic `{active,gen}` guard, shadow staging, authoritative K/K,
  gen-qualified identity cells, port-qualified arming, static 7>6>5>4, inactive drain).
- §4 lifecycle present: modes OFF/D1(event-watchdog, not deadline)/D2/D3/D4/FAIL_OPEN; `T_A`/`T_RESP`
  armed at native ACK; dual `{role,gen}` shims (held-ACK + held-RESP, validated + stripped);
  match-before-mutation (identity gated before any hold/latch/lifecycle change); **qid4** retirement
  barrier (NOT qid7) that also retires a no-RESPONSE transaction via the `SHIM_BART` token-watchdog;
  zero-budget → barrier.
- **Byte identity described as preserved by construction, pending packet-level verification** — not
  claimed verified. Silicon continuity not claimed.

**Adversarial lifecycle traces:** because placement fails, no `tofino.bin` exists, so the 22 traces
cannot be run at model level (that requires a placing binary). Source-level review confirmed the
load-bearing items (overlapping-READ side-effect-free; qid4-not-qid7 barrier; no-RESPONSE retirement
via the watchdog barrier; zero-budget→barrier; byte-identity scoping). The full 22-trace model
validation must be re-run on whichever alternative places — it is a Gate-3-adjacent step gated on a
placing construction.

## Smallest behavior-preserving alternatives (NOT implemented — for decision)

None weakens exact matching, removes the atomic guard, moves correctness to the control plane, adds a
per-transaction controller, changes TM policy, adds multipass, or alters release semantics.

1. **Split `reg_deadline` into two registers (`reg_ta`, `reg_tresp`).** Each then has ≤2 access sites
   and can co-locate (as the minimal probe's single 2-site deadline did). This **raises** the count
   to 10 but should **improve** placement — the direct application of the finding that count is not
   the constraint. **Lowest risk, single-pass — recommended to try first.**
2. **Partially de-consolidate `reg_lifecycle`** — split its loop-read flags from its native-write
   flags into two registers so neither is the ~8-site over-constrained word. Trades count for
   co-locatability; single-pass.
3. **PHV relief** — reduce the 32-bit metadata concentration (W0-15) by narrowing/retiming scratch
   fields, without coupling ACK/RESP paths (the merge that backfired shows the constraint).
4. **Bounded ingress→egress redistribution** — move only the loop-only deadline/lifecycle *reads* to
   the empty egress pipeline (egress 0/12). **Explicitly out of Gate-2B scope and NOT authorized;**
   listed for completeness and ranked last.

## Is the egress fallback now justified?

**Not yet.** The wall is co-location + PHV-group saturation, not depth or capacity, and there is at
least one **single-pass, behavior-preserving** alternative (split `reg_deadline`, alt 1) that is
untried and lower-risk than egress redistribution. The egress fallback becomes justified only if the
single-pass co-location alternatives (1–3) also fail. Per the directive, egress redistribution and
two-pass remain unimplemented and unauthorized.

## Preserved artifacts
- `probes/gate2b_timing_probe.p4` (`38b81dd`) — the complete failing source (banner marks it a
  preserved negative probe).
- `evidence/gate2b_exact_compile.log` — the exact-commit compile transcript (0 errors, placement
  failure, no binary).
