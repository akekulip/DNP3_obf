# Defense 4 §4 — offline Gate-2 integration: result + dependency wall

**Verdict: Gate 2 (the full integrated §4 timing core) does NOT pass the ≤12-ingress-stage fit — it
hits a register-ordering / stage-budget wall.** The minimal single-deadline core fits at exactly
12/12 (zero headroom), which locates the wall precisely: the full §4 lifecycle's exact-matching and
lifecycle state (four additional registers) cannot be added to the v5 bootstrap within 12 stages.
Per the implementation plan and the Phase-2 directive, no semantic tradeoff was taken — the failed
result is preserved, the wall is characterized below, the smallest behavior-preserving alternatives
are presented, and this **stops for a decision**. No hardware, TM, Gate 3, or size work performed.

## The measurement (three grounded compile points, BF-SDE 9.13.1, offline)

| build | registers | ingress stages | result |
|---|---|---|---|
| v5 bootstrap alone (`bootstrap_probe_v5.p4`, frozen) | 6 | **11 / 12** | 0 errors, tofino.bin |
| **minimal §4: v5 + ONE ACK-deadline hold** (`probes/min_ack_deadline_probe.p4`) | 7 | **12 / 12** | **0 errors, tofino.bin — fits, ZERO headroom** |
| **full §4 integration** (`probes/full_integration_wall_probe.p4`) | 11 | — | **FAILS table placement (register-ordering wall)** |

The minimal-probe register is `reg_deadline` (the frozen D3 modular-sign-bit deadline, mask
`0x800000FF`, armed at native ACK; `dl_cand = now_word + D_A` precomputed in the MAU because bf-asm
cannot assemble a PHV+PHV stateful add — the same class of toolchain limit seen throughout). It adds
`reg_deadline` + four single-op tables (params, mask-ts, or-mark, build-cand, expiry) and lands at
12/12 with critical path 7, SRAM 37, 7 stateful ALUs, 8 stats ALUs, TCAM 1.

Committed minimal-probe source sha256:
`c4da4fbb89925097c762d6e97a5cb6edaaf74a71dd00bf330a41d2c06be31d9b` (this hash is the pre-banner
diagnostic; the in-repo file carries a status banner — recompile it to reproduce 12/12).

## The dependency wall — precisely

The v5 bootstrap already consumes 11/12 stages with a strictly-increasing 6-register chain. Adding
**one** deadline register exhausts the budget (12/12). The full §4 core needs **four more** registers
than the minimal core (11 vs 7):

| register | §4 role (TIMING_SPEC) | in minimal? |
|---|---|---|
| `reg_txn`, `reg_ident_resp`, `reg_resp_stage`, `reg_ident_ack`, `reg_pop_packed`, `reg_failopen` | v5 bootstrap (atomic guard, shadow staging, identities, authoritative K/K, fail-open) | ✅ (6) |
| `reg_deadline` | `T_A`/`T_RESP` deadline (§2) | ✅ (7 → 12/12) |
| `reg_exp_ack` | expected TCP ACK number — exact ACK matching (§6) | ✗ |
| `reg_exp_seq` | expected relay sequence — exact RESPONSE matching (§6) | ✗ |
| `reg_flow_fp` | canonical bidirectional flow fingerprint + collision guard (§6) | ✗ |
| `reg_flags` | `ack_committed_to_master` / `response_present` / D1 event (§4, §6) | ✗ |

The compiler's placement error is a register-ordering conflict (`reg_exp_ack` and `reg_resp_stage`
cannot co-allocate), i.e. the strict per-register single-stage ordering plus the added matching/flag
state has no satisfying assignment within 12 stages. (The preserved full-integration probe also
contains leftover unused tables — its stage count is not a clean number; the **clean** measurement is
the minimal probe's 12/12, which proves there is no room for even one more register beyond
`reg_deadline`, let alone four.)

**Wall statement:** the exact-flow/transaction-matching state (`reg_exp_ack`, `reg_exp_seq`,
`reg_flow_fp`) and the lifecycle flags (`reg_flags`) — all required by TIMING_SPEC §4/§6 and the
implementation plan, and all of which the directive forbids weakening — cannot be added to the v5
bootstrap + one deadline within the 12-stage ingress budget.

## Smallest behavior-preserving alternatives (NOT implemented — for decision)

Per the directive, these are presented for a decision; none weakens exact matching, removes the
atomic guard, moves correctness to the control plane, adds per-transaction controller actions,
changes TM policy, or alters release semantics.

1. **Bounded ingress→egress redistribution.** The egress pipeline is empty (0 stages). The queue
   assignment must stay in ingress (it precedes the TM), but on the loopback/release pass the
   **deadline-expiry compare, the flag reads, and the completion/cleanup bookkeeping** could run in
   egress, freeing several ingress stages. Feasibility needs a study: which registers are read only on
   the loop pass (candidates to move) vs. read on the native pass (must stay ingress). Estimated
   headroom: enough for the 4 matching/flag registers if 3–4 late-chain stages move. **Lowest-risk,
   single-pass, recommended to scope first.**
2. **State packing (no register removed, only merged).** Pack `reg_flags` (already one register for
   three 1-bit flags — verify it stays one SALU). Consider whether `reg_exp_ack` and `reg_exp_seq`
   can share one 32-bit word (they are both exact-match expectations of the same transaction) — this
   keeps exact matching intact. `T_RESP = T_A + D_R` is already computed at compare time from a single
   `reg_deadline` (no second deadline register), which the spec explicitly permits. Estimated
   headroom: 1–2 registers.
3. **Same-Tofino two-pass (recirculation).** Establishment + matching on pass 1; deadline/release on
   pass 2, bridging the transaction key + deadline in a shim (the v5 shim already demonstrates a
   loopback-carried field). Adds a recirculation hop and its latency; heavier — rank last.

**Recommendation:** scope alternative 1 (ingress→egress redistribution) first; it is single-pass,
behavior-preserving, and the empty egress pipeline is free headroom. If it does not yield enough,
compose with alternative 2.

## What this establishes / does NOT

**Establishes (offline):** the frozen D3 deadline mechanism integrates onto the v5 bootstrap and the
minimal single-deadline timing core **fits at 12/12 with zero headroom**; the full §4 lifecycle
(exact matching + flags + deadline) **exceeds the 12-stage budget** — a real, precisely-located
dependency wall, not a coding defect. The `deadline < poll interval` operating condition is
**documented, not a safety mechanism**; the §4 watchdog (which resolves v5's §3-isolation
fail-closed wedge by bounded fail-open) is part of the state that does not yet fit and must be
retained in whichever alternative is chosen.

**Does NOT establish:** a passing integrated Gate-2 artifact, any silicon behaviour, or packet-level
byte identity. **Gate 2 = FAILS the fit; R11 remains OPEN; complete Defense 4 remains NOT
DEMONSTRATED.** The designated core `timing/p4/defense4_timing.p4` is left at its prior WIP; the
integrated core is not committed as passing. **Stopping for a decision on the alternative to pursue.**

## Preserved artifacts
- `probes/min_ack_deadline_probe.p4` — minimal single-deadline core, **compiles 12/12** (the clean floor).
- `probes/full_integration_wall_probe.p4` — the full integration, **does not place** (preserved failed result).
