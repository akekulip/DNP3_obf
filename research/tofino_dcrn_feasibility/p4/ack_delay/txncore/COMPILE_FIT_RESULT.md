# Phase 2 "fits a variant" — measured compile-fit result (bf-p4c 9.13.1, local)

Bounded offline compile experiment during the 2026-07-23 autonomous run. Converts the plan's predicted
risk ("generation freshness adds a register read on ≥2 paths — risk of pushing Defense 1 past 12 stages
→ will require a compact redesign", `END_TO_END_IMPLEMENTATION_PLAN.md` §5) into a measured fact.

Compiler: `bf-p4c 9.13.1` (SHA e558d01), `--target tofino --arch tna`. Tofino-1 has 12 ingress MAU
stages. All three programs were compiled unprivileged on gambit; no switch involved.

| Program | Result | Ingress stages | Note |
|---|---|---|---|
| `dcrn_defense1.p4` (FROZEN baseline) | **compiles** (exit 0) | **12 / 12** (stages 0–11) | zero headroom — confirms the plan's "12/12 full" |
| `dcrn_defense1_gen.p4` — generation **carried** (bump@arm + stamp@both hold-enters) | **compiles** (exit 0) | **12 / 12** (`reg_gen` placed at stage 5) | the hardcoded `bridge.gen = 0` becomes a real per-flow generation; still fits |
| generation **enforced** (adds the recirc `reg_gen` read + staleness flush) | **does NOT compile** | placement fails | table-placement exhaustion, not an idiom |

### The enforcement failure (measured, verbatim)

```
error: Table placement was not able to allocate tbl_..._gen594, tbl_..._gen504 in the same stage
       along with Register DcrnIngress.reg_expected_ack
error: Table placement was not able to allocate tbl_..._gen593, tbl_..._gen628, tbl_..._gen503 in the
       same stage along with Register DcrnIngress.reg_armed
```
(`evidence/gen_enforce_placement_error.log`; baseline + stamp-only resource maps in `evidence/`.)

Two P4 idiom issues were fixed along the way and are **not** the blocker (both are standard Tofino
constraints, mechanically resolved): (1) a `RegisterAction.execute()` result cannot be assigned directly
into a header field inside a no-key-table action → hoist into a temp; (2) the indexed `events` Counter
cannot be counted non-mutually-exclusively in the recirc block → signal the flush via `bridge.event`
instead. After both fixes, the remaining failure is genuine **stage/dependency exhaustion**: the third
`reg_gen` touch on the recirc path cannot co-allocate with `reg_armed`/`reg_expected_ack` inside the
12-stage budget.

### Conclusion

- The generation can be **carried** (bumped + stamped) within the existing 12/12 budget — a real,
  compiling improvement over the frozen hardcoded `gen = 0`. That variant is `dcrn_defense1_gen.p4` here.
- **Enforcing** it (the recirc read that actually discards stale stragglers) does **not** fit as a naive
  add. This is exactly the compact redesign the plan anticipated: free a stage, restructure the register
  dependency chain, or trade a feature. That is a materially new design decision and is **left for a
  human-authorized architecture step (red-line #8)** — not invented autonomously here.
- The freshness **logic** is fully validated offline regardless, in the Python reference model + tests
  (`txncore_refmodel.py`, `tests/test_txncore.py`, `replay_txncore.py`) — the enforcement is a silicon
  resource question, not a logic question.

**Nothing here is hardware-validated** — these are local compiles only; dp8 remained physically blocked.
