# Defense 1 & Defense 2 — offline-gate status (2026-07-24, offline fallback)

Records the offline acceptance state for Phases 3 (Defense 1) and 4 (Defense 2) reached during the
autonomous run, and the exact blockers that keep them from advancing without hardware or a human decision.
Nothing here is hardware- or relay-validated. Both mechanisms and their reference models already exist in
the repo; this run **verified** their offline gates and made the pytest-style tests runnable in the
pytest-less research venv via `tests/run_offline.py`.

## Offline test results (this run)

```
tests/run_offline.py  ->  test_defense1.py 17/17 · test_defense2.py 10/10 · test_hardening_fix124.py 12/12
```
- Defense-1 reference model `refmodel/defense1_state_machine.py`: zero-inversion (default + randomized
  sweep), response-before-ACK still ordered, high-visibility-delay ordering, reduced-CLRT guard, combined
  bypass, fail-open when no response. **17/17 PASS.**
- Defense-2 reference model `refmodel/defense2_state_machine.py`: deadline-governed release (not maxpass),
  deadline-miss → release at readiness, broken-clock → maxpass degeneration, plus Case-A/…-B invariants.
  **10/10 PASS.**
- Hardening FIX 1+2+4 (exact ACK qualification, lifecycle clear, occupancy one-shot): **12/12 PASS.**

## Compile / resource (measured earlier, unchanged)

- Defense 1 `dcrn_defense1.p4`: bf-p4c 9.13.1 **12/12 ingress** (SRAM 55, TCAM 0, SALU 9). Full, 0 headroom.
- Defense 2 `dcrn_defense2.p4`: **10/12 ingress**, 2 stages headroom (per `ACK_DELAY_DEFENSE2_DESIGN.md`).

## Offline acceptance — Defense 1 (Phase 3)

| Gate item | Status |
|---|---|
| Mechanism implemented | done (frozen `dcrn_defense1.p4`) |
| Compiles + resources recorded | PASS (12/12) |
| Reference model + invariant tests pass | PASS (17/17: zero-inversion, combined bypass, fail-open) |
| Disabled mode preserves baseline | PASS (txncore `enabled=False` transparency; Defense passthrough) |
| No controller in fast path | PASS (structural) |
| **Continuous sequential replay without cold reload (silicon)** | **BLOCKED — needs dp8/GATE-1** |
| Generation-freshness fold (Phase 2) | **BLOCKED — enforcement does not fit 12/12 (human redesign)** |

## Offline acceptance — Defense 2 (Phase 4)

| Gate item | Status |
|---|---|
| Mechanism implemented | done (`dcrn_defense2.p4`) |
| Compiles + resources recorded | PASS (10/12) |
| Reference model + invariant tests pass | PASS (10/10: deadline-governed, miss, broken-clock) |
| **G_i target set decided** | **BLOCKED — 4 disagreeing specs (C2): 60 / 8-12-16-20 / 25-40 / measured ~107 ms** |
| **Recirc-drain/qid calibration (release tracks G)** | **BLOCKED — hardware-only; measured constant ~107 ms, qid not set on recirc** |

## What was deliberately NOT done (per constraints)

- No G_i value was chosen (that is a design decision — contradiction C2, human-gated).
- No calibration was attempted (the recirc-drain/qid fix and its verification are hardware-only; dp8 down).
- Neither frozen P4 was edited. No silicon load, no relay contact.

**Next (human/hardware):** pick the canonical G_i set (resolve C2, and C1 native-CLRT first); once dp8
links, run Defense-2 on silicon to confirm the qid fix makes release deadline-governed; run Defense-1
continuous replay to close its silicon gate; decide the generation-enforcement redesign for the Phase-2/3 fold.
