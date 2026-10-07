# Case4 continuation checkpoint — 2026-10-07

**Resume from the [core functionality and testing plan](PLAN.md).** This checkpoint replaces the
2026-10-06 one in full: steps 1 and 2 are done at the level stated below, step 3 is in progress.
The complete target is still absent (no 9.13.2 build, no hardware run); everything here is
source-fragment, whole-program-harness or local-Tofino-model evidence, never hardware-measured.

Base: `388f78a33`, branch `main`, unpushed. Work directly on `main`; preserve frozen sources,
evidence, the paper and unrelated local changes. Lead alone commits, `akekulip <akekulip@gmail.com>`
as author AND committer, no contributor trailers. This checkpoint does not authorize a push or any
hardware action (physical OPERATE is attended-only per repo `CLAUDE.md`).

## What changed since 2026-10-06

- **A whole-program packet harness now exists**: `integration/core/harness/` runs the parser,
  ingress control and deparser of a generated TNA source, with recirculation through the private
  return port, up to 8 passes. It is source-level (a restricted interpreter), not the target; its
  README says so. Tests: `integration/core/harness/tests` (`python3 -m unittest discover -s
  integration/core/harness/tests -p 'test_*.py'`, 42 tests).
- **The local Tofino-1 model runs** inside `unshare -Urn` with an LD_PRELOAD pagemap shim (DMA
  physical addresses are otherwise unavailable to an unprivileged process). Setup, the shim, and a
  reusable launcher/driver are in `integration/core/launch_model.sh`, `integration/core/
  model_driver.py`, `integration/evidence/model_02/RESULT.md`. This is **functional** evidence
  only: the model's clock is not wall time, and it is not hardware. It has independently verified:
  validator, forward/reverse mapping, the selected-wire composition, cross-pipe forwarding
  (4-pipe probe, `model_28`), the e2e mirror, and the packet generator.
- **Native connection binding (`integration/connection/binding/`)** was restructured (a merged
  guard table, banks keyed directly, folded event rows) to fit stage limits, checked against the
  pre-restructure source on **590,976 differential cases, 0 mismatches** (the frozen oracle is
  `tests/oracle_35bf9aa3_native_binding.p4`). It now carries: the step-1 retry/ACK forwarding fix,
  READ kinds 9 (request), 10 (ACK), 11 (response) with a `tev` handoff, the step-3 OPERATE-response
  exchange with per-exchange ACK offset, busy-WorkRecord drop-and-count, whole-segment-resend
  counting, and fixes for three real bugs the model/review found: an epoch-0 endless-recirculation
  wedge, a guard-miss private-envelope leak, and a flow-miss WorkRecord pin. **Current: `native_18`,
  source sha `642dfe54…`, 12 of 12 ingress stages, no spare stage.**
- **A separate READ timing role** `integration/read/read_timing.p4` (copy-evolved from the
  `held_timing_expected_probe.p4`; the probe itself is untouched) implements D_A-parametrized
  ADMIT/hold/release/fallback/policy-off/reset, checked against an independent schedule oracle
  `integration/read/join_reference.py`. **Current: `read_timing_05`, 12 of 12 ingress stages.**
  It runs on the local model functionally (admit and held paths).
- **A step-3 design note** `integration/core/STEP3_DESIGN.md` places roles across Tofino-1's four
  pipes: N (connection) pipe 0 ingress, M (padding/mapping/carve, not yet built) pipe 1, T (timing)
  pipe 2, pipe 3 reserved for step 4. The model's cross-pipe probe confirms the placement is
  physically possible; it does not confirm the pipe-0/pipe-1/pipe-2 port numbers until gate
  G-PORTS runs on the switch (`integration/evidence/model_28/PORTS_PROPOSAL.md` has the current
  device-port table; `ports.p4` and `read_timing.p4`/`native_binding.p4` already use it).
- **A resource canary for role M** (`integration/core/m/m_skeleton.p4`) compiles the mapping,
  geometry and ledger core at exactly 12 of 12 ingress stages in pipe 1, with sequence translation
  checked against the independent transport oracle (`framework/size/case4_transport.py`). The full
  M (padding construct, descriptor build, carve decision, exact-byte replay) is **not yet built** —
  see "Open / stopped" below.

## Open / stopped

- **Role M beyond the canary (step-3 tickets S3-4–S3-6) is stopped, not failed.** The builder
  assigned to it was interrupted twice by a safety classifier while reading the assignment prompt
  and planning the produce/carve work; no code or test exists beyond the committed canary. This is
  an authorized defensive-research task (timing-side-channel mitigation for DNP3, offline/model
  only), and I did not try to reword or route around the stop. If you want this ticket to proceed,
  that decision — and any rephrasing of the task — is yours to make, not mine.
- **The supported-tuple catch-all** (an unparsed-but-matched IP length forwarded natively) needs
  M's mapping-only path and is a documented gap in N until M exists.
- **The foreign-epoch client-bank store** would add a 13th stage to N; pinned as a known limit,
  not fixed.
- **Step 4 (loss/lifecycle, fragment assembly)** is not started; the old assembly layouts
  (`integration/assembly_passes/REPORT.md`) still fail PHV and were not revisited this session.
- **Step 5 (qualification: 9.13.2 build, schema/inventory, hardware package)** is not started.
  `candidate_bringup.py`'s SDE path (`SETUP_DIR`) and controller registry are from the earlier
  framework track and have not been re-verified against the Case 4 sources.
- **No hardware action of any kind occurred.** Every verified claim above is source-fragment,
  whole-program-harness, or local-model evidence; the model's own clock is explicitly not timing
  evidence (`read_timing_model_07`, `model_02/RESULT.md`).

## Reproduce

From this directory:
```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s integration/connection/binding/tests -p 'test_*.py'
python3 -m unittest discover -s integration/controller/tests -p 'test_*.py'
python3 -m unittest discover -s integration/core/harness/tests -p 'test_*.py'
python3 -m unittest discover -s integration/core/m/tests -p 'test_*.py'
python3 -m unittest discover -s integration/read/tests -p 'test_*.py'
```
Compile a changed candidate to a NEW evidence directory with `build.py`; never overwrite retained
evidence. `build.verify_evidence` checks source/compiler/schema identity. `python3 integration/
core/scan_static_entries.py <out>` catches a table whose const entries exceed its declared size
(the defect that stopped `native_04`/retained `handshake_14` loading on the model). The local
model is driven via `integration/core/launch_model.sh` (see `model_17/RESULT.md` and
`model_28/RESULT.md` for usage and what each prior run proved); it needs `unshare -Urn` and the
pagemap shim built once (`integration/evidence/model_02/shim/`).

See `LEDGER.md` for the full dated history of this session's findings and fixes.
