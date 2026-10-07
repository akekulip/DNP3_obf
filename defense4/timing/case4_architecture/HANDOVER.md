# Case4 continuation checkpoint — 2026-10-07

Current continuation: [PLAN.md](PLAN.md). Task1 source-bound evidence is
[integration/evidence/TASK1_VERIFICATION.json](integration/evidence/TASK1_VERIFICATION.json).
The historical results below retain their original identities.

Task1 fix-round current N `721fd4b7…` fits12/0,critical11
(`task1_fix_n_01`); T `52b43d5a…` fits12/0,critical12 (`task1_fix_t_04`).
The exact-source N0/T2 composition `task1_fix_nt_01` passes40 N/T model cases
in `task1_fix_nt_model_01` and50 T model cases in `task1_fix_t_model_02`.
Full suites: N84 with one existing coalesced finalACK+SELECT skip; T103 pass.
Logs/identity checks are in `integration/evidence/task1_fix_verification_01`.
Earlier N05/T06/model34/35 had the two reviewed races and are historical evidence.

Terminals now consume full owner/epoch checks. Returning T requests cancel before
mint/install/commit, carry refusal through genuine Work terminals, and forward
once while preserving installed receipts and consumed cookies. Model paused
boundary fixtures are distinguished from the genuine full-packet source races.
The raw-close parse token remains epoch-derived, not an observed Work generation.
The old T selector12→11 A/B is historical; current guard chain uses12 stages.
Current T stage4 grows from old0/9/59 SALUs/tables/xbar to1/9/63, an explicit
resource concern. Model clocks prove functional commit order, not physical timing
or normal deadline priority. No controller rearm authority exists.

M receiving ports196/197 remain source-bound to `task1_m_ports_01`,12/0;
its production/rendering path remains unfinished. Complete retirement/loss,
full Case4,9.13.2 qualification, physical port authority and hardware remain open.

The following continuation details retain pre-review historical identities;
the current Task1 facts above and the linked PLAN supersede their N/T claims.

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
  wedge, a guard-miss private-envelope leak, and a flow-miss WorkRecord pin. **Previous baseline: `native_18`,
  source sha `642dfe54…`, 12 of 12 ingress stages, no spare stage.**
  **Correction (found by the 2026-10-07 acceptance audit): the 68/71-step model agreement
  (`model_24`–`model_27`) ran against `native_11` (sha `c2352572…`), one commit before the
  flow-miss fix and two before the port renumbering. `native_18` itself carries only a bare
  `primitive_compiled` manifest — it has NOT been loaded on the model or diffed against the
  harness. Do not read "model-verified" as applying to the committed `native_18` source until
  that rerun exists.**
- **A separate READ timing role** `integration/read/read_timing.p4` (copy-evolved from the
  `held_timing_expected_probe.p4`; the probe itself is untouched) implements D_A-parametrized
  ADMIT/hold/release/fallback/policy-off/reset, checked against an independent schedule oracle
  `integration/read/join_reference.py`. **Previous baseline: `read_timing_05`, 12 of 12 ingress stages.**
  **Correction (same audit): the one passing held-path model run (`read_timing_model_05`) was
  launched against `read_timing_04` (sha `01b93f01…`), not `read_timing_05` (sha `d2b35563…`,
  the port-renumbered current source, different hash). `read_timing_05` has not been run on the
  model either.**
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

- **Role M beyond the canary is unfinished (plan step3).** Task1 only normalizes
  parser/apply receiving ports196/197. The canary already occupies12 stages;
  actual35→55 production, descriptor/carve decisions and exact replay must be
  integrated and measured before any complete-target claim. Earlier planning
  interruptions remain historical evidence, not a qualification result.
- **The supported-tuple catch-all** (an unparsed-but-matched IP length forwarded natively) needs
  M's mapping-only path and is a documented gap in N until M exists.
- **Foreign-epoch client/server stores and terminal leakage are repaired in Task1.**
  The exact current build stays within12 stages; see the current evidence index above.
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
