# Case4 continuation checkpoint — 2026-10-07

Continue directly from [PLAN.md](PLAN.md#execution-checklist--2026-10-07).
Core transport is the active step: ACK/window normalization, SELECT response,
then OPERATE padding/carving and replay. Full Case4 remains incomplete.

SDK constraint: use the switch's existing version; no updates. Read-only
inspection confirms `p4c9.13.2 (SHA:1baf055)` at
`/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf-p4c` on `decps@10.10.54.81`.
`installed_sdk_build.py` compiles in private temporary directories without chip
activation or software changes. Older local9.13.1 results remain development
evidence, not installed-version qualification.

## Accepted first SELECT milestone

External SYN/SYNACK/ACK then SELECT35 produce one exact109-byte Ethernet frame
with55-byte padded payload in the isolated local model. Genuine completion leaves
N Work9, M4 and E4; no ownership/cache/register proof presets were configured.
Normal100, zero0 and wrapped0xfffffff0 coordinates each pass6/6 checks:
[verification and packet identities](integration/core/ordinary/evidence/split_verification_01/verification.json).
Lead freshly reran52 source/config tests successfully. IP/TCP checksums and DNP3
CRCs independently pass for all three retained endpoint frames.

| Same modeled device0 role | Exact source SHA prefix | Build | Ingress / egress | Critical path |
| --- | --- | --- | --- | --- |
| N + final emitter, pipe0 | `610d129d7446` | `nf_02` |12 /4 |11 |
| M preparation/activation, pipe1 | `c8820a1f7f14` | `m3_01` |10 /0 |9 |
| E cache + typed bridge, pipe3 | `dae2efee6c5e` | `e3_02` |1 /10 |7 |

All three programs loaded together using
[the source-bound split configuration](integration/core/ordinary/evidence/model_config_split_01/bindings.json).
Pipe2 is reserved for the T join. N still uses all12 ingress stages; M now has two
spare stages. NF's normal32 PHV is62/64, SALUs4/4 at7–9 and table IDs16/16
at1 and10. M peaks at2/4 SALUs and5/16 table IDs. E image SALUs occupy4/4
at4–6; retain the full image instead of narrowing identity checks for capacity. Failed coupled N/E14-stage compositions are retained, not fit claims.
The split retains all14 image banks, full owner/epoch/generation checks, actual
publication/completion returns and a full32 current-generation emission receipt.
Component sources and rendering are in [ordinary/README.md](integration/core/ordinary/README.md).

Observed first-SELECT model accounting:19 ingress visits,6 service egress visits,
18 private TX records totaling2346 Ethernet bytes excluding model trailers,
plus an internal24-byte completion header. This is functional model accounting;
TM/fabric and physical wire service are not measured. Successful runs omit the
model's `--int-port-loop` flag; front ports remain cold-added with loopback NONE.
Failed front-loop attempts and the SYN-only controlled comparison are preserved.

## Remaining core work, in execution order

1. ACK/window inverse before N association, including inside-insertion clamps,
   both edges, zero-window and full32 wrap; completed SELECT owner18 and its57-byte
   matching response. Avoid the older N response's second20-byte subtraction.
2. OPERATE35→55, matching57-byte response carved into exactly ordered28/29,
   both insertions, every subsequent packet mapped, sender-driven cached-tail repair.
3. Actual READ/T timing join and current-association OPERATE deadlines; finite
   fallback, independent heartbeat and genuine credits.
4. Post-M cancellation, duplicate/stale emission model witnesses, loss/lifecycle,
   fragments/resegmentation, reset/FIN/reconnect/exhaustion and complete retirement.
5. Complete exact9.13.2 offline build/model/schema/controller inventory and rollback
   package. The qualification registry stays empty until the complete target passes.

Full transport, timing and hardware gates in [PLAN.md](PLAN.md) remain unchecked.
The52 tests and18 model checks qualify this first-SELECT slice only. Earlier
590,976-case results include no-leak-only branches and are not that many full
state/packet equivalences. Original N/T prerequisite model evidence is retained
with its own exact sources; it does not qualify the new full target.

## Continuation boundaries

Use one continuing implementer and one bounded reviewer. Lead integrates and
commits on `main` as `akekulip <akekulip@gmail.com>` for author AND committer,
without contributor trailers. No push. Preserve unrelated `CLAUDE.md`, frozen
sources/evidence and the paper. Local isolated model/source work is authorized;
live loading and physical port/TM/PRE/mirror/pktgen changes or traffic retain their
separate gates. Physical OPERATE is attended-only. No hardware action occurred.

## Historical continuation notes

The following notes retain earlier identities and limits. Their old words
"current" and "not yet" describe those checkpoints; the accepted split milestone
above and [PLAN.md](PLAN.md) define the present execution state.

The following continuation details retain pre-review historical identities;
the current facts above and the linked PLAN supersede their role and completion claims.

**Resume from the [core functionality and testing plan](PLAN.md).** This checkpoint replaces the
2026-10-06 one in full: historical step1/2 prerequisite results below do not close
the current connection/timing acceptance gates; step3 remains unfinished.
The complete target is still absent (no 9.13.2 build, no hardware run); everything here is
source-fragment, whole-program-harness or local-Tofino-model evidence, never hardware-measured.

Historical base: `388f78a33`; current base is stated above, branch `main`, unpushed. Work directly on `main`; preserve frozen sources,
evidence, the paper and unrelated local changes. Lead alone commits, `akekulip <akekulip@gmail.com>`
as author AND committer, no contributor trailers. This checkpoint does not authorize a push or any
hardware action (physical OPERATE is attended-only per repo `CLAUDE.md`).

## What changed since 2026-10-06

- **A restricted N source packet harness exists**: `integration/core/harness/` runs the parser,
  ingress control and deparser of a generated TNA source, with recirculation through the private
  return port, up to 8 passes. It is source-level (a restricted interpreter), not the target; its
  README says so. It does not implement the composed M/T/egress/TM path. Tests: `integration/core/harness/tests` (`python3 -m unittest discover -s
  integration/core/harness/tests -p 'test_*.py'`, 42 tests).
- **The local Tofino-1 model runs** inside `unshare -Urn` with an LD_PRELOAD pagemap shim (DMA
  physical addresses are otherwise unavailable to an unprivileged process). Setup, the shim, and a
  reusable launcher/driver are in `integration/core/launch_model.sh`, `integration/core/
  model_driver.py`, `integration/evidence/model_02/RESULT.md`. This is **functional** evidence
  only: the model's clock is not wall time, and it is not hardware. It has independently verified:
  validator, forward/reverse mapping, the selected-wire composition, cross-pipe forwarding
  (4-pipe probe, `model_28`), the e2e mirror, and the packet generator.
- **Native connection binding (`integration/connection/binding/`)** was restructured (a merged
  guard table, banks keyed directly, folded event rows) to fit stage limits. The
  historical590,976-case grid reports zero failures, but includes guard-miss
  branches that check only private-header refusal; it is not590,976 full state/
  packet equivalences. READ is outside that grid and has separate invariant and
  direct tests. The frozen oracle is `tests/oracle_35bf9aa3_native_binding.p4`.
  The baseline also carries the step-1 retry/ACK forwarding fix,
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
  parser/apply receiving ports196/197. The historical canary occupies12 stages;
  current admission/replay repairs fail15 stages and require protected staged integration;
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
